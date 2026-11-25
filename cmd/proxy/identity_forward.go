package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/identityclient"
)

// forwardOpts are the resolved flags of `identity forward`.
type forwardOpts struct {
	listen, worker, healthListen, credentialEnv string
	maxTunnels                                  int
}

func (r *identityRunner) forwardCmd() *cobra.Command {
	var o forwardOpts
	cmd := leaf(&cobra.Command{
		Use:   "forward --listen addr --worker host:port [flags]",
		Short: "Run the token-injecting CONNECT forwarder as a long-lived sidecar.",
		Long: "Listens on --listen and, for every CONNECT, opens a CONNECT to the one --worker with the current " +
			"token as Proxy-Authorization, so a child that read HTTPS_PROXY once keeps working while tokens " +
			"rotate, and no token is ever in the child's container. It dials only --worker, never the CONNECT " +
			"target, and answers any method but CONNECT with 405.\n\n" +
			"With --agent-id (or " + identityclient.EnvAgentID + ") the token is the agent's Warden token, exchanged " +
			"at --token-endpoint with the agent's key and the user's ID token (from the login cache, or " +
			"--subject-token-file); without it the user's ID token from the login cache is sent. A worker 407 " +
			"forces one refresh and a retry. With no usable token a CONNECT gets 503 with the reason in " +
			"X-Warden-Forwarder-Reason (login_required, cp_unreachable or exchange_denied); the forwarder keeps " +
			"retrying the exchange and never exits because of it, including during the minutes after a control " +
			"plane creates its first token key.\n\n" +
			"--client-credential-env NAME makes clients send the value of that environment variable as the " +
			"Proxy-Authorization password (user wx); it is never forwarded. --health-listen serves GET /healthz " +
			"with the token state (valid, expiring, login_required, cp_unreachable or exchange_denied) and exp, " +
			"never the token. Logs are structured events on stderr and never hold a token. SIGTERM and SIGINT " +
			"stop accepting and give open tunnels 5 seconds.",
		RunE: func(cmd *cobra.Command, _ []string) error { return r.runForward(cmd, o) },
	})
	fl := cmd.Flags()
	fl.StringVar(&o.listen, "listen", "", "address the forwarder listens on, host:port")
	_ = cmd.MarkFlagRequired("listen")
	fl.StringVar(&o.worker, "worker", "", "worker explicit-proxy listener, host:port")
	_ = cmd.MarkFlagRequired("worker")
	fl.IntVar(&o.maxTunnels, "max-tunnels", 512, "most CONNECTs served at once; more get 503")
	fl.StringVar(&o.healthListen, "health-listen", "", "serve GET /healthz on this `addr` (off by default)")
	fl.StringVar(&o.credentialEnv, "client-credential-env", "", "NAME of the environment variable whose value clients must send as the proxy password")
	return cmd
}

func (r *identityRunner) runForward(cmd *cobra.Command, o forwardOpts) error {
	if _, _, err := net.SplitHostPort(o.worker); err != nil || strings.ContainsAny(o.worker, "/@ ") {
		return errors.New("--worker must be host:port")
	}
	if _, _, err := net.SplitHostPort(o.listen); err != nil {
		return fmt.Errorf("--listen %q: %w", o.listen, err)
	}
	if o.maxTunnels < 1 {
		return errors.New("--max-tunnels must be at least 1")
	}
	var credential string
	if o.credentialEnv != "" {
		if credential = r.deps.getenv(o.credentialEnv); credential == "" {
			return fmt.Errorf("--client-credential-env %s: the variable is not set or is empty", o.credentialEnv)
		}
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelInfo}))

	fw := &identityclient.Forwarder{
		WorkerAddr: o.worker, ClientCredential: credential, AllowAnonymousClients: credential == "",
		MaxTunnels: o.maxTunnels, Log: log,
	}
	run := identityclient.ForwardRun{Forwarder: fw, Log: log}
	if r.agentMode() {
		src, err := r.agentTokenSource(cmd, "")
		if err != nil {
			return err
		}
		// A CONNECT must not wait out several retries: it fails fast with the
		// reason and the source's own backoff retries the exchange.
		src.Attempts = 1
		fw.Source = src
		run.State = src.State
		run.Poke = func(ctx context.Context) { _, _ = src.Token(ctx) }
	} else {
		c, err := r.client(cmd)
		if err != nil {
			return err
		}
		cs := &identityclient.ClientState{Client: c}
		fw.Token = cs.Token
		run.State = cs.State
		run.Poke = func(ctx context.Context) { _, _ = cs.Token(ctx) }
	}

	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	run.Listener = ln
	if o.healthListen != "" {
		hl, err := net.Listen("tcp", o.healthListen)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("health listen: %w", err)
		}
		run.Health = hl
		defer func() { _ = hl.Close() }()
	}
	defer func() { _ = ln.Close() }()

	if host, _, _ := net.SplitHostPort(ln.Addr().String()); !isLoopbackHost(host) {
		log.Warn("the forwarder listens on a non-loopback address: any peer that can reach it can use the token",
			"listen", ln.Addr().String(), "client_credential", credential != "")
	} else if credential == "" {
		log.Info("no client credential: any local process can use the forwarder")
	}
	log.Info("forwarder_start", "listen", ln.Addr().String(), "worker", o.worker, "agent_mode", fw.Source != nil,
		"max_tunnels", o.maxTunnels, "health", o.healthListen != "")

	sigs, stopSigs := notifySignals()
	if r.deps.signals != nil {
		sigs, stopSigs = r.deps.signals()
	}
	defer stopSigs()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-sigs:
			cancel()
		case <-ctx.Done():
		}
	}()
	return identityclient.RunForwarder(ctx, run)
}

// isLoopbackHost reports whether host is localhost or a loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
