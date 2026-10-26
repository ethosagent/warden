package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/identityclient"
)

// execProcess adapts an *exec.Cmd to identityclient.Process.
type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Signal(sig os.Signal) error { return p.cmd.Process.Signal(sig) }

func (p execProcess) Wait() (int, os.Signal, error) {
	err := p.cmd.Wait()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil, nil
	case errors.As(err, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return -1, ws.Signal(), nil
		}
		return ee.ExitCode(), nil, nil
	}
	return 0, nil, err
}

// stdinIsTerminal reports whether r is a terminal: a character device other
// than /dev/null.
func stdinIsTerminal(r any) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(st, null)
}

// loopbackListenAddr validates that addr is host:port on a loopback address.
func loopbackListenAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", addr, err)
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 0 || n > 65535 {
		return fmt.Errorf("--listen %q: port must be a number from 0 to 65535", addr)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--listen %q is not a loopback address; the forwarder only listens on loopback", addr)
	}
	return nil
}

func (r *identityRunner) execCmd() *cobra.Command {
	var (
		worker, listen, ca string
		includeHTTP        bool
	)
	cmd := &cobra.Command{
		Use:   "exec --worker host:port [flags] -- COMMAND [ARGS...]",
		Short: "Run a command behind a loopback forwarder that injects the identity token.",
		Long: "Starts a forwarder on loopback, runs COMMAND with HTTPS_PROXY pointing at it and waits for it. " +
			"The forwarder takes a fresh ID token from the login cache for every new CONNECT and sends it to the " +
			"worker, so the token is never in the command's environment or arguments. The command sees only " +
			"a random per-run proxy credential.\n\n" +
			"Without a login, a terminal runs the device-code login on stderr; otherwise exec exits 2 without " +
			"starting the command. The exit code is the command's, or 128+N when signal N killed it. A command " +
			"running as the same user can still read the identity cache file; use another user for the command.",
		SilenceUsage: true, SilenceErrors: true,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.runExec(cmd, args, worker, listen, ca, includeHTTP)
		},
	}
	cmd.Flags().SetInterspersed(false) // flags after COMMAND belong to the command
	fl := cmd.Flags()
	fl.StringVar(&worker, "worker", "", "worker explicit-proxy listener, host:port")
	_ = cmd.MarkFlagRequired("worker")
	fl.StringVar(&listen, "listen", "127.0.0.1:0", "loopback address of the forwarder")
	fl.StringVar(&ca, "ca", "", "CA bundle `PATH` to export as SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE and NODE_EXTRA_CA_CERTS")
	fl.BoolVar(&includeHTTP, "include-http", false, "also set HTTP_PROXY and http_proxy (the worker denies plain http)")
	return cmd
}

func (r *identityRunner) runExec(cmd *cobra.Command, args []string, worker, listen, ca string, includeHTTP bool) error {
	if _, _, err := net.SplitHostPort(worker); err != nil || strings.ContainsAny(worker, "/@ ") {
		return errors.New("--worker must be host:port")
	}
	if err := loopbackListenAddr(listen); err != nil {
		return err
	}
	c, err := r.client(cmd)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	errw := cmd.ErrOrStderr()
	terminal := stdinIsTerminal(r.deps.stdin)

	_, err = c.Token(ctx)
	if errors.Is(err, identityclient.ErrLoginRequired) && terminal {
		warnings, lerr := c.Login(ctx, errw)
		if lerr != nil {
			return mapErr(lerr)
		}
		warn(cmd, warnings...)
		_, err = c.Token(ctx)
	}
	if err != nil {
		return mapErr(err)
	}

	credential, err := identityclient.NewProxyCredential(nil)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	level := slog.LevelError
	if r.f.verbose {
		level = slog.LevelInfo
	}
	fw := &identityclient.Forwarder{
		WorkerAddr: worker, ClientCredential: credential,
		Token: func(ctx context.Context) (string, error) {
			res, err := c.Token(ctx)
			return res.IDToken, err
		},
		Log: slog.New(slog.NewTextHandler(errw, &slog.HandlerOptions{Level: level})),
	}
	fctx, stopFwd := context.WithCancel(ctx)
	fwdDone := make(chan error, 1)
	go func() { fwdDone <- fw.Serve(fctx, ln) }()
	defer func() { stopFwd(); <-fwdDone }()

	environ := os.Environ
	if r.deps.environ != nil {
		environ = r.deps.environ
	}
	env, warnings := identityclient.BuildChildEnv(environ(), identityclient.LoopbackProxyURL(ln.Addr(), credential),
		identityclient.ChildEnvOptions{IncludeHTTP: includeHTTP, CA: ca})
	warn(cmd, warnings...)

	sigs, stopSigs := notifySignals()
	if r.deps.signals != nil {
		sigs, stopSigs = r.deps.signals()
	}
	defer stopSigs()

	child := exec.CommandContext(ctx, args[0], args[1:]...)
	child.Env = env
	child.Stdin = r.deps.stdin
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = errw
	code, err := identityclient.Run(ctx, identityclient.ExecSpec{
		Start: func() (identityclient.Process, error) {
			if err := child.Start(); err != nil {
				return nil, err
			}
			return execProcess{child}, nil
		},
		Signals: sigs, StdinIsTerminal: terminal,
	})
	if err != nil {
		return err
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

// notifySignals subscribes to the signals exec forwards.
func notifySignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	return ch, func() { signal.Stop(ch) }
}
