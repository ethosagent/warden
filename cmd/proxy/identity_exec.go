package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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
		worker, listen, ca, signInNotify string
		includeHTTP, challenge, inTunnel bool
		passEnv                          []string
	)
	cmd := &cobra.Command{
		Use:   "exec --worker host:port [flags] -- COMMAND [ARGS...]",
		Short: "Run a command behind a loopback forwarder that injects the identity token.",
		Long: "Starts a forwarder on loopback, runs COMMAND with HTTPS_PROXY pointing at it and waits for it. " +
			"The forwarder takes a fresh ID token from the login cache for every new CONNECT and sends it to the " +
			"worker, so the token is never in the command's environment or arguments. The command sees only " +
			"a random per-run proxy credential.\n\n" +
			"The command does not inherit the whole environment. It gets PATH, HOME, USER, LOGNAME, SHELL, TERM, " +
			"TMPDIR, TZ, LANG and the LC_* locale variables when they are set, plus the proxy, NO_PROXY and --ca " +
			"variables exec sets. Pass any other variable, such as an API key, by name with --env NAME (repeatable); " +
			"its value is read from this environment, never from the command line. --env refuses the proxy " +
			"variables and WARDEN_IDENTITY_*.\n\n" +
			"Without a login, a terminal runs the device-code login on stderr; otherwise exec exits 2 without " +
			"starting the command. With --challenge (or --signin-notify) exec starts without a login and lets the " +
			"worker ask for one: a worker in identity challenge mode answers the first request with a 407 and a " +
			"sign-in URL, which exec prints on stderr as `warden: sign in at URL (code CODE)`; exec then waits for the " +
			"sign-in at the issuer, stores the login and sends the token on later requests. The agent sees the 407 " +
			"without the device code. With --challenge-in-tunnel exec asks a TLS-terminating worker to send the challenge " +
			"inside the tunnel instead: the CONNECT succeeds and the agent's first request gets a 403 whose " +
			"error.message holds the link, which an agent that never reads a 407 body shows in its chat. " +
			"--signin-notify COMMAND also runs COMMAND (through sh -c) with the URL in " +
			"WARDEN_SIGNIN_URL and the code in WARDEN_SIGNIN_CODE, for a chat message or a desktop notification; it " +
			"never gets a token. The exit code is the command's, or 128+N when signal N killed it. A command " +
			"running as the same user can still read the identity cache file; use another user for the command.",
		SilenceUsage: true, SilenceErrors: true,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.runExec(cmd, args, execOpts{worker: worker, listen: listen, ca: ca, includeHTTP: includeHTTP,
				passEnv: passEnv, challenge: challenge || inTunnel || signInNotify != "", inTunnel: inTunnel,
				signInNotify: signInNotify})
		},
	}
	cmd.Flags().SetInterspersed(false) // flags after COMMAND belong to the command
	fl := cmd.Flags()
	fl.StringVar(&worker, "worker", "", "worker explicit-proxy listener, host:port")
	_ = cmd.MarkFlagRequired("worker")
	fl.StringVar(&listen, "listen", "127.0.0.1:0", "loopback address of the forwarder")
	fl.StringVar(&ca, "ca", "", "CA bundle `PATH` to export as SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE and NODE_EXTRA_CA_CERTS")
	fl.BoolVar(&includeHTTP, "include-http", false, "also set HTTP_PROXY and http_proxy (the worker denies plain http)")
	fl.BoolVar(&challenge, "challenge", false, "start without a login and sign in through the worker's 407 sign-in challenge (identity.defaultMode: challenge)")
	fl.BoolVar(&inTunnel, "challenge-in-tunnel", false, "with --challenge, ask the worker to send the sign-in challenge inside the tunnel, so the agent's own request gets a 403 that names the link (needs a TLS-terminating worker); implies --challenge")
	fl.StringVar(&signInNotify, "signin-notify", "", "run `COMMAND` (sh -c) when a sign-in is needed, with WARDEN_SIGNIN_URL and WARDEN_SIGNIN_CODE set; implies --challenge")
	fl.StringArrayVar(&passEnv, "env", nil, "pass the environment variable `NAME` to the command as well (repeatable; name only, the value is read from the environment)")
	return cmd
}

// execOpts are the resolved flags of `identity exec`.
type execOpts struct {
	worker, listen, ca string
	includeHTTP        bool
	passEnv            []string
	// challenge starts without a login and lets the worker's 407 drive it;
	// signInNotify is the hook command run when a sign-in is needed.
	challenge    bool
	signInNotify string
	// inTunnel asks the worker for the challenge inside the tunnel (#621).
	inTunnel bool
}

func (r *identityRunner) runExec(cmd *cobra.Command, args []string, o execOpts) error {
	worker, listen, ca, includeHTTP, passEnv := o.worker, o.listen, o.ca, o.includeHTTP, o.passEnv
	if _, _, err := net.SplitHostPort(worker); err != nil || strings.ContainsAny(worker, "/@ ") {
		return errors.New("--worker must be host:port")
	}
	if err := loopbackListenAddr(listen); err != nil {
		return err
	}
	for _, n := range passEnv {
		if err := identityclient.ValidatePassthroughName(n); err != nil {
			return err
		}
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
	if errors.Is(err, identityclient.ErrLoginRequired) && o.challenge {
		// No login yet: the worker's sign-in challenge will ask for one.
		err = nil
	}
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
	lookup := os.LookupEnv
	if r.deps.lookupEnv != nil {
		lookup = r.deps.lookupEnv
	}
	fwLog := slog.New(slog.NewTextHandler(errw, &slog.HandlerOptions{Level: level}))
	fw := &identityclient.Forwarder{
		WorkerAddr: worker, ClientCredential: credential,
		Token: func(ctx context.Context) (string, error) {
			res, err := c.Token(ctx)
			return res.IDToken, err
		},
		Log: fwLog, InTunnel: o.inTunnel && o.challenge,
	}
	fctx, stopFwd := context.WithCancel(ctx)
	var hooks sync.WaitGroup
	if o.challenge {
		fw.Challenge = &identityclient.Challenger{
			Client: c, Log: fwLog,
			Notify: signInNotifier(fctx, errw, o.signInNotify, lookup, &hooks),
		}
	}
	fwdDone := make(chan error, 1)
	go func() { fwdDone <- fw.Serve(fctx, ln) }()
	defer func() { stopFwd(); <-fwdDone; hooks.Wait() }()

	env, warnings, err := identityclient.BuildChildEnv(lookup, identityclient.LoopbackProxyURL(ln.Addr(), credential),
		identityclient.ChildEnvOptions{IncludeHTTP: includeHTTP, CA: ca, Passthrough: passEnv})
	if err != nil {
		return err
	}
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

// signInHookTimeout bounds one --signin-notify command.
const signInHookTimeout = 30 * time.Second

// signInNotifier returns the Challenger's Notify: it prints the sign-in line on
// errw and, when hook is set, starts it in the background (tracked by wg, bound
// by ctx and a timeout). The hook runs through `sh -c` with the same small
// environment as the supervised child plus WARDEN_SIGNIN_URL and
// WARDEN_SIGNIN_CODE; it never gets a token, a device code or any
// WARDEN_IDENTITY_* setting.
func signInNotifier(ctx context.Context, errw io.Writer, hook string, lookup func(string) (string, bool), wg *sync.WaitGroup) func(url, code string) {
	return func(url, code string) {
		_, _ = fmt.Fprintf(errw, "warden: sign in at %s (code %s)\n", url, code)
		if hook == "" {
			return
		}
		var env []string
		for _, n := range identityclient.ChildEnvAllowlist {
			if v, ok := lookup(n); ok {
				env = append(env, n+"="+v)
			}
		}
		env = append(env, "WARDEN_SIGNIN_URL="+url, "WARDEN_SIGNIN_CODE="+code)
		hctx, cancel := context.WithTimeout(ctx, signInHookTimeout)
		c := exec.CommandContext(hctx, "sh", "-c", hook)
		c.Env, c.Stdout, c.Stderr = env, errw, errw
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			if err := c.Run(); err != nil {
				_, _ = fmt.Fprintf(errw, "warden: the --signin-notify command failed: %v\n", err)
			}
		}()
	}
}

// notifySignals subscribes to the signals exec forwards.
func notifySignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	return ch, func() { signal.Stop(ch) }
}
