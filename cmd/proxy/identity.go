package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/identityclient"
)

// Exit codes of the identity commands; anything else that fails exits 1.
const (
	exitLoginRequired     = 2
	exitIssuerUnreachable = 3
)

// maxTokenInput caps a token read from stdin or a file; real ID tokens are a
// few KiB.
const maxTokenInput = 64 << 10

// exitError carries a process exit code through cobra to main.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}
func (e *exitError) Unwrap() error { return e.err }

// exitCode is the process exit code for an error returned by Execute.
func exitCode(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// identityDeps are the process-level inputs of the identity commands, so tests
// can replace them.
type identityDeps struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	openFile func(string) (io.ReadCloser, error)
	stdin    io.Reader
	// lookupEnv reads one parent variable for the `exec` child; nil selects
	// os.LookupEnv. The parent environment is never enumerated (rule X3).
	lookupEnv func(string) (string, bool)
	// signals delivers the signals `exec` forwards; nil subscribes to the
	// process's SIGTERM, SIGHUP, SIGINT and SIGQUIT.
	signals func() (<-chan os.Signal, func())
	// tune adjusts the client after construction (tests inject a fake sleeper).
	tune func(*identityclient.Client)
}

func defaultIdentityDeps() identityDeps {
	return identityDeps{getenv: os.Getenv, readFile: os.ReadFile, openFile: func(p string) (io.ReadCloser, error) { return os.Open(p) }, stdin: os.Stdin}
}

// identityFlags are the persistent flags of `warden identity`.
type identityFlags struct {
	issuer, clientID, audience, secretEnv, cacheDir string
	scopes                                          []string
	verbose                                         bool
}

func newIdentityCmd() *cobra.Command { return newIdentityCmdWith(defaultIdentityDeps()) }

// newIdentityCmdWith builds the `identity` subtree. It never reads the root
// --config (the worker config): its settings come from its own flags, the
// WARDEN_IDENTITY_* variables and identity.yaml, resolved by identityclient.
// cmd/ stays thin: all logic lives in internal/identityclient.
func newIdentityCmdWith(deps identityDeps) *cobra.Command {
	f := &identityFlags{}
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Log in to the identity issuer and get tokens for the worker.",
		Long: "Commands for an agent, script or harness to obtain an OIDC ID token from the " +
			"configured issuer and route through the Warden worker. These commands do not read " +
			"the worker --config. Exit codes: 2 login is required, 3 the issuer is unreachable " +
			"and no valid cached token remains, 1 any other error.",
	}
	pf := cmd.PersistentFlags()
	pf.StringVar(&f.issuer, "issuer", "", "OIDC issuer URL (env WARDEN_IDENTITY_ISSUER); https, or http on loopback only")
	pf.StringVar(&f.clientID, "client-id", "", "OAuth client id (env WARDEN_IDENTITY_CLIENT_ID; default "+identityclient.DefaultClientID+")")
	pf.StringVar(&f.audience, "audience", "", "expected token audience (env WARDEN_IDENTITY_AUDIENCE; default "+identityclient.DefaultAudience+")")
	pf.StringVar(&f.secretEnv, "client-secret-env", "", "NAME of the environment variable holding the client secret of a confidential client")
	pf.StringSliceVar(&f.scopes, "scopes", nil, "scopes added to "+strings.Join(identityclient.DefaultScopes, ","))
	pf.StringVar(&f.cacheDir, "cache-dir", "", "token cache directory (env WARDEN_IDENTITY_CACHE_DIR)")
	pf.BoolVar(&f.verbose, "verbose", false, "log issuer, client id, scopes, expiry and a token fingerprint to stderr (never a token)")

	r := &identityRunner{deps: deps, f: f}
	cmd.AddCommand(r.loginCmd(), r.tokenCmd(), r.statusCmd(), r.envCmd(), r.logoutCmd(), r.execCmd())
	return cmd
}

type identityRunner struct {
	deps identityDeps
	f    *identityFlags
}

// leaf finishes a subcommand: the error is printed once by main, not by cobra.
func leaf(c *cobra.Command) *cobra.Command {
	c.SilenceUsage = true
	c.SilenceErrors = true
	c.Args = cobra.NoArgs
	return c
}

func (r *identityRunner) config() (identityclient.Config, error) {
	return identityclient.LoadConfig(identityclient.Flags{
		Issuer: r.f.issuer, ClientID: r.f.clientID, Audience: r.f.audience,
		ClientSecretEnv: r.f.secretEnv, Scopes: r.f.scopes, CacheDir: r.f.cacheDir,
	}, r.deps.getenv, r.deps.readFile)
}

func (r *identityRunner) client(cmd *cobra.Command) (*identityclient.Client, error) {
	cfg, err := r.config()
	if err != nil {
		return nil, err
	}
	level := slog.LevelError
	if r.f.verbose {
		level = slog.LevelDebug
	}
	c := &identityclient.Client{
		Config: cfg,
		Getenv: r.deps.getenv,
		Log:    slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level})),
	}
	if r.deps.tune != nil {
		r.deps.tune(c)
	}
	return c, nil
}

// mapErr turns the library's sentinel errors into exit codes.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, identityclient.ErrLoginRequired):
		return &exitError{exitLoginRequired, err}
	case errors.Is(err, identityclient.ErrIssuerUnreachable):
		return &exitError{exitIssuerUnreachable, err}
	}
	return err
}

func warn(cmd *cobra.Command, msgs ...string) {
	for _, m := range msgs {
		if m != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+m)
		}
	}
}

func (r *identityRunner) loginCmd() *cobra.Command {
	return leaf(&cobra.Command{
		Use:   "login",
		Short: "Log in with the OAuth device code flow.",
		Long: "Starts the RFC 8628 device authorization grant. The verification URI and user code " +
			"are printed to stderr; open the URI in any browser and enter the code.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := r.client(cmd)
			if err != nil {
				return err
			}
			warnings, err := c.Login(cmd.Context(), cmd.ErrOrStderr())
			if err != nil {
				return mapErr(err)
			}
			warn(cmd, warnings...)
			fmt.Fprintln(cmd.ErrOrStderr(), "logged in")
			return nil
		},
	})
}

func (r *identityRunner) tokenCmd() *cobra.Command {
	return leaf(&cobra.Command{
		Use:   "token",
		Short: "Print a valid ID token to stdout.",
		Long: "Prints the ID token to stdout, refreshing it first when it is past two thirds of its " +
			"lifetime. It never prompts: with no valid login it exits 2.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := r.client(cmd)
			if err != nil {
				return err
			}
			res, err := c.Token(cmd.Context())
			if err != nil {
				return mapErr(err)
			}
			warn(cmd, res.Warning)
			fmt.Fprintln(cmd.OutOrStdout(), res.IDToken)
			return nil
		},
	})
}

func (r *identityRunner) statusCmd() *cobra.Command {
	return leaf(&cobra.Command{
		Use:   "status",
		Short: "Show the cached login. Never prints the token.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := r.client(cmd)
			if err != nil {
				return err
			}
			st, err := c.Status()
			if err != nil {
				return mapErr(err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "iss: %s\n", st.Issuer)
			fmt.Fprintf(out, "sub: %s\n", st.Subject)
			fmt.Fprintf(out, "email: %s\n", st.Email)
			fmt.Fprintf(out, "groups: %s\n", strings.Join(st.Groups, ","))
			fmt.Fprintf(out, "exp: %s\n", st.Expiry.UTC().Format(time.RFC3339))
			fmt.Fprintf(out, "cache: %s\n", st.CachePath)
			return nil
		},
	})
}

func (r *identityRunner) logoutCmd() *cobra.Command {
	return leaf(&cobra.Command{
		Use:   "logout",
		Short: "Delete the cached login.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := r.client(cmd)
			if err != nil {
				return err
			}
			if err := c.Logout(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "logged out")
			return nil
		},
	})
}

func (r *identityRunner) envCmd() *cobra.Command {
	var (
		worker, tokenFile, ca, shell, format string
		tokenStdin, includeHTTP              bool
	)
	cmd := leaf(&cobra.Command{
		Use:   "env --worker host:port",
		Short: "Print proxy environment variables for an explicit-proxy agent.",
		Long: "Prints HTTPS_PROXY and https_proxy (credentials session:<token>) and NO_PROXY for the " +
			"worker's explicit-proxy listener, for `eval \"$(warden identity env ...)\"` or a dotenv " +
			"file. It is for explicit-proxy agents: a transparent-mode worker needs no proxy variables.\n\n" +
			"The token comes from the login cache, or from --token-stdin or --token-file. It is never " +
			"accepted as a command-line value. The output contains the token and goes to stdout only; " +
			"any process started with these variables can read it.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tokenStdin && tokenFile != "" {
				return errors.New("use only one of --token-stdin and --token-file")
			}
			opts := identityclient.EnvOptions{CA: ca, Shell: shell, Format: format, IncludeHTTP: includeHTTP}
			if format != "" && format != identityclient.FormatDotenv && format != identityclient.FormatJSON {
				return fmt.Errorf("unknown --format %q (dotenv or json)", format)
			}
			token, exp, err := r.envToken(cmd, tokenStdin, tokenFile)
			if err != nil {
				return err
			}
			out, err := identityclient.ProxyEnv(worker, token, opts)
			if err != nil {
				return err
			}
			errw := cmd.ErrOrStderr()
			if exp.IsZero() {
				fmt.Fprintln(errw, "warning: the token expiry is unknown")
			} else {
				fmt.Fprintf(errw, "token expires at %s\n", exp.UTC().Format(time.RFC3339))
			}
			fmt.Fprintln(errw, "warning: any child process started with these variables can read the token")
			if includeHTTP {
				fmt.Fprintln(errw, "note: the worker denies plain http, so HTTP_PROXY only makes http requests fail at the worker")
			}
			_, err = io.WriteString(cmd.OutOrStdout(), out)
			return err
		},
	})
	fl := cmd.Flags()
	fl.StringVar(&worker, "worker", "", "worker explicit-proxy listener, host:port")
	_ = cmd.MarkFlagRequired("worker")
	fl.BoolVar(&tokenStdin, "token-stdin", false, "read the ID token from stdin instead of the login cache")
	fl.StringVar(&tokenFile, "token-file", "", "read the ID token from `PATH` instead of the login cache")
	fl.StringVar(&ca, "ca", "", "CA bundle `PATH` to export as SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE and NODE_EXTRA_CA_CERTS")
	fl.StringVar(&shell, "shell", identityclient.ShellSh, "output shell: sh, fish or powershell")
	fl.StringVar(&format, "format", "", "output format instead of a shell script: dotenv or json")
	fl.BoolVar(&includeHTTP, "include-http", false, "also set HTTP_PROXY and http_proxy (the worker denies plain http)")
	return cmd
}

// envToken returns the token for `env` and its expiry (zero when unknown). The
// cache path needs the issuer configuration; stdin and file tokens do not.
func (r *identityRunner) envToken(cmd *cobra.Command, fromStdin bool, file string) (string, time.Time, error) {
	var raw []byte
	var err error
	switch {
	case fromStdin:
		raw, err = io.ReadAll(io.LimitReader(r.deps.stdin, maxTokenInput+1))
	case file != "":
		raw, err = readCapped(r.deps.openFile, file)
	default:
		c, cerr := r.client(cmd)
		if cerr != nil {
			return "", time.Time{}, cerr
		}
		res, terr := c.Token(cmd.Context())
		if terr != nil {
			return "", time.Time{}, mapErr(terr)
		}
		warn(cmd, res.Warning)
		return res.IDToken, res.Expiry, nil
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read token: %w", err)
	}
	if len(raw) > maxTokenInput {
		return "", time.Time{}, errors.New("token input is larger than 64 KiB")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", time.Time{}, errors.New("the token input is empty")
	}
	exp, _ := identityclient.TokenExpiry(token)
	return token, exp, nil
}

// readCapped reads at most maxTokenInput+1 bytes of the named file, so an
// oversize file is refused without being buffered whole.
func readCapped(open func(string) (io.ReadCloser, error), path string) ([]byte, error) {
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxTokenInput+1))
}
