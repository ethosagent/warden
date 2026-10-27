package identityclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
)

// ProxyClientUser is the user name of the per-run proxy credential the child
// presents to the loopback Forwarder.
const ProxyClientUser = clientUser

// loopbackNoProxy keeps loopback traffic off the proxy.
const loopbackNoProxy = "localhost,127.0.0.1,::1"

// NewProxyCredential returns a per-run secret of 128 random bits from r
// (crypto/rand when nil), hex encoded.
func NewProxyCredential(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("identityclient: generate proxy credential: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// LoopbackProxyURL is http://wx:<credential>@<addr>, the HTTPS_PROXY value of
// the supervised child. addr is the listener address.
func LoopbackProxyURL(addr net.Addr, credential string) string {
	u := url.URL{Scheme: "http", User: url.UserPassword(ProxyClientUser, credential), Host: addr.String()}
	return u.String()
}

// ChildEnvAllowlist names the parent variables every supervised child gets
// when they are set: the ones a shell, a locale and a terminal need. Every
// other parent variable reaches the child only through
// ChildEnvOptions.Passthrough. The LC_* names are listed one by one because the
// parent environment is looked up by name, never enumerated (rule X3).
var ChildEnvAllowlist = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TMPDIR", "TZ",
	"LANG", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
	"LC_MONETARY", "LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS",
	"LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION",
}

// proxyVarNames are the proxy variables, upper cased, that the child gets
// only from BuildChildEnv itself.
var proxyVarNames = map[string]bool{"ALL_PROXY": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true}

// ValidatePassthroughName reports whether name may be passed from the parent
// to the child with `--env`. It refuses a name that is not a shell variable
// name (NAME=VALUE included, so a value never sits in argv), a proxy variable
// in any case and a WARDEN_IDENTITY_* variable in any case: those are what the
// child environment strips on purpose.
func ValidatePassthroughName(name string) error {
	if strings.Contains(name, "=") {
		return fmt.Errorf("--env %q: give a variable name only; its value is read from the environment", name)
	}
	if !validEnvName(name) {
		return fmt.Errorf("--env %q is not a valid variable name", name)
	}
	up := strings.ToUpper(name)
	if proxyVarNames[up] {
		return fmt.Errorf("--env %s: the proxy variables are set by exec and cannot be passed through", name)
	}
	if strings.HasPrefix(up, "WARDEN_IDENTITY_") {
		return fmt.Errorf("--env %s: WARDEN_IDENTITY_* variables never reach the command", name)
	}
	return nil
}

// validEnvName reports whether s matches [A-Za-z_][A-Za-z0-9_]*.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// ChildEnvOptions selects optional parts of the child environment.
type ChildEnvOptions struct {
	// IncludeHTTP also sets HTTP_PROXY and http_proxy.
	IncludeHTTP bool
	// CA is a CA bundle path exported through CAVars.
	CA string
	// Passthrough names further parent variables to copy, beyond
	// ChildEnvAllowlist. Each must pass ValidatePassthroughName.
	Passthrough []string
}

// BuildChildEnv returns the environment of the supervised child. lookup reads
// one parent variable (os.LookupEnv in the CLI). The child gets the set
// variables of ChildEnvAllowlist and of opts.Passthrough, then HTTPS_PROXY and
// https_proxy set to proxyURL, NO_PROXY and no_proxy set to loopback,
// HTTP_PROXY and http_proxy only with IncludeHTTP, and the CA variables with
// CA. Nothing else from the parent reaches it, so an API key or a
// WARDEN_IDENTITY_* setting stays behind unless it is named. It fails when a
// Passthrough name is refused by ValidatePassthroughName. The warnings say
// what was skipped or overridden; they never hold a value, because an
// inherited proxy URL may carry credentials.
func BuildChildEnv(lookup func(string) (string, bool), proxyURL string, opts ChildEnvOptions) (env []string, warnings []string, err error) {
	for _, n := range opts.Passthrough {
		if err := ValidatePassthroughName(n); err != nil {
			return nil, nil, err
		}
	}
	ca := CAVars(opts.CA)
	caNames := map[string]bool{}
	for _, v := range ca {
		caNames[v.Name] = true
	}
	seen := map[string]bool{}
	for _, n := range ChildEnvAllowlist {
		seen[n] = true
		if v, ok := lookup(n); ok {
			env = append(env, n+"="+v)
		}
	}
	for _, n := range opts.Passthrough {
		if seen[n] {
			continue
		}
		seen[n] = true
		if caNames[n] {
			warnings = append(warnings, "--env "+n+" was ignored: --ca sets it")
			continue
		}
		v, ok := lookup(n)
		if !ok {
			warnings = append(warnings, "--env "+n+" is not set in the environment; skipped")
			continue
		}
		env = append(env, n+"="+v)
	}
	_, upper := lookup("HTTPS_PROXY")
	_, lower := lookup("https_proxy")
	if upper || lower {
		warnings = append(warnings, "an inherited HTTPS_PROXY was replaced by the loopback forwarder")
	}
	set := func(name, value string) { env = append(env, name+"="+value) }
	set("HTTPS_PROXY", proxyURL)
	set("https_proxy", proxyURL)
	if opts.IncludeHTTP {
		set("HTTP_PROXY", proxyURL)
		set("http_proxy", proxyURL)
	}
	set("NO_PROXY", loopbackNoProxy)
	set("no_proxy", loopbackNoProxy)
	for _, v := range ca {
		set(v.Name, v.Value)
	}
	return env, warnings, nil
}

// Process is a started child. Tests substitute a fake.
type Process interface {
	// Signal delivers sig to the child.
	Signal(sig os.Signal) error
	// Wait blocks until the child exits and returns its exit code, or -1 and
	// the signal that killed it.
	Wait() (code int, killedBy os.Signal, err error)
}

// ExecSpec describes one supervised run.
type ExecSpec struct {
	// Start starts the child.
	Start func() (Process, error)
	// Signals delivers the signals received by the supervisor. A nil or closed
	// channel means no signals; Run then waits for the child alone.
	Signals <-chan os.Signal
	// StdinIsTerminal is true when stdin is a terminal; the terminal then
	// delivers SIGINT and SIGQUIT to the child's foreground group itself.
	StdinIsTerminal bool
}

// ForwardSignal reports whether the supervisor passes sig to the child.
// SIGTERM and SIGHUP always; SIGINT and SIGQUIT only without a terminal, so a
// terminal's own delivery is not doubled.
func ForwardSignal(sig os.Signal, stdinIsTerminal bool) bool {
	switch sig {
	case syscall.SIGTERM, syscall.SIGHUP:
		return true
	case syscall.SIGINT, syscall.SIGQUIT:
		return !stdinIsTerminal
	}
	return false
}

// Run starts the child, forwards signals per ForwardSignal and returns its
// exit code: the child's own, or 128+signo when a signal killed it. ctx
// cancellation is not a signal; cancel the child through Signals.
func Run(ctx context.Context, spec ExecSpec) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p, err := spec.Start()
	if err != nil {
		return 0, fmt.Errorf("identityclient: start child: %w", err)
	}
	type result struct {
		code   int
		signal os.Signal
		err    error
	}
	done := make(chan result, 1)
	go func() {
		c, s, e := p.Wait()
		done <- result{c, s, e}
	}()
	sigs := spec.Signals
	for {
		select {
		case sig, ok := <-sigs:
			if !ok {
				sigs = nil // a closed channel means no more signals; wait for the child only
				continue
			}
			if ForwardSignal(sig, spec.StdinIsTerminal) {
				_ = p.Signal(sig)
			}
		case r := <-done:
			if r.err != nil {
				return 0, fmt.Errorf("identityclient: wait for child: %w", r.err)
			}
			if r.signal != nil {
				if s, ok := r.signal.(syscall.Signal); ok {
					return 128 + int(s), nil
				}
				return 128, nil
			}
			return r.code, nil
		}
	}
}
