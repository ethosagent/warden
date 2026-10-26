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

// ChildEnvOptions selects optional parts of the child environment.
type ChildEnvOptions struct {
	// IncludeHTTP also sets HTTP_PROXY and http_proxy.
	IncludeHTTP bool
	// CA is a CA bundle path exported through CAVars.
	CA string
}

// BuildChildEnv returns the environment of the supervised child: parent with
// every proxy variable (ALL_PROXY, HTTP_PROXY, HTTPS_PROXY, NO_PROXY in any
// case), the CA variables and every WARDEN_IDENTITY_* variable removed, then
// HTTPS_PROXY and https_proxy set to proxyURL, NO_PROXY and no_proxy set to
// loopback, HTTP_PROXY and http_proxy only with IncludeHTTP, and the CA
// variables with CA. The warnings say what was overridden; they never hold a
// value, because an inherited proxy URL may carry credentials.
func BuildChildEnv(parent []string, proxyURL string, opts ChildEnvOptions) (env []string, warnings []string) {
	drop := map[string]bool{}
	for _, n := range []string{"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
		drop[n] = true
	}
	ca := CAVars(opts.CA)
	for _, v := range ca {
		drop[v.Name] = true
	}
	overrodeHTTPS := false
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		switch {
		case strings.HasPrefix(name, "WARDEN_IDENTITY_"):
			continue
		case drop[up]:
			if up == "HTTPS_PROXY" {
				overrodeHTTPS = true
			}
			continue
		}
		env = append(env, kv)
	}
	if overrodeHTTPS {
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
	return env, warnings
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
	// Signals delivers the signals received by the supervisor.
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
