// Package proxy is the listener / TCP-accept / TLS-termination skeleton. Phase 1
// (M1) fills in real connection handling: TCP accept with default-deny, TLS
// termination with a cert the agent trusts, protocol detection, secret swap,
// and forwarding. This file provides the constructor and small pure helpers so
// the wiring is testable without raw networking in the skeleton.
package proxy

import (
	"fmt"
	"net"
	"strconv"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/secrets"
)

// Config holds the proxy's listen address and collaborators. All external
// dependencies are interfaces, honoring the day-zero interface rule.
type Config struct {
	// ListenAddr is the loopback / pod-internal address the agent connects to
	// (e.g. "127.0.0.1:8080").
	ListenAddr string
	Policy     *policy.Evaluator
	Secrets    secrets.SecretProvider
	Analytics  analytics.AnalyticsStore
}

// Proxy is the egress guardrail front door. M1 adds Serve()/accept loops; the
// skeleton constructs it and validates its configuration.
type Proxy struct {
	cfg Config
}

// New constructs a Proxy, validating that the required collaborators are
// present. It does not bind a socket; Serve (M1) does.
func New(cfg Config) (*Proxy, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("proxy: ListenAddr is required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("proxy: Policy evaluator is required")
	}
	if cfg.Secrets == nil {
		return nil, fmt.Errorf("proxy: Secrets provider is required")
	}
	if cfg.Analytics == nil {
		return nil, fmt.Errorf("proxy: Analytics store is required")
	}
	return &Proxy{cfg: cfg}, nil
}

// ListenAddr returns the configured listen address.
func (p *Proxy) ListenAddr() string { return p.cfg.ListenAddr }

// SplitHostPort parses a "host:port" destination into its host and numeric
// port. It is a thin, pure helper used on the accept path to feed the policy
// evaluator.
func SplitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: split %q: %w", addr, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: bad port in %q: %w", addr, err)
	}
	return h, port, nil
}
