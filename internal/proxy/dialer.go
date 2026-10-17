package proxy

import (
	"crypto/tls"
	"net"
)

// Dialer is the seam for the proxy's UPSTREAM egress dials: plain TCP (CONNECT
// tunnels and opaque passthrough) and TLS (terminated-HTTP forwarding and raw
// passthrough). *SafeDialer is the production implementation — its SSRF
// blocklist is a security invariant and the production path never changes.
//
// The interface exists so the L1 harness (#350) can substitute a mapping dialer
// that points allowlisted names at local fake upstreams, which the SafeDialer
// by design refuses (private/loopback addresses are blocked). Reaching it is
// assembly-only: nothing in YAML or on the CLI can set it (enforced by
// TestOverridesAreNotConfigurable in internal/worker).
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialTLS(network, addr string, cfg *tls.Config) (*tls.Conn, error)
}

// Compile-time proof that the production dialer satisfies the seam.
var _ Dialer = (*SafeDialer)(nil)

// upstreamTLSConfig builds the tls.Config for an upstream TLS dial: SNI keeps
// the client-supplied hostname; the root pool is the assembly-only override
// when one was injected, else nil RootCAs — the system pool, byte-identical to
// before. Every site that dials upstream TLS goes through this helper, so the
// override cannot drift between them.
func (p *Proxy) upstreamTLSConfig(host string) *tls.Config {
	cfg := &tls.Config{ServerName: host}
	if p.cfg.UpstreamRootCAs != nil {
		cfg.RootCAs = p.cfg.UpstreamRootCAs
	}
	return cfg
}
