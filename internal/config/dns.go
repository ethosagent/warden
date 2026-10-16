package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DNSConfig configures the DNS resolution warden itself uses for its own
// upstream dials (CONNECT tunnels, TLS-terminated upstreams, and the
// SafeDialer-based auth-fetch client). It never affects the dashboard/admin
// listeners, and it is NOT the agent's DNS path: under the transparent-
// interception contract (#376) agent-side names are routed to warden by the
// orchestration runtime, while this block only governs warden's own outgoing
// dials. Boot-time LOCAL config (never on the settings wire); the zero value
// means Go's default resolver — byte-identical to the behavior before this
// block existed.
type DNSConfig struct {
	// UpstreamResolver is the "<host>:<port>" DNS server warden's own lookups
	// query, over plain UDP (TCP only for the DNS-standard truncation fallback;
	// DoH/DoT transports are explicitly out of scope for v1). Intended for
	// corporate-VPN / split-horizon networks where the resolver the container
	// inherits cannot resolve the public allowlisted names.
	UpstreamResolver string
}

// rawDNS mirrors the on-disk `dns:` block. Pointer so absence is distinct from
// an empty block; both map to the zero DNSConfig (default resolver).
type rawDNS struct {
	UpstreamResolver string `yaml:"upstreamResolver"`
}

// parseDNS converts the raw dns block into a typed DNSConfig. An absent block
// (nil) yields the zero value.
func parseDNS(r *rawDNS) DNSConfig {
	if r == nil {
		return DNSConfig{}
	}
	return DNSConfig{UpstreamResolver: strings.TrimSpace(r.UpstreamResolver)}
}

// validateDNS enforces the "<host>:<port>" shape at LOAD, so a malformed
// resolver fails fast with a clear message instead of surfacing later as
// per-request dial failures. The host may be an IP literal or a name (a name is
// resolved by the system resolver when the dial to the server itself is made);
// the port must be 1-65535.
func validateDNS(c DNSConfig) error {
	if c.UpstreamResolver == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(c.UpstreamResolver)
	if err != nil {
		return fmt.Errorf("config: dns.upstreamResolver %q must be <host>:<port> (e.g. \"10.20.30.2:53\"): %v", c.UpstreamResolver, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("config: dns.upstreamResolver %q is missing the host", c.UpstreamResolver)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("config: dns.upstreamResolver %q has an invalid port %q; want 1-65535", c.UpstreamResolver, portStr)
	}
	return nil
}
