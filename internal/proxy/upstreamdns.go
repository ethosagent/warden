package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// NameResolver is the DNS seam the proxy's own upstream dials resolve names
// through. *net.Resolver satisfies it directly; NewUpstreamResolver returns one
// wrapped with first-failure observability. Defined consumer-side (like Judge
// and MCPGateway) so the proxy depends on the capability, never the concrete
// type — and so the wrapper's LookupIPAddr override survives the trip from the
// worker's wiring into the SafeDialer.
type NameResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// upstreamDNSDialTimeout bounds each individual UDP/TCP dial to the configured
// upstream DNS server. The surrounding lookup context (SafeDialer's resolve
// timeout, or an http.Transport deadline) can only shorten it.
const upstreamDNSDialTimeout = 5 * time.Second

// upstreamResolver is a *net.Resolver pointed at the configured dns.
// upstreamResolver server, wrapped so the FIRST resolver-reachability failure —
// a refused or timed-out exchange with the server — fires onUnreachable exactly
// once, process-wide. A not-found answer (NXDOMAIN) does not fire: see
// unreachableResolverErr. It must sit at the LOOKUP level, not the Dial level:
// a dead UDP server does not fail its dial (the query simply goes unanswered),
// so a Dial-level hook would miss the most common unreachability case.
type upstreamResolver struct {
	*net.Resolver
	// addr is the configured "<host>:<port>" server, kept so failed lookups can
	// be re-stamped with it (see stampServer).
	addr          string
	once          sync.Once
	onUnreachable func(error)
}

// LookupIPAddr resolves host through the configured server and reports the
// first resolver-reachability failure once via onUnreachable. A not-found
// answer (NXDOMAIN / no data) does NOT fire the hook — see
// unreachableResolverErr. Every failed lookup still returns its error — there
// is no fallback to the system resolver.
func (r *upstreamResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	ips, err := r.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		err = r.stampServer(err)
		if r.onUnreachable != nil && unreachableResolverErr(err) {
			r.once.Do(func() { r.onUnreachable(err) })
		}
	}
	return ips, err
}

// stampServer re-stamps a failed lookup's *net.DNSError.Server to the
// configured server. Go builds DNSError.Server from /etc/resolv.conf even
// though this resolver's Dial redirects the exchange to r.addr, so un-stamped
// errors name the SYSTEM resolver ("lookup x on 127.0.0.53:53" while the query
// actually went to the configured server) and whoever debugs an outage chases
// the wrong DNS server — in the WARN line, per-request failure messages, and
// analytics alike. Only the display field changes: the error stays a
// *net.DNSError (errors.As keeps working) and the classification fields
// (IsNotFound / IsTimeout / IsTemporary) are untouched, so
// unreachableResolverErr and transport retries behave exactly as before.
// It copies rather than mutates: net's resolver shares one error object across
// concurrent lookups of the same host, and callers racing on the same error
// must not write it. A non-DNSError (or an error with nothing to re-stamp)
// passes through unchanged.
func (r *upstreamResolver) stampServer(err error) error {
	dnsErr, ok := err.(*net.DNSError)
	if !ok || dnsErr.Server == r.addr {
		return err
	}
	fixed := *dnsErr
	fixed.Server = r.addr
	return &fixed
}

// unreachableResolverErr reports whether err is a resolver-REACHABILITY failure
// — the operator-facing condition the one-shot hook exists for: a timed-out or
// otherwise refused/broken exchange with the configured server. A not-found
// answer (DNSError.IsNotFound) is the server doing its job on a healthy
// resolver, so it must not fire the hook: a typo'd hostname would otherwise
// consume the one-shot and silence a later real outage. Any error that is not
// recognizably a not-found answer (dial failures, context deadlines, malformed
// replies) defaults to firing — noisy is safer than silent here.
func unreachableResolverErr(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}
	return true
}

// NewUpstreamResolver returns a NameResolver that sends every query to addr
// ("<host>:<port>") over plain UDP — switching to TCP only for the
// DNS-standard truncation fallback; DoH/DoT transports are out of scope for
// v1. It is the implementation of dns.upstreamResolver: the resolver the
// proxy's own upstream dials look names up through when the resolver the
// container inherits cannot resolve the allowlisted names (corporate VPNs,
// split-horizon DNS).
//
// The system resolver is bypassed entirely — every connection the resolver
// makes is redirected to addr — so there is NO silent fallback to resolv.conf
// when the server is unreachable: lookups fail and each affected request fails
// exactly like any other upstream-connect failure, keeping the
// misconfiguration visible instead of masked.
//
// onUnreachable, when non-nil, is called exactly once on the first failed
// lookup (the operator-facing "one clear line" hook; the worker wires it to the
// structured logger). Every failed lookup's error is re-stamped so it names
// addr (see stampServer). Safe for concurrent lookups.
func NewUpstreamResolver(addr string, onUnreachable func(error)) NameResolver {
	return &upstreamResolver{
		addr: addr,
		Resolver: &net.Resolver{
			// PreferGo routes resolution through THIS resolver's Dial (the
			// pure-Go resolver); the cgo resolver can bypass a custom Dial and
			// read resolv.conf, which would silently re-introduce the system
			// resolver.
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// network is "udp" or "tcp" per the DNS transport need; the
				// resolver's own (resolv.conf) server address is ignored in
				// favor of the configured one — that redirection is the point.
				d := net.Dialer{Timeout: upstreamDNSDialTimeout}
				return d.DialContext(ctx, network, addr)
			},
		},
		onUnreachable: onUnreachable,
	}
}
