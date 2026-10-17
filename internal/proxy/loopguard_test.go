package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// mapResolver is a NameResolver answering from a fixed in-memory record set —
// for the cases the A-only dnstest stub cannot express (several addresses per
// name, IPv6).
type mapResolver map[string][]net.IPAddr

func (m mapResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := m[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("mapResolver: no record for %q", host)
}

// mapDialer is a SafeDialer over mapResolver.
func mapDialer(t *testing.T, records mapResolver, allowPrivate ...string) *SafeDialer {
	t.Helper()
	d, err := NewSafeDialerWithResolver(2*time.Second, allowPrivate, records)
	if err != nil {
		t.Fatalf("NewSafeDialerWithResolver: %v", err)
	}
	return d
}

// The transparent-mode loop guard (#376): an upstream dial whose resolved
// address is one of Warden's OWN transparent listener addresses would
// re-enter the proxy (an interception loop — the agent's traffic bouncing off
// itself forever), so the SafeDialer must refuse it as a POLICY decision —
// audited as transparent_loop_guard — and the refusal must hold even when the
// subnet is explicitly allowPrivate-exempted, which is exactly how a
// transparent deployment's allowlist is configured.

func TestLoopGuard_RefusesSelfListenerIP(t *testing.T) {
	d := ssrfTestDialer(t, map[string]string{"self.example.test": "10.201.0.5"})
	d.SetSelfListenerIPs([]net.IP{net.ParseIP("10.201.0.5")})
	_, _, err := d.safeHostAndIPs("self.example.test")
	se, ok := AsSSRFError(err)
	if !ok {
		t.Fatalf("err = %v, want a *SSRFError", err)
	}
	if se.Reason != SSRFReasonSelfListener {
		t.Errorf("reason = %q, want %q", se.Reason, SSRFReasonSelfListener)
	}
	if se.AddrClass != "self_listener" {
		t.Errorf("addr class = %q, want self_listener", se.AddrClass)
	}
}

func TestLoopGuard_HoldsAgainstAllowPrivate(t *testing.T) {
	// allowPrivate 10.201.0.0/24 is the realistic transparent deployment (the
	// allowlist must admit the internal subnet for real egress). The guard is
	// not an address-class rule: it must win over the exemption.
	d := ssrfTestDialer(t, map[string]string{"self.example.test": "10.201.0.5"}, "10.201.0.0/24")
	d.SetSelfListenerIPs([]net.IP{net.ParseIP("10.201.0.5")})
	_, _, err := d.safeHostAndIPs("self.example.test")
	se, ok := AsSSRFError(err)
	if !ok {
		t.Fatalf("err = %v, want a *SSRFError", err)
	}
	if se.Reason != SSRFReasonSelfListener {
		t.Errorf("reason = %q, want %q", se.Reason, SSRFReasonSelfListener)
	}
}

func TestLoopGuard_AnyResolvedSelfIPRefuses(t *testing.T) {
	// A record with one self IP among several must refuse: dialing the other
	// address would still serve the looped name.
	d := mapDialer(t, mapResolver{
		"dual.example.test": {net.IPAddr{IP: net.ParseIP("10.201.0.5")}, net.IPAddr{IP: net.ParseIP("10.201.0.99")}},
	})
	d.SetSelfListenerIPs([]net.IP{net.ParseIP("10.201.0.5")})
	_, allowed, err := d.safeHostAndIPs("dual.example.test")
	se, ok := AsSSRFError(err)
	if !ok {
		t.Fatalf("err = %v, want a *SSRFError; allowed = %v", err, allowed)
	}
	if se.Reason != SSRFReasonSelfListener {
		t.Errorf("reason = %q, want %q", se.Reason, SSRFReasonSelfListener)
	}
}

func TestLoopGuard_NonSelfTrafficUnaffected(t *testing.T) {
	// Without self IPs installed — the forward-mode default — the same dialer
	// allows a private address covered by allowPrivate, exactly as before.
	d := ssrfTestDialer(t, map[string]string{"backend.test": "10.201.0.7"}, "10.201.0.0/24")
	host, allowed, err := d.safeHostAndIPs("backend.test")
	if err != nil {
		t.Fatalf("safeHostAndIPs: %v", err)
	}
	if host != "backend.test" || len(allowed) != 1 || !allowed[0].Equal(net.ParseIP("10.201.0.7")) {
		t.Errorf("host = %q, allowed = %v", host, allowed)
	}
}

func TestLoopGuard_SelfIPsNilableAndIPv6(t *testing.T) {
	d := mapDialer(t, mapResolver{"v6.example.test": {net.IPAddr{IP: net.ParseIP("fd00::5")}}}, "fd00::/8")
	d.SetSelfListenerIPs([]net.IP{net.ParseIP("fd00::5")})
	_, _, err := d.safeHostAndIPs("v6.example.test")
	se, ok := AsSSRFError(err)
	if !ok || se.Reason != SSRFReasonSelfListener {
		t.Fatalf("err = %v, want %q", err, SSRFReasonSelfListener)
	}
	// A different address in the same subnet still dials.
	d2 := mapDialer(t, mapResolver{"v6.example.test": {net.IPAddr{IP: net.ParseIP("fd00::6")}}}, "fd00::/8")
	d2.SetSelfListenerIPs([]net.IP{net.ParseIP("fd00::5")})
	if _, _, err := d2.safeHostAndIPs("v6.example.test"); err != nil {
		t.Errorf("non-self IPv6 address refused: %v", err)
	}
}

func TestLoopGuard_IPListenerTargetRefused(t *testing.T) {
	// An IP-literal dial target skips DNS, but the guard must still see it.
	d := ssrfTestDialer(t, nil, "10.201.0.0/24")
	d.SetSelfListenerIPs([]net.IP{net.ParseIP("10.201.0.5")})
	_, _, err := d.safeHostAndIPs("10.201.0.5")
	se, ok := AsSSRFError(err)
	if !ok || se.Reason != SSRFReasonSelfListener {
		t.Fatalf("err = %v, want %q", err, SSRFReasonSelfListener)
	}
}

func TestLoopGuard_DialReturnsTypedError(t *testing.T) {
	// The full Dial path surfaces the typed refusal (checked with errors.As by
	// the deny-audit sites), not an ordinary dial failure.
	d := ssrfTestDialer(t, map[string]string{"self.example.test": "10.201.0.5"}, "10.201.0.0/24")
	d.SetSelfListenerIPs([]net.IP{net.ParseIP("10.201.0.5")})
	_, err := d.Dial("tcp", "self.example.test:443")
	var se *SSRFError
	if !errors.As(err, &se) || se.Reason != SSRFReasonSelfListener {
		t.Fatalf("err = %v, want *SSRFError with %q", err, SSRFReasonSelfListener)
	}
}

// TestLoopGuard_ReachesThroughProxyPipeline proves the guard fires on a real
// transparent-mode request: an allowed destination whose DNS points at the
// proxy's own transparent listener address is denied with transparent_loop_guard
// through the emitDeny chokepoint — through the PRODUCTION dialer (an overridden
// dial seam would bypass the guard) — and the dial itself never happens.
func TestLoopGuard_ReachesThroughProxyPipeline(t *testing.T) {
	env := newTransparentEnv(t, transparentOpts{
		allow: []config.AllowlistEntry{{Domain: "loop.test"}},
		// The realistic transparent deployment: the internal subnet is
		// allowPrivate-exempted so real egress works. The guard is not an
		// address-class rule and must win over the exemption.
		allowPrivateCIDRs: []string{"127.0.0.0/8"},
		prodDial:          true,
		dns:               map[string]string{"loop.test": "127.0.0.1"},
	})

	// SNI and Host are the same allowed name, whose DNS points back at us.
	req, _ := http.NewRequest(http.MethodGet, "https://loop.test/echo", nil)
	_, status, err := env.doH1("loop.test", req)
	if err == nil && status == 200 {
		t.Errorf("looped request succeeded (status %d), want refusal", status)
	}
	env.wantDenied("loop.test", "transparent_loop_guard")
	// The guard refused before any dial: the upstream saw nothing.
	if rs := env.backend.requests(); len(rs) != 0 {
		t.Errorf("the looped dial reached an upstream: %d requests", len(rs))
	}
}
