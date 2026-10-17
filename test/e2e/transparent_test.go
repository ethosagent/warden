//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
)

// The transparent interception tests (#376): agent-3 holds NO proxy
// environment — its dials land on worker-3's transparent listeners because the
// interception network's name resolution (the agent's host entries; DNS in
// production) points the fake hosts at worker-3's pinned t-net IP. Everything
// here must behave exactly like the CONNECT workers: same swap, same audit,
// same deny reasons, same canary discipline.

// tnetIP is worker-3's address on the interception network, read per call (a
// restarted container keeps the pinned compose IP, but read it anyway so the
// assertions fail with the actual address in the message).
func tnetIP(t *testing.T) string {
	t.Helper()
	return containerIP(t, svcWorker3, netT)
}

// TestTransparent_InterceptedCallRunsThePipeline: an agent with no proxy
// configuration reaches an allowed host THROUGH worker-3's :443 listener; the
// pipeline ran (the upstream sees the real secret, the audit names a
// SecretRef), and the MITM leaf verified against the proxy CA the agent holds.
func TestTransparent_InterceptedCallRunsThePipeline(t *testing.T) {
	resetRecorded(t)
	since := time.Now()
	ip := tnetIP(t)

	p := curlProbe(t, svcAgent3, "-H", "Authorization: Bearer "+placeholder, "https://api.example.test/")
	if p.exit != 0 || p.httpCode != "200" {
		t.Fatalf("intercepted call: exit %d http %s (%s); want 200", p.exit, p.httpCode, p.errMsg)
	}
	// The remote is the WORKER, not the upstream: the agent dialed the
	// interception address with no proxy env, and the leaf it verified was the
	// worker's MITM certificate for api.example.test.
	if p.remoteIP != ip {
		t.Fatalf("remote_ip = %q, want worker-3's t-net address %s: the call was not intercepted", p.remoteIP, ip)
	}

	seen := findRecorded(t, "api.example.test")
	if got, want := seen.Header.Get("Authorization"), "Bearer "+canary; got != want {
		t.Fatalf("upstream Authorization = %q, want the swapped canary %q: the swap stage did not run", got, want)
	}

	evs := events(t, svcWorker3, since, 1, func(e analytics.Event) bool {
		return e.Domain == "api.example.test" && e.Decision == "allow"
	})
	n := 0
	for _, e := range evs {
		if e.Domain != "api.example.test" {
			continue
		}
		n++
		if e.SecretRef == "" {
			t.Errorf("allow event carries no SecretRef although a secret was swapped: %+v", e)
		}
		if hits := leaksIn(e.SecretRef, canaryNeedles(canary)); len(hits) > 0 {
			t.Errorf("event SecretRef holds the raw canary (%v)", hits)
		}
	}
	if n != 1 {
		t.Errorf("allow events for api.example.test = %d, want exactly 1 (%s)", n, summarize(evs))
	}
	AssertCanaryNeverLeaked(t, p.raw.stdout+p.raw.stderr)
}

// TestTransparent_PlainHTTPHostGate: the :80 listener admits on the Host
// header and runs the same pipeline — the upstream hop is http and the swap,
// audit and protocol tag are the tunnel's.
func TestTransparent_PlainHTTPHostGate(t *testing.T) {
	resetRecorded(t)
	since := time.Now()
	ip := tnetIP(t)

	p := curlProbe(t, svcAgent3, "-H", "Authorization: Bearer "+placeholder, "http://api.example.test/")
	if p.exit != 0 || p.httpCode != "200" {
		t.Fatalf("plain intercepted call: exit %d http %s (%s); want 200", p.exit, p.httpCode, p.errMsg)
	}
	if p.remoteIP != ip {
		t.Fatalf("remote_ip = %q, want worker-3's t-net address %s: the call was not intercepted", p.remoteIP, ip)
	}

	seen := findRecorded(t, "api.example.test")
	if got, want := seen.Header.Get("Authorization"), "Bearer "+canary; got != want {
		t.Fatalf("upstream Authorization = %q, want the swapped canary %q", got, want)
	}

	evs := events(t, svcWorker3, since, 1, func(e analytics.Event) bool {
		return e.Domain == "api.example.test" && e.Decision == "allow"
	})
	n := 0
	for _, e := range evs {
		if e.Domain != "api.example.test" {
			continue
		}
		n++
		if e.Protocol != "http" {
			t.Errorf("event protocol = %q, want %q (plain-HTTP admission)", e.Protocol, "http")
		}
	}
	if n != 1 {
		t.Errorf("allow events for api.example.test = %d, want exactly 1 (%s)", n, summarize(evs))
	}
	AssertCanaryNeverLeaked(t, p.raw.stdout+p.raw.stderr)
}

// TestTransparent_NonAllowlistedSNIRefusedAtHello: the SNI gate runs BEFORE
// any handshake — the client's TCP dials the interception address, the
// handshake never completes, nothing reaches the upstream, and the deny is
// audited with the same reason the CONNECT workers give the same destination.
func TestTransparent_NonAllowlistedSNIRefusedAtHello(t *testing.T) {
	resetRecorded(t)
	since := time.Now()

	p := curlProbe(t, svcAgent3, "https://evil.example.test/")
	if p.exit == 0 {
		t.Fatalf("ESCAPE: denied SNI completed a request (http %s)", p.httpCode)
	}
	// The refusal is at the TLS layer: no HTTP exchange, and curl cannot even
	// name a remote_ip for a transfer that never started (it stays empty on a
	// failed handshake). The proof the TCP dial landed on WORKER-3's listener
	// is the deny event below, audited by worker-3 for exactly this SNI.
	if p.httpCode != "000" || p.errMsg == "" {
		t.Fatalf("refused SNI produced http %q / err %q; want a TLS-level failure with no HTTP exchange", p.httpCode, p.errMsg)
	}

	evs := events(t, svcWorker3, since, 1, func(e analytics.Event) bool {
		return e.Domain == "evil.example.test" && e.Decision == "deny"
	})
	n := 0
	for _, e := range evs {
		if e.Domain != "evil.example.test" {
			continue
		}
		n++
		if e.Reason != string(denyreason.PolicyDenylist) {
			t.Errorf("deny reason %q, want %q (the CONNECT workers' reason for the same host)", e.Reason, denyreason.PolicyDenylist)
		}
	}
	if n != 1 {
		t.Errorf("deny events for evil.example.test = %d, want exactly 1 (%s)", n, summarize(evs))
	}
	for _, r := range recorded(t) {
		if strings.Contains(r.Host, "evil.example.test") {
			t.Errorf("denied host reached the upstream: %+v", r)
		}
	}
}

// TestTransparent_LoopGuardRefusesSelfDial: self.example.test is allowlisted
// and resolves (via the worker's own host entries) to worker-3's OWN
// interception address — the dial would re-enter the proxy's transparent
// listener and loop forever. The loop guard refuses it as a policy decision
// (declared transparent_loop_guard reason, 502 to the client), and nothing
// reaches the upstream. t-net is exempted from the SSRF private-IP blocklist
// in worker-3's config, so the guard — not the blocklist — is what fires.
func TestTransparent_LoopGuardRefusesSelfDial(t *testing.T) {
	resetRecorded(t)
	since := time.Now()

	p := curlProbe(t, svcAgent3, "https://self.example.test/")
	// The guard refuses at the dial stage: the pipeline answers 502. A hang or
	// a reset would mean the guard never fired.
	if p.exit != 0 || p.httpCode != "502" {
		t.Fatalf("self-dial: exit %d http %s (%s); want a 502 from the refused dial", p.exit, p.httpCode, p.errMsg)
	}

	evs := events(t, svcWorker3, since, 1, func(e analytics.Event) bool {
		return e.Domain == "self.example.test" && e.Decision == "deny"
	})
	n := 0
	for _, e := range evs {
		if e.Domain != "self.example.test" {
			continue
		}
		n++
		if e.Reason != string(denyreason.TransparentLoopGuard) {
			t.Errorf("deny reason %q, want %q", e.Reason, denyreason.TransparentLoopGuard)
		}
	}
	if n != 1 {
		t.Errorf("deny events for self.example.test = %d, want exactly 1 (%s)", n, summarize(evs))
	}
	for _, r := range recorded(t) {
		if strings.Contains(r.Host, "self.example.test") {
			t.Errorf("the looped dial reached the upstream: %+v", r)
		}
	}
}

// findRecorded returns the last recorded request to host, failing when none.
func findRecorded(t *testing.T, host string) Request {
	t.Helper()
	var seen *Request
	for _, r := range recorded(t) {
		r := r
		if r.Host == host {
			seen = &r
		}
	}
	if seen == nil {
		t.Fatalf("upstream recorded no request to %s", host)
	}
	return *seen
}
