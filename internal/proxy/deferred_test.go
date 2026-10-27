package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// W-P1-GPOL-03: the connection-level handling of identity-conditional
// decisions. Evaluators are built directly from a policy with a scoped entry
// (the config guard from GPOL-01 is bypassed on purpose); GPOL-10 passes the
// request subject, so a member's request on such a session is allowed.

// scopedEdit installs an evaluator with {domain: idHost, groups: [eng]}.
func scopedEdit(extra func(*Config)) func(*Config) {
	return func(c *Config) {
		c.Policy = policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: idHost, Port: 443, Groups: []string{"eng"}},
		}})
		if extra != nil {
			extra(c)
		}
	}
}

func noCA(c *Config) { c.CACertPath, c.CAKeyPath = "", "" }

func TestDeferredFor(t *testing.T) {
	cases := []struct {
		v    policy.RequestVerdict
		want deferred
	}{
		{policy.RequestVerdict{Decision: policy.NoMatch}, deferJudge},
		{policy.RequestVerdict{Decision: policy.Conditional, Scoped: true}, deferIdentity},
		{policy.RequestVerdict{Decision: policy.Allow, Scoped: true}, deferIdentity},
		{policy.RequestVerdict{Decision: policy.Allow}, deferNone},
		{policy.RequestVerdict{Decision: policy.Deny}, deferNone},
	}
	for _, c := range cases {
		if got := deferredFor(c.v); got != c.want {
			t.Errorf("deferredFor(%+v) = %v, want %v", c.v, got, c.want)
		}
	}
	for d, s := range map[deferred]string{deferNone: "deferNone", deferJudge: "deferJudge", deferIdentity: "deferIdentity", deferred(9): "deferUnknown"} {
		if d.String() != s {
			t.Errorf("deferred(%d).String() = %q, want %q", d, d.String(), s)
		}
	}
}

func (e *idEnv) denyEvents() []analytics.Event {
	var out []analytics.Event
	for _, ev := range e.store.snapshot() {
		if ev.Decision == "deny" {
			out = append(out, ev)
		}
	}
	return out
}

func (e *idEnv) waitDeny(t *testing.T, reason denyreason.Reason, n int) []analytics.Event {
	t.Helper()
	var got []analytics.Event
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got = got[:0]
		for _, ev := range e.denyEvents() {
			if ev.Reason == string(reason) {
				got = append(got, ev)
			}
		}
		if len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("want %d deny events %q, got %+v", n, reason, e.store.snapshot())
	return nil
}

func TestDeferredIdentity_ConnectWithCA(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, scopedEdit(nil))
	// W-P1-GPOL-10: the request subject is passed, so a member's token opens
	// the host while a request with no identity is still refused.
	for name, tc := range map[string]struct {
		hdr  string
		want int
	}{
		"member token": {"Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n", http.StatusOK},
		"no token":     {"", http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(e.denyEvents())
			conn, br, status := e.connect(tc.hdr)
			if !strings.Contains(status, "200") {
				t.Fatalf("CONNECT status = %q, want 200", status)
			}
			c := &idH1{t: t, tc: e.tlsOver(conn, br, "http/1.1")}
			c.br = bufio.NewReader(c.tc)
			if got := c.get(""); got != tc.want {
				t.Fatalf("request status = %d, want %d", got, tc.want)
			}
			if tc.want == http.StatusForbidden {
				e.waitDeny(t, denyreason.IdentityRequired, before+1)
			}
		})
	}
	if e.dials.Load() != 1 {
		t.Errorf("upstream dials = %d, want 1 (the member's only)", e.dials.Load())
	}
}

func TestDeferredIdentity_NoCA(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, scopedEdit(noCA))
	conn, _, status := e.connect("")
	_ = conn
	if !strings.Contains(status, "403") {
		t.Fatalf("anonymous CONNECT status = %q, want 403", status)
	}
	evs := e.waitDeny(t, denyreason.IdentityRequired, 1)
	if len(e.denyEvents()) != 1 || evs[0].Domain != idHost {
		t.Errorf("deny events = %+v, want exactly one for %s", e.denyEvents(), idHost)
	}
	if e.dials.Load() != 0 {
		t.Errorf("upstream dials = %d, want 0", e.dials.Load())
	}
}

func TestDeferredIdentity_RawTunnelExpiry(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, scopedEdit(noCA))
	now := e.clk.now()
	e.v.Set("tok-short", idClaims("carol", now.Add(400*time.Millisecond)), identity.StatusValid, "")
	e.v.Set("tok-noexp", idClaims("dave", time.Time{}), identity.StatusValid, "")

	// The upstream is an echo server on a loopback listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	e.setRaw(func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) })

	t.Run("cut at expiry", func(t *testing.T) {
		conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-short") + "\r\n")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status = %q, want 200", status)
		}
		_, _ = io.WriteString(conn, "ping")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo before expiry = %q, %v", buf, err)
		}
		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := br.ReadByte(); err == nil {
			t.Fatal("tunnel still open past expiry")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("tunnel not cut within 5s of a 400ms expiry")
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("cut took %v", time.Since(start))
		}
	})

	t.Run("zero expiry denied", func(t *testing.T) {
		dials := e.dials.Load()
		_, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-noexp") + "\r\n")
		if !strings.Contains(status, "403") {
			t.Fatalf("zero-expiry CONNECT status = %q, want 403", status)
		}
		e.waitDeny(t, denyreason.IdentityRequired, 1)
		if e.dials.Load() != dials {
			t.Error("zero-expiry CONNECT dialed upstream")
		}
	})

	t.Run("non member denied", func(t *testing.T) {
		e.v.Set("tok-ops", identity.Claims{Sub: "erin", Groups: []string{"ops"}, Expiry: now.Add(time.Hour)}, identity.StatusValid, "")
		_, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-ops") + "\r\n")
		if !strings.Contains(status, "403") {
			t.Fatalf("non-member CONNECT status = %q, want 403", status)
		}
	})
}

func TestDeferredIdentity_FailClosedBranches(t *testing.T) {
	judge := &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "allows everything"}}
	e := newIDEnvCfg(t, IdentityModeAttribute, scopedEdit(func(c *Config) { c.Judge = judge }))

	closed := func(t *testing.T, r io.Reader) {
		t.Helper()
		if c, ok := r.(net.Conn); ok {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		if _, err := io.ReadAll(r); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("connection not closed")
			}
		}
	}

	t.Run("non-TLS bytes", func(t *testing.T) {
		conn, br, status := e.connect("")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status = %q, want 200", status)
		}
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+idHost+"\r\n\r\n")
		closed(t, &bufConn{Reader: br, Conn: conn})
		e.waitDeny(t, denyreason.IdentityRequired, 1)
	})

	t.Run("unknown protocol inside TLS", func(t *testing.T) {
		conn, br, _ := e.connect("")
		tc := e.tlsOver(conn, br, "http/1.1")
		_, _ = tc.Write([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"))
		closed(t, tc)
		e.waitDeny(t, denyreason.IdentityRequired, 2)
	})

	if e.dials.Load() != 0 {
		t.Errorf("upstream dials = %d, want 0", e.dials.Load())
	}
	if n := judge.callCount(); n != 0 {
		t.Errorf("judge calls = %d, want 0", n)
	}
}

// bufConn reads through br (which may hold bytes past the CONNECT response).
type bufConn struct {
	io.Reader
	net.Conn
}

func (b *bufConn) Read(p []byte) (int, error) { return b.Reader.Read(p) }

// unknownDecision is an evaluator whose EvaluateFor returns a decision value
// no gate knows.
type unknownDecision struct{ *policy.Evaluator }

func (unknownDecision) EvaluateFor(policy.RequestContext) policy.RequestVerdict {
	return policy.RequestVerdict{Decision: policy.Decision(99)}
}

func TestConnectGate_UnknownDecisionFailsClosed(t *testing.T) {
	logs := &lockedBuf{}
	store := &syncStore{}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     unknownDecision{policy.NewEvaluator(config.Policy{})},
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		Logger:     slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	out := connectRun(p, []byte("CONNECT any.test:443 HTTP/1.1\r\nHost: any.test:443\r\n\r\n"), &dialed)
	if !strings.HasPrefix(out, "HTTP/1.1 403") {
		t.Fatalf("response = %q, want 403", out)
	}
	if len(dialed) != 0 {
		t.Errorf("dialed %v, want none", dialed)
	}
	if !strings.Contains(logs.String(), "unhandled policy decision") || !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("no ERROR log for the unknown decision: %s", logs.String())
	}
	evs := waitEvents(t, store, 1)
	if evs[0].Reason != string(denyreason.PolicyNoMatch) {
		t.Errorf("reason = %q, want %q", evs[0].Reason, denyreason.PolicyNoMatch)
	}
}
