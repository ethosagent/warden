package proxy

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/test/fakes"
)

// These tests cover W-P1-VRFY-09: every analytics event and decision log line
// the proxy writes carries the caller's identity, through one chokepoint.

// waitEvent polls the store until pred matches an event (the WS event is written
// after the response, so a plain snapshot can race it).
func waitEvent(t *testing.T, st *syncStore, what string, pred func(analytics.Event) bool) analytics.Event {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		for _, ev := range st.snapshot() {
			if pred(ev) {
				return ev
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s event; have %+v", what, st.snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitDecisions polls the store until it holds at least want[decision] events
// for every decision, and returns that snapshot.
func waitDecisions(t *testing.T, st *syncStore, want map[string]int) []analytics.Event {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		evs := st.snapshot()
		have := map[string]int{}
		for _, ev := range evs {
			have[ev.Decision]++
		}
		done := true
		for d, n := range want {
			if have[d] < n {
				done = false
			}
		}
		if done {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("want events %v, have %v: %+v", want, have, evs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func wantAlice(t *testing.T, what string, ev analytics.Event) {
	t.Helper()
	if ev.UserSub != "alice" || ev.UserEmail != "alice@example.test" || !reflect.DeepEqual(ev.UserGroups, []string{"eng"}) ||
		ev.IdentityStatus != string(identity.StatusValid) || ev.IdentityReason != "" {
		t.Errorf("%s event identity = sub %q email %q groups %v status %q reason %q; want alice/valid",
			what, ev.UserSub, ev.UserEmail, ev.UserGroups, ev.IdentityStatus, ev.IdentityReason)
	}
}

func wantNoUser(t *testing.T, what string, ev analytics.Event) {
	t.Helper()
	if ev.UserSub != "" || ev.UserEmail != "" || len(ev.UserGroups) != 0 || ev.UserGroupsTruncated || ev.UserSID != "" {
		t.Errorf("%s event carries user fields without status valid: %+v", what, ev)
	}
}

// connectDenied sends a CONNECT for a host the policy does not allow, with
// extra header lines, and returns the status line.
func (e *idEnv) connectDenied(extra string) string {
	e.t.Helper()
	conn, br, status, err := e.dialConnectTo("denied.test", extra)
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	_ = br
	return status
}

func TestStamp(t *testing.T) {
	claims := identity.Claims{Sub: "s", Email: "e@x", Groups: []string{"a", "b"}, GroupsTruncated: true, SID: "sid1"}
	tests := []struct {
		name string
		ci   connIdentity
		want analytics.Event
	}{
		{"zero is none", connIdentity{}, analytics.Event{IdentityStatus: "none"}},
		{"none is recorded", connIdentity{Status: identity.StatusNone}, analytics.Event{IdentityStatus: "none"}},
		{"valid writes all", connIdentity{Claims: claims, Status: identity.StatusValid},
			analytics.Event{IdentityStatus: "valid", UserSub: "s", UserEmail: "e@x", UserGroups: []string{"a", "b"}, UserGroupsTruncated: true, UserSID: "sid1"}},
		{"expired drops claims", connIdentity{Claims: claims, Status: identity.StatusExpired}, analytics.Event{IdentityStatus: "expired"}},
		{"invalid keeps reason only", connIdentity{Claims: claims, Status: identity.StatusInvalid, Reason: identity.ReasonBadSignature},
			analytics.Event{IdentityStatus: "invalid", IdentityReason: string(identity.ReasonBadSignature)}},
		{"unverified", connIdentity{Status: identity.StatusUnverified, Reason: identity.ReasonJWKSUnavailable},
			analytics.Event{IdentityStatus: "unverified", IdentityReason: string(identity.ReasonJWKSUnavailable)}},
		{"conflict drops claims", connIdentity{Claims: claims, Status: identity.StatusConflict}, analytics.Event{IdentityStatus: "conflict"}},
		{"off is recorded", connIdentity{Status: identity.StatusOff}, analytics.Event{IdentityStatus: "off"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := analytics.Event{Domain: "d"}
			tt.ci.stamp(&ev, true)
			tt.want.Domain = "d"
			if !reflect.DeepEqual(ev, tt.want) {
				t.Errorf("stamped %+v, want %+v", ev, tt.want)
			}
			// Identity off leaves every connection's event untouched.
			off := analytics.Event{Domain: "d"}
			tt.ci.stamp(&off, false)
			if !reflect.DeepEqual(off, analytics.Event{Domain: "d"}) {
				t.Errorf("identity off stamped %+v", off)
			}
		})
	}
}

// TestAllEventsCarryIdentity keeps the stamping chokepoint closed: no non-test
// file in the package may call StoreEvent except recordEvent, and the files
// that do reach recordEvent are exactly the known set, so a new event site is a
// deliberate edit here (grpc.go records through the shared paths).
func TestAllEventsCarryIdentity(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string]int{}
	fset := token.NewFileSet()
	for _, fn := range files {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, fn, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			inRecord := fd.Name.Name == "recordEvent" && fd.Recv != nil
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "StoreEvent", "StoreEventsBatch":
					if !inRecord {
						t.Errorf("%s: %s calls %s outside recordEvent; use p.recordEvent(ci, ev) so the event carries identity",
							fset.Position(call.Pos()), fd.Name.Name, sel.Sel.Name)
					}
				case "recordEvent":
					sites[fn]++
				}
				return true
			})
		}
	}
	var got []string
	for fn := range sites {
		got = append(got, fn)
	}
	sort.Strings(got)
	want := []string{"deny.go", "http.go", "secretscope.go", "serve.go", "tls.go", "ws.go"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("files recording events through recordEvent = %v, want %v; a new site must be added here on purpose", got, want)
	}
}

func TestDenyEventCarriesIdentity(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	if st := e.connectDenied("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"); !strings.Contains(st, "403") {
		t.Fatalf("status = %q, want 403", st)
	}
	ev := waitEvent(t, e.store, "deny", func(ev analytics.Event) bool { return ev.Decision == "deny" && ev.Domain == "denied.test" })
	wantAlice(t, "CONNECT deny", ev)
	if ev.UserSub != "alice" || ev.IdentityStatus != "valid" {
		t.Fatalf("deny event not attributed: %+v", ev)
	}
}

func TestEventsCarryIdentityAllPaths(t *testing.T) {
	auth := "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"

	t.Run("allowed", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		if st := e.h1(auth).get(""); st != 200 {
			t.Fatalf("status = %d", st)
		}
		wantAlice(t, "allowed", waitEvent(t, e.store, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" }))
	})

	t.Run("secret_scope_deny", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		e.h1(auth).get("Authorization: Bearer " + scopedPlaceholder + "\r\n")
		wantAlice(t, "secret scope", waitEvent(t, e.store, "secret_out_of_scope", func(ev analytics.Event) bool { return ev.Decision == decisionSecretOutOfScope }))
	})

	t.Run("websocket", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		_, _, caCert, caKey := generateTestCA(t)
		b := &wsBackend{reqHeaders: make(chan string, 1)}
		e.p.dialTLS = dialBackend(startWSBackend(t, caCert, caKey, b))
		conn, br, status := e.connect(auth)
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status = %q", status)
		}
		tc := e.tlsOver(conn, br, "http/1.1")
		_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		hr := bufio.NewReader(tc)
		if line, err := hr.ReadString('\n'); err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
			t.Fatalf("status = %q err %v, want 101", line, err)
		}
		// Read the whole 101 header block before closing: the proxy writes the
		// status line, headers and blank line separately, and a close that lands
		// between them fails a write and ends the handler before any event.
		for {
			l, err := hr.ReadString('\n')
			if err != nil {
				t.Fatalf("reading 101 headers: %v", err)
			}
			if l == "\r\n" {
				break
			}
		}
		_ = tc.Close() // the session event is written when the pump ends
		wantAlice(t, "websocket", waitEvent(t, e.store, "websocket", func(ev analytics.Event) bool { return ev.Decision == "allow" }))
	})

	t.Run("h2", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		if st := h2Get(t, e.h2(auth), nil); st != 200 {
			t.Fatalf("status = %d", st)
		}
		wantAlice(t, "h2", waitEvent(t, e.store, "h2 allow", func(ev analytics.Event) bool { return ev.Decision == "allow" }))
	})

	t.Run("header_identity", func(t *testing.T) {
		// No CONNECT token: the X-Warden-Identity result stamps the event.
		e := newIDEnv(t, IdentityModeAttribute)
		if st := e.h1("").get("X-Warden-Identity: Bearer tok-alice\r\n"); st != 200 {
			t.Fatalf("status = %d", st)
		}
		wantAlice(t, "header identity", waitEvent(t, e.store, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" }))
	})

	t.Run("no_token_is_none", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		if st := h2Get(t, e.h2(""), nil); st != 200 {
			t.Fatalf("status = %d", st)
		}
		ev := waitEvent(t, e.store, "h2 allow", func(ev analytics.Event) bool { return ev.Decision == "allow" })
		if ev.IdentityStatus != "none" {
			t.Errorf("h2 no token: identity_status = %q, want none", ev.IdentityStatus)
		}
		wantNoUser(t, "h2 no token", ev)
	})
}

func TestUnverifiedClaimsNotRecorded(t *testing.T) {
	cases := []struct {
		tok, status, reason string
	}{
		{"tok-expired", "expired", ""},
		{"tok-bad", "invalid", string(identity.ReasonBadSignature)},
		{"tok-down", "unverified", string(identity.ReasonJWKSUnavailable)},
	}
	for _, c := range cases {
		t.Run(c.tok, func(t *testing.T) {
			e := newIDEnv(t, IdentityModeAttribute)
			auth := "Proxy-Authorization: " + basicAuth(c.tok) + "\r\n"
			if st := e.h1(auth).get(""); st != 200 {
				t.Fatalf("status = %d", st)
			}
			ev := waitEvent(t, e.store, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" })
			if ev.IdentityStatus != c.status || ev.IdentityReason != c.reason {
				t.Errorf("allow event status/reason = %q/%q, want %q/%q", ev.IdentityStatus, ev.IdentityReason, c.status, c.reason)
			}
			wantNoUser(t, "allow", ev)

			e.connectDenied(auth)
			dev := waitEvent(t, e.store, "deny", func(ev analytics.Event) bool { return ev.Decision == "deny" })
			if dev.IdentityStatus != c.status {
				t.Errorf("deny event status = %q, want %q", dev.IdentityStatus, c.status)
			}
			wantNoUser(t, "deny", dev)
		})
	}
}

// TestNoIdentityEventsUnchanged: with identity off the events are byte-identical
// to pre-identity ones, even when the agent sends a token.
func TestNoIdentityEventsUnchanged(t *testing.T) {
	e := newIDEnv(t, IdentityModeOff)
	if st := e.h1("").get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	if st := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n").get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	e.connectDenied("")
	// Each event is written after its response, so the deny arriving says
	// nothing about the two allows: wait for the whole expected set.
	evs := waitDecisions(t, e.store, map[string]int{"allow": 2, "deny": 1})
	for _, ev := range evs {
		wantNoUser(t, ev.Decision, ev)
		if ev.IdentityStatus != "" || ev.IdentityReason != "" {
			t.Errorf("%s event has identity_* with identity off: %+v", ev.Decision, ev)
		}
	}
}

// TestNoTokenStatusNone: identity on and no token is status none, not empty, so
// an auditor can tell it from identity off (empty). Both a CONNECT deny and an
// h1 request without a header are checked, next to the off baseline.
func TestNoTokenStatusNone(t *testing.T) {
	on := newIDEnv(t, IdentityModeAttribute)
	if st := on.h1("").get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	on.connectDenied("")
	allow := waitEvent(t, on.store, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" })
	deny := waitEvent(t, on.store, "deny", func(ev analytics.Event) bool { return ev.Decision == "deny" })
	for what, ev := range map[string]analytics.Event{"h1 allow": allow, "CONNECT deny": deny} {
		if ev.IdentityStatus != "none" || ev.IdentityReason != "" {
			t.Errorf("%s: identity_status/reason = %q/%q, want none/empty", what, ev.IdentityStatus, ev.IdentityReason)
		}
		wantNoUser(t, what, ev)
	}

	off := newIDEnv(t, IdentityModeOff)
	if st := off.h1("").get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	off.connectDenied("")
	for what, ev := range map[string]analytics.Event{
		"h1 allow":     waitEvent(t, off.store, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" }),
		"CONNECT deny": waitEvent(t, off.store, "deny", func(ev analytics.Event) bool { return ev.Decision == "deny" }),
	} {
		if ev.IdentityStatus != "" {
			t.Errorf("identity off, %s: identity_status = %q, want empty", what, ev.IdentityStatus)
		}
	}
}

func TestDecisionLogIdentity(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	auth := "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"
	if st := e.h1(auth).get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	waitEvent(t, e.store, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" })
	// The log line is written just after the event is stored.
	for i := 0; i < 200 && !strings.Contains(e.logs.String(), "decision=allow"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	out := e.logs.String()
	var decision string
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, `msg="egress decision"`) && strings.Contains(ln, "decision=allow") {
			decision = ln
		}
	}
	for _, w := range []string{"user_sub=alice", "identity_status=valid", "groups_count=1"} {
		if !strings.Contains(decision, w) {
			t.Errorf("decision log %q lacks %s", decision, w)
		}
	}
	if strings.Contains(decision, "alice@example.test") {
		t.Errorf("email on the info-level decision line: %q", decision)
	}
	if strings.Contains(out, "tok-alice") {
		t.Errorf("raw token in logs:\n%s", out)
	}
	if !strings.Contains(out, `msg="egress decision identity"`) || !strings.Contains(out, "user_email=alice@example.test") {
		t.Errorf("debug record with email/groups missing:\n%s", out)
	}

	// At info level the email and groups are never logged at all.
	var buf lockedBuf
	p := stageProxy(t, fakes.NewVerifier(), IdentityModeAttribute, nil, newFakeMetrics())
	p.cfg.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	p.logDecision(decisionLog{Domain: "d", Decision: "allow", ID: connIdentity{Status: identity.StatusValid,
		Claims: identity.Claims{Sub: "alice", Email: "alice@example.test", Groups: []string{"eng"}}}})
	if got := buf.String(); strings.Contains(got, "alice@example.test") || strings.Contains(got, "eng") || !strings.Contains(got, "user_sub=alice") {
		t.Errorf("info-level log = %q", got)
	}

	// Identity on and no token logs identity_status=none; identity off logs none of it.
	buf = lockedBuf{}
	p.logDecision(decisionLog{Domain: "d", Decision: "allow"})
	if got := buf.String(); !strings.Contains(got, "identity_status=none") || strings.Contains(got, "user_sub") {
		t.Errorf("identity on, no token: log = %q", got)
	}
	buf = lockedBuf{}
	pOff := stageProxy(t, nil, IdentityModeOff, nil, newFakeMetrics())
	pOff.cfg.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	pOff.logDecision(decisionLog{Domain: "d", Decision: "allow", ID: connIdentity{Status: identity.StatusValid, Claims: identity.Claims{Sub: "alice"}}})
	if got := buf.String(); strings.Contains(got, "identity_") || strings.Contains(got, "user_sub") {
		t.Errorf("identity off: log carries identity fields: %q", got)
	}

	// An invalid token logs status and reason but never a sub.
	buf = lockedBuf{}
	p.logDecision(decisionLog{Domain: "d", Decision: "allow", ID: connIdentity{Status: identity.StatusInvalid, Reason: identity.ReasonBadSignature,
		Claims: identity.Claims{Sub: "mallory"}}})
	if got := buf.String(); strings.Contains(got, "mallory") || !strings.Contains(got, "identity_status=invalid") || !strings.Contains(got, "identity_reason=bad_signature") {
		t.Errorf("invalid log = %q", got)
	}
}

// BenchmarkStamp is the cost recordEvent adds to every event: a status copy for
// none, a few field copies for a valid one.
func BenchmarkStamp(b *testing.B) {
	valid := connIdentity{Status: identity.StatusValid, Claims: identity.Claims{Sub: "alice", Email: "a@x", Groups: []string{"eng"}}}
	for name, ci := range map[string]connIdentity{"none": {}, "valid": valid} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var ev analytics.Event
			for i := 0; i < b.N; i++ {
				ci.stamp(&ev, true)
			}
		})
	}
}
