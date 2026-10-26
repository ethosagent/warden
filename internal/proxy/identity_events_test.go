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
)

// These tests cover W-P1-VRFY-09: every analytics event and decision log line
// the proxy writes carries the caller's identity, through one chokepoint.

// waitEvent polls the store until pred matches an event (the WS event is written
// after the response, so a plain snapshot can race it).
func waitEvent(t *testing.T, st *syncStore, what string, pred func(analytics.Event) bool) analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
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
		{"zero is untouched", connIdentity{}, analytics.Event{}},
		{"none is untouched", connIdentity{Status: identity.StatusNone}, analytics.Event{}},
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
			tt.ci.stamp(&ev)
			tt.want.Domain = "d"
			if !reflect.DeepEqual(ev, tt.want) {
				t.Errorf("stamped %+v, want %+v", ev, tt.want)
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
		if line, err := bufio.NewReader(tc).ReadString('\n'); err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
			t.Fatalf("status = %q err %v, want 101", line, err)
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

func TestNoIdentityEventsUnchanged(t *testing.T) {
	for _, mode := range []IdentityMode{IdentityModeOff, IdentityModeAttribute} {
		t.Run(string(mode), func(t *testing.T) {
			e := newIDEnv(t, mode)
			if st := e.h1("").get(""); st != 200 {
				t.Fatalf("status = %d", st)
			}
			e.connectDenied("")
			waitEvent(t, e.store, "deny", func(ev analytics.Event) bool { return ev.Decision == "deny" })
			for _, ev := range e.store.snapshot() {
				wantNoUser(t, ev.Decision, ev)
				if ev.IdentityStatus != "" || ev.IdentityReason != "" {
					t.Errorf("%s event has identity_* with no token: %+v", ev.Decision, ev)
				}
			}
		})
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
	p := stageProxy(t, nil, IdentityModeOff, nil, newFakeMetrics())
	p.cfg.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	p.logDecision(decisionLog{Domain: "d", Decision: "allow", ID: connIdentity{Status: identity.StatusValid,
		Claims: identity.Claims{Sub: "alice", Email: "alice@example.test", Groups: []string{"eng"}}}})
	if got := buf.String(); strings.Contains(got, "alice@example.test") || strings.Contains(got, "eng") || !strings.Contains(got, "user_sub=alice") {
		t.Errorf("info-level log = %q", got)
	}

	// An invalid token logs status and reason but never a sub.
	buf = lockedBuf{}
	p.logDecision(decisionLog{Domain: "d", Decision: "allow", ID: connIdentity{Status: identity.StatusInvalid, Reason: identity.ReasonBadSignature,
		Claims: identity.Claims{Sub: "mallory"}}})
	if got := buf.String(); strings.Contains(got, "mallory") || !strings.Contains(got, "identity_status=invalid") || !strings.Contains(got, "identity_reason=bad_signature") {
		t.Errorf("invalid log = %q", got)
	}
}

// BenchmarkStamp is the cost recordEvent adds to every event: none for an
// event with no identity, a few field copies for a valid one.
func BenchmarkStamp(b *testing.B) {
	valid := connIdentity{Status: identity.StatusValid, Claims: identity.Claims{Sub: "alice", Email: "a@x", Groups: []string{"eng"}}}
	for name, ci := range map[string]connIdentity{"none": {}, "valid": valid} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var ev analytics.Event
			for i := 0; i < b.N; i++ {
				ci.stamp(&ev)
			}
		})
	}
}
