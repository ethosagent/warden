package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
)

// invSession is one open agent connection that carries several requests: the
// tunnel (or transparent connection) is opened once and every send rides it.
type invSession struct {
	send func(invReq) (view string, status int, err error)
	// conns reports how many client connections the session opened, so a row
	// can prove the requests shared ONE tunnel.
	conns func() int64
}

// invSessionDrivers open a multi-request session on each protocol path whose
// per-request policy check could see a mid-tunnel reload: h1 keep-alive and h2
// streams on a CONNECT tunnel, and h1 keep-alive on both transparent listeners.
func invSessionDrivers() []struct {
	name        string
	transparent bool
	open        func(e *invEnv) invSession
} {
	return []struct {
		name        string
		transparent bool
		open        func(e *invEnv) invSession
	}{
		{"connect-h1", false, func(e *invEnv) invSession {
			tc, err := e.connectTLS(invHost)
			if err != nil {
				e.t.Fatalf("connect: %v", err)
			}
			return invSession{
				send:  func(r invReq) (string, int, error) { return e.doHTTP1On(tc, r) },
				conns: func() int64 { return 1 },
			}
		}},
		{"connect-h2", false, func(e *invEnv) invSession {
			var dials atomic.Int64
			tr := &http.Transport{
				ForceAttemptHTTP2: true,
				DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					dials.Add(1)
					return e.connectTLS(invHost, "h2")
				},
			}
			e.t.Cleanup(tr.CloseIdleConnections)
			return invSession{
				send: func(r invReq) (string, int, error) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					resp, err := tr.RoundTrip(r.build().WithContext(ctx))
					if err != nil {
						return err.Error(), 0, err
					}
					defer func() { _ = resp.Body.Close() }()
					var sb strings.Builder
					sb.WriteString(resp.Status + "\n")
					_ = resp.Header.Write(&sb)
					return sb.String(), resp.StatusCode, nil
				},
				conns: dials.Load,
			}
		}},
		{"transparent-h1", true, func(e *invEnv) invSession {
			conn, err := net.DialTimeout("tcp", e.tlsAddr, 2*time.Second)
			if err != nil {
				e.t.Fatal(err)
			}
			e.t.Cleanup(func() { _ = conn.Close() })
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(e.caPEM)
			tc := tls.Client(conn, &tls.Config{ServerName: invHost, RootCAs: pool})
			_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
			if err := tc.Handshake(); err != nil {
				e.t.Fatal(err)
			}
			return invSession{
				send:  func(r invReq) (string, int, error) { return e.doHTTP1On(tc, r) },
				conns: func() int64 { return 1 },
			}
		}},
		{"transparent-plain", true, func(e *invEnv) invSession {
			conn, err := net.DialTimeout("tcp", e.httpAddr, 2*time.Second)
			if err != nil {
				e.t.Fatal(err)
			}
			e.t.Cleanup(func() { _ = conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			return invSession{
				send:  func(r invReq) (string, int, error) { return e.doHTTP1On(conn, r) },
				conns: func() int64 { return 1 },
			}
		}},
	}
}

// reloadRemovingInvHost hot-swaps the policy so the entry that admitted the
// open session is gone: invHost now matches nothing (NoMatch).
func reloadRemovingInvHost(e *invEnv) {
	e.p.cfg.Policy.Replace(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "other.test", Port: 443}}})
}

// Default-deny across a hot reload: a session admitted on an allowlist entry
// (deferNone) keeps carrying requests after a reload removed that entry. The
// next request's per-request verdict is NoMatch, and on a connection that was
// never deferred to the judge it must be the policy_no_match default-deny — not
// forwarded with no decision. The second request carries the placeholder, so a
// forward would also have swapped the canary in.
func TestInvariants_DefaultDenyAfterReload(t *testing.T) {
	for _, d := range invSessionDrivers() {
		for _, withJudge := range []bool{false, true} {
			name := d.name
			if withJudge {
				// A judge configured on the proxy does not make a deferNone
				// connection judge-eligible: nothing was deferred to it.
				name += "/judge-configured"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				var fj *fakeJudge
				var o invOpts
				if withJudge {
					fj = &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "invariants: judge says yes"}}
					o.judge = fj
				}
				if d.transparent {
					o = transOpts(o)
				}
				e := newInvEnv(t, o)
				sess := d.open(e)

				if _, st, err := sess.send(invReq{path: "/before"}); err != nil || st != http.StatusOK {
					t.Fatalf("request before the reload = %d (%v), want 200", st, err)
				}
				reloadRemovingInvHost(e)
				view, st, err := sess.send(invReq{
					path:   "/after",
					header: http.Header{"Authorization": {"Bearer " + invPlaceholder}},
				})
				if err != nil {
					t.Fatalf("request after the reload: %v", err)
				}
				if st != http.StatusForbidden {
					t.Fatalf("request after the reload = %d, want 403 (default-deny)", st)
				}
				if n := sess.conns(); n != 1 {
					t.Fatalf("session opened %d connections, want 1 (the reload must hit an OPEN tunnel)", n)
				}
				e.settle()

				for _, r := range e.backend.requests() {
					if strings.HasPrefix(r.path, "/after") {
						t.Errorf("upstream received the request sent after the reload: %q", r.path)
					}
				}
				if e.backend.upstreamSawCanary() {
					t.Error("upstream saw the real secret after the reload")
				}
				var denies int
				for _, ev := range e.store.snapshot() {
					if ev.Decision == "deny" {
						denies++
						if ev.Reason != string(denyreason.PolicyNoMatch) {
							t.Errorf("deny reason = %q, want %q", ev.Reason, denyreason.PolicyNoMatch)
						}
						if !strings.Contains(ev.URL, "/after") {
							t.Errorf("deny event URL = %q, want the /after request", ev.URL)
						}
					}
				}
				if denies != 1 {
					t.Errorf("deny events = %d, want 1: %+v", denies, e.store.snapshot())
				}
				var blocked bool
				for _, m := range e.metrics.snapshot() {
					if m == "blocked reason="+string(denyreason.PolicyNoMatch) {
						blocked = true
					}
				}
				if !blocked {
					t.Errorf("no blocked reason=policy_no_match metric: %v", e.metrics.snapshot())
				}
				if fj != nil && fj.callCount() != 0 {
					t.Errorf("judge consulted %d times on a deferNone connection, want 0", fj.callCount())
				}
				if l := e.leaks(view); len(l) > 0 {
					t.Errorf("canary leaked: %v", l)
				}
			})
		}
	}
}

// Control: a connection the admission gate deferred to the judge (the
// destination matched no rule, judge enabled) still sends a NoMatch to the
// judge after a reload — the default-deny above is only for connections that
// were never deferred to it.
func TestInvariants_ReloadKeepsDeferJudge(t *testing.T) {
	for _, d := range invSessionDrivers() {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			fj := &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "invariants: judge says yes"}}
			e := newInvEnv(t, invOpts{
				transparent: d.transparent,
				judge:       fj,
				allow:       []config.AllowlistEntry{{Domain: "unrelated.test", Port: 443}},
			})
			sess := d.open(e)
			if _, st, err := sess.send(invReq{path: "/before"}); err != nil || st != http.StatusOK {
				t.Fatalf("judge-allowed request before the reload = %d (%v), want 200", st, err)
			}
			reloadRemovingInvHost(e)
			if _, st, err := sess.send(invReq{path: "/after"}); err != nil || st != http.StatusOK {
				t.Fatalf("judge-allowed request after the reload = %d (%v), want 200", st, err)
			}
			if n := fj.callCount(); n != 2 {
				t.Fatalf("judge calls = %d, want 2 (one per request, after the reload too)", n)
			}
			e.settle()
			var sawAfter bool
			for _, r := range e.backend.requests() {
				if strings.HasPrefix(r.path, "/after") {
					sawAfter = true
				}
			}
			if !sawAfter {
				t.Error("judge-allowed request after the reload never reached the upstream")
			}
		})
	}
}
