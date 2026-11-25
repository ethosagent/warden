//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/security"
)

// TestIdentityRequire proves the done_when of the agent-bound tokens feature on
// the real control plane and real workers (W-P2-WBND-10): a Warden token minted
// through POST /oauth2/token with an agent assertion is accepted by the worker
// bound to that agent in require mode, every other credential is refused
// before the worker dials anything, and the worker talks to the control plane
// with its client certificate only.
//
// The stack is test/security's: controlplane.Run and worker.Run in this
// process on loopback, one fake clock shared by all of them. Token lifetimes
// are therefore driven by advancing that clock on a condition, never by sleeping
// (the ticket's real-time expiry with tokenService.ttl at its 1m minimum would
// make every expiry subtest wait a minute for nothing).
func TestIdentityRequire(t *testing.T) {
	t.Run("reject", testRejects)
	t.Run("accepted", testAccepted)
	t.Run("revocation", testRevocation)
	t.Run("expiry", testExpiry)
	t.Run("degraded", testDegraded)
	t.Run("mtls", testMTLS)
}

// refused is a credential the require-mode worker answers with a 407 challenge
// (or the 403 of a revoked binding) without dialing the upstream: one count of
// warden_identity_verify_total under result, reason and token type, one
// identity_required deny event, zero upstream dials.
func refused(name, result, reason, tokenType string, token func(t testing.TB, s *security.Stack) string) security.Case {
	return security.Case{
		Name:             name,
		Path:             security.PathWorker,
		WantStatus:       http.StatusProxyAuthRequired,
		WantHeader:       map[string]string{"Proxy-Authenticate": `Basic realm="warden"`},
		WantBody:         "identity_required",
		WantResult:       result,
		WantReason:       reason,
		WantTokenType:    tokenType,
		WantDeny:         "identity_required",
		WantUpstreamHits: 0,
		Attack: func(t testing.TB, s *security.Stack) security.Observed {
			dials := s.UpstreamDials()
			obs := security.Seen(connect(t, s, s.Worker("agent-a"), token(t, s)))
			if got := s.UpstreamDials() - dials; got != 0 {
				t.Errorf("the worker dialed the upstream %d times for a refused credential, want 0", got)
			}
			return obs
		},
	}
}

func forgedFor(agent string, opts ...security.TokenOption) func(t testing.TB, s *security.Stack) string {
	return func(t testing.TB, s *security.Stack) string {
		return s.ForgeWarden(t, s.Agent(agent), "user-1", opts...)
	}
}

func testRejects(t *testing.T) {
	s, a, b := requireStack(t, security.StackOptions{})
	good := s.MintWardenToken(t, a, "user-1", "eng")
	other := s.MintWardenToken(t, b, "user-2", "eng")
	removedKey := s.MintWardenToken(t, a, "user-3", "eng")
	disabled := s.MintWardenToken(t, b, "user-4", "eng")
	rel := func(d time.Duration) int64 { return s.Clock.Now().Truncate(time.Second).Add(d).Unix() }

	s.PositiveControl(t, "worker", func(t *testing.T) {
		before := s.Upstream.Hits()
		if r := connect(t, s, s.Worker("agent-a"), good); r.Status != http.StatusOK {
			t.Fatalf("a valid token = %d, want 200 (%s)", r.Status, r.Body)
		}
		if got := s.Upstream.Hits() - before; got != 1 {
			t.Fatalf("a valid token reached the upstream %d times, want 1", got)
		}
	})

	noToken := refused("no token", "", "", "", func(testing.TB, *security.Stack) string { return "" })
	// Nothing is presented, so nothing is verified: the counter must not move.
	noToken.Attack = func(t testing.TB, s *security.Stack) security.Observed {
		w := s.Worker("agent-a")
		s.WaitIdle(t)
		before := s.Metric(t, w, "warden_identity_verify_total", nil)
		dials := s.UpstreamDials()
		obs := security.Seen(connect(t, s, w, ""))
		s.WaitIdle(t)
		if got := s.Metric(t, w, "warden_identity_verify_total", nil) - before; got != 0 {
			t.Errorf("warden_identity_verify_total rose by %v for a request with no token, want 0 (nothing to verify)", got)
		}
		if got := s.UpstreamDials() - dials; got != 0 {
			t.Errorf("the worker dialed the upstream %d times for a request with no token, want 0", got)
		}
		return obs
	}

	removedKeyCase := refused("a removed agent key", "invalid", "cnf_mismatch", "warden", func(testing.TB, *security.Stack) string { return removedKey })
	removedKeyCase.Setup = func(t testing.TB, s *security.Stack) {
		// The token minted with the old key keeps its cnf.jkt, which the next
		// bundle no longer lists.
		w := s.Worker("agent-a")
		seq := s.BundleSeq(t, w)
		s.RotateAgentKey(t, a, fakes.NewAgentKey(t, "agent-a-key-2"), "eng")
		s.AwaitBundle(t, w, seq)
	}

	disabledAgent := security.Case{
		Name: "a disabled agent",
		Path: security.PathWorker,
		Setup: func(t testing.TB, s *security.Stack) {
			w := s.Worker("agent-b")
			seq := s.BundleSeq(t, w)
			s.SetAgentEnabled(t, "agent-b", false)
			s.AwaitBundle(t, w, seq)
		},
		Worker: "agent-b",
		Attack: func(t testing.TB, s *security.Stack) security.Observed {
			dials := s.UpstreamDials()
			wb := s.Worker("agent-b")
			s.WaitIdle(t)
			blocked := s.Metric(t, wb, "warden_blocked_total", map[string]string{"reason": "agent_disabled"})
			defer func() {
				s.WaitIdle(t)
				if got := s.Metric(t, wb, "warden_blocked_total", map[string]string{"reason": "agent_disabled"}) - blocked; got != 1 {
					t.Errorf(`warden_blocked_total{reason="agent_disabled"} rose by %v, want 1`, got)
				}
			}()
			obs := security.Seen(connect(t, s, s.Worker("agent-b"), disabled))
			if got := s.UpstreamDials() - dials; got != 0 {
				t.Errorf("the worker dialed the upstream %d times for a disabled agent, want 0", got)
			}
			return obs
		},
		WantStatus: http.StatusForbidden,
		WantBody:   `{"error":"agent_disabled"}`,
		WantDeny:   "agent_disabled",
	}

	security.Run(t, s, "worker", []security.Case{
		noToken,
		refused("a Dex token", "invalid", "unbound_token", "idp", func(_ testing.TB, s *security.Stack) string {
			return s.UserToken("user-1", []string{"eng"})
		}),
		refused("an expired token", "expired", "none", "warden", func(t testing.TB, s *security.Stack) string {
			return s.ForgeWarden(t, s.Agent("agent-a"), "user-1",
				security.Claim("iat", rel(-10*time.Minute)), security.Claim("exp", rel(-(skew+5*time.Second))))
		}),
		refused("a forged token", "invalid", "bad_signature", "warden", forgedFor("agent-a", security.FlippedSignature())),
		refused("a token with an unknown kid", "invalid", "unknown_kid", "warden", forgedFor("agent-a", security.Header("kid", "no-such-key-id"))),
		refused("a token for another agent", "invalid", "agent_mismatch", "warden", func(testing.TB, *security.Stack) string { return other }),
		// The cuts come last: they change the registry every later case would see.
		removedKeyCase,
		disabledAgent,
	})
}

// testAccepted: the token minted through the token endpoint is accepted on all
// three transports, and the worker's stored event, its decision line and the
// control plane's fleet event all carry the same verified identity: sub, act,
// sid, groups and token_type=warden. No token appears in any captured log.
func testAccepted(t *testing.T) {
	s, a, b := requireStack(t, security.StackOptions{DecisionLog: true, CentralIngest: true})
	tokA := s.MintWardenToken(t, a, "user-1", "eng")
	tokB := s.MintWardenToken(t, b, "user-2", "eng")
	want := decode(t, tokA)
	if want.Sub != "user-1" || want.Act.Sub != "agent-a" || want.SID == "" || !slices.Equal(want.Groups, []string{"eng"}) {
		t.Fatalf("the minted token carries sub %q act %q sid %q groups %v, want user-1, agent-a, a sid and [eng]",
			want.Sub, want.Act.Sub, want.SID, want.Groups)
	}
	wa, wb := s.Worker("agent-a"), s.Worker("agent-b")
	validBefore := verifyCount(t, s, wa, map[string]string{"result": "valid", "token_type": "warden"})
	for _, tr := range security.Transports {
		if r := s.Do(t, wa, security.Via(tr, tokA)); r.Status != http.StatusOK {
			t.Fatalf("%s: a minted token = %d, want 200 (%s)", tr, r.Status, r.Body)
		}
	}
	if r := connect(t, s, wb, tokB); r.Status != http.StatusOK {
		t.Fatalf("agent-b's own token = %d, want 200", r.Status)
	}
	s.WaitIdle(t)
	if got := verifyCount(t, s, wa, map[string]string{"result": "valid", "token_type": "warden"}) - validBefore; got < float64(len(security.Transports)) {
		t.Errorf(`warden_identity_verify_total{result="valid",token_type="warden"} rose by %v, want at least %d`, got, len(security.Transports))
	}

	// carries is the identity every record of the request must hold.
	type seen struct{ sub, act, sid, status, tokenType string }
	wantSeen := seen{"user-1", "agent-a", want.SID, "valid", "warden"}

	t.Run("worker event", func(t *testing.T) {
		evs := eventsFor(t, s, wa, "user-1")
		if len(evs) < len(security.Transports) {
			t.Fatalf("%d stored events for user-1, want at least %d", len(evs), len(security.Transports))
		}
		for _, e := range evs {
			got := seen{e.UserSub, e.UserAct, e.UserSID, e.IdentityStatus, e.IdentityTokenType}
			if got != wantSeen || !slices.Equal(e.UserGroups, want.Groups) {
				t.Errorf("event identity = %+v groups %v, want %+v groups %v", got, e.UserGroups, wantSeen, want.Groups)
			}
		}
	})

	t.Run("decision line", func(t *testing.T) {
		n := 0
		for _, rec := range s.DecisionLines(t) {
			if rec.User == nil || rec.User.Sub != "user-1" {
				continue
			}
			n++
			got := seen{rec.User.Sub, rec.User.Act, rec.User.SID, rec.User.Status, rec.User.TokenType}
			if got != wantSeen || !slices.Equal(rec.User.Groups, want.Groups) {
				t.Errorf("decision line identity = %+v groups %v, want %+v groups %v", got, rec.User.Groups, wantSeen, want.Groups)
			}
		}
		if n < len(security.Transports) {
			t.Errorf("%d decision lines for user-1, want at least %d", n, len(security.Transports))
		}
	})

	t.Run("fleet event", func(t *testing.T) {
		// The worker pushes its events to /central/ingest on its own schedule,
		// which the shared clock drives.
		var fleet []analytics.Event
		s.EventuallyAdvance("the control plane's fleet store to hold agent-a's events", 5*time.Second, func() bool {
			fleet = s.FleetEvents(t, "act=agent-a&user=user-1")
			return len(fleet) >= len(security.Transports)
		})
		for _, e := range fleet {
			got := seen{e.UserSub, e.UserAct, e.UserSID, e.IdentityStatus, e.IdentityTokenType}
			if got != wantSeen || !slices.Equal(e.UserGroups, want.Groups) {
				t.Errorf("fleet event identity = %+v groups %v, want %+v groups %v", got, e.UserGroups, wantSeen, want.Groups)
			}
		}
		// ?act= is exact: agent-b's traffic never answers for agent-a.
		s.EventuallyAdvance("the control plane's fleet store to hold agent-b's event", 5*time.Second, func() bool {
			return len(s.FleetEvents(t, "act=agent-b")) > 0
		})
		for _, e := range s.FleetEvents(t, "act=agent-b") {
			if e.UserAct != "agent-b" || e.UserSub != "user-2" {
				t.Errorf("the act=agent-b filter returned an event of act %q sub %q", e.UserAct, e.UserSub)
			}
		}
		raw, err := json.Marshal(s.FleetEvents(t, ""))
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{tokA, tokB} {
			if strings.Contains(string(raw), tok) {
				t.Error("a minted token appears in the fleet events")
			}
		}
	})

	t.Run("no token in any log", func(t *testing.T) {
		logs := s.Logs(t)
		for name, tok := range map[string]string{"agent-a's": tokA, "agent-b's": tokB} {
			if strings.Contains(logs, tok) {
				t.Errorf("%s token appears in the captured logs", name)
			}
			// A raw signature or payload segment is as good as the token.
			for _, seg := range strings.Split(tok, ".")[1:] {
				if strings.Contains(logs, seg) {
					t.Errorf("a payload or signature segment of %s token appears in the captured logs", name)
				}
			}
		}
		s.AssertNoLeak(t, security.LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})
}

// cutBound is how long a cut may take to reach a worker from the moment the
// admin call returned: one long-poll (the stack's 2s controlPlane.longPollWait)
// plus a second of slack for the apply itself. It is real time, measured with
// no clock advance, so a cut that only worked because the test moved the fake
// clock would fail it.
const cutBound = 3 * time.Second

// testRevocation: blocking a user by email, and disabling an agent, close the
// tunnels already open for them within one long-poll, and refuse their next
// request even though their tokens are still unexpired.
func testRevocation(t *testing.T) {
	s, a, b := requireStack(t, security.StackOptions{})
	wa, wb := s.Worker("agent-a"), s.Worker("agent-b")
	u1 := s.MintWardenToken(t, a, "user-1", "eng")
	u2 := s.MintWardenToken(t, a, "user-2", "eng")
	bu := s.MintWardenToken(t, b, "user-1", "eng")
	if c := decode(t, u1); c.Email != "user-1@example.com" {
		t.Fatalf("the minted token carries email %q, want user-1@example.com (a block by email has nothing to match)", c.Email)
	}
	open := func(w *security.Worker, token string) *security.Tunnel {
		tun := s.OpenTunnel(t, w, security.TransportTerminated, token)
		if tun.Open.Status != http.StatusOK {
			t.Fatalf("the tunnel on %s did not open: %d %s", w.Name, tun.Open.Status, tun.Open.Body)
		}
		if r := tun.MustGet(t); r.Status != http.StatusOK {
			t.Fatalf("the warm-up request on %s = %d, want 200", w.Name, r.Status)
		}
		return tun
	}
	tun1, tun2, tunB := open(wa, u1), open(wa, u2), open(wb, bu)

	t.Run("block by email", func(t *testing.T) {
		cut := s.StartCut(t, wa, func() { s.BlockEmail(t, "user-1@example.com") })
		cut.Within(t, cutBound, "close the blocked user's open tunnel", tun1.Closed)
		cut.Within(t, cutBound, "refuse the blocked user's next request", func() bool {
			return connect(t, s, wa, u1).Status == http.StatusForbidden
		})
		r := connect(t, s, wa, u1)
		if r.Status != http.StatusForbidden || !strings.Contains(r.Body, `"user_blocked"`) {
			t.Errorf("a blocked user with an unexpired token = %d %s, want 403 user_blocked", r.Status, r.Body)
		}
		// Another user of the same agent is untouched, on the open tunnel and a new one.
		if r := tun2.MustGet(t); r.Status != http.StatusOK {
			t.Errorf("the other user's open tunnel = %d, want 200", r.Status)
		}
		if r := connect(t, s, wa, u2); r.Status != http.StatusOK {
			t.Errorf("the other user on a new CONNECT = %d, want 200", r.Status)
		}
	})

	t.Run("agent disable", func(t *testing.T) {
		cut := s.StartCut(t, wb, func() { s.SetAgentEnabled(t, "agent-b", false) })
		cut.Within(t, cutBound, "close the disabled agent's open tunnel", tunB.Closed)
		cut.Within(t, cutBound, "refuse the disabled agent's next request", func() bool {
			return connect(t, s, wb, bu).Status == http.StatusForbidden
		})
		r := connect(t, s, wb, bu)
		if r.Status != http.StatusForbidden || !strings.Contains(r.Body, `"agent_disabled"`) {
			t.Errorf("a disabled agent with an unexpired token = %d %s, want 403 agent_disabled", r.Status, r.Body)
		}
		// The other agent is untouched.
		if r := connect(t, s, wa, u2); r.Status != http.StatusOK {
			t.Errorf("agent-a after agent-b was disabled = %d, want 200", r.Status)
		}
	})
	s.AssertNoLeak(t, security.LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}

// testExpiry: a session is closed at its token's exp (a raw tunnel at exp plus
// skew), each closure is one identity_expired deny event, and the client's
// reconnect with a fresh token works. Time is the shared fake clock, advanced
// only until the condition holds.
func testExpiry(t *testing.T) {
	closedByExpiry := func(t *testing.T, s *security.Stack, w *security.Worker) int {
		t.Helper()
		n := 0
		for _, e := range s.DenyEvents(t, w) {
			if e.Reason == "identity_expired" && e.IdentityStatus == "expired" {
				n++
			}
		}
		return n
	}

	t.Run("terminated tunnel closes at exp", func(t *testing.T) {
		s, a, _ := requireStack(t, security.StackOptions{})
		w := s.Worker("agent-a")
		tok := s.MintWardenToken(t, a, "user-1", "eng")
		exp := time.Unix(decode(t, tok).Exp, 0)
		tun := s.OpenTunnel(t, w, security.TransportTerminated, tok)
		if tun.Open.Status != http.StatusOK {
			t.Fatalf("the tunnel did not open: %d %s", tun.Open.Status, tun.Open.Body)
		}
		if r := tun.MustGet(t); r.Status != http.StatusOK {
			t.Fatalf("a request before exp = %d, want 200", r.Status)
		}
		blocked := s.Metric(t, w, "warden_blocked_total", map[string]string{"reason": "identity_expired"})

		// Just before exp the session is still open and serves.
		advanceTo(s, exp.Add(-30*time.Second))
		if tun.Closed() {
			t.Fatal("the tunnel was closed before its token's exp")
		}
		if r := tun.MustGet(t); r.Status != http.StatusOK {
			t.Fatalf("a request 30s before exp = %d, want 200", r.Status)
		}

		s.EventuallyAdvance("the worker to close the tunnel at its token's exp", time.Second, tun.Closed)
		if now := s.Clock.Now(); now.Before(exp) {
			t.Errorf("the tunnel was closed at %s, before its token's exp %s", now, exp)
		}
		s.Eventually("the closure to be counted as identity_expired", func() bool {
			s.WaitIdle(t)
			return s.Metric(t, w, "warden_blocked_total", map[string]string{"reason": "identity_expired"}) == blocked+1
		})
		if got := closedByExpiry(t, s, w); got != 1 {
			t.Errorf("%d identity_expired deny events (identity_status expired), want exactly 1", got)
		}

		// The old token is spent for good once exp plus skew has passed.
		advanceTo(s, expiry(t, tok).Add(time.Second))
		dials := s.UpstreamDials()
		if r := connect(t, s, w, tok); r.Status != http.StatusProxyAuthRequired {
			t.Errorf("the expired token on a new CONNECT = %d, want 407", r.Status)
		}
		if got := s.UpstreamDials() - dials; got != 0 {
			t.Errorf("the worker dialed the upstream %d times for an expired token, want 0", got)
		}

		// The client reconnects with a fresh token.
		fresh := s.MintWardenToken(t, a, "user-1", "eng")
		if decode(t, fresh).Exp <= decode(t, tok).Exp {
			t.Fatalf("the fresh token does not outlive the old one")
		}
		tun2 := s.OpenTunnel(t, w, security.TransportTerminated, fresh)
		if tun2.Open.Status != http.StatusOK {
			t.Fatalf("the reconnect with a fresh token did not open: %d %s", tun2.Open.Status, tun2.Open.Body)
		}
		if r := tun2.MustGet(t); r.Status != http.StatusOK {
			t.Errorf("a request on the reconnected tunnel = %d, want 200", r.Status)
		}
		s.AssertNoLeak(t, security.LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	t.Run("raw tunnel closes at exp plus skew", func(t *testing.T) {
		// No MITM CA: the tunnel is opaque and bound at CONNECT only, so only
		// the session closer can end it.
		s, a, _ := requireStack(t, security.StackOptions{NoCA: true})
		w := s.Worker("agent-a")
		tok := s.MintWardenToken(t, a, "user-1", "eng")
		tun := s.OpenTunnel(t, w, security.TransportConnect, tok)
		if tun.Open.Status != http.StatusOK {
			t.Fatalf("the raw tunnel did not open: %d %s", tun.Open.Status, tun.Open.Body)
		}
		if r := tun.MustGet(t); r.Status != http.StatusOK {
			t.Fatalf("a request on the raw tunnel = %d, want 200", r.Status)
		}
		advanceTo(s, expiry(t, tok).Add(-30*time.Second))
		if tun.Closed() {
			t.Fatal("the raw tunnel was closed before its token's exp plus skew")
		}
		s.EventuallyAdvance("the worker to close the raw tunnel at exp plus skew", time.Second, tun.Closed)
		if now := s.Clock.Now(); now.Before(expiry(t, tok)) {
			t.Errorf("the raw tunnel was closed at %s, before exp plus skew %s", now, expiry(t, tok))
		}
		s.Eventually("the closure to be stored as an identity_expired deny event", func() bool { return closedByExpiry(t, s, w) == 1 })

		fresh := s.MintWardenToken(t, a, "user-1", "eng")
		tun2 := s.OpenTunnel(t, w, security.TransportConnect, fresh)
		if tun2.Open.Status != http.StatusOK {
			t.Fatalf("the reconnect with a fresh token did not open: %d %s", tun2.Open.Status, tun2.Open.Body)
		}
		if r := tun2.MustGet(t); r.Status != http.StatusOK {
			t.Errorf("a request on the reconnected raw tunnel = %d, want 200", r.Status)
		}
	})
}

// testDegraded: what the worker does when it cannot reach the control plane,
// and in attribute mode.
func testDegraded(t *testing.T) {
	// A stopped control plane changes nothing the worker already verified: a
	// token that has not expired keeps working on the bundle the worker holds,
	// and stops at exp plus skew, because expiry is the worker's own check.
	t.Run("control plane stopped", func(t *testing.T) {
		s, a, _ := requireStack(t, security.StackOptions{})
		w := s.Worker("agent-a")
		tok := s.MintWardenToken(t, a, "user-1", "eng")
		if r := connect(t, s, w, tok); r.Status != http.StatusOK {
			t.Fatalf("a valid token before the stop = %d, want 200", r.Status)
		}
		s.StopCP(t)
		if r := connect(t, s, w, tok); r.Status != http.StatusOK {
			t.Errorf("an unexpired token with the control plane stopped = %d, want 200 (%s)", r.Status, r.Body)
		}
		advanceTo(s, expiry(t, tok).Add(time.Second))
		dials := s.UpstreamDials()
		expired := verifyCount(t, s, w, map[string]string{"result": "expired"})
		if r := connect(t, s, w, tok); r.Status != http.StatusProxyAuthRequired {
			t.Errorf("an expired token with the control plane stopped = %d, want 407 (%s)", r.Status, r.Body)
		}
		s.WaitIdle(t)
		if got := verifyCount(t, s, w, map[string]string{"result": "expired"}) - expired; got != 1 {
			t.Errorf(`warden_identity_verify_total{result="expired"} rose by %v, want 1`, got)
		}
		if got := s.UpstreamDials() - dials; got != 0 {
			t.Errorf("the worker dialed the upstream %d times for an expired token, want 0", got)
		}
	})

	// A worker that restarts before it holds any verified bundle has no token
	// keys: every request is refused, whatever it carries, until the control
	// plane serves one.
	t.Run("restart before the first verified bundle", func(t *testing.T) {
		s, a, _ := requireStack(t, security.StackOptions{})
		w := s.Worker("agent-a")
		tok := s.MintWardenToken(t, a, "user-1", "eng")
		if r := connect(t, s, w, tok); r.Status != http.StatusOK {
			t.Fatalf("a valid token before the restart = %d, want 200", r.Status)
		}
		// Signed with the CP's own key, so it is built while the key manager is open.
		forgedKid := s.ForgeWarden(t, a, "user-1")
		s.StopCP(t)
		s.StopWorker(t, w)
		// Without the last-known-good cache the worker has nothing verified to
		// enforce at boot.
		s.DropBundleCache(t, w)
		s.RestartWorker(t, w)

		if seq := s.Metric(t, w, "warden_bundle_seq", nil); seq != 0 {
			t.Fatalf("warden_bundle_seq = %v after a restart with no control plane and no cache, want 0", seq)
		}
		dials, hits := s.UpstreamDials(), s.Upstream.Hits()
		for name, token := range map[string]string{
			"the minted token":        tok,
			"no token":                "",
			"a Dex token":             s.UserToken("user-1", []string{"eng"}),
			"a token with a real kid": forgedKid,
		} {
			// Denied by the fail-closed policy before identity is even asked.
			if r := connect(t, s, w, token); r.Status != http.StatusForbidden {
				t.Errorf("%s with no verified bundle = %d, want 403 (deny all)", name, r.Status)
			}
		}
		if got := s.UpstreamDials() - dials; got != 0 {
			t.Errorf("the worker dialed the upstream %d times with no verified bundle, want 0", got)
		}
		if got := s.Upstream.Hits() - hits; got != 0 {
			t.Errorf("%d requests reached the upstream with no verified bundle, want 0", got)
		}
		if !strings.Contains(s.Logs(t), "starting FAIL-CLOSED (deny all) until policy arrives") {
			t.Error("the worker did not log that it started fail-closed")
		}

		// Positive control: the control plane comes back, the worker pulls and
		// verifies a bundle, and the same token works again.
		s.RestartCP(t)
		s.EventuallyAdvance("the worker to apply its first verified bundle", time.Second, func() bool {
			v, ok := s.TryMetric(w, "warden_bundle_seq", nil)
			return ok && v > 0
		})
		s.Eventually("the minted token to be accepted again", func() bool {
			return connect(t, s, w, tok).Status == http.StatusOK
		})
	})

	// Attribute mode is not enforcement: a valid Dex token is allowed and
	// recorded as the user's identity with token_type=idp.
	t.Run("attribute mode records Dex tokens", func(t *testing.T) {
		s := security.StartStack(t, security.StackOptions{AgentModes: map[string]string{"agent-a": "attribute"}})
		a := s.RegisterAgent(t, "agent-a", fakes.NewAgentKey(t, "agent-a-key-1"), "eng")
		w := s.Worker("agent-a")
		valid := map[string]string{"result": "valid", "token_type": "idp"}
		before := verifyCount(t, s, w, valid)
		if r := connect(t, s, w, s.UserToken("user-1", []string{"eng"})); r.Status != http.StatusOK {
			t.Fatalf("a Dex token in attribute mode = %d, want 200 (%s)", r.Status, r.Body)
		}
		s.WaitIdle(t)
		if got := verifyCount(t, s, w, valid) - before; got != 1 {
			t.Errorf(`warden_identity_verify_total{result="valid",token_type="idp"} rose by %v, want 1`, got)
		}
		var recorded bool
		for _, e := range eventsFor(t, s, w, "user-1") {
			recorded = recorded || e.IdentityStatus == "valid" && e.IdentityTokenType == "idp" && e.UserAct == ""
		}
		if !recorded {
			t.Error("the stored event of a valid Dex token does not carry identity_status valid and token_type idp")
		}
		// A Warden token is attributed too, with its agent.
		if r := connect(t, s, w, s.MintWardenToken(t, a, "user-2", "eng")); r.Status != http.StatusOK {
			t.Errorf("a Warden token in attribute mode = %d, want 200", r.Status)
		}
		s.AssertNoLeak(t, security.LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})
}

// workerRoutes are the control plane routes a worker calls on its own.
var workerRoutes = []string{"/policy", "/control/heartbeat", "/central/ingest"}

// testMTLS: the worker calls the control plane with its client certificate and
// nothing else, before and after the certificate renews, and the control plane
// refuses a bearer on the worker routes. A TamperProxy sits in front of the
// control plane and records every request the worker makes (path, whether an
// Authorization header was present, the certificate the worker presented); it
// relays everything unchanged.
func testMTLS(t *testing.T) {
	s := security.StartStack(t, security.StackOptions{
		CentralIngest: true,
		WorkerCertTTL: time.Hour,
		CPEndpoint:    func(s *security.Stack, w *security.Worker) string { return security.NewTamperProxy(s, w).Addr },
	})
	a := s.RegisterAgent(t, "agent-a", fakes.NewAgentKey(t, "agent-a-key-1"), "eng")
	w := s.Worker("agent-a")
	proxy := w.Tamper

	tok := s.MintWardenToken(t, a, "user-1", "eng")
	if r := connect(t, s, w, tok); r.Status != http.StatusOK {
		t.Fatalf("a valid token = %d, want 200", r.Status)
	}
	// seen returns the proxied requests to path since index from.
	seen := func(path string, from int) []security.ProxiedRequest {
		var out []security.ProxiedRequest
		for _, r := range proxy.Requests()[from:] {
			if r.Path == path {
				out = append(out, r)
			}
		}
		return out
	}
	// fingerprint of the certificate the worker holds now.
	fingerprint := func() string {
		cert := s.Credential(t, w)
		sum := sha256.Sum256(cert.Certificate[0])
		return hex.EncodeToString(sum[:])
	}
	accepted := func(r security.ProxiedRequest) bool {
		return httpOK(r.Status) || r.Status == http.StatusNotModified
	}

	t.Run("worker routes carry a client certificate and no Authorization header", func(t *testing.T) {
		for _, path := range workerRoutes {
			s.EventuallyAdvance("the worker to call "+path, time.Second, func() bool {
				return slices.ContainsFunc(seen(path, 0), accepted)
			})
		}
		cert := fingerprint()
		for _, r := range proxy.Requests() {
			if r.Authorization {
				t.Errorf("%s %s carried an Authorization header", r.Method, r.Path)
			}
			if slices.Contains(workerRoutes, r.Path) {
				if r.ClientCert != cert {
					t.Errorf("%s %s presented certificate %.12q, want the worker's own %.12q", r.Method, r.Path, r.ClientCert, cert)
				}
				if r.Status == http.StatusUnauthorized || r.Status == http.StatusForbidden {
					t.Errorf("%s %s = %d, want the control plane to accept the worker's certificate", r.Method, r.Path, r.Status)
				}
			}
		}
	})

	t.Run("the control plane refuses a bearer on the worker routes", func(t *testing.T) {
		anon := s.CPClient(t, nil)
		bearers := map[string]string{
			"a worker token":        "Bearer wwt_" + strings.Repeat("a", 43),
			"a shared token":        "Bearer legacy-shared-worker-token",
			"a minted Warden token": "Bearer " + tok,
			"basic credentials":     "Basic " + base64.StdEncoding.EncodeToString([]byte("worker:secret")),
		}
		for name, auth := range bearers {
			for _, path := range workerRoutes {
				method, body := http.MethodPost, []byte(`{}`)
				hdr := http.Header{"Authorization": {auth}}
				if path == "/policy" {
					method, body = http.MethodGet, nil
					hdr.Set("Accept", controlplane.BundleMediaType)
				}
				if r := s.Send(t, anon, method, path, hdr, body); r.Status != http.StatusUnauthorized {
					t.Errorf("%s with %s and no certificate = %d, want 401", path, name, r.Status)
				}
			}
		}
		// A valid certificate wins: a bearer next to it is ignored, and the
		// caller is the certificate's worker, never a token worker.
		withCert := s.Credential(t, w)
		hdr := http.Header{"Authorization": {"Bearer wwt_" + strings.Repeat("b", 43)}, "Accept": {controlplane.BundleMediaType}}
		if r := s.Send(t, s.CPClient(t, &withCert), http.MethodGet, "/policy", hdr, nil); r.Status != http.StatusOK {
			t.Errorf("GET /policy with the worker certificate and a bearer = %d, want 200 (the certificate wins)", r.Status)
		}
		views := s.AdminSession(t).Do(t, http.MethodGet, "/dashboard/api/workers", nil)
		var workers []struct {
			ProxyID  string `json:"proxyID"`
			AuthKind string `json:"authKind"`
		}
		if err := json.Unmarshal([]byte(views.Body), &workers); err != nil || views.Status != http.StatusOK {
			t.Fatalf("GET /dashboard/api/workers = %d %v", views.Status, err)
		}
		found := false
		for _, v := range workers {
			if v.ProxyID == w.Name {
				found = true
				if v.AuthKind != "cert" {
					t.Errorf("%s authenticated as %q, want cert", v.ProxyID, v.AuthKind)
				}
			} else if v.AuthKind != "cert" {
				t.Errorf("a worker %q authenticated as %q: the bearer created an identity", v.ProxyID, v.AuthKind)
			}
		}
		if !found {
			t.Errorf("no worker %q in the fleet list", w.Name)
		}
		// The positive control: the certificate alone is accepted.
		cert := s.Credential(t, w)
		if r := s.Send(t, s.CPClient(t, &cert), http.MethodGet, "/policy", http.Header{"Accept": {controlplane.BundleMediaType}}, nil); r.Status != http.StatusOK {
			t.Errorf("GET /policy with the worker certificate and no Authorization header = %d, want 200", r.Status)
		}
	})

	t.Run("a forced renewal keeps the worker connected", func(t *testing.T) {
		before := fingerprint()
		from := len(proxy.Requests())
		renewed := func() float64 {
			return s.Metric(t, w, "warden_worker_cert_renewals_total", map[string]string{"outcome": "ok"})
		}
		if got := renewed(); got != 0 {
			t.Fatalf("warden_worker_cert_renewals_total{outcome=ok} = %v before the forced renewal, want 0", got)
		}
		// Renewal is due before the certificate's hour is up: advance the shared
		// clock a minute at a time until the worker has renewed.
		s.EventuallyAdvance("the worker to renew its certificate", time.Minute, func() bool { return renewed() >= 1 })
		after := fingerprint()
		if after == before {
			t.Fatal("the worker renewed but its certificate on disk did not change")
		}

		// The worker's next requests present the new certificate, never the
		// old one again, with still no Authorization header.
		s.EventuallyAdvance("the worker to present the renewed certificate", time.Second, func() bool {
			return slices.ContainsFunc(seen("/control/heartbeat", from), func(r security.ProxiedRequest) bool { return r.ClientCert == after })
		})
		switched := false
		for _, r := range proxy.Requests()[from:] {
			if r.Authorization {
				t.Errorf("%s %s carried an Authorization header across the renewal", r.Method, r.Path)
			}
			switch {
			case r.Path == "/control/renew":
				// The renewal request itself is made with the old certificate.
			case r.ClientCert != before && r.ClientCert != after:
				t.Errorf("%s %s presented certificate %.12q, want the worker's old or renewed one", r.Method, r.Path, r.ClientCert)
			case r.ClientCert == after:
				switched = true
			case switched && r.ClientCert == before:
				t.Errorf("%s %s presented the replaced certificate after the renewed one", r.Method, r.Path)
			}
			if slices.Contains(workerRoutes, r.Path) && (r.Status == http.StatusUnauthorized || r.Status == http.StatusForbidden) {
				t.Errorf("%s %s = %d across the renewal, want the control plane to accept it", r.Method, r.Path, r.Status)
			}
		}
		for _, path := range workerRoutes {
			s.EventuallyAdvance("an accepted "+path+" request with the renewed certificate", time.Second, func() bool {
				return slices.ContainsFunc(seen(path, from), func(r security.ProxiedRequest) bool { return r.ClientCert == after && accepted(r) })
			})
		}
		// The worker still enforces on the renewed identity: a freshly minted
		// token is accepted, a forged one is not.
		fresh := s.MintWardenToken(t, a, "user-2", "eng")
		s.Eventually("the renewed worker to accept a fresh token", func() bool { return connect(t, s, w, fresh).Status == http.StatusOK })
		if r := connect(t, s, w, s.ForgeWarden(t, a, "user-2", security.FlippedSignature())); r.Status != http.StatusProxyAuthRequired {
			t.Errorf("a forged token after the renewal = %d, want 407", r.Status)
		}
	})

	t.Run("no token in any log", func(t *testing.T) {
		if strings.Contains(s.Logs(t), tok) {
			t.Error("a minted token appears in the captured logs")
		}
		s.AssertNoLeak(t, security.LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})
}
