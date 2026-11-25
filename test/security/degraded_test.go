package security

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Degraded-mode and restart cases (W-P2-SECT-07): the security controls must
// hold while parts of the system are down or restart. Every case proves the
// closed door, not an error: the status and reason, no request at the upstream,
// no token issued, the metric and the deny event or token_events row, and then
// that the door opens again when the dependency returns.

const (
	keyDegU1     = "degraded.user-1-agent-a"
	keyDegU2     = "degraded.user-2-agent-a"
	keyDegB1     = "degraded.user-1-agent-b"
	keyDegForged = "degraded.forged"
)

// degradedStack boots agent-a and agent-b, mints tokens for user-1 and user-2 on
// agent-a and for user-1 on agent-b, and passes the worker positive control.
func degradedStack(t *testing.T, opts StackOptions) *Stack {
	t.Helper()
	opts.DebugCP = true
	s := StartStack(t, opts)
	a := agentSetup(t, s, "agent-a")
	b := agentSetup(t, s, "agent-b")
	s.Put(keyAgentA, a)
	s.Put(keyDegU1, s.MintWardenToken(t, a, "user-1", "eng"))
	s.Put(keyDegU2, s.MintWardenToken(t, a, "user-2", "eng"))
	s.Put(keyDegB1, s.MintWardenToken(t, b, "user-1", "eng"))
	// Forged now: the signing keys live in the control plane's state, which a
	// stopped control plane no longer serves.
	s.Put(keyDegForged, s.ForgeWarden(t, a, "user-1", FlippedSignature()))
	s.PositiveControl(t, "worker", func(t *testing.T) {
		for _, p := range []struct{ agent, key string }{{"agent-a", keyDegU1}, {"agent-a", keyDegU2}, {"agent-b", keyDegB1}} {
			for _, tr := range Transports {
				if r := s.Do(t, s.Worker(p.agent), Via(tr, scratchToken(s, p.key))); r.Status != http.StatusOK {
					t.Fatalf("%s over %s: status %d, want 200 (%s)", p.agent, tr, r.Status, tail(r.Body, 200))
				}
			}
		}
	})
	return s
}

// cutOff blocks user-2 and disables agent-b, and waits until both workers
// enforce it, so the degraded case starts from a state with something to lose.
func cutOff(t *testing.T, s *Stack) {
	t.Helper()
	s.BlockUser(t, "user-2")
	s.SetAgentEnabled(t, "agent-b", false)
	s.EventuallyAdvance("agent-a's worker to refuse the blocked user", time.Second, func() bool {
		return s.ConnectStatus(t, s.Worker("agent-a"), UpstreamHost, scratchToken(s, keyDegU2)) == http.StatusForbidden
	})
	s.EventuallyAdvance("agent-b's worker to refuse the disabled agent", time.Second, func() bool {
		return s.ConnectStatus(t, s.Worker("agent-b"), UpstreamHost, scratchToken(s, keyDegB1)) == http.StatusForbidden
	})
}

// enforcedCases are what a worker must still answer on its last-known-good
// bundle, whatever happened to the control plane: a valid token is accepted, a
// forged one refused, a blocked user and a disabled agent stay cut off.
func enforcedCases(prefix string) []Case {
	out := []Case{
		workerAccept(prefix+"a valid token", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string { return scratchToken(s, keyDegU1) }),
		workerRefusal(prefix+"a forged token", "invalid", "bad_signature", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string { return scratchToken(s, keyDegForged) }),
		Case{
			Name: prefix + "a blocked user's still-valid token",
			Path: PathWorker,
			Attack: func(t testing.TB, s *Stack) Observed {
				return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyDegU2))))
			},
			WantStatus: http.StatusForbidden, WantBody: `{"error":"user_blocked"}`,
			WantResult: "valid", WantDeny: "user_blocked",
		},
		Case{
			Name: prefix + "a disabled agent's still-valid token",
			Path: PathWorker, Worker: "agent-b",
			Attack: func(t testing.TB, s *Stack) Observed {
				return Seen(s.Do(t, s.Worker("agent-b"), Via(TransportConnect, scratchToken(s, keyDegB1))))
			},
			WantStatus: http.StatusForbidden, WantBody: `{"error":"agent_disabled"}`, WantDeny: "agent_disabled",
		},
	}
	return out
}

// terminatedAndMCPStillServe sends the valid token over the two transports the
// matrix cases do not cover (each verifies twice, so the metric delta of the
// one-verification cases does not fit): 200 with one upstream hit each.
func terminatedAndMCPStillServe(t *testing.T, s *Stack, prefix string) {
	t.Helper()
	for _, tr := range []Transport{TransportTerminated, TransportMCP} {
		hits := s.Upstream.Hits()
		if r := s.Do(t, s.Worker("agent-a"), Via(tr, scratchToken(s, keyDegU1))); r.Status != http.StatusOK {
			t.Errorf("%sa valid token over %s = %d, want 200 (%s)", prefix, tr, r.Status, tail(r.Body, 200))
		}
		s.WaitIdle(t)
		if d := s.Upstream.Hits() - hits; d != 1 {
			t.Errorf("%sa valid token over %s reached the upstream %d times, want 1", prefix, tr, d)
		}
	}
}

// tokenLifetime is the Warden token TTL plus the verifier's skew, the time the
// control plane's absence is bridged by tokens alone.
const tokenLifetime = 15*time.Minute + defaultSkew

// noTokenFrom asserts that an exchange attempt cannot get a token because the
// control plane is not there: the connection fails, nothing is issued.
func noTokenFrom(t testing.TB, s *Stack, tokKey string) {
	t.Helper()
	form := s.ExchangeForm(s.Agent("agent-a"), s.UserToken("user-1", []string{"eng"}), nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.CP.URL+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("security: build the token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.CP.HTTP.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Errorf("a token request reached the stopped control plane: %s", resp.Status)
	}
}

// TestDegraded_CPDown stops the control plane under running workers. Require
// mode keeps enforcing on the signed bundle each worker holds: it accepts valid
// Warden tokens and refuses forged ones, a blocked user and a disabled agent
// stay cut off, no new token can be issued, and once the tokens expire nothing
// is accepted. The control plane's return restores new exchanges.
func TestDegraded_CPDown(t *testing.T) {
	s := degradedStack(t, StackOptions{})
	cutOff(t, s)

	s.StopCP(t)
	noTokenFrom(t, s, keyDegU1)
	Run(t, s, "worker", enforcedCases("CP down: "))
	terminatedAndMCPStillServe(t, s, "CP down: ")

	// Until the tokens expire: advancing past their lifetime, the worker that
	// accepted them refuses them, with nobody to issue a replacement.
	s.Clock.Advance(tokenLifetime + time.Minute)
	Run(t, s, "worker", []Case{
		workerRefusal("CP down: the token after its expiry", "expired", "", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string { return scratchToken(s, keyDegU1) }),
	})

	s.RestartCP(t)
	a := s.Agent("agent-a")
	var fresh string
	s.EventuallyAdvance("a new exchange to succeed after the control plane returned", time.Second, func() bool {
		r := s.PostToken(t, s.ExchangeForm(a, s.UserToken("user-1", []string{"eng"}), nil))
		if r.Status != http.StatusOK {
			return false
		}
		fresh = decodeAccessToken(t, s, r)
		return true
	})
	Run(t, s, "worker", []Case{workerAccept("CP back: a new token", "warden", TransportConnect,
		func(t testing.TB, s *Stack) string { return fresh })})
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}
