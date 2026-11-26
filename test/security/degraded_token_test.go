package security

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/fakes"
)

// Degraded dependencies of the token endpoint (W-P2-SECT-07). Every refusal is
// the endpoint failing closed: 503 temporarily_unavailable with a Retry-After,
// no token in the body, no request at the upstream, the closed reason on the
// token_events row (or, when no row can be written, on the log line), and a
// normal exchange as soon as the dependency is back.
//
// The warden_cp_tokens_denied_total counter that counts these is not exposed by
// the control plane yet (see the doc.go section on degraded modes): the row and the log line are what an
// operator reads today.

// storeOutage describes one store of the token endpoint that is down and how
// the endpoint records the refusal.
type storeOutage struct {
	name, reason, sub string
	// verified is true when the client assertion authenticated before the
	// store failed, so the refusal is a denied token_events row; otherwise it
	// is a log line only.
	verified bool
}

var (
	// The replay store is written when the assertion verifies: the agent is not
	// yet authenticated, so the refusal leaves a log line and no row.
	replayDown = storeOutage{"replay store down", "replay_store_unavailable", "user-6", false}
	// The session is touched after every check of the exchange passed.
	sessionDown = storeOutage{"session store down", "session_store_unavailable", "user-7", true}
	// The event row is the last write: without it no token is released, and the
	// refusal itself cannot be recorded either, so it is a log line only.
	eventDown = storeOutage{"event store down", "event_store_unavailable", "user-8", false}
	// The registry is read first, to find the agent's keys.
	agentDown = storeOutage{"agent store down", "agent_store_unavailable", "user-9", false}
)

// storeOutageCases are the refusals of the four stores, one case each.
func storeOutageCases() []Case {
	var out []Case
	for _, o := range []storeOutage{replayDown, sessionDown, eventDown, agentDown} {
		out = append(out, o.refusal())
	}
	return out
}

// refusal is an exchange for agent-a that must be refused because the store is
// down: 503 temporarily_unavailable with a Retry-After, no token in the body.
func (o storeOutage) refusal() Case {
	c := Case{
		Name:   o.name,
		Path:   PathToken,
		Covers: []string{CoverToken(o.reason)},
		Attack: func(t testing.TB, s *Stack) Observed {
			r := s.PostToken(t, s.ExchangeForm(agentOf(s, keyAgentA), s.UserToken(o.sub, []string{"eng"}), nil))
			if strings.Contains(r.Body, "access_token") {
				t.Errorf("a token was issued while the %s: %s", o.name, tail(r.Body, 200))
			}
			return SeenReply(r)
		},
		WantStatus: http.StatusServiceUnavailable,
		WantBody:   `"error":"temporarily_unavailable"`,
		WantHeader: map[string]string{"Retry-After": "*"},
		WantReason: o.reason,
	}
	if o.verified {
		c.WantResult = "denied"
	} else {
		c.Unverified = true
		c.WantLog = denied("temporarily_unavailable", o.reason)
	}
	return c
}

const keyRotated = "degraded.rotated-subject-token"

// idpUnavailable is an exchange of a user token signed by a key the control
// plane has never fetched, with the issuer down and its key cache cold.
var idpUnavailable = Case{
	Name:   "cold key cache: the issuer is unavailable",
	Path:   PathToken,
	Covers: []string{CoverToken("idp_unavailable")},
	Attack: func(t testing.TB, s *Stack) Observed {
		rotated, _ := s.Get(keyRotated).(string)
		r := s.PostToken(t, s.ExchangeForm(agentOf(s, keyAgentA), rotated, nil))
		if strings.Contains(r.Body, "access_token") {
			t.Errorf("a token was issued while the IdP was down: %s", tail(r.Body, 200))
		}
		return SeenReply(r)
	},
	WantStatus: http.StatusServiceUnavailable, WantBody: `"error":"temporarily_unavailable"`,
	WantHeader: map[string]string{"Retry-After": "*"},
	WantResult: "denied", WantReason: "idp_unavailable",
}

// recovered fails t unless an exchange for sub is issued once the dependency is
// back; the wait is a condition on the endpoint, not a sleep.
func recovered(t *testing.T, s *Stack, desc, sub string) {
	t.Helper()
	var tok string
	s.EventuallyWithin(readyDeadline, "the token endpoint to issue again after "+desc, func() bool {
		r := s.PostToken(t, s.ExchangeForm(agentOf(s, keyAgentA), s.UserToken(sub, []string{"eng"}), nil))
		if r.Status != http.StatusOK {
			return false
		}
		tok = decodeAccessToken(t, s, r)
		return true
	})
	if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, tok)); r.Status != http.StatusOK {
		t.Errorf("the token issued after %s = %d on the worker, want 200", desc, r.Status)
	}
}

// degradedIdPDown stops the OIDC issuer. A user token signed by a key the
// control plane has not fetched cannot be verified, and the issuer cannot be
// asked: the feature doc says that is 503 idp_unavailable (retryable) whether
// the key cache is warm or cold (a control plane that restarted while the
// issuer is down). No token is issued, the refusal is a denied row, and running
// workers keep serving the Warden tokens they already accept. The exchange
// works again when the issuer is back.
//
// The warm-cache case fails until the key set answers an unknown kid with
// keysUnavailable while a refresh fails (it answers 400 subject_invalid today;
// fix on fix/oidc-keyset-unknown-kid-outage).
func degradedIdPDown(t *testing.T) {
	s := degradedStack(t, StackOptions{})
	a := agentOf(s, keyAgentA)
	s.PositiveControl(t, "token", func(t *testing.T) {
		if r, tok := s.Exchange(t, a, s.UserToken("user-4", []string{"eng"}), nil); tok == "" {
			t.Fatalf("exchange = %d %s, want a token", r.Status, r.Body)
		}
	})

	// Minted while the issuer is up; its key is published but the control plane
	// has never fetched it.
	rotated := s.UserToken("user-5", []string{"eng"}, fakes.RotateKey())
	s.Put(keyRotated, rotated)
	s.Issuer.Stop()
	workerStillServes := func(prefix string) []Case {
		return []Case{
			workerAccept(prefix+"a valid token", "warden", TransportConnect,
				func(t testing.TB, s *Stack) string { return scratchToken(s, keyDegU1) }),
			workerRefusal(prefix+"a forged token", "invalid", "bad_signature", "warden", TransportConnect,
				func(t testing.TB, s *Stack) string { return scratchToken(s, keyDegForged) }),
		}
	}

	Run(t, s, "token", []Case{{
		Name: "warm key cache: an unfetched key with the issuer down is unavailable",
		Path: PathToken,
		Attack: func(t testing.TB, s *Stack) Observed {
			r := s.PostToken(t, s.ExchangeForm(a, rotated, nil))
			if strings.Contains(r.Body, "access_token") {
				t.Errorf("a token was issued while the IdP was down: %s", tail(r.Body, 200))
			}
			return SeenReply(r)
		},
		WantStatus: http.StatusServiceUnavailable, WantBody: `"error":"temporarily_unavailable"`,
		WantHeader: map[string]string{"Retry-After": "*"},
		WantResult: "denied", WantReason: "idp_unavailable",
	}})
	Run(t, s, "worker", workerStillServes("IdP down, warm cache: "))

	// A restart empties the key cache; the issuer is still down.
	s.StopCP(t)
	s.RestartCP(t)
	Run(t, s, "token", []Case{idpUnavailable})
	Run(t, s, "worker", workerStillServes("IdP down, cold cache: "))

	s.Issuer.Start()
	var tok string
	s.EventuallyAdvance("the token endpoint to fetch the new key and issue", time.Second, func() bool {
		r := s.PostToken(t, s.ExchangeForm(a, rotated, nil))
		if r.Status != http.StatusOK {
			return false
		}
		tok = decodeAccessToken(t, s, r)
		return true
	})
	if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, tok)); r.Status != http.StatusOK {
		t.Errorf("the token issued after the IdP returned = %d on the worker, want 200", r.Status)
	}
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}

// degradedTokenStores breaks, one at a time, each store the token
// endpoint reads or writes: the endpoint refuses to issue (503, closed reason)
// and issues again when the store is back. The stores are the control plane's
// own state database, failed through a second connection to it (see FailWrites
// and HideTable), so the refusal is the shipped code's answer to a real
// storage fault.
func degradedTokenStores(t *testing.T) {
	s := degradedStack(t, StackOptions{})
	a := agentOf(s, keyAgentA)
	s.PositiveControl(t, "token", func(t *testing.T) {
		if r, tok := s.Exchange(t, a, s.UserToken("user-4", []string{"eng"}), nil); tok == "" {
			t.Fatalf("exchange = %d %s, want a token", r.Status, r.Body)
		}
	})

	// Writes to a table fail. The case's own exchange is the first thing to
	// touch it, so nothing is waited for.
	writeFails := func(o storeOutage, table string) {
		t.Run(o.name, func(t *testing.T) {
			restore := s.FailWrites(t, table)
			Run(t, s, "token", []Case{o.refusal()})
			restore()
			recovered(t, s, o.name, o.sub)
		})
	}
	writeFails(replayDown, "token_assertion_jti")
	writeFails(sessionDown, "token_sessions")
	writeFails(eventDown, "token_events")

	// The agent registry's reads fail once its snapshot is dropped (its watch
	// sees the other connection's commit on the next tick).
	t.Run(agentDown.name, func(t *testing.T) {
		restore := s.HideTable(t, "agents")
		s.EventuallyWithin(readyDeadline, "the token endpoint to lose the agent registry", func() bool {
			return s.PostToken(t, s.ExchangeForm(a, s.UserToken("probe", []string{"eng"}), nil)).Status == http.StatusServiceUnavailable
		})
		Run(t, s, "token", []Case{agentDown.refusal()})
		restore()
		recovered(t, s, "the agent registry returned", agentDown.sub)
	})
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}
