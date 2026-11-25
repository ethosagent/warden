package security

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// Lifetime cases (W-P2-SECT-03): a valid, unexpired token stops working when the
// agent, the user or the signing key behind it is cut off, even though the
// worker verified it before and holds a tunnel opened with it. Every cut is an
// admin request to the control plane; the worker learns it with the next signed
// bundle, which arrives on the control plane's real-time policy reload (3s) and
// the worker's long poll, so the waits are conditions (AwaitBundle, Eventually),
// never fixed sleeps and never a fake-time deadline.

const (
	keyU1     = "lifetime.user-1-token"
	keyU2     = "lifetime.user-2-token"
	keyB1     = "lifetime.agent-b-token"
	keyT1     = "lifetime.tunnel-user-1"
	keyTB     = "lifetime.tunnel-agent-b"
	keyAgentA = "lifetime.agent-a"
	keyOldKID = "lifetime.old-kid"
)

func agentOf(s *Stack, key string) *Agent {
	a, _ := s.Get(key).(*Agent)
	return a
}

func tunnelOf(s *Stack, key string) *Tunnel {
	tun, _ := s.Get(key).(*Tunnel)
	return tun
}

// userExchange is the attack of a token case: user's ID token (in groups)
// exchanged as agent-a, with extra form values.
func userExchange(user string, groups []string, extra url.Values) func(t testing.TB, s *Stack) Observed {
	return func(t testing.TB, s *Stack) Observed {
		r, _ := s.Exchange(t, agentOf(s, keyAgentA), s.UserToken(user, groups), extra)
		return SeenReply(r)
	}
}

// blockedUserCases: user-1 is blocked while holding a valid token and a tunnel.
var blockedUserCases = []Case{{
	Name: "a blocked user's next request with a still-valid token",
	Path: PathWorker,
	Attack: func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU1))))
	},
	WantStatus: http.StatusForbidden,
	WantBody:   `{"error":"user_blocked"}`,
	WantResult: "valid",
	WantDeny:   "user_blocked",
}, {
	Name:       "a blocked user cannot exchange a new token",
	Path:       PathToken,
	Covers:     []string{CoverToken("user_blocked")},
	Attack:     userExchange("user-1", []string{"eng"}, nil),
	WantStatus: http.StatusBadRequest,
	WantBody:   "invalid_grant",
	WantResult: "denied",
	WantReason: "user_blocked",
}}

// disabledAgentCases: agent-a is disabled while a user holds a valid token.
var disabledAgentCases = func() []Case {
	var out []Case
	for _, tr := range Transports {
		tr := tr
		out = append(out, Case{
			Name: "a valid token on the disabled agent's worker over " + string(tr),
			Path: PathWorker,
			Attack: func(t testing.TB, s *Stack) Observed {
				return Seen(s.Do(t, s.Worker("agent-a"), Via(tr, scratchToken(s, keyU1))))
			},
			WantStatus: http.StatusForbidden,
			WantBody:   `{"error":"agent_disabled"}`,
			WantDeny:   "agent_disabled",
		})
	}
	return append(out, Case{
		Name:   "a disabled agent cannot exchange a new token",
		Path:   PathToken,
		Covers: []string{CoverToken("agent_disabled")},
		Setup: func(t testing.TB, s *Stack) {
			// The token endpoint reads the registry on its own tick: wait until
			// it refuses the agent. Its unauthenticated warning is limited to
			// one a minute per reason, so move the clock past that window
			// before the attack is the one asserted.
			s.EventuallyAdvance("the token endpoint to refuse the disabled agent", 100*time.Millisecond, func() bool {
				a := agentOf(s, keyAgentA)
				return s.PostToken(t, s.ExchangeForm(a, s.UserToken("probe", []string{"eng"}), nil)).Status != http.StatusOK
			})
			s.Clock.Advance(2 * time.Minute)
		},
		Attack:          userExchange("user-1", []string{"eng"}, nil),
		WantStatus:      http.StatusUnauthorized,
		WantBody:        "invalid_client",
		WantReason:      "agent_disabled",
		Unauthenticated: true,
	})
}()

// revokedKeyCases: the token signing key is rotated in an emergency while a
// user holds a token signed by it and a tunnel opened with it.
var revokedKeyCases = []Case{{
	Name: "a cached token signed by the revoked key, on a new CONNECT",
	Path: PathWorker,
	Attack: func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU1))))
	},
	WantStatus:       http.StatusProxyAuthRequired,
	WantBody:         "identity_required",
	WantResult:       "invalid",
	WantReason:       "unknown_kid",
	WantDeny:         "identity_required",
	WantUpstreamHits: 0,
}, {
	Name: "the next request of a tunnel opened with a token of the revoked key",
	Path: PathWorker,
	Attack: func(t testing.TB, s *Stack) Observed {
		r, err := tunnelOf(s, keyT1).Get(t)
		if err != nil {
			t.Fatalf("the open tunnel was closed instead of answered: %v", err)
		}
		return Seen(r)
	},
	WantStatus:       http.StatusForbidden,
	WantBody:         "identity_required",
	WantResult:       "invalid",
	WantReason:       "unknown_kid",
	WantDeny:         "identity_required",
	WantUpstreamHits: 0,
}}

// issuanceCases are the token-service refusals that stop a user getting a new
// token while an old one still verifies on the worker.
var issuanceCases = []Case{{
	Name:       "a user outside the agent's allowed groups cannot exchange",
	Path:       PathToken,
	Covers:     []string{CoverToken("group_not_allowed")},
	Attack:     userExchange("user-3", []string{"ops"}, nil),
	WantStatus: http.StatusBadRequest,
	WantBody:   "unauthorized_client",
	WantResult: "denied",
	WantReason: "group_not_allowed",
}, {
	Name:       "a scope the agent may not hold is refused",
	Path:       PathToken,
	Covers:     []string{CoverToken("scope_not_allowed")},
	Attack:     userExchange("user-3", []string{"eng"}, url.Values{"scope": {"admin"}}),
	WantStatus: http.StatusBadRequest,
	WantBody:   "invalid_scope",
	WantResult: "denied",
	WantReason: "scope_not_allowed",
}, {
	Name: "a subject token issued before the session was revoked is refused",
	Path: PathToken,
	Setup: func(t testing.TB, s *Stack) {
		// The revoke stamps the clock's now; the user token minted next carries
		// that second as iat, which the store treats as revoked.
		r := s.AdminSession(t).Do(t, http.MethodPost, "/dashboard/api/token-sessions/revoke", map[string]string{"sub": "user-3"})
		if r.Status != http.StatusOK {
			t.Fatalf("revoking the sessions of user-3 = %d %s", r.Status, r.Body)
		}
	},
	Covers:     []string{CoverToken("session_revoked")},
	Attack:     userExchange("user-3", []string{"eng"}, nil),
	WantStatus: http.StatusBadRequest,
	WantBody:   "invalid_grant",
	WantResult: "denied",
	WantReason: "session_revoked",
}}

// lifetimeStack boots the stack with agent-a and agent-b and tokens of user-1
// and user-2 on agent-a and of user-1 on agent-b, and runs the worker positive
// control.
func lifetimeStack(t *testing.T) *Stack {
	t.Helper()
	s := StartStack(t, StackOptions{})
	a := agentSetup(t, s, "agent-a")
	b := agentSetup(t, s, "agent-b")
	s.Put(keyAgentA, a)
	s.Put(keyU1, s.MintWardenToken(t, a, "user-1", "eng"))
	s.Put(keyU2, s.MintWardenToken(t, a, "user-2", "eng"))
	s.Put(keyB1, s.MintWardenToken(t, b, "user-1", "eng"))
	s.PositiveControl(t, "worker", func(t *testing.T) {
		for _, p := range []struct{ agent, key string }{{"agent-a", keyU1}, {"agent-a", keyU2}, {"agent-b", keyB1}} {
			for _, tr := range Transports {
				if r := s.Do(t, s.Worker(p.agent), Via(tr, scratchToken(s, p.key))); r.Status != http.StatusOK {
					t.Fatalf("%s over %s: status %d, want 200 (%s)", p.agent, tr, r.Status, tail(r.Body, 200))
				}
			}
		}
	})
	return s
}

// holdTunnel opens a terminated tunnel on agent's worker with the token kept
// under tokKey, proves it serves (so the worker holds a verified identity for
// it) and keeps it under key.
func holdTunnel(t testing.TB, s *Stack, agent, tokKey, key string) *Tunnel {
	t.Helper()
	tun := s.OpenTunnel(t, s.Worker(agent), TransportTerminated, scratchToken(s, tokKey))
	if tun.Open.Status != http.StatusOK {
		t.Fatalf("the tunnel for %s did not open: %d %s", tokKey, tun.Open.Status, tun.Open.Body)
	}
	if r := tun.MustGet(t); r.Status != http.StatusOK {
		t.Fatalf("the warm-up request for %s = %d, want 200", tokKey, r.Status)
	}
	s.Put(key, tun)
	return tun
}

func TestLifetime(t *testing.T) {
	t.Run("user_blocked", func(t *testing.T) {
		s := lifetimeStack(t)
		tun1 := holdTunnel(t, s, "agent-a", keyU1, keyT1)
		tun2 := holdTunnel(t, s, "agent-a", keyU2, "lifetime.tunnel-user-2")

		cut := s.StartCut(t, s.Worker("agent-a"), func() { s.BlockUser(t, "user-1") })
		// The block closes the user's open tunnels (W-P1-BLOCK-05); the closed
		// tunnel is what the user sees instead of a 403 on it.
		cut.Within(t, cutBound, "close the blocked user's tunnel", tun1.Closed)
		cut.Within(t, cutBound, "refuse the blocked user's next request", func() bool {
			return s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU1))).Status == http.StatusForbidden
		})
		Run(t, s, "worker", blockedUserCases)

		// A second user is unaffected, on the open tunnel and on a new one.
		if r := tun2.MustGet(t); r.Status != http.StatusOK {
			t.Errorf("the other user's open tunnel = %d, want 200", r.Status)
		}
		if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU2))); r.Status != http.StatusOK {
			t.Errorf("the other user on a new CONNECT = %d, want 200", r.Status)
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	t.Run("agent_disabled", func(t *testing.T) {
		s := lifetimeStack(t)
		tun := holdTunnel(t, s, "agent-a", keyU1, keyT1)
		tunB := holdTunnel(t, s, "agent-b", keyB1, keyTB)

		cut := s.StartCut(t, s.Worker("agent-a"), func() { s.SetAgentEnabled(t, "agent-a", false) })
		cut.Within(t, cutBound, "close the disabled agent's tunnel", tun.Closed)
		cut.Within(t, cutBound, "refuse a request with a valid token", func() bool {
			return s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU1))).Status == http.StatusForbidden
		})
		Run(t, s, "worker", disabledAgentCases)

		// agent-b keeps working, on its open tunnel and on a new one.
		if r := tunB.MustGet(t); r.Status != http.StatusOK {
			t.Errorf("agent-b's open tunnel = %d, want 200", r.Status)
		}
		if r := s.Do(t, s.Worker("agent-b"), Via(TransportConnect, scratchToken(s, keyB1))); r.Status != http.StatusOK {
			t.Errorf("agent-b on a new CONNECT = %d, want 200", r.Status)
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	t.Run("token_key_revoked", func(t *testing.T) {
		s := lifetimeStack(t)
		holdTunnel(t, s, "agent-a", keyU1, keyT1)

		cut := s.StartCut(t, s.Worker("agent-a"), func() { s.RotateTokenKey(t, true) })
		cut.Within(t, cutBound, "refuse the revoked key's token", func() bool {
			return s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU1))).Status == http.StatusProxyAuthRequired
		})
		Run(t, s, "worker", revokedKeyCases)

		// A token signed by the new key works. The mint guard holds minting back
		// until the bundle that serves the new key is signed, which the clock
		// drives (Exchange advances it on the 503).
		fresh := s.MintWardenToken(t, agentOf(s, keyAgentA), "user-5", "eng")
		if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, fresh)); r.Status != http.StatusOK {
			t.Errorf("a token of the new key = %d, want 200 (%s)", r.Status, tail(r.Body, 200))
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	t.Run("issuance", func(t *testing.T) {
		s := lifetimeStack(t)
		a := agentOf(s, keyAgentA)
		s.PositiveControl(t, "token", func(t *testing.T) {
			if r, tok := s.Exchange(t, a, s.UserToken("user-3", []string{"eng"}), nil); tok == "" {
				t.Fatalf("exchange = %d %s, want a token", r.Status, r.Body)
			}
		})
		Run(t, s, "token", issuanceCases)
	})

	// A token issued before allowed_groups shrank stays valid on the worker
	// until it expires (the accepted gap of p2-worker-bound: the worker holds no
	// group policy for an agent), while a new exchange is refused.
	t.Run("allowed_groups_shrink", func(t *testing.T) {
		s := lifetimeStack(t)
		a := agentOf(s, keyAgentA)
		// Groups are not in the bundle: only the token endpoint sees the change.
		s.UpdateAgent(t, a, "ops")
		Run(t, s, "worker", []Case{{
			Name: "a user outside the shrunk allowed_groups cannot exchange",
			Path: PathToken,
			Setup: func(t testing.TB, s *Stack) {
				s.EventuallyAdvance("the token endpoint to read the shrunk allowed_groups", 100*time.Millisecond, func() bool {
					return s.PostToken(t, s.ExchangeForm(a, s.UserToken("probe", []string{"eng"}), nil)).Status != http.StatusOK
				})
			},
			Attack:     userExchange("user-1", []string{"eng"}, nil),
			WantStatus: http.StatusBadRequest,
			WantBody:   "unauthorized_client",
			WantResult: "denied",
			WantReason: "group_not_allowed",
		}})
		// The refusal proves the control plane holds the shrunk groups; the
		// token issued before still serves.
		if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyU1))); r.Status != http.StatusOK {
			t.Errorf("a token issued before allowed_groups shrank = %d, want 200 until it expires", r.Status)
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})
}
