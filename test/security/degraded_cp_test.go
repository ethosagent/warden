package security

import (
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
)

const blockedUsersPath = "/dashboard/api/blocked-users"

// degradedCPRestart restarts the control plane on the same state
// directory. What it persisted still refuses: a client assertion's jti used
// before the restart is still a replay, a used wet_ enrollment token is still
// spent, and the block list and the agent registry are what they were, both on
// the token endpoint and on the workers.
func degradedCPRestart(t *testing.T) {
	s := degradedStack(t, StackOptions{})
	a := agentOf(s, keyAgentA)
	adm := s.AdminSession(t)

	// Spent before the restart: one assertion, one enrollment token.
	spent := s.ExchangeForm(a, s.UserToken("user-3", []string{"eng"}), nil)
	if r := s.PostToken(t, spent); r.Status != http.StatusOK {
		t.Fatalf("the first use of the assertion = %d %s, want 200", r.Status, r.Body)
	} else {
		decodeAccessToken(t, s, r)
	}
	wet := adm.CreateEnrollmentTokenWith(t, map[string]any{"name": "sec-restart", "workerId": "sec-restart"})
	key, csr := s.NewCSR(t, CSROptions{})
	s.ParseIssued(t, s.Enroll(t, wet, csr, ""), key)

	cutOff(t, s)
	blocksBefore := adm.Do(t, http.MethodGet, blockedUsersPath, nil)
	agentsBefore := adm.Do(t, http.MethodGet, agentsPath, nil)
	if blocksBefore.Status != http.StatusOK || agentsBefore.Status != http.StatusOK {
		t.Fatalf("listing the block list and the registry = %d, %d", blocksBefore.Status, agentsBefore.Status)
	}
	s.StopCP(t)
	s.RestartCP(t)

	// The positive control: the restarted token endpoint issues a token (a probe
	// for a user nobody uses), so the refusals below are not a dead endpoint.
	s.PositiveControl(t, "token", func(t *testing.T) {
		s.EventuallyAdvance("the token endpoint to issue after the restart", time.Second, func() bool {
			return s.PostToken(t, s.ExchangeForm(a, s.UserToken("probe", []string{"eng"}), nil)).Status == http.StatusOK
		})
	})

	Run(t, s, "token", []Case{{
		Name:       "a client assertion used before the restart is still a replay",
		Path:       PathToken,
		Attack:     func(t testing.TB, s *Stack) Observed { return SeenReply(s.PostToken(t, spent)) },
		Unverified: true,
		WantStatus: http.StatusUnauthorized, WantBody: `"error":"invalid_client"`,
		WantReason: "replay", WantLog: denied("invalid_client", "replay"),
	}, {
		Name: "a blocked user is still blocked at the token endpoint",
		Path: PathToken,
		Attack: func(t testing.TB, s *Stack) Observed {
			return SeenReply(s.PostToken(t, s.ExchangeForm(a, s.UserToken("user-2", []string{"eng"}), nil)))
		},
		WantStatus: http.StatusBadRequest, WantBody: "invalid_grant",
		WantResult: "denied", WantReason: "user_blocked",
	}, {
		Name: "a disabled agent is still disabled at the token endpoint",
		Path: PathToken,
		Attack: func(t testing.TB, s *Stack) Observed {
			return SeenReply(s.PostToken(t, s.ExchangeForm(s.Agent("agent-b"), s.UserToken("user-1", []string{"eng"}), nil)))
		},
		Unverified: true,
		WantStatus: http.StatusUnauthorized, WantBody: "invalid_client",
		WantReason: "agent_disabled", WantLog: denied("invalid_client", "agent_disabled"),
	}})

	Run(t, s, "token", []Case{{
		Name: "a used enrollment token is still spent",
		Path: PathEnroll,
		Attack: func(t testing.TB, s *Stack) Observed {
			fresh(s)
			_, csr := s.NewCSR(t, CSROptions{})
			before := s.State(t)
			var r Reply
			expectCount(t, "warden_cp_worker_enroll_total{outcome=bad_token}",
				func() int64 { return s.Server().EnrollCount(controlplane.EnrollOutcomeBadToken) }, 1,
				func() { r = s.Enroll(t, wet, csr, "") })
			expectDelta(t, before, s.State(t), State{})
			return SeenReply(r)
		},
		WantStatus: http.StatusUnauthorized, WantBody: unauthorizedBody, WantLog: `"reason":"exhausted"`,
	}})

	// The registry and the block list are byte for byte what they were, and the
	// workers, which kept enforcing throughout, still enforce them.
	adm = s.AdminSession(t)
	if r := adm.Do(t, http.MethodGet, blockedUsersPath, nil); r.Status != http.StatusOK || r.Body != blocksBefore.Body {
		t.Errorf("the block list changed over the restart:\nbefore %s\nafter  %s", blocksBefore.Body, r.Body)
	}
	if r := adm.Do(t, http.MethodGet, agentsPath, nil); r.Status != http.StatusOK || r.Body != agentsBefore.Body {
		t.Errorf("the agent registry changed over the restart:\nbefore %s\nafter  %s", agentsBefore.Body, r.Body)
	}
	Run(t, s, "worker", enforcedCases("after the restart: "))
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}
