package worker

import (
	"context"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
)

// TestBindingKeyRemovalAppliesOnLongPoll: a token that binds to the worker's
// agent under bundle 1 gets cnf_mismatch on the very next check once a long-poll
// applies a bundle that removed its key, and agent_disabled once a later bundle
// disables the agent. The check reads the verifier's current snapshot each time,
// so nothing is cached between the bundles.
func TestBindingKeyRemovalAppliesOnLongPoll(t *testing.T) {
	clk := clocktest.NewFake(bundleStart.Add(time.Minute))
	tc := newTokenCP(t, clk, true)
	k1 := newTokenKey(t)
	t1, t2 := newTokenKey(t).jkt, newTokenKey(t).jkt // the agent's two key thumbprints
	agent := config.RegisteredAgent{ID: tokTestAgent, Status: config.RegisteredAgentActive, JKT: []string{t1, t2}}

	tc.serve(tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1), agents: []config.RegisteredAgent{agent}})
	if err := tc.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	w := newBindingWiring(tc, clk, "https://idp.example.test")
	w.applyBinding(tc.rp)

	tok := wardenToken(t, k1, clk.Now(), func(c map[string]any) { c["cnf"] = map[string]string{"jkt": t1} })
	bind := func() (identity.Reason, bool) {
		t.Helper()
		claims, st, r := w.warden.Verify(context.Background(), tok)
		if st != identity.StatusValid {
			t.Fatalf("token verify = %s/%s, want valid (the signature and claims did not change)", st, r)
		}
		return identity.BindingCheck(w.warden.Snapshot(), tokTestAgent, claims)
	}
	if r, ok := bind(); !ok {
		t.Fatalf("under bundle 1: %s, want bound", r)
	}

	poll := func(b tokenBundle) {
		t.Helper()
		tc.serve(b)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if changed, err := tc.rp.PollLong(ctx, time.Second); err != nil || !changed {
			t.Fatalf("PollLong = %v, %v, want a change", changed, err)
		}
		w.applyBinding(tc.rp)
	}

	rotated := agent
	rotated.JKT = []string{t2}
	poll(tokenBundle{seq: 2, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1), agents: []config.RegisteredAgent{rotated}})
	if r, ok := bind(); ok || r != identity.ReasonCnfMismatch {
		t.Fatalf("after the key was removed: %q, %v, want cnf_mismatch", r, ok)
	}

	disabled := agent
	disabled.Status = config.RegisteredAgentDisabled
	poll(tokenBundle{seq: 3, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1), agents: []config.RegisteredAgent{disabled}})
	if r, ok := bind(); ok || r != identity.ReasonAgentDisabled {
		t.Fatalf("after the agent was disabled: %q, %v, want agent_disabled", r, ok)
	}
}
