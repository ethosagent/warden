package proxy

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// TestIdentityClockSeamDrivesExpiry proves Config.IdentityClock (the
// assembly-only seam fed from worker.Overrides.Clock) decides identity expiry:
// an open connection's identity is valid up to exp+skew and expired on the next
// request after it, with no other clock hook (p.now) set. It also pins that the
// seam does not leak into the leaf-cert clock.
func TestIdentityClockSeamDrivesExpiry(t *testing.T) {
	clk := &idClock{t: time.Now()}
	exp := clk.now().Add(30 * time.Second)
	v := fakes.NewVerifier()
	v.Set("tok-short", idClaims("alice", exp), identity.StatusValid, "")

	p, err := New(Config{
		ListenAddr:    "127.0.0.1:0",
		Policy:        policy.NewEvaluator(config.Policy{}),
		Secrets:       &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:     &syncStore{},
		AgentID:       "agent-7",
		Identity:      IdentityConfig{Verifier: v, Mode: IdentityModeAttribute},
		IdentityClock: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.now != nil {
		t.Fatal("IdentityClock must not set the leaf-cert clock")
	}

	ci := p.resolveConnIdentity(1, basicAuth("tok-short"))
	if ci.Status != identity.StatusValid {
		t.Fatalf("connection identity = %+v, want valid", ci)
	}
	run := func() *requestScope {
		s := stageScope(ci)
		runIdentity(t, p, s)
		return s
	}
	if s := run(); s.idStatus != identity.StatusValid {
		t.Fatalf("before exp: status %q, want valid", s.idStatus)
	}
	clk.advance(30*time.Second + identity.DefaultClockSkew - time.Second)
	if s := run(); s.idStatus != identity.StatusValid {
		t.Fatalf("inside skew: status %q, want valid", s.idStatus)
	}
	clk.advance(2 * time.Second)
	if s := run(); s.idStatus != identity.StatusExpired || s.subject != nil {
		t.Fatalf("after exp+skew: status %q subject %+v, want expired and nil", s.idStatus, s.subject)
	}

	if d := time.Since(p.clock()); d < -time.Second || d > time.Second {
		t.Errorf("leaf clock moved with the identity clock: off by %v", d)
	}
}
