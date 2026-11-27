package controlplane

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The per-user cost-cap rollout guard (W-P3-PUL-04): a worker without
// usercost/v1 fails open on dailyCostUSD, so a write that adds a cost cap is
// refused while a connected worker lacks the cap, unless an admin forces it.

func assertLacksUserCost(t *testing.T, err error, want ...string) {
	t.Helper()
	var wl *dashboard.WorkersLackCapabilityError
	if !errors.As(err, &wl) || wl.Capability != config.CapUserCostV1 || !slices.Equal(wl.Workers, want) {
		t.Fatalf("err = %v, want WorkersLackCapabilityError usercost/v1 %v", err, want)
	}
}

func TestUserCostGuard_Versioned(t *testing.T) {
	srv := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	if err := srv.importInitialVersion(sessionCtx("ada", "ada@example.com")); err != nil {
		t.Fatal(err)
	}
	// "rate" enforces rate limits but not cost caps.
	beat(srv, "rate", "", config.CapUserLimitsV1)
	beat(srv, "full", "", config.CapUserLimitsV1, config.CapUserCostV1)
	ctx := sessionCtx("ada", "ada@example.com")

	// A rate-only rule is not a cost cap.
	p := policyOfWire(headVersion(t, srv).Doc)
	p.UserLimits = []config.UserLimit{engLimit("60/minute")}
	if err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("rate-only save = %v", err)
	}
	// Setting dailyCostUSD on that rule adds a cap.
	p.UserLimits[0].DailyCostUSD = 5
	assertLacksUserCost(t, srv.WritePolicy(ctx, p, dashboard.WriteMeta{}), "rate")
	if v := headVersion(t, srv); v.Doc.UserLimits[0].DailyCostUSD != 0 {
		t.Fatal("a refused save reached the head")
	}
	// An anonymous cost cap counts too.
	q := policyOfWire(headVersion(t, srv).Doc)
	q.AnonymousLimit = &config.UserLimit{DailyCostUSD: 1}
	assertLacksUserCost(t, srv.WritePolicy(ctx, q, dashboard.WriteMeta{}), "rate")

	// Once every worker has the cap the save goes through, and a later change
	// of the cap's value is not adding one.
	beat(srv, "rate", "", config.CapUserLimitsV1, config.CapUserCostV1)
	if err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("save once every worker has the cap = %v", err)
	}
	beat(srv, "rate", "", config.CapUserLimitsV1)
	p.UserLimits[0].DailyCostUSD = 7
	if err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("changing an existing cap = %v", err)
	}
	if v := headVersion(t, srv); v.Doc.UserLimits[0].DailyCostUSD != 7 {
		t.Fatalf("head cap = %v", v.Doc.UserLimits[0].DailyCostUSD)
	}
}

func TestUserCostGuard_FileModeForce(t *testing.T) {
	var logs lockedBuffer
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path, Logger: testJSONLogger(&logs)})
	beat(srv, "old", "agent-a", config.CapUserLimitsV1)
	ctx := sessionCtx("ada", "ada@example.com")
	cur, _, _, _ := srv.policy.snapshot()
	p := policyOfWire(cur)
	l := engLimit("60/minute")
	l.DailyCostUSD = 5
	p.UserLimits = []config.UserLimit{l}

	assertLacksUserCost(t, srv.WritePolicy(ctx, p, dashboard.WriteMeta{}), "old")
	if strings.Contains(readFile(t, path), "dailyCostUSD") {
		t.Fatal("a refused save reached the config file")
	}
	if err := srv.WritePolicy(dashboard.WithForce(ctx), p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("forced save = %v", err)
	}
	if !strings.Contains(readFile(t, path), "dailyCostUSD") {
		t.Fatal("the forced save did not reach the config file")
	}
	if !strings.Contains(logs.String(), "user_cost_forced") {
		t.Errorf("no user_cost_forced log:\n%s", logs.String())
	}
}
