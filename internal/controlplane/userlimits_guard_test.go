package controlplane

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The per-user rate-limit rollout guard (W-P3-PUL-09): a worker without
// userlimits/v1 refuses a whole wire that carries a limit rule and freezes on
// stale policy, so a write that introduces a rateLimit rule is refused while a
// connected worker lacks the cap, unless an admin forces it (audited).

func limitsPolicy(base config.Policy) config.Policy {
	base.UserLimits = []config.UserLimit{engLimit("60/minute")}
	return base
}

func assertLacksUserLimits(t *testing.T, err error, want ...string) {
	t.Helper()
	var wl *dashboard.WorkersLackCapabilityError
	if !errors.As(err, &wl) || wl.Capability != config.CapUserLimitsV1 || !slices.Equal(wl.Workers, want) {
		t.Fatalf("err = %v, want WorkersLackCapabilityError userlimits/v1 %v", err, want)
	}
}

func TestUserLimitsGuard_FileMode(t *testing.T) {
	var logs lockedBuffer
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path, Logger: testJSONLogger(&logs)})
	beat(srv, "old", "agent-a", config.CapBlocklistV1)
	beat(srv, "new", "agent-a", config.CapUserLimitsV1)
	ctx := sessionCtx("ada", "ada@example.com")
	cur, _, _, _ := srv.policy.snapshot()
	p := limitsPolicy(policyOfWire(cur))

	assertLacksUserLimits(t, srv.WritePolicy(ctx, p, dashboard.WriteMeta{}), "old")
	if strings.Contains(readFile(t, path), "userLimits") {
		t.Fatal("a refused save reached the config file")
	}
	// An allow/deny edit that carries no limit keys is never refused.
	if err := srv.WritePolicy(ctx, policyOfWire(cur), dashboard.WriteMeta{}); err != nil {
		t.Fatalf("plain save = %v", err)
	}
	// console.auth none: the bearer is admin, so force goes through.
	if err := srv.WritePolicy(dashboard.WithForce(ctx), p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("forced save = %v", err)
	}
	if !strings.Contains(readFile(t, path), "userLimits") {
		t.Fatal("the forced save did not reach the config file")
	}
	if !strings.Contains(logs.String(), "user_limits_forced") {
		t.Errorf("no user_limits_forced log:\n%s", logs.String())
	}
	// Limits are already served: changing them is not introducing them.
	p.UserLimits[0].RateLimit = "30/minute"
	if err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("edit of existing limits = %v", err)
	}
}

func TestUserLimitsGuard_Versioned(t *testing.T) {
	srv := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	if err := srv.importInitialVersion(sessionCtx("ada", "ada@example.com")); err != nil {
		t.Fatal(err)
	}
	beat(srv, "old", "", config.CapBlocklistV1)
	ctx := sessionCtx("ada", "ada@example.com")
	p := limitsPolicy(policyOfWire(headVersion(t, srv).Doc))
	assertLacksUserLimits(t, srv.WritePolicy(ctx, p, dashboard.WriteMeta{}), "old")
	if n := versionCount(t, srv); n != 1 {
		t.Fatalf("%d versions after a refused save, want 1", n)
	}
	// Once the worker heartbeats the cap, the same save goes through.
	beat(srv, "old", "", config.CapBlocklistV1, config.CapUserLimitsV1)
	if err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("save once every worker has the cap = %v", err)
	}
	if v := headVersion(t, srv); len(v.Doc.UserLimits) != 1 {
		t.Fatalf("head limits = %+v", v.Doc.UserLimits)
	}
}

// A rollback that brings rate limits back meets the guard; force by an admin
// goes through and the audit row records it.
func TestUserLimitsGuard_Rollback(t *testing.T) {
	e := newHistoryEnv(t, historyEnvOpts{oidc: true, audit: true})
	admin := sessionAs(t, e, "ad1", groupAdmin)
	ctx := sessionCtx("ad1", "ad1@example.com")
	p := limitsPolicy(policyOfWire(headVersion(t, e.srv).Doc))
	if err := e.srv.WritePolicy(ctx, p, dashboard.WriteMeta{}); err != nil { // v2: limits
		t.Fatal(err)
	}
	if rec := e.send(admin, http.MethodPost, rollbackPath(1), "", ifMatch(2)); rec.Code != http.StatusOK { // v3: none
		t.Fatalf("rollback to v1 = %d %s", rec.Code, rec.Body.String())
	}
	beat(e.srv, "old", "agent-a", config.CapBlocklistV1)

	rec := e.send(admin, http.MethodPost, rollbackPath(2), "", ifMatch(3))
	const want = `{"error":"workers_lack_capability","capability":"userlimits/v1","workers":["old"]}`
	if rec.Code != http.StatusConflict || strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("rollback to limits with an old worker = %d %s, want 409 %s", rec.Code, rec.Body.String(), want)
	}
	if head := mustHead(t, e.srv.versions); head != 3 {
		t.Fatalf("head = %d after a refused rollback, want 3", head)
	}
	before := len(e.rec.inputs())
	if rec := e.send(admin, http.MethodPost, rollbackPath(2)+"?force=true", "", ifMatch(3)); rec.Code != http.StatusOK {
		t.Fatalf("forced rollback = %d %s, want 200", rec.Code, rec.Body.String())
	}
	var forced bool
	for _, in := range e.rec.inputs()[before:] {
		if in.Action == "policy.rollback" && in.Details[adminaudit.DetailForce] == "true" && in.Details[adminaudit.DetailWorkersLacking] == "old" {
			forced = true
		}
	}
	if !forced {
		t.Fatalf("no policy.rollback audit row with force and workersLacking=old: %+v", e.rec.inputs()[before:])
	}
}
