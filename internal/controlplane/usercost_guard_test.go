package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// createRules appends a version whose doc is head's with userLimits replaced,
// bypassing the writers (and so the guard), as an old import would.
func createRules(t *testing.T, s *Server, rules ...config.UserLimit) int64 {
	t.Helper()
	head := mustHead(t, s.versions)
	doc := baseDoc(t, s)
	doc.UserLimits = rules
	v, _, err := s.versions.Create(context.Background(), doc, testAuthor, "rules", SourcePolicy, head)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantCostLack(t *testing.T, err error, workers ...string) {
	t.Helper()
	var wl *dashboard.WorkersLackCapabilityError
	if !errors.As(err, &wl) || wl.Capability != config.CapUserCostV1 || !slices.Equal(wl.Workers, workers) {
		t.Fatalf("err = %v, want WorkersLackCapabilityError %s %v", err, config.CapUserCostV1, workers)
	}
}

// TestCostCapCapabilityGate: with a connected worker lacking usercost/v1, a
// save that adds dailyCostUSD (or sets it on an existing rule) is a 409 naming
// the worker and leaves head unchanged; an admin's force=true goes through and
// the audit row records force, the capability and the worker; an editor
// cannot force; a rateLimit-only rule needs no check. Every writer is covered:
// rollback over HTTP, the dashboard policy write (versioned and file mode) and
// the publish funnel an approvals apply goes through.
func TestCostCapCapabilityGate(t *testing.T) {
	config.LiftUserLimitsGuardForTesting(t)

	t.Run("rollback", func(t *testing.T) {
		e := newHistoryEnv(t, historyEnvOpts{oidc: true, audit: true})
		admin, editor := sessionAs(t, e, "ad1", groupAdmin), sessionAs(t, e, "ed1", groupEditor)
		createRules(t, e.srv, engLLM(5)) // v2: a cost cap
		createRules(t, e.srv, engLLM(0)) // v3: the same rule, rateLimit only
		createRules(t, e.srv)            // v4: no rules
		beat(e.srv, "old", "agent-a", config.CapBlocklistV1)
		beat(e.srv, "new", "agent-b", config.CapUserCostV1)

		if rec := e.send(admin, http.MethodPost, rollbackPath(3), "", ifMatch(4)); rec.Code != http.StatusOK {
			t.Fatalf("rateLimit-only rollback = %d %s, want 200", rec.Code, rec.Body.String())
		}
		// v5 is v3: eng-llm without a cap. Rolling back to v2 sets one on it.
		rec := e.send(admin, http.MethodPost, rollbackPath(2), "", ifMatch(5))
		var body struct {
			Error      string   `json:"error"`
			Capability string   `json:"capability"`
			Workers    []string `json:"workers"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusConflict || body.Error != "workers_lack_capability" || body.Capability != config.CapUserCostV1 || !slices.Equal(body.Workers, []string{"old"}) {
			t.Fatalf("cost rollback with an old worker = %d %s, want 409 workers_lack_capability usercost/v1 [old]", rec.Code, rec.Body.String())
		}
		if head := mustHead(t, e.srv.versions); head != 5 {
			t.Fatalf("head = %d after the refused rollback, want 5", head)
		}
		if rec := e.send(editor, http.MethodPost, rollbackPath(2)+"?force=true", "", ifMatch(5)); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"role_required"`) {
			t.Fatalf("editor force = %d %s, want 403 role_required", rec.Code, rec.Body.String())
		}
		before := len(e.rec.inputs())
		if rec := e.send(admin, http.MethodPost, rollbackPath(2)+"?force=true", "", ifMatch(5)); rec.Code != http.StatusOK {
			t.Fatalf("admin force = %d %s, want 200", rec.Code, rec.Body.String())
		}
		if head := mustHead(t, e.srv.versions); head != 6 {
			t.Fatalf("head = %d after the forced rollback, want 6", head)
		}
		var forced *adminaudit.Input
		for _, in := range e.rec.inputs()[before:] {
			if in.Details[adminaudit.DetailForce] == "true" {
				in := in
				forced = &in
			}
		}
		if forced == nil || forced.Action != "policy.rollback" ||
			forced.Details[adminaudit.DetailCapability] != config.CapUserCostV1 ||
			forced.Details[adminaudit.DetailWorkersLacking] != "old" ||
			forced.Details[adminaudit.DetailWorkersLacking+adminaudit.DetailCountSuffix] != "1" {
			t.Fatalf("forced audit row = %+v, want policy.rollback with force, capability usercost/v1, workersLacking old", forced)
		}
		// Once every connected worker has the cap, no force is needed.
		beat(e.srv, "old", "agent-a", config.CapUserCostV1)
		if rec := e.send(admin, http.MethodPost, rollbackPath(4), "", ifMatch(6)); rec.Code != http.StatusOK {
			t.Fatalf("rollback to no rules = %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.send(admin, http.MethodPost, rollbackPath(2), "", ifMatch(7)); rec.Code != http.StatusOK {
			t.Fatalf("cost rollback with every worker upgraded = %d %s, want 200", rec.Code, rec.Body.String())
		}
	})

	t.Run("dashboard write", func(t *testing.T) {
		s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
		if err := s.importInitialVersion(context.Background()); err != nil {
			t.Fatal(err)
		}
		beat(s, "old", "", config.CapBlocklistV1)
		p := policyOfWire(baseDoc(t, s))
		p.UserLimits = []config.UserLimit{{Name: "eng-rate", RateLimit: "60/minute", Match: config.UserLimitMatch{Groups: []string{"eng"}}}}
		if err := s.WritePolicy(context.Background(), p, dashboard.WriteMeta{}); err != nil {
			t.Fatalf("rateLimit-only save = %v, want success", err)
		}
		p.UserLimits = append(p.UserLimits, engLLM(5))
		wantCostLack(t, s.WritePolicy(context.Background(), p, dashboard.WriteMeta{}), "old")
		if head := mustHead(t, s.versions); head != 2 {
			t.Fatalf("head = %d after the refused save, want 2", head)
		}
		if err := s.WritePolicy(dashboard.WithForce(context.Background()), p, dashboard.WriteMeta{}); err != nil {
			t.Fatalf("forced save (console.auth none is admin) = %v", err)
		}
		if got := baseDoc(t, s); len(got.UserLimits) != 2 || got.UserLimits[1].DailyCostUSD != 5 {
			t.Fatalf("head userLimits = %+v, want the forced cost rule", got.UserLimits)
		}
		// Changing an existing cap's value adds no cap: no check.
		p.UserLimits[1].DailyCostUSD = 10
		if err := s.WritePolicy(context.Background(), p, dashboard.WriteMeta{}); err != nil {
			t.Fatalf("changing a cap's value = %v, want success", err)
		}
	})

	t.Run("publish funnel", func(t *testing.T) {
		s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
		if err := s.importInitialVersion(context.Background()); err != nil {
			t.Fatal(err)
		}
		beat(s, "old", "", config.CapBlocklistV1)
		_, hd, err := s.headDoc(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		clr, err := s.gate.Clear(context.Background(), approvals.Change{Target: approvals.TargetPolicy, Base: 1, BaseDoc: draftDoc(hd), Draft: draftDoc(hd)})
		if err != nil {
			t.Fatal(err)
		}
		addCap := func(w *policyWire) error { w.UserLimits = []config.UserLimit{engLLM(5)}; return nil }
		_, _, err = s.publish(context.Background(), clr, testAuthor, addCap, dashboard.WriteMeta{}, SourceApproval)
		wantCostLack(t, err, "old")
		if head := mustHead(t, s.versions); head != 1 {
			t.Fatalf("head = %d after the refused publish, want 1", head)
		}
		if _, _, err := s.publish(dashboard.WithForce(context.Background()), clr, testAuthor, addCap, dashboard.WriteMeta{}, SourceApproval); err != nil {
			t.Fatalf("forced publish = %v", err)
		}
	})

	t.Run("file mode", func(t *testing.T) {
		path := writePolicyFile(t, "api.openai.com")
		s := New(Config{PolicyPath: path, Logger: testJSONLogger(nil)})
		beat(s, "old", "", config.CapBlocklistV1)
		p := policyOfWire(baseDoc(t, s))
		p.UserLimits = []config.UserLimit{engLLM(5)}
		wantCostLack(t, s.WritePolicy(context.Background(), p, dashboard.WriteMeta{}), "old")
		if strings.Contains(readFile(t, path), "dailyCostUSD") {
			t.Fatal("a refused save reached the policy file")
		}
		if err := s.WritePolicy(dashboard.WithForce(context.Background()), p, dashboard.WriteMeta{}); err != nil {
			t.Fatalf("forced save = %v", err)
		}
		if !strings.Contains(readFile(t, path), "dailyCostUSD: 5") {
			t.Fatalf("forced save did not reach the file:\n%s", readFile(t, path))
		}
	})
}
