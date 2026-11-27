package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
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

	t.Run("rollback", func(t *testing.T) {
		e := newHistoryEnv(t, historyEnvOpts{oidc: true, audit: true})
		admin, editor := sessionAs(t, e, "ad1", groupAdmin), sessionAs(t, e, "ed1", groupEditor)
		createRules(t, e.srv, engLLM(5)) // v2: a cost cap
		createRules(t, e.srv, engLLM(0)) // v3: the same rule, rateLimit only
		createRules(t, e.srv)            // v4: no rules
		beat(e.srv, "old", "agent-a", config.CapBlocklistV1, config.CapUserLimitsV1)
		beat(e.srv, "new", "agent-b", config.CapUserCostV1, config.CapUserLimitsV1)

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
		beat(e.srv, "old", "agent-a", config.CapUserCostV1, config.CapUserLimitsV1)
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
		beat(s, "old", "", config.CapBlocklistV1, config.CapUserLimitsV1)
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
		beat(s, "old", "", config.CapBlocklistV1, config.CapUserLimitsV1)
		_, hd, err := s.headDoc(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		// The clearance covers the doc with the rule added: since #293 the
		// draft doc carries the limit keys, so a clearance for head would not.
		withCap := hd
		withCap.UserLimits = []config.UserLimit{engLLM(5)}
		clr, err := s.gate.Clear(context.Background(), approvals.Change{Target: approvals.TargetPolicy, Base: 1, BaseDoc: draftDoc(hd), Draft: draftDoc(withCap)})
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
		beat(s, "old", "", config.CapBlocklistV1, config.CapUserLimitsV1)
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

// writeImportFile writes a config YAML with the base allow/deny lists plus
// userLimits (raw YAML list items, indented under policy).
func writeImportFile(t *testing.T, limits string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "import.yaml")
	body := "policy:\n  allowlist:\n    - domain: api.openai.com\n  denylist:\n    - domain: evil.example.com\n"
	if limits != "" {
		body += "  userLimits:\n" + limits
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCostCapCapabilityGate_OfflineImport: `warden policy import` cannot see
// the connected workers, so a file that adds a dailyCostUSD cap against the
// head is refused unless --force (ForceCostCaps) is set; a forced import's
// policy.import audit row records force and the capability. A rateLimit-only
// rule, and a file that keeps an existing cap, import without it.
func TestCostCapCapabilityGate_OfflineImport(t *testing.T) {
	stateDir := t.TempDir()
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), State: db, PolicyStore: PolicyStoreVersioned, Logger: testJSONLogger(nil)})
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := OpenPolicyStore(context.Background(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	imp := func(limits string) (PolicyImportResult, *fakeRecorder, error) {
		t.Helper()
		doc, err := ValidatePolicyDocFile(writeImportFile(t, limits))
		if err != nil {
			t.Fatal(err)
		}
		rec := &fakeRecorder{}
		res, err := st.Import(context.Background(), doc, "", -1, rec)
		return res, rec, err
	}
	const rateOnly = "    - name: eng-llm\n      match: {groups: [eng]}\n      rateLimit: 60/minute\n"
	const withCap = "    - name: eng-llm\n      match: {groups: [eng]}\n      rateLimit: 60/minute\n      dailyCostUSD: 5\n"

	if res, _, err := imp(rateOnly); err != nil || !res.Changed {
		t.Fatalf("rateLimit-only import = %+v, %v; want a new version", res, err)
	}
	if _, rec, err := imp(withCap); !errors.Is(err, ErrCostCapNeedsForce) || len(rec.rows) != 0 {
		t.Fatalf("unforced cap import = %v (%d audit rows), want ErrCostCapNeedsForce and no row", err, len(rec.rows))
	}
	if head := mustHead(t, s.versions); head != 2 {
		t.Fatalf("head = %d after the refused import, want 2", head)
	}
	st.ForceCostCaps = true
	res, rec, err := imp(withCap)
	if err != nil || !res.Changed {
		t.Fatalf("forced cap import = %+v, %v", res, err)
	}
	if len(rec.rows) != 1 || rec.rows[0].Details[adminaudit.DetailForce] != "true" || rec.rows[0].Details[adminaudit.DetailCapability] != config.CapUserCostV1 {
		t.Fatalf("forced import audit rows = %+v, want one with force and capability", rec.rows)
	}
	// The cap is in the head now: re-importing it (or changing other fields)
	// adds no cap and needs no force.
	st.ForceCostCaps = false
	if _, rec, err := imp(withCap + "    - name: other\n      match: {groups: [ops]}\n      rateLimit: 1/second\n"); err != nil || len(rec.rows) != 1 || rec.rows[0].Details[adminaudit.DetailForce] != "" {
		t.Fatalf("import keeping the existing cap = %v, rows %+v; want success without force", err, rec.rows)
	}
}

// A forced write that trips both the userlimits/v1 and the usercost/v1 guard
// names the first in a fixed order (userlimits/v1) on the 409, and its audit row
// records both capabilities and both lacking lists instead of the last one.
func TestRolloutGuards_BothForced(t *testing.T) {
	e := newHistoryEnv(t, historyEnvOpts{oidc: true, audit: true})
	admin := sessionAs(t, e, "ad1", groupAdmin)
	createRules(t, e.srv, engLLM(5))                     // v2: a rate limit and a cost cap
	createRules(t, e.srv)                                // v3: no rules
	beat(e.srv, "w1", "agent-a", config.CapUserCostV1)   // lacks userlimits/v1
	beat(e.srv, "w2", "agent-b", config.CapUserLimitsV1) // lacks usercost/v1

	rec := e.send(admin, http.MethodPost, rollbackPath(2), "", ifMatch(3))
	var body struct {
		Capability string   `json:"capability"`
		Workers    []string `json:"workers"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusConflict || body.Capability != config.CapUserLimitsV1 || !slices.Equal(body.Workers, []string{"w1"}) {
		t.Fatalf("unforced = %d %s, want 409 naming userlimits/v1 [w1] first", rec.Code, rec.Body.String())
	}
	before := len(e.rec.inputs())
	if rec := e.send(admin, http.MethodPost, rollbackPath(2)+"?force=true", "", ifMatch(3)); rec.Code != http.StatusOK {
		t.Fatalf("forced = %d %s, want 200", rec.Code, rec.Body.String())
	}
	var forced *adminaudit.Input
	for _, in := range e.rec.inputs()[before:] {
		if in.Details[adminaudit.DetailForce] == "true" {
			in := in
			forced = &in
		}
	}
	if forced == nil {
		t.Fatal("no forced audit row")
	}
	d := forced.Details
	if d[adminaudit.DetailCapability] != config.CapUserLimitsV1+","+config.CapUserCostV1 ||
		d[adminaudit.DetailWorkersLacking] != "w1;w2" ||
		d[adminaudit.DetailWorkersLacking+adminaudit.DetailCountSuffix] != "1;1" {
		t.Fatalf("forced audit details = %v, want both capabilities and both lacking lists", d)
	}
}

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
	if !strings.Contains(logs.String(), "cost_cap_forced") {
		t.Errorf("no cost_cap_forced log:\n%s", logs.String())
	}
}
