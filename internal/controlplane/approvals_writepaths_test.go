package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// W-P2-APPR-06: every versioned write path goes through one clearance check.

const (
	policyPath    = "/dashboard/api/policy"
	settingsPath  = "/dashboard/api/settings"
	providersPath = "/dashboard/api/llmproviders"
)

// heldBody is the 202 body of a held write.
type heldBody struct {
	DraftID  string `json:"draft_id"`
	Revision int    `json:"revision"`
	State    string `json:"state"`
	Widening bool   `json:"widening"`
	Reasons  []struct {
		Code string `json:"code"`
		Path string `json:"path"`
	} `json:"reasons"`
}

func matchV(v string) []string { return []string{"If-Match", `"v` + v + `"`} }

func (e *draftEnv) put(who, path, body, ver string) *httptest.ResponseRecorder {
	return e.do(who, http.MethodPut, path, body, matchV(ver)...)
}

// wantHeld asserts a 202 held response and returns it and the draft it names.
func (e *draftEnv) wantHeld(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) (heldBody, dashboard.ChangeDraftDetail) {
	t.Helper()
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d %s, want 202", rec.Code, rec.Body.String())
	}
	h := decodeBody[heldBody](t, rec)
	if h.DraftID == "" || h.Revision != 1 || h.State != "pending" || !h.Widening {
		t.Fatalf("held body = %+v", h)
	}
	if loc := rec.Header().Get("Location"); loc != draftsPath+"/"+h.DraftID {
		t.Errorf("Location = %q, want %q", loc, draftsPath+"/"+h.DraftID)
	}
	found := false
	for _, r := range h.Reasons {
		found = found || r.Code == wantCode
	}
	if !found {
		t.Errorf("reasons = %+v, want one coded %s", h.Reasons, wantCode)
	}
	return h, e.view(t, h.DraftID)
}

func (e *draftEnv) wantHead(t *testing.T, head int64) {
	t.Helper()
	if got := e.head(t); got != head {
		t.Fatalf("head = %d, want %d", got, head)
	}
}

// seedEvent gives replays a fleet event to compare.
func seedEvent(t *testing.T, e *draftEnv) {
	t.Helper()
	if err := e.srv.central.StoreAggregatedEvent(replayEvent("api.openai.com", "allow", "/v1")); err != nil {
		t.Fatal(err)
	}
}

func openDrafts(t *testing.T, e *draftEnv) int {
	t.Helper()
	ds, _, err := e.srv.Approvals().Store().List(context.Background(), approvals.Filter{}, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(ds)
}

// TestApprovalsWritePaths: with approvals enabled a widening save on the policy,
// settings and llmProviders routes is held as a draft (202, head unchanged) and
// a narrowing one publishes at once (200).
func TestApprovalsWritePaths(t *testing.T) {
	t.Run("policy widening held then approved", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		seedEvent(t, e)
		etag := e.srv.policy.currentETag()
		rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"},{"domain":"new.example.com"}],"denylist":[{"domain":"evil.example.com"}]}`, "1")
		h, d := e.wantHeld(t, rec, approvals.CodeAllowAdded)
		e.wantHead(t, 1)
		if e.srv.policy.currentETag() != etag {
			t.Error("the served ETag moved for a held change")
		}
		if d.Author.Sub != "u1" || d.Source != "console" || d.BaseVersion != 1 || d.State != "pending" {
			t.Errorf("draft = %+v", d.ChangeDraftView)
		}
		if fs := e.pub.byRule("policy_approval_requested"); len(fs) != 1 || fs[0].DedupKey != "policy_approval_requested:"+h.DraftID {
			t.Errorf("approval finding = %+v", fs)
		}
		// The save is one audited row naming the draft, status 202.
		rows := e.rec.inputs()
		last := rows[len(rows)-1]
		if last.Action != "policy.write" || last.HTTPStatus != http.StatusAccepted || last.TargetRef != "draft:"+h.DraftID+"@r1" ||
			last.Details["op"] != "held" || last.Actor.Sub != "u1" {
			t.Errorf("audit row = %+v", last)
		}
		// The two-person rule applies to it: u1 cannot approve, u2 can.
		rp := e.settledReplay(t, h.DraftID)
		if r := e.do("u1", http.MethodPost, draftsPath+"/"+h.DraftID+"/approve", approveBody(d.ChangeDraftView, rp.ID, "")); r.Code != http.StatusForbidden {
			t.Errorf("author approve = %d, want 403", r.Code)
		}
		if r := e.do("u2", http.MethodPost, draftsPath+"/"+h.DraftID+"/approve", approveBody(d.ChangeDraftView, rp.ID, "")); r.Code != http.StatusOK {
			t.Fatalf("approve = %d %s", r.Code, r.Body.String())
		}
		e.wantHead(t, 2)
	})

	t.Run("policy narrowing applies at once", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"worse.example.com"}]}`, "1")
		if rec.Code != http.StatusOK {
			t.Fatalf("narrowing save = %d %s, want 200", rec.Code, rec.Body.String())
		}
		e.wantHead(t, 2)
		if rec.Header().Get(dashboard.PolicyVersionHeader) != "2" {
			t.Errorf("version header = %q", rec.Header().Get(dashboard.PolicyVersionHeader))
		}
	})

	t.Run("narrowing is held when self-approval is off", func(t *testing.T) {
		e := newDraftEnv(t, func(ac *config.ConsoleApprovals) { ac.AllowSelfApproveNarrowing = false })
		rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"worse.example.com"}]}`, "1")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d %s, want 202", rec.Code, rec.Body.String())
		}
		e.wantHead(t, 1)
	})

	t.Run("stale and missing If-Match", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		wide := `{"allowlist":[{"domain":"api.openai.com"},{"domain":"new.example.com"}],"denylist":[{"domain":"evil.example.com"}]}`
		// Move the head with a narrowing save, then save a widening one from v1.
		if rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"x.example.com"}]}`, "1"); rec.Code != http.StatusOK {
			t.Fatalf("setup save = %d", rec.Code)
		}
		rec := e.put("u1", policyPath, wide, "1")
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "policy_conflict") {
			t.Fatalf("stale widening save = %d %s, want 409 policy_conflict", rec.Code, rec.Body.String())
		}
		if rec := e.do("u1", http.MethodPut, policyPath, wide); rec.Code != http.StatusPreconditionRequired {
			t.Errorf("missing If-Match = %d, want 428", rec.Code)
		}
		e.wantHead(t, 2)
		if n := openDrafts(t, e); n != 0 {
			t.Errorf("%d drafts created by refused saves", n)
		}
	})

	t.Run("settings", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		const judge = `{"observability":{"enabled":true,"serviceName":"svc-gpt4omini"}}`
		// A judge edit is widening and admin-only.
		_, d := e.wantHeld(t, e.put("admin", settingsPath, judge, "1"), approvals.CodeSettingsChanged)
		if d.RequiredRole != "admin" {
			t.Errorf("required role = %s, want admin", d.RequiredRole)
		}
		e.wantHead(t, 1)
		// Field-level roles still run at save time: an editor is refused.
		if rec := e.put("u1", settingsPath, judge, "1"); rec.Code != http.StatusForbidden {
			t.Errorf("editor judge save = %d %s, want 403", rec.Code, rec.Body.String())
		}
		// A narrowing toggle publishes at once.
		rec := e.put("u1", settingsPath, `{"compliance":{"enabled":true}}`, "1")
		if rec.Code != http.StatusOK {
			t.Fatalf("narrowing settings save = %d %s, want 200", rec.Code, rec.Body.String())
		}
		e.wantHead(t, 2)
	})

	t.Run("llmProviders", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		rec := e.put("admin", providersPath, `[{"name":"p","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY","timeoutSeconds":5}]`, "1")
		e.wantHeld(t, rec, approvals.CodeSettingsChanged)
		e.wantHead(t, 1)
	})

	t.Run("a new raw credential is refused, never held", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		const raw = "raw-credential-value-0123456789"
		rec := e.put("admin", settingsPath, `{"secrets":{"backend":"aws","region":"us-east-1","accessKeyId":"AKIAEXAMPLEEXAMPLE00","secretAccessKey":"`+raw+`"}}`, "1")
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Fatalf("credential save = %d %s, want a refusal", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), raw) {
			t.Error("the refusal echoes the credential")
		}
		if !strings.Contains(rec.Body.String(), "credential") {
			t.Errorf("refusal %q does not name the credential", rec.Body.String())
		}
		e.wantHead(t, 1)
		if n := openDrafts(t, e); n != 0 {
			t.Errorf("%d drafts created for a credential save", n)
		}
		if b, _ := os.ReadFile(e.srv.cfg.PolicyPath); strings.Contains(string(b), raw) {
			t.Error("the credential reached the served config")
		}
	})

	t.Run("an unchanged save creates nothing", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"}]}`, "1")
		if rec.Code != http.StatusOK {
			t.Fatalf("no-op save = %d %s", rec.Code, rec.Body.String())
		}
		e.wantHead(t, 1)
	})
}

// TestRollbackAsDraft: a rollback that removes a deny entry is held (202,
// source rollback, reason deny.removed); a narrowing rollback applies at once.
func TestRollbackAsDraft(t *testing.T) {
	t.Run("widening rollback is held", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		if rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"bad.example.com"}]}`, "1"); rec.Code != http.StatusOK {
			t.Fatalf("setup = %d %s", rec.Code, rec.Body.String())
		}
		rec := e.do("u1", http.MethodPost, policyPath+"/versions/1/rollback", `{"note":"undo"}`, matchV("2")...)
		_, d := e.wantHeld(t, rec, approvals.CodeDenyRemoved)
		e.wantHead(t, 2)
		if d.Source != "rollback" || d.BaseVersion != 2 || d.Author.Sub != "u1" {
			t.Errorf("draft = %+v", d.ChangeDraftView)
		}
		if !strings.Contains(d.Message, "rollback to v1") {
			t.Errorf("message = %q", d.Message)
		}
		// A stale rollback is still a 409.
		if rec := e.do("u1", http.MethodPost, policyPath+"/versions/1/rollback", `{}`, matchV("1")...); rec.Code != http.StatusConflict {
			t.Errorf("stale rollback = %d, want 409", rec.Code)
		}
	})

	t.Run("narrowing rollback applies at once", func(t *testing.T) {
		e := newDraftEnv(t, nil)
		seedEvent(t, e)
		// v2 adds an allow entry through a draft and an approval.
		d := e.create(t, "u1", docWith(`{"domain":"new.example.com"}`))
		if r := e.submit(t, "u1", d.ID); r.Code != http.StatusOK {
			t.Fatalf("submit = %d", r.Code)
		}
		rp := e.settledReplay(t, d.ID)
		if r := e.do("u2", http.MethodPost, draftsPath+"/"+d.ID+"/approve", approveBody(d.ChangeDraftView, rp.ID, "")); r.Code != http.StatusOK {
			t.Fatalf("approve = %d %s", r.Code, r.Body.String())
		}
		rec := e.do("u1", http.MethodPost, policyPath+"/versions/1/rollback", `{}`, matchV("2")...)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"head":3`) {
			t.Fatalf("narrowing rollback = %d %s, want 200 head 3", rec.Code, rec.Body.String())
		}
		e.wantHead(t, 3)
	})
}

// TestApprovalsGateFailsClosed: approvals enabled but no Service means no write
// publishes.
func TestApprovalsGateFailsClosed(t *testing.T) {
	e := newDraftEnv(t, nil)
	e.srv.gate = approvals.NewGate(true, nil)
	rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"x.example.com"}]}`, "1")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "approvals_unavailable") {
		t.Fatalf("save through a broken gate = %d %s, want 503 approvals_unavailable", rec.Code, rec.Body.String())
	}
	if rec := e.do("u1", http.MethodPost, policyPath+"/versions/1/rollback", `{}`, matchV("1")...); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("rollback through a broken gate = %d, want 503", rec.Code)
	}
	e.wantHead(t, 1)
}

// TestPublishRequiresClearance: the zero Clearance publishes nothing, and every
// kind of clearance has a reason.
func TestPublishRequiresClearance(t *testing.T) {
	e := newDraftEnv(t, nil)
	ctx := context.Background()
	mutate := func(w *policyWire) error {
		w.Allowlist = append(w.Allowlist, config.AllowlistEntry{Domain: "sneak.example.com"})
		return nil
	}
	_, _, err := e.srv.publish(ctx, approvals.Clearance{}, PolicyAuthor{Sub: "u1", Kind: AuthorKindOIDC}, mutate, dashboard.WriteMeta{}, SourcePolicy)
	if !errors.Is(err, approvals.ErrNotCleared) {
		t.Fatalf("publish with the zero Clearance = %v, want ErrNotCleared", err)
	}
	_, _, err = e.srv.publishLocked(ctx, approvals.Clearance{}, PolicyAuthor{Sub: "u1"}, 1, "", policyWire{}, dashboard.WriteMeta{}, SourcePolicy)
	if !errors.Is(err, approvals.ErrNotCleared) {
		t.Fatalf("publishLocked with the zero Clearance = %v, want ErrNotCleared", err)
	}
	e.wantHead(t, 1)

	// A draft clearance needs a draft in applying; a pending one is refused.
	d := pendingDraft(t, e.srv, 1, "pending.example.com")
	if _, err := e.srv.gate.ClearApplied(d); !errors.Is(err, approvals.ErrNotCleared) {
		t.Errorf("ClearApplied(pending draft) = %v, want ErrNotCleared", err)
	}
	d.State = approvals.StateApplying
	clr, err := e.srv.gate.ClearApplied(d)
	if err != nil || clr.Reason() != "applied_draft" {
		t.Errorf("ClearApplied(applying draft) = %v, %v", clr, err)
	}
	if (approvals.Clearance{}).Valid() {
		t.Error("the zero Clearance is valid")
	}
	// With approvals disabled the Gate clears everything.
	off, err := approvals.NewGate(false, nil).Clear(ctx, approvals.Change{})
	if err != nil || off.Reason() != "disabled" {
		t.Errorf("disabled gate = %v, %v", off, err)
	}
	if _, err := (*approvals.Gate)(nil).Clear(ctx, approvals.Change{}); !errors.Is(err, approvals.ErrGateUnavailable) {
		t.Errorf("nil gate = %v, want ErrGateUnavailable", err)
	}
}

// gatedRoute is one audited dashboard route that creates a policy version, with
// the caller and a request that widens the head.
type gatedRoute struct {
	who, body string
}

// versionedWriteRoutes lists the audited routes that create a policy version.
// TestVersionedWritesAreGated sends each a widening request and asserts a 202.
var versionedWriteRoutes = map[routeKey]gatedRoute{
	{http.MethodPost, "/dashboard/api/policy"}:                       {"u1", `{"allowlist":[{"domain":"api.openai.com"},{"domain":"w1.example.com"}],"denylist":[{"domain":"evil.example.com"}]}`},
	{http.MethodPut, "/dashboard/api/policy"}:                        {"u1", `{"allowlist":[{"domain":"api.openai.com"},{"domain":"w2.example.com"}],"denylist":[{"domain":"evil.example.com"}]}`},
	{http.MethodPost, "/dashboard/api/settings"}:                     {"admin", `{"observability":{"enabled":true,"serviceName":"svc-m"}}`},
	{http.MethodPut, "/dashboard/api/settings"}:                      {"admin", `{"observability":{"enabled":true,"serviceName":"svc-m2"}}`},
	{http.MethodPost, "/dashboard/api/llmproviders"}:                 {"admin", `[{"name":"p1","baseURL":"https://api.openai.com/v1","model":"m","apiKeyEnv":"K","timeoutSeconds":5}]`},
	{http.MethodPut, "/dashboard/api/llmproviders"}:                  {"admin", `[{"name":"p2","baseURL":"https://api.openai.com/v1","model":"m","apiKeyEnv":"K","timeoutSeconds":5}]`},
	{http.MethodPost, "/dashboard/api/policy/versions/{v}/rollback"}: {"u1", `{}`},
}

// notVersionedWriteRoutes lists every other audited mutating route and why it is
// outside the gate: it does not create a policy version.
var notVersionedWriteRoutes = map[routeKey]string{
	{http.MethodPost, "/dashboard/api/changes"}:               "creates a draft, not a version",
	{http.MethodPut, "/dashboard/api/changes/{id}"}:           "edits a draft",
	{http.MethodPost, "/dashboard/api/changes/{id}/submit"}:   "applies only through Service.Apply (ClearApplied)",
	{http.MethodPost, "/dashboard/api/changes/{id}/withdraw"}: "ends a draft",
	{http.MethodPost, "/dashboard/api/changes/{id}/rebase"}:   "edits a draft",
	{http.MethodPost, "/dashboard/api/changes/{id}/approve"}:  "applies only through Service.Apply (ClearApplied)",
	{http.MethodPost, "/dashboard/api/changes/{id}/reject"}:   "ends a draft",
	{http.MethodPost, "/dashboard/api/changes/{id}/replay"}:   "runs a replay",
	// CP-local blocks and stores that are not part of a policy version
	// (docs/control-plane.md).
	{http.MethodPost, "/dashboard/api/secretstore"}:          "served YAML secretStore block, not a version",
	{http.MethodDelete, "/dashboard/api/secretstore"}:        "served YAML secretStore block, not a version",
	{http.MethodPost, "/dashboard/api/integrations"}:         "CP-local integrations block",
	{http.MethodDelete, "/dashboard/api/integrations"}:       "CP-local integrations block",
	{http.MethodPost, "/dashboard/api/detection"}:            "CP-local detection block",
	{http.MethodPut, "/dashboard/api/detection"}:             "CP-local detection block",
	{http.MethodPost, "/dashboard/api/backup"}:               "writes a backup, not a version",
	{http.MethodPost, "/dashboard/api/worker-tokens"}:        "worker token store",
	{http.MethodDelete, "/dashboard/api/worker-tokens/{id}"}: "worker token store",
	{http.MethodPost, "/dashboard/api/blocked-users"}:        "block list store, a serve-time overlay (W-P2-APPR-08 gates removals)",
	{http.MethodDelete, "/dashboard/api/blocked-users/{id}"}: "block list store, a serve-time overlay (W-P2-APPR-08 gates removals)",
	{http.MethodPost, "/dashboard/api/keys/rotate"}:          "signing key store",
	{http.MethodDelete, "/dashboard/api/sessions"}:           "session store",
}

// TestVersionedWritesAreGated walks the authz table: every audited mutating
// route is either a listed versioned write (and answers 202 for a widening
// request, so it goes through the Gate) or is listed as not creating a version.
// A new audited write route fails here until it is classified.
func TestVersionedWritesAreGated(t *testing.T) {
	table := authzTable()
	for key, row := range table {
		if !row.Audited || key.Method == http.MethodGet {
			continue
		}
		_, gated := versionedWriteRoutes[key]
		_, other := notVersionedWriteRoutes[key]
		if gated == other {
			t.Errorf("%s %s (%s) must be in exactly one of versionedWriteRoutes and notVersionedWriteRoutes (gated=%v other=%v)",
				key.Method, key.Path, row.Action, gated, other)
		}
	}
	for key := range versionedWriteRoutes {
		if _, ok := table[key]; !ok {
			t.Errorf("versionedWriteRoutes names %s %s, which is not a route", key.Method, key.Path)
		}
	}
	for key := range notVersionedWriteRoutes {
		if _, ok := table[key]; !ok {
			t.Errorf("notVersionedWriteRoutes names %s %s, which is not a route", key.Method, key.Path)
		}
	}

	keys := make([]routeKey, 0, len(versionedWriteRoutes))
	for k := range versionedWriteRoutes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Method+keys[i].Path < keys[j].Method+keys[j].Path })
	for _, k := range keys {
		g := versionedWriteRoutes[k]
		t.Run(k.Method+" "+k.Path, func(t *testing.T) {
			e := newDraftEnv(t, nil)
			path := strings.ReplaceAll(k.Path, "{v}", "1")
			ifMatch, head := "1", int64(1)
			if strings.HasSuffix(path, "/rollback") {
				// Give the rollback something to remove: v2 adds a deny entry.
				if rec := e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"d.example.com"}]}`, "1"); rec.Code != http.StatusOK {
					t.Fatalf("setup = %d", rec.Code)
				}
				ifMatch, head = "2", 2
			}
			rec := e.do(g.who, k.Method, path, g.body, matchV(ifMatch)...)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d %s, want 202 (a versioned write must be held)", rec.Code, rec.Body.String())
			}
			e.wantHead(t, head)
			rows := e.rec.inputs()
			if len(rows) == 0 || rows[len(rows)-1].Action != table[k].Action {
				t.Errorf("no %s audit row for the held write", table[k].Action)
			}
		})
	}
}

// TestVersionedStoreCreateCallers is the source-level half: only the publish
// funnel, the offline CLI import and the initial import call the policy store's
// Create, and only the Gate-aware files call publish. A new caller fails here.
func TestVersionedStoreCreateCallers(t *testing.T) {
	createCall := regexp.MustCompile(`\b(versions|st|store)\.Create\(ctx, (doc\b|w\b|d\b)`)
	publishCall := regexp.MustCompile(`\.(publish|publishLocked)\(ctx, `)
	wantCreate := map[string]bool{"policy_publish.go": true, "policycli.go": true, "policystore.go": true}
	wantPublish := map[string]bool{"policy_publish.go": true, "approvals_apply.go": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if createCall.Match(b) && !wantCreate[f] {
			t.Errorf("%s calls the policy store's Create; route the write through Server.writeVersioned", f)
		}
		if publishCall.Match(b) && !wantPublish[f] {
			t.Errorf("%s calls Server.publish; only the Gate-aware paths may", f)
		}
	}
	for f := range wantCreate {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !createCall.Match(b) {
			t.Errorf("%s no longer calls Create; update the allow list", f)
		}
	}
}

// TestQueueMissingReplays: a pending draft with no replay (one the offline CLI
// created) gets one from the sweeper's pass; a second pass queues nothing.
func TestQueueMissingReplays(t *testing.T) {
	e := newDraftEnv(t, nil)
	seedEvent(t, e)
	d := pendingDraft(t, e.srv, 1, "cli-made.example.com")
	svc := e.srv.Approvals()
	if _, ok, _ := svc.LatestReplay(context.Background(), d.ID, d.Revision); ok {
		t.Fatal("the draft already has a replay")
	}
	n, err := svc.QueueMissingReplays(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("QueueMissingReplays = %d, %v; want 1", n, err)
	}
	waitSettled(t, svc, d.ID)
	if n, err := svc.QueueMissingReplays(context.Background()); err != nil || n != 0 {
		t.Errorf("second pass = %d, %v; want 0", n, err)
	}
}

// TestApprovalsMetaWrittenAtStart: a control plane with approvals enabled
// records it for the offline CLI, and records when it is disabled again.
func TestApprovalsMetaWrittenAtStart(t *testing.T) {
	e := newDraftEnv(t, nil)
	m, found, err := sqlstore.ReadMeta(context.Background(), e.srv.cfg.State.SQL())
	if err != nil || !found || !m.Enabled || m.MaxOpenDrafts != 20 {
		t.Fatalf("meta = %+v, %v, %v", m, found, err)
	}
	// The same database under a disabled control plane flips it off.
	off := New(Config{PolicyPath: e.srv.cfg.PolicyPath, Token: dashTestToken, State: e.srv.cfg.State, PolicyStore: PolicyStoreVersioned})
	_ = off
	m, found, err = sqlstore.ReadMeta(context.Background(), e.srv.cfg.State.SQL())
	if err != nil || !found || m.Enabled {
		t.Fatalf("meta after a disabled start = %+v, %v, %v; want found and disabled", m, found, err)
	}
}
