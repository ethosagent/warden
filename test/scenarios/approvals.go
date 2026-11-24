package scenarios

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Approvals default off (W-P2-APPR-01): a control plane without
// console.approvals.enabled creates no approvals table, applies no approvals
// migration, and serves /policy as before.

func approvalsOffOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

// approvalsOffByDefault: on a versioned control plane with the approvals block
// absent, the state database holds no change_* table and no approvals
// migration, while the policy store itself is live and /policy still serves.
func approvalsOffByDefault(t *testing.T, h *harness.H) {
	ctx := context.Background()
	var served map[string]any
	if err := h.CP().GetJSON("/policy", &served); err != nil {
		t.Fatalf("GET /policy: %v", err)
	}
	if _, ok := served["allowlist"]; !ok {
		t.Fatalf("/policy = %v, want an allowlist", served)
	}

	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var tables int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'change_%'").Scan(&tables); err != nil {
		t.Fatalf("inspect the state db: %v", err)
	}
	if tables != 0 {
		t.Errorf("a control plane without console.approvals has %d change_* tables, want none", tables)
	}
	var applied int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE id LIKE 'approvals/%'").Scan(&applied); err != nil {
		t.Fatalf("inspect schema_migrations: %v", err)
	}
	if applied != 0 {
		t.Errorf("approvals migration applied %d times without console.approvals.enabled", applied)
	}
	var policyTables int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name = 'policy_versions'").Scan(&policyTables); err != nil || policyTables != 1 {
		t.Errorf("policy_versions tables = %d, %v; want the versioned store live", policyTables, err)
	}
}

// The two-person rule over the draft API (W-P2-APPR-04): with
// console.approvals.enabled a widening change is a draft that its author
// submits and a different editor approves, citing the replay of recent fleet
// traffic. The author's own approval is refused; the second person's approval
// publishes the version in the same request and workers enforce it.

func approvalsTwoPersonOpts() []harness.Option { return []harness.Option{harness.WithApprovals()} }

// approvalsHost is allowed only by the approved draft.
const approvalsHost = "approved.example.com"

// draftCall sends one write to the draft API as the browser's session.
func draftCall(t *testing.T, b *harness.Browser, csrf, method, path string, ifMatch string, body any) (int, []byte) {
	t.Helper()
	hdr := http.Header{controlplane.CSRFHeader: {csrf}}
	if ifMatch != "" {
		hdr.Set("If-Match", ifMatch)
	}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := b.DoBody(method, path, hdr, raw)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out
}

func approvalsTwoPerson(t *testing.T, h *harness.H) {
	h.Upstream(approvalsHost)
	if got := connectStatus(t, h, approvalsHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s before the draft = %d, want 403", approvalsHost, got)
	}
	ana, anaCSRF := consoleLogin(t, h, fakes.Valid("ana", "ana@example.com", harness.ConsoleEditorGroup))
	ben, benCSRF := consoleLogin(t, h, fakes.Valid("ben", "ben@example.com", harness.ConsoleEditorGroup))

	// ana drafts the current policy plus the new host.
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if resp, body := consoleDo(t, ana, http.MethodGet, "/dashboard/api/policy", nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &cur) != nil {
		t.Fatalf("GET policy = %d %s", resp.StatusCode, body)
	}
	doc := map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": approvalsHost}),
		"denylist":  cur.Denylist,
	}
	status, raw := draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/changes", `"v1"`,
		map[string]any{"target": "policy", "message": "allow " + approvalsHost, "doc": doc})
	var d dashboard.ChangeDraftDetail
	if status != http.StatusCreated || json.Unmarshal(raw, &d) != nil || d.ID == "" || !d.Widening {
		t.Fatalf("create draft = %d %s, want 201 and a widening draft", status, raw)
	}
	path := "/dashboard/api/changes/" + d.ID
	if status, raw = draftCall(t, ana, anaCSRF, http.MethodPost, path+"/submit", "", nil); status != http.StatusOK {
		t.Fatalf("submit = %d %s", status, raw)
	}

	// The replay of recent fleet traffic is visible on the draft once it settles.
	var latest *dashboard.ChangeReplayView
	h.Eventually("the draft's replay settles", func() bool {
		var got dashboard.ChangeDraftDetail
		if resp, body := consoleDo(t, ana, http.MethodGet, path, nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil {
			return false
		}
		latest = got.LatestReplay
		return latest != nil && latest.Status != "pending" && latest.Status != "running"
	})

	// The author's own approval is refused, whatever it cites.
	approve := map[string]any{"revision": d.Revision, "doc_sha256": d.DocSHA256, "acknowledgeNoReplay": latest.Status != "done"}
	if latest.Status == "done" {
		approve["replay_id"] = latest.ID
	}
	if status, raw = draftCall(t, ana, anaCSRF, http.MethodPost, path+"/approve", "", approve); status != http.StatusForbidden || !strings.Contains(string(raw), "self_approval_forbidden") {
		t.Fatalf("author approves own change = %d %s, want 403 self_approval_forbidden", status, raw)
	}
	if got := connectStatus(t, h, approvalsHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s after the refused approval = %d, want 403", approvalsHost, got)
	}

	// A second person approves; the same request applies the draft.
	status, raw = draftCall(t, ben, benCSRF, http.MethodPost, path+"/approve", "", approve)
	var res dashboard.ChangeResult
	if status != http.StatusOK || json.Unmarshal(raw, &res) != nil || res.State != "applied" || res.Version != 2 {
		t.Fatalf("second person approves = %d %s, want 200 applied at v2", status, raw)
	}
	h.Eventually("workers enforce the approved version", func() bool {
		return connectStatus(t, h, approvalsHost+":443") == http.StatusOK
	})

	// Admin audit: create, submit, the refused self approval, the approval and
	// the policy row it published.
	var got []string
	for _, r := range h.AdminAuditRows() {
		if strings.HasPrefix(r.Action, "change.draft.") || r.Action == "policy.write" {
			got = append(got, r.Action+":"+r.Outcome+":"+r.Sub)
		}
	}
	want := []string{
		"change.draft.create:ok:ana", "change.draft.submit:ok:ana",
		"change.draft.approve:denied:ana", "change.draft.approve:ok:ben", "policy.write:ok:ben",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("change draft audit rows = %v, want %v", got, want)
	}
}

// A console policy save with approvals enabled (W-P2-APPR-06): a widening save is
// held as a draft (202) and workers keep denying the host until a second person
// approves it; no write path publishes past the gate.
func approvalsHeldSave(t *testing.T, h *harness.H) {
	h.Upstream(approvalsHost)
	ana, anaCSRF := consoleLogin(t, h, fakes.Valid("ana", "ana@example.com", harness.ConsoleEditorGroup))
	ben, benCSRF := consoleLogin(t, h, fakes.Valid("ben", "ben@example.com", harness.ConsoleEditorGroup))
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if resp, body := consoleDo(t, ana, http.MethodGet, "/dashboard/api/policy", nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &cur) != nil {
		t.Fatalf("GET policy = %d %s", resp.StatusCode, body)
	}
	doc := map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": approvalsHost}),
		"denylist":  cur.Denylist,
	}
	status, raw := draftCall(t, ana, anaCSRF, http.MethodPut, "/dashboard/api/policy", `"v1"`, doc)
	var held struct {
		DraftID  string `json:"draft_id"`
		State    string `json:"state"`
		Widening bool   `json:"widening"`
	}
	if status != http.StatusAccepted || json.Unmarshal(raw, &held) != nil || held.DraftID == "" || held.State != "pending" || !held.Widening {
		t.Fatalf("widening save = %d %s, want 202 with a pending widening draft", status, raw)
	}
	if got := connectStatus(t, h, approvalsHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s after the held save = %d, want 403", approvalsHost, got)
	}

	path := "/dashboard/api/changes/" + held.DraftID
	var d dashboard.ChangeDraftDetail
	h.Eventually("the held draft's replay settles", func() bool {
		if resp, body := consoleDo(t, ana, http.MethodGet, path, nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &d) != nil {
			return false
		}
		return d.LatestReplay != nil && d.LatestReplay.Status != "pending" && d.LatestReplay.Status != "running"
	})
	approve := map[string]any{"revision": d.Revision, "doc_sha256": d.DocSHA256, "acknowledgeNoReplay": d.LatestReplay.Status != "done"}
	if d.LatestReplay.Status == "done" {
		approve["replay_id"] = d.LatestReplay.ID
	}
	if status, raw = draftCall(t, ben, benCSRF, http.MethodPost, path+"/approve", "", approve); status != http.StatusOK {
		t.Fatalf("second person approves = %d %s", status, raw)
	}
	h.Eventually("workers enforce the approved save", func() bool {
		return connectStatus(t, h, approvalsHost+":443") == http.StatusOK
	})
}
