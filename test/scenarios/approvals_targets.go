package scenarios

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Block-list removals and widening agent edits are held for a second admin
// (W-P2-APPR-08). Adding a block and disabling an agent stay immediate; the
// served /policy changes only when the second admin approves.

func approvalsTargetsOpts() []harness.Option { return []harness.Option{harness.WithApprovals()} }

// servedRegistry is what the control plane serves workers from /policy: the
// blocked subs and each registered agent's status.
func servedRegistry(t *testing.T, h *harness.H) (blocked []string, agents map[string]string) {
	t.Helper()
	var p struct {
		BlockedUsers []struct {
			Sub string `json:"sub"`
		} `json:"blockedUsers"`
		RegisteredAgents []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"registeredAgents"`
	}
	if err := h.CP().GetJSON("/policy", &p); err != nil {
		t.Fatalf("GET /policy: %v", err)
	}
	agents = map[string]string{}
	for _, u := range p.BlockedUsers {
		blocked = append(blocked, u.Sub)
	}
	for _, a := range p.RegisteredAgents {
		agents[a.ID] = a.Status
	}
	return blocked, agents
}

// awaitServed waits until the served policy satisfies ok. A registry write by
// another process shows at the next policy reload, so the check polls.
func awaitServed(t *testing.T, h *harness.H, what string, ok func(blocked []string, agents map[string]string) bool) {
	t.Helper()
	h.Eventually(what, func() bool {
		b, a := servedRegistry(t, h)
		return ok(b, a)
	})
}

func hasSub(list []string, sub string) bool {
	for _, s := range list {
		if s == sub {
			return true
		}
	}
	return false
}

// held202 asserts a 202 held response and returns its draft id.
func held202(t *testing.T, status int, raw []byte, what string) string {
	t.Helper()
	var held struct {
		DraftID  string `json:"draft_id"`
		State    string `json:"state"`
		Widening bool   `json:"widening"`
	}
	if status != http.StatusAccepted || json.Unmarshal(raw, &held) != nil || held.DraftID == "" || held.State != "pending" || !held.Widening {
		t.Fatalf("%s = %d %s, want 202 with a pending widening draft", what, status, raw)
	}
	return held.DraftID
}

// approveTargetDraft has b approve draft id, acknowledging there is no replay
// (replay covers policy decisions only), and returns the status and body.
func approveTargetDraft(t *testing.T, h *harness.H, b *harness.Browser, csrf, id string) (int, []byte) {
	t.Helper()
	var d dashboard.ChangeDraftDetail
	if resp, body := consoleDo(t, b, http.MethodGet, "/dashboard/api/changes/"+id, nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &d) != nil {
		t.Fatalf("GET draft %s = %d %s", id, resp.StatusCode, body)
	}
	return draftCall(t, b, csrf, http.MethodPost, "/dashboard/api/changes/"+id+"/approve", "",
		map[string]any{"revision": d.Revision, "doc_sha256": d.DocSHA256, "acknowledgeNoReplay": true})
}

func approvalsHoldRemovals(t *testing.T, h *harness.H) {
	ana, anaCSRF := consoleLogin(t, h, fakes.Valid("ana", "ana@example.com", harness.ConsoleAdminGroup))
	ben, benCSRF := consoleLogin(t, h, fakes.Valid("ben", "ben@example.com", harness.ConsoleAdminGroup))

	// Adding a block is immediate: 201 and the served policy lists the user.
	status, raw := draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/blocked-users", "", map[string]any{"sub": "victim", "reason": "incident 42"})
	var added struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &added) != nil || added.ID == "" {
		t.Fatalf("add block = %d %s, want 201", status, raw)
	}
	awaitServed(t, h, "the served policy to list the blocked user", func(b []string, _ map[string]string) bool { return hasSub(b, "victim") })
	etag := servedETag(t, h)

	// The removal is held: 202, and the served policy still blocks the user.
	status, raw = draftCall(t, ana, anaCSRF, http.MethodDelete, "/dashboard/api/blocked-users/"+added.ID, "", nil)
	draft := held202(t, status, raw, "remove block")
	if b, _ := servedRegistry(t, h); !hasSub(b, "victim") || servedETag(t, h) != etag {
		t.Fatalf("a held removal changed the served policy (blocked %v)", b)
	}
	// The author cannot approve; the second admin's approval removes the entry.
	if status, raw = approveTargetDraft(t, h, ana, anaCSRF, draft); status != http.StatusForbidden || !strings.Contains(string(raw), "self_approval_forbidden") {
		t.Fatalf("author approves own removal = %d %s, want 403 self_approval_forbidden", status, raw)
	}
	if status, raw = approveTargetDraft(t, h, ben, benCSRF, draft); status != http.StatusOK || !strings.Contains(string(raw), `"state":"applied"`) {
		t.Fatalf("second admin approves = %d %s, want 200 applied", status, raw)
	}
	awaitServed(t, h, "the served policy to drop the unblocked user", func(b []string, _ map[string]string) bool { return !hasSub(b, "victim") })
	if servedETag(t, h) == etag {
		t.Error("the served ETag did not move after the approved removal")
	}

	// An agent registration is held; nothing is served until it is approved.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	agent := func(name string, groups ...string) map[string]any {
		return map[string]any{"id": "bot", "displayName": name, "keys": []any{jwk}, "allowedGroups": groups}
	}
	status, raw = draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/agents", "", agent("Bot", "devs"))
	draft = held202(t, status, raw, "register agent")
	if _, a := servedRegistry(t, h); len(a) != 0 {
		t.Fatalf("a held registration is served: %v", a)
	}
	if status, raw = approveTargetDraft(t, h, ben, benCSRF, draft); status != http.StatusOK {
		t.Fatalf("approve registration = %d %s", status, raw)
	}
	awaitServed(t, h, "the served policy to list the approved agent", func(_ []string, a map[string]string) bool { return a["bot"] == "active" })

	// Disabling is immediate; re-enabling is held until a second approval.
	if status, raw = draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/agents/bot/disable", `"r1"`, nil); status != http.StatusOK {
		t.Fatalf("disable = %d %s, want 200", status, raw)
	}
	awaitServed(t, h, "the served policy to show the agent disabled", func(_ []string, a map[string]string) bool { return a["bot"] == "disabled" })
	status, raw = draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/agents/bot/enable", `"r2"`, nil)
	draft = held202(t, status, raw, "enable agent")
	if _, a := servedRegistry(t, h); a["bot"] != "disabled" {
		t.Fatalf("a held enable re-enabled the agent: %v", a)
	}
	if status, raw = approveTargetDraft(t, h, ben, benCSRF, draft); status != http.StatusOK {
		t.Fatalf("approve enable = %d %s", status, raw)
	}
	awaitServed(t, h, "the served policy to show the agent enabled", func(_ []string, a map[string]string) bool { return a["bot"] == "active" })

	// A display name edit applies directly; a new group is held and the agent
	// keeps its groups until it is approved.
	if status, raw = draftCall(t, ana, anaCSRF, http.MethodPut, "/dashboard/api/agents/bot", `"r3"`, agent("Renamed", "devs")); status != http.StatusOK {
		t.Fatalf("rename = %d %s, want 200", status, raw)
	}
	status, raw = draftCall(t, ana, anaCSRF, http.MethodPut, "/dashboard/api/agents/bot", `"r4"`, agent("Renamed", "devs", "ops"))
	draft = held202(t, status, raw, "add group")
	var got dashboard.AgentView
	if resp, body := consoleDo(t, ana, http.MethodGet, "/dashboard/api/agents/bot", nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || len(got.AllowedGroups) != 1 {
		t.Fatalf("agent after the held group add = %d %s, want groups unchanged", resp.StatusCode, body)
	}
	if status, raw = approveTargetDraft(t, h, ben, benCSRF, draft); status != http.StatusOK {
		t.Fatalf("approve group add = %d %s", status, raw)
	}
	if resp, body := consoleDo(t, ana, http.MethodGet, "/dashboard/api/agents/bot", nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || len(got.AllowedGroups) != 2 {
		t.Fatalf("agent after the approved group add = %d %s, want two groups", resp.StatusCode, body)
	}

	// Admin audit: every held write and every approval names its actor; the
	// approved writes carry their own rows by the approver.
	var rows []string
	for _, r := range h.AdminAuditRows() {
		if strings.HasPrefix(r.Action, "blocked_users.") || strings.HasPrefix(r.Action, "agent.") || r.Action == "change.draft.approve" {
			rows = append(rows, r.Action+":"+r.Outcome+":"+r.Sub)
		}
	}
	for _, want := range []string{
		"blocked_users.add:ok:ana", "blocked_users.remove:ok:ana", "change.draft.approve:denied:ana",
		"change.draft.approve:ok:ben", "blocked_users.remove:ok:ben", "agent.create:ok:ana", "agent.create:ok:ben",
		"agent.disable:ok:ana", "agent.enable:ok:ana", "agent.enable:ok:ben", "agent.update:ok:ben",
	} {
		if !hasSub(rows, want) {
			t.Errorf("admin audit rows %v lack %s", rows, want)
		}
	}
}

func approvalsBlockEnforcementOpts() []harness.Option {
	return append(blockListFleetOpts(), harness.WithApprovals())
}

// approvalsBlockEnforcement: with approvals on, adding a block is immediate (the
// worker denies the user at once, no second admin), a removal is held while a
// long-poll parked on the served ETag stays parked, and the second admin's
// approval wakes that long-poll and lets the user through again.
func approvalsBlockEnforcement(t *testing.T, h *harness.H) {
	h.Upstream(blockHost)
	users := mintBlockUsers(h)
	hostPort := blockHost + ":443"
	ana, anaCSRF := consoleLogin(t, h, fakes.Valid("ana", "ana@example.com", harness.ConsoleAdminGroup))
	ben, benCSRF := consoleLogin(t, h, fakes.Valid("ben", "ben@example.com", harness.ConsoleAdminGroup))
	awaitAllowed(h, 0, hostPort, users.alice)

	status, raw := draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/blocked-users", "", map[string]any{"sub": "alice", "reason": "incident"})
	var added struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &added) != nil {
		t.Fatalf("add block = %d %s, want 201", status, raw)
	}
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
	}

	// A long-poll parks on the served ETag; the held removal does not wake it.
	etag := servedETag(t, h)
	held := h.CP().HoldWorker(http.MethodGet, "/policy?wait=30s", h.CP().Token(), http.Header{"If-None-Match": {etag}})
	status, raw = draftCall(t, ana, anaCSRF, http.MethodDelete, "/dashboard/api/blocked-users/"+added.ID, "", nil)
	draft := held202(t, status, raw, "remove block")
	select {
	case r := <-held:
		t.Fatalf("a held removal woke the long-poll: %d", r.Status)
	default:
	}
	awaitBlocked(t, h, 0, hostPort, users.alice)

	if status, raw = approveTargetDraft(t, h, ben, benCSRF, draft); status != http.StatusOK {
		t.Fatalf("approve removal = %d %s", status, raw)
	}
	var got harness.RawResponse
	h.Eventually("the approval to wake the parked long-poll", func() bool {
		select {
		case got = <-held:
			return true
		default:
			return false
		}
	})
	if got.Status != http.StatusOK || got.Header.Get("ETag") == etag {
		t.Fatalf("woken long-poll = %d ETag %q (was %q), want 200 with a new ETag", got.Status, got.Header.Get("ETag"), etag)
	}
	for i := 0; i < blockWorkers; i++ {
		awaitAllowed(h, i, hostPort, users.alice)
	}
}
