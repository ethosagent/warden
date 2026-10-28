package scenarios

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The block-survival scenarios (W-P1-BLOCK-12): the block list is the incident
// kill switch, so nothing that could silently undo it may. A versioned control
// plane (the block list never enters a policy version), a two-worker fleet and
// the in-process IdP prove that a block outlives a policy rollback, a worker
// restart and a control-plane outage, that a block written offline while the
// control plane is down is enforced once it returns, and that unblocking
// restores access and returns the served ETag to its pre-block value.

func blockSurvivalOpts() []harness.Option {
	return append(blockListFleetOpts(), harness.WithVersionedPolicyStore())
}

// survivalHostA and B are allowed only by the policy edits of the rollback
// scenario, never by the YAML.
const (
	survivalHostA = "edit-a.example.com"
	survivalHostB = "edit-b.example.com"
)

// connectStatusAt is worker i's answer to an unauthenticated CONNECT to hostPort.
func connectStatusAt(h *harness.H, i int, hostPort string) int {
	status, _ := h.ConnectReplyAt(i, hostPort, "")
	return status
}

// awaitAllowed waits until worker i tunnels tok's CONNECT to hostPort.
func awaitAllowed(h *harness.H, i int, hostPort, tok string) {
	h.Eventually("worker to tunnel the CONNECT", func() bool {
		status, _ := h.ConnectReplyAt(i, hostPort, basicAuth("session", tok))
		return status == http.StatusOK
	})
}

// servedETag is the ETag of the control plane's GET /policy.
func servedETag(t *testing.T, h *harness.H) string {
	t.Helper()
	resp, err := h.CP().Send(http.MethodGet, "/policy", nil, nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("GET /policy = %d, %v; want 200", resp.Status, err)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("GET /policy carries no ETag")
	}
	return etag
}

// openBlockStore opens the control plane's state db the way the offline CLI
// does. The caller closes it before the control plane starts again.
func openBlockStore(t *testing.T, h *harness.H) (*controlplane.BlockStore, func()) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	return controlplane.NewBlockStore(db, controlplane.BlockStoreOptions{}), func() { _ = db.Close() }
}

// bobStillServed fails unless bob's CONNECT to blockHost succeeds on every worker.
func bobStillServed(t *testing.T, h *harness.H, bob string) {
	t.Helper()
	for i := 0; i < blockWorkers; i++ {
		if status, _ := h.ConnectReplyAt(i, blockHost+":443", basicAuth("session", bob)); status != http.StatusOK {
			t.Errorf("worker-%d: bob's CONNECT = %d, want 200 (the block names alice only)", i+1, status)
		}
	}
}

// policyEdit saves the current allowlist plus host through the dashboard API
// against ifMatch and returns the new version header.
func policyEdit(t *testing.T, h *harness.H, ifMatch, host string) string {
	t.Helper()
	cp := h.CP()
	resp, err := cp.Send(http.MethodGet, "/dashboard/api/policy", nil, nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy = %d, %v", resp.Status, err)
	}
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := json.Unmarshal(resp.Body, &cur); err != nil {
		t.Fatal(err)
	}
	edit, err := json.Marshal(map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": host}),
		"denylist":  cur.Denylist,
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{}
	hdr.Set("If-Match", ifMatch)
	r, err := cp.SendBearer(h.ControlPlaneAdminToken(), http.MethodPost, "/dashboard/api/policy", hdr, edit)
	if err != nil || r.Status != http.StatusOK {
		t.Fatalf("save adding %s (If-Match %s) = %d %s, %v; want 200", host, ifMatch, r.Status, r.Body, err)
	}
	return r.Header.Get(dashboard.PolicyVersionHeader)
}

// blockListSurvivesRollback: alice is blocked, two policy edits make versions
// 2 and 3, then a rollback to version 1 creates version 4. Workers enforce the
// rolled-back allowlist, yet alice stays user_blocked on both workers and bob is
// unaffected: the list lives outside policy versions.
func blockListSurvivesRollback(t *testing.T, h *harness.H) {
	h.Upstream(blockHost)
	h.Upstream(survivalHostA)
	h.Upstream(survivalHostB)
	users := mintBlockUsers(h)
	hostPort := blockHost + ":443"

	h.BlockUser("alice", "")
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
	}

	if v := policyEdit(t, h, `"v1"`, survivalHostA); v != "2" {
		t.Fatalf("first edit = version %s, want 2", v)
	}
	if v := policyEdit(t, h, `"v2"`, survivalHostB); v != "3" {
		t.Fatalf("second edit = version %s, want 3", v)
	}
	for i := 0; i < blockWorkers; i++ {
		h.Eventually("worker to enforce version 3", func() bool {
			return connectStatusAt(h, i, survivalHostB+":443") == http.StatusOK
		})
		awaitBlocked(t, h, i, hostPort, users.alice)
	}

	hdr := http.Header{}
	hdr.Set("If-Match", `"v3"`)
	r, err := h.CP().SendBearer(h.ControlPlaneAdminToken(), http.MethodPost, "/dashboard/api/policy/versions/1/rollback", hdr, nil)
	if err != nil || r.Status != http.StatusOK {
		t.Fatalf("rollback to v1 = %d %s, %v; want 200", r.Status, r.Body, err)
	}
	for i := 0; i < blockWorkers; i++ {
		h.Eventually("worker to enforce the rollback", func() bool {
			return connectStatusAt(h, i, survivalHostB+":443") == http.StatusForbidden
		})
		// The rollback is live on this worker; the block must be too.
		awaitBlocked(t, h, i, hostPort, users.alice)
		awaitBlocked(t, h, i, hostPort, users.aliceExpired)
	}
	bobStillServed(t, h, users.bob)
	h.AssertCanaryNeverLeaked()
}

// blockListSurvivesRestart: alice is blocked, the control plane goes down and
// worker-1 restarts. With no policy yet it is fail-closed (bob is denied too);
// once the control plane is back and the worker has pulled policy again alice is
// user_blocked on it, and bob is served. Worker-2 never restarted and is
// unaffected throughout. A second restart with the control plane up lands the
// block again.
func blockListSurvivesRestart(t *testing.T, h *harness.H) {
	h.Upstream(blockHost)
	users := mintBlockUsers(h)
	hostPort := blockHost + ":443"

	h.BlockUser("alice", "")
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
	}

	h.CP().Stop()
	h.RestartWorker(0)
	if status, _ := h.ConnectReplyAt(0, hostPort, basicAuth("session", users.bob)); status != http.StatusForbidden {
		t.Fatalf("restarted worker-1 before its first pull: bob's CONNECT = %d, want 403 (fail closed)", status)
	}
	awaitBlocked(t, h, 1, hostPort, users.alice)

	h.CP().Start()
	h.Eventually("the restarted worker to pull policy and serve bob", func() bool {
		h.Clock().Advance(longPollBackoff)
		status, _ := h.ConnectReplyAt(0, hostPort, basicAuth("session", users.bob))
		return status == http.StatusOK
	})
	awaitBlocked(t, h, 0, hostPort, users.alice)
	awaitBlocked(t, h, 0, hostPort, users.aliceExpired)

	// Again with the control plane up: the block arrives with the boot pull.
	h.RestartWorker(1)
	awaitBlocked(t, h, 1, hostPort, users.alice)
	bobStillServed(t, h, users.bob)
	h.AssertCanaryNeverLeaked()
}

// blockListSurvivesCPOutage: with the control plane stopped both workers keep
// enforcing alice's block (fail-static) while bob is served; a block for carol
// written offline (the BlockStore, as the CLI does) while it is down reaches
// both workers once it returns, and alice stays blocked.
func blockListSurvivesCPOutage(t *testing.T, h *harness.H) {
	h.Upstream(blockHost)
	users := mintBlockUsers(h)
	carol := h.MintUserToken(fakes.Valid("carol", "carol@example.com"))
	hostPort := blockHost + ":443"

	h.BlockUser("alice", "")
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
		awaitAllowed(h, i, hostPort, carol)
	}

	h.CP().Stop()
	// Let each worker's long-poll fail and retry a few times on the fake clock.
	for n := 0; n < 3; n++ {
		h.Clock().Advance(longPollBackoff)
	}
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
	}
	bobStillServed(t, h, users.bob)

	store, closeStore := openBlockStore(t, h)
	if _, err := store.Add(context.Background(), controlplane.BlockEntry{Sub: "carol", Reason: blockReason}, "cli:harness"); err != nil {
		closeStore()
		t.Fatalf("offline BlockStore.Add: %v", err)
	}
	closeStore()
	// The control plane is still down: carol is not blocked yet.
	if status, _ := h.ConnectReplyAt(0, hostPort, basicAuth("session", carol)); status != http.StatusOK {
		t.Fatalf("carol's CONNECT during the outage = %d, want 200 (nothing can have told the worker)", status)
	}

	h.CP().Start()
	for i := 0; i < blockWorkers; i++ {
		h.Eventually("worker to enforce the offline block after the control plane returned", func() bool {
			h.Clock().Advance(longPollBackoff)
			status, _ := h.ConnectReplyAt(i, hostPort, basicAuth("session", carol))
			return status == http.StatusForbidden
		})
		awaitBlocked(t, h, i, hostPort, carol)
		awaitBlocked(t, h, i, hostPort, users.alice)
	}
	bobStillServed(t, h, users.bob)
	if logs := h.Logs(); strings.Contains(logs, blockReason) {
		t.Error("a log line carries a block reason")
	}
	h.AssertCanaryNeverLeaked()
}

// blockListUnblockRestores: deleting alice's entry through the admin API gives
// her access back on both workers, and the ETag the control plane serves equals
// the one it served before the block (an empty list leaves the wire unchanged).
func blockListUnblockRestores(t *testing.T, h *harness.H) {
	up := h.Upstream(blockHost)
	users := mintBlockUsers(h)
	hostPort := blockHost + ":443"
	before := servedETag(t, h)

	id := h.BlockUser("alice", "")
	h.Eventually("the served ETag to change with the block", func() bool { return servedETag(t, h) != before })
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
	}

	code, _, err := h.CP().Do(http.MethodDelete, blockedUsersAPIPath+"/"+id, h.ControlPlaneAdminToken(), nil)
	if err != nil || code != http.StatusNoContent {
		t.Fatalf("DELETE the block = %d, %v; want 204", code, err)
	}
	for i := 0; i < blockWorkers; i++ {
		awaitAllowed(h, i, hostPort, users.alice)
		awaitAllowed(h, i, hostPort, users.aliceExpired)
	}
	h.Eventually("the served ETag to return to its pre-block value", func() bool { return servedETag(t, h) == before })

	resp, err := h.AgentWithProxyTokenAt(0, users.alice).Get("https://" + blockHost + "/alice-back")
	if err != nil {
		t.Fatalf("alice's GET after the unblock: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(up.Requests()) == 0 {
		t.Fatalf("alice's GET after the unblock = %d with %d upstream requests, want 200 reaching the upstream", resp.StatusCode, len(up.Requests()))
	}
	h.AssertCanaryNeverLeaked()
}

// blockedUsersAPIPath is the block-list admin API collection.
const blockedUsersAPIPath = "/dashboard/api/blocked-users"

