package scenarios

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/harness"
)

// identityRequireRolloutGuard (W-P2-WBND-07): the control plane refuses to
// serve require for an agent while a connected worker bound to it lacks
// identity/require-v1 (409 workers_lack_capability naming the worker), writes
// nothing, and lets an admin's force=true through, after which the capable
// worker enforces require.
func identityRequireRolloutGuard(t *testing.T, h *harness.H) {
	bootSetup(t, h)
	cp := h.CP()
	// An old worker bound to the agent: its heartbeat has caps but not identity/require-v1.
	hb := `{"policyETag":"x","caps":["blocklist/v1","agentreg/v1"],"agentID":"` + bootAgentID + `"}`
	if r := cp.DoWorker(http.MethodPost, "/control/heartbeat", cp.Token(), "old-worker", hb); r.Status != http.StatusNoContent {
		t.Fatalf("old worker heartbeat = %d", r.Status)
	}

	admin := h.ControlPlaneAdminToken()
	got, err := cp.SendBearer(admin, http.MethodGet, "/dashboard/api/settings", nil, nil)
	if err != nil || got.Status != http.StatusOK {
		t.Fatalf("read settings: %d %s %v", got.Status, got.Body, err)
	}
	var cur struct {
		Settings *config.SettingsWire `json:"settings"`
	}
	if err := json.Unmarshal(got.Body, &cur); err != nil || cur.Settings == nil {
		t.Fatalf("decode settings: %v", err)
	}
	cur.Settings.Agents = append(cur.Settings.Agents, config.AgentSettings{ID: bootAgentID, Identity: config.IdentityModeRequire})
	body, err := json.Marshal(cur.Settings)
	if err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{}
	if v := got.Header.Get(dashboard.PolicyVersionHeader); v != "" {
		hdr.Set("If-Match", `"v`+v+`"`)
	}

	refused, err := cp.SendBearer(admin, http.MethodPost, "/dashboard/api/settings", hdr, body)
	var reply struct {
		Error   string   `json:"error"`
		Workers []string `json:"workers"`
	}
	_ = json.Unmarshal(refused.Body, &reply)
	if err != nil || refused.Status != http.StatusConflict || reply.Error != "workers_lack_capability" || !slices.Equal(reply.Workers, []string{"old-worker"}) {
		t.Fatalf("require with an old worker = %d %s %v, want 409 workers_lack_capability [old-worker]", refused.Status, refused.Body, err)
	}
	if r := requireConnect(t, h, ""); r.status == http.StatusProxyAuthRequired {
		t.Fatal("the refused save still put the worker in require mode")
	}

	forced, err := cp.SendBearer(admin, http.MethodPost, "/dashboard/api/settings?force=true", hdr, body)
	if err != nil || forced.Status != http.StatusOK {
		t.Fatalf("forced save = %d %s %v, want 200", forced.Status, forced.Body, err)
	}
	h.Eventually("the capable worker to apply require mode", func() bool {
		return requireConnect(t, h, "").status == http.StatusProxyAuthRequired
	})
}
