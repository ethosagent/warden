package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The Agents tab (W-P2-AREG-03): the console learns from /dashboard/api/setup
// that the registry exists, serves the tab, an agent registered through the
// API shows up in the list with an escaped-by-the-UI display name and the
// worker whose heartbeat names it, and a malformed heartbeat agentID or mode
// is dropped. The tab's own rendering is pinned by the dashboard's index tests.

func agentRegistryConsoleOpts() []harness.Option { return agentRegistryAPIOpts() }

func agentRegistryConsole(t *testing.T, h *harness.H) {
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	get := func(target string) string {
		t.Helper()
		resp, err := admin.Do(http.MethodGet, target, http.Header{})
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d %s", target, resp.StatusCode, b)
		}
		return string(b)
	}

	var setup struct {
		AgentRegistry bool `json:"agentRegistry"`
	}
	if err := json.Unmarshal([]byte(get("/dashboard/api/setup")), &setup); err != nil || !setup.AgentRegistry {
		t.Fatalf("setup agentRegistry = %v, %v; want true on a control plane with a state dir", setup.AgentRegistry, err)
	}
	if page := get("/dashboard/"); !strings.Contains(page, `id="page-agents"`) || !strings.Contains(page, `id="agentsNav"`) {
		t.Fatal("the console does not serve the Agents tab")
	}

	// Register an agent whose display name is markup: the API stores it as text.
	const name = `<img src=x onerror=alert(1)>`
	nameJSON, _ := json.Marshal(name)
	body := `{"id":"a1","displayName":` + string(nameJSON) + `,"keys":[` + string(agentregtest.Ed25519JWK(t, "scn-console")) + `],"allowedGroups":["g1"]}`
	resp, err := admin.DoBody(http.MethodPost, agentsPathScn, http.Header{controlplane.CSRFHeader: {csrf}, "Content-Type": {"application/json"}}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d, want 201", resp.StatusCode)
	}
	var list struct {
		Agents []struct {
			ID            string   `json:"id"`
			DisplayName   string   `json:"displayName"`
			AllowedGroups []string `json:"allowedGroups"`
			Keys          []struct {
				KID string `json:"kid"`
			} `json:"keys"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(get(agentsPathScn)), &list); err != nil || len(list.Agents) != 1 ||
		list.Agents[0].ID != "a1" || list.Agents[0].DisplayName != name ||
		len(list.Agents[0].AllowedGroups) != 1 || list.Agents[0].AllowedGroups[0] != "g1" ||
		len(list.Agents[0].Keys) != 1 || list.Agents[0].Keys[0].KID == "" {
		t.Fatalf("list = %+v, %v", list, err)
	}

	// Worker heartbeats: the first names the agent, the second sends garbage.
	cp := h.CP()
	for _, c := range []struct{ worker, body string }{
		{"w-bound", `{"policyETag":"x","caps":["agentreg/v1"],"agentID":"a1","identityMode":"attribute"}`},
		{"w-bad", `{"policyETag":"x","agentID":"not valid!","identityMode":"<b>"}`},
	} {
		if r := cp.DoWorker(http.MethodPost, "/control/heartbeat", cp.Token(), c.worker, c.body); r.Status != http.StatusNoContent {
			t.Fatalf("heartbeat %s = %d", c.worker, r.Status)
		}
	}
	var workers []struct {
		ProxyID      string `json:"proxyID"`
		AgentID      string `json:"agentID"`
		IdentityMode string `json:"identityMode"`
	}
	if err := json.Unmarshal([]byte(get("/dashboard/api/workers")), &workers); err != nil {
		t.Fatal(err)
	}
	got := map[string][2]string{}
	for _, w := range workers {
		got[w.ProxyID] = [2]string{w.AgentID, w.IdentityMode}
	}
	if got["w-bound"] != [2]string{"a1", "attribute"} || got["w-bad"] != [2]string{"", ""} {
		t.Fatalf("worker bindings = %v, want w-bound=a1/attribute and w-bad dropped", got)
	}
}
