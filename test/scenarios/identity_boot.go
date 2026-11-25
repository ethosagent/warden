package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/harness"
)

// A managed worker enforces the identity settings the control plane distributes
// from its first request after boot, not from the first policy change after it.
// The worker's own config file still says attribute; the control plane has since
// moved the fleet to challenge mode (through the identity block, or through this
// agent's entry in the agents block). After a restart, with no policy change,
// a CONNECT with no credential must get the 407 at once, and the Warden token
// keys from the boot bundle must already verify the agent's token.
//
// Before the fix the boot path applied only the local identity block and the
// distributed one waited for a changed long-poll: the restarted worker answered
// 200 to an anonymous CONNECT until some unrelated policy edit.

const bootAgentID = "boot-agent"

func identityBootOpts() []harness.Option {
	return append(wardenTokenVerifyOpts(), harness.WithWorkerAgent(bootAgentID))
}

// editSettings reads the settings the control plane distributes, edits them
// and saves them back with the control plane admin token.
func editSettings(t *testing.T, h *harness.H, edit func(*config.SettingsWire)) {
	t.Helper()
	admin := h.ControlPlaneAdminToken()
	got, err := h.CP().SendBearer(admin, http.MethodGet, "/dashboard/api/settings", nil, nil)
	if err != nil || got.Status != http.StatusOK {
		t.Fatalf("read the distributed settings: %d %s %v", got.Status, got.Body, err)
	}
	var cur struct {
		Settings *config.SettingsWire `json:"settings"`
	}
	if err := json.Unmarshal(got.Body, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Settings == nil || cur.Settings.Identity == nil {
		t.Fatal("the control plane distributes no identity block")
	}
	edit(cur.Settings)
	body, err := json.Marshal(cur.Settings)
	if err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{}
	if v := got.Header.Get(dashboard.PolicyVersionHeader); v != "" {
		hdr.Set("If-Match", `"v`+v+`"`)
	}
	resp, err := h.CP().SendBearer(admin, http.MethodPost, "/dashboard/api/settings", hdr, body)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("save the settings: %d %s %v", resp.Status, resp.Body, err)
	}
}

// bootSetup registers the worker's agent, mints its Warden token and waits
// until the worker verifies it, so the bundle the worker boots from later
// carries the key.
func bootSetup(t *testing.T, h *harness.H) string {
	t.Helper()
	h.Upstream(identityHost)
	agent := h.RegisterTokenAgent(bootAgentID, []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	good := decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil))).AccessToken
	p := &wardenProber{t: t, h: h}
	h.Eventually("the worker verifies the agent's Warden token", func() bool {
		return p.probe(good).IdentityStatus == "valid"
	})
	return good
}

// enterChallenge applies edit on the control plane and waits until the running
// worker challenges an anonymous CONNECT, so the control plane serves the edit.
func enterChallenge(t *testing.T, h *harness.H, edit func(*config.SettingsWire)) {
	t.Helper()
	if status, _ := h.ConnectReplyAt(0, challengeTarget, ""); status != http.StatusOK {
		t.Fatalf("attribute mode: anonymous CONNECT = %d, want 200", status)
	}
	editSettings(t, h, edit)
	h.Eventually("the running worker to apply challenge mode", func() bool {
		status, _ := h.ConnectReplyAt(0, challengeTarget, "")
		return status == http.StatusProxyAuthRequired
	})
}

// assertBootChallenge restarts the worker and checks its very first answers:
// no Eventually, so a worker that serves under its local config for even one
// request fails.
func assertBootChallenge(t *testing.T, h *harness.H, good string) {
	t.Helper()
	h.RestartWorker(0)
	if status, body := h.ConnectReplyAt(0, challengeTarget, ""); status != http.StatusProxyAuthRequired {
		t.Fatalf("first anonymous CONNECT after restart = %d (%q), want 407: the worker serves under its local identity config", status, body)
	}
	if status, _ := h.ConnectReplyAt(0, challengeTarget, basicAuth("session", good)); status != http.StatusOK {
		t.Fatalf("first CONNECT with the agent's Warden token after restart = %d, want 200: the boot bundle's token keys are not in force", status)
	}
	path := "/after-restart"
	req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.AgentWithProxyTokenAt(0, good).Do(req)
	if err != nil {
		t.Fatalf("GET with the Warden token after restart: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with the Warden token after restart = %d, want 200", resp.StatusCode)
	}
	e := only(t, h.Events(), "https://"+identityHost+path)
	if e.IdentityStatus != "valid" || e.UserSub != "user-1" {
		t.Errorf("after restart: identity %s/%s sub %q, want valid user-1", e.IdentityStatus, e.IdentityReason, e.UserSub)
	}
	requireNoCredentialsInLogs(t, h, good)
}

// identityBootDistributedMode: the identity block's defaultMode moved to
// challenge on the control plane.
func identityBootDistributedMode(t *testing.T, h *harness.H) {
	good := bootSetup(t, h)
	enterChallenge(t, h, func(s *config.SettingsWire) { s.Identity.DefaultMode = config.IdentityModeChallenge })
	assertBootChallenge(t, h, good)
}

// identityBootDistributedAgent: the defaultMode stays attribute; this agent's
// entry in the distributed agents block says challenge.
func identityBootDistributedAgent(t *testing.T, h *harness.H) {
	good := bootSetup(t, h)
	enterChallenge(t, h, func(s *config.SettingsWire) {
		s.Agents = append(s.Agents, config.AgentSettings{ID: bootAgentID, Identity: config.IdentityModeChallenge})
	})
	assertBootChallenge(t, h, good)
}
