package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The agent kill switch (W-P2-AREG-05): a worker bound to a registered agent
// denies every CONNECT and request with 403 agent_disabled once an admin
// disables the agent, closes the sessions already open (one deny event each),
// and serves again after the agent is re-enabled. The disable arrives both ways
// an operator has: the dashboard API and the offline CLI. The wait bound is the
// long-poll cycle, plus the control plane's reload tick for the CLI path (a
// write made out of process).

const (
	bindAgentID  = "claude-code"
	bindHTTPHost = "bound.example.com"
	bindTunHost  = "bound-tunnel.example.com"
)

func agentBindingOpts() []harness.Option {
	return append(agentRegistryAPIOpts(),
		harness.WithWorkerAgent(bindAgentID),
		harness.Allow(bindHTTPHost, bindTunHost),
	)
}

func agentBindingKillSwitch(t *testing.T, h *harness.H) {
	up := h.Upstream(bindHTTPHost)
	_ = h.Upstream(bindTunHost)
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	do := func(method, target, body string, hdr ...string) (*http.Response, string) {
		t.Helper()
		hd := http.Header{"Content-Type": {"application/json"}}
		if method != http.MethodGet {
			hd.Set(controlplane.CSRFHeader, csrf)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			hd.Set(hdr[i], hdr[i+1])
		}
		var payload []byte
		if body != "" {
			payload = []byte(body)
		}
		resp, err := admin.DoBody(method, target, hd, payload)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, string(out)
	}

	// A bound worker with the agent not yet registered serves normally: an
	// agent with no registry entry is not disabled.
	if status, _ := h.ConnectReplyAt(0, bindHTTPHost+":443", ""); status != http.StatusOK {
		t.Fatalf("CONNECT before registration = %d, want 200", status)
	}

	create := `{"id":"` + bindAgentID + `","keys":[` + string(agentregtest.Ed25519JWK(t, "bind-key")) + `],"allowedGroups":["warden-agents"]}`
	if resp, body := do(http.MethodPost, agentsPathScn, create); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %s, want 201", resp.StatusCode, body)
	}

	// The heartbeat names the bound agent, its effective identity mode and the
	// agentreg/v1 capability. The harness drives heartbeats on its fake clock.
	var hb struct {
		AgentID, IdentityMode string
		Caps                  []string
	}
	h.Eventually("the worker's heartbeat to name its agent", func() bool {
		h.Clock().Advance(time.Second)
		resp, body := do(http.MethodGet, "/dashboard/api/workers", "")
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var ws []struct {
			AgentID      string   `json:"agentID"`
			IdentityMode string   `json:"identityMode"`
			Caps         []string `json:"caps"`
		}
		if json.Unmarshal([]byte(body), &ws) != nil {
			return false
		}
		for _, w := range ws {
			if w.AgentID == bindAgentID {
				hb.AgentID, hb.IdentityMode, hb.Caps = w.AgentID, w.IdentityMode, w.Caps
				return true
			}
		}
		return false
	})
	if hb.IdentityMode != config.IdentityModeOff || !contains(hb.Caps, config.CapAgentRegV1) {
		t.Fatalf("heartbeat = %+v, want identityMode %s and cap %s", hb, config.IdentityModeOff, config.CapAgentRegV1)
	}

	get := func(path string) {
		t.Helper()
		resp, err := h.Agent().Get("https://" + bindHTTPHost + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
	get("/before")

	// Sessions that must not outlive the disable: a keep-alive TLS session and a
	// raw tunnel, both anonymous.
	ka := openTLSSession(t, h, 0, bindHTTPHost, "", "/open")
	if got := ka.status(t); got != http.StatusOK {
		t.Fatalf("keep-alive request = %d, want 200", got)
	}
	tun, _, status := h.DialConnectAt(0, bindTunHost+":443", "")
	if status != http.StatusOK {
		t.Fatalf("tunnel CONNECT = %d, want 200", status)
	}
	_, _ = fmt.Fprint(tun, "G")
	tunnel := &openSession{name: bindTunHost, conn: tun, r: tun}

	// phase disables the agent with off, waits for the worker to refuse a new
	// CONNECT, then checks the refusal, the sessions and the recovery.
	rev := int64(1)
	phase := func(name string, off, on func()) {
		t.Helper()
		off()
		h.Eventually(name+": the worker to deny a new CONNECT", func() bool {
			status, _ := h.ConnectReplyAt(0, bindHTTPHost+":443", "")
			return status == http.StatusForbidden
		})
		status, body := h.ConnectReplyAt(0, bindHTTPHost+":443", "")
		if status != http.StatusForbidden || strings.TrimSpace(body) != `{"error":"agent_disabled"}` {
			t.Fatalf("%s: CONNECT = %d %q, want 403 {\"error\":\"agent_disabled\"}", name, status, body)
		}
		on()
		h.Eventually(name+": traffic to resume after the re-enable", func() bool {
			status, _ := h.ConnectReplyAt(0, bindHTTPHost+":443", "")
			return status == http.StatusOK
		})
		get("/after-" + name)
	}

	// 1. Disable and enable through the dashboard API.
	phase("api", func() {
		if resp, body := do(http.MethodPost, agentsPathScn+"/"+bindAgentID+"/disable", "", "If-Match", fmt.Sprintf(`"r%d"`, rev)); resp.StatusCode != http.StatusOK {
			t.Fatalf("disable = %d %s", resp.StatusCode, body)
		}
		rev++
		// The sessions opened above are closed by the disable.
		ka.expectClosed(t)
		tunnel.expectClosed(t)
	}, func() {
		if resp, body := do(http.MethodPost, agentsPathScn+"/"+bindAgentID+"/enable", "", "If-Match", fmt.Sprintf(`"r%d"`, rev)); resp.StatusCode != http.StatusOK {
			t.Fatalf("enable = %d %s", resp.StatusCode, body)
		}
		rev++
	})

	// 2. Disable and enable through the offline CLI, which writes the registry
	// out of process; the control plane picks it up on its reload tick.
	ctx := context.Background()
	stateDir := h.AdminAuditStateDir()
	phase("cli", func() {
		if _, err := controlplane.RunAgentSetStatus(ctx, stateDir, "", bindAgentID, agentreg.StatusDisabled, rev, nil); err != nil {
			t.Fatalf("cli disable: %v", err)
		}
		rev++
	}, func() {
		if _, err := controlplane.RunAgentSetStatus(ctx, stateDir, "", bindAgentID, agentreg.StatusActive, rev, nil); err != nil {
			t.Fatalf("cli enable: %v", err)
		}
		rev++
	})

	// What the audit trail shows: deny events with the declared reason for the
	// refused CONNECTs and one for each of the two closed sessions, and the
	// upstream saw only the requests made while the agent was enabled.
	var denies []analytics.Event
	for _, e := range h.Events() {
		if e.Reason == string(denyreason.AgentDisabled) && e.Decision == "deny" {
			denies = append(denies, e)
		}
	}
	closed := 0
	for _, e := range denies {
		if e.Domain == bindTunHost || (e.Domain == bindHTTPHost && e.Method == "" && e.Protocol != "tcp") {
			closed++
		}
	}
	if len(denies) < 4 {
		t.Errorf("agent_disabled deny events = %d, want at least 4 (two refused CONNECTs, two closed sessions): %+v", len(denies), denies)
	}
	if closed < 1 {
		t.Errorf("no agent_disabled deny event for a closed session: %+v", denies)
	}
	for _, r := range up.Requests() {
		if !strings.HasPrefix(r.Path, "/before") && !strings.HasPrefix(r.Path, "/open") && !strings.HasPrefix(r.Path, "/after-") {
			t.Errorf("the upstream saw %s while the agent was disabled", r.Path)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
