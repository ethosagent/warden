package scenarios

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// Registered agents in the policy wire (W-P2-AREG-04). A registry write made
// out of process (the offline CLI) must show in GET /policy within one reload
// tick (3s), with a new ETag, and the wire must carry only id, status and key
// thumbprints: no JWK body, owner or group. The control plane's own registry
// Watch runs on the harness fake clock, which this scenario never advances, so
// the only thing that can surface the write is the reload tick re-checking the
// registry. In-process only (CP state dir).

// The reload tick is a real 3s ticker, so the waits use the standard
// h.Eventually budget. The "within one reload interval" bound is proven
// deterministically by controlplane's
// TestPolicyWireRegisteredAgents_ReloadSeesOtherHandleWithoutWatch.

func agentRegistryPolicyWireOpts() []harness.Option {
	return []harness.Option{harness.WithAdminAudit()}
}

func agentRegistryPolicyWire(t *testing.T, h *harness.H) {
	ctx := context.Background()
	stateDir := h.AdminAuditStateDir()

	// The empty registry leaves the wire without the key at all.
	body, _ := fetchPolicy(t, h)
	if strings.Contains(body, "registeredAgents") {
		t.Fatalf("an empty registry changed the /policy bytes: %s", body)
	}

	jwk := agentregtest.Ed25519JWK(t, "policy-wire")
	j, err := keys.ParseJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := keys.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.RunAgentRegister(ctx, stateDir, "", agentreg.Agent{
		ID: "claude-code", OwnerEmail: "owner@corp.example", DisplayName: "Claude Code",
		Keys: []agentreg.Key{{JWK: jwk}}, AllowedGroups: []string{"warden-agents"},
	}, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	first := awaitAgent(t, h, "the registered agent reaches /policy", func(a config.RegisteredAgent) bool {
		return a.Status == config.RegisteredAgentActive
	})
	if len(first.agent.JKT) != 1 || first.agent.JKT[0] != jkt {
		t.Fatalf("served thumbprints = %v, want [%s]", first.agent.JKT, jkt)
	}
	for _, leak := range []string{"owner@corp.example", "warden-agents", "Claude Code", j.X, `"jwk"`, `"owner`} {
		if strings.Contains(first.body, leak) {
			t.Errorf("/policy carries %q: %s", leak, first.body)
		}
	}

	// CLI disable: visible within one reload interval, with a new ETag.
	start := time.Now()
	if _, err := controlplane.RunAgentSetStatus(ctx, stateDir, "", "claude-code", agentreg.StatusDisabled, 1, nil); err != nil {
		t.Fatalf("disable: %v", err)
	}
	disabled := awaitAgent(t, h, "a CLI disable reaches /policy on a reload tick", func(a config.RegisteredAgent) bool {
		return a.Status == config.RegisteredAgentDisabled
	})
	t.Logf("CLI disable served after %s", time.Since(start))
	if disabled.etag == first.etag {
		t.Errorf("the ETag did not change on disable (%s)", disabled.etag)
	}

	// Re-enable restores the entry and moves the ETag again.
	if _, err := controlplane.RunAgentSetStatus(ctx, stateDir, "", "claude-code", agentreg.StatusActive, 2, nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	enabled := awaitAgent(t, h, "a CLI enable reaches /policy", func(a config.RegisteredAgent) bool {
		return a.Status == config.RegisteredAgentActive
	})
	if enabled.etag == disabled.etag {
		t.Errorf("the ETag did not change on enable (%s)", enabled.etag)
	}
}

type policySeen struct {
	agent config.RegisteredAgent
	etag  string
	body  string
}

func fetchPolicy(t *testing.T, h *harness.H) (string, string) {
	t.Helper()
	r, err := h.CP().Send(http.MethodGet, "/policy", nil, nil)
	if err != nil || r.Status != http.StatusOK {
		t.Fatalf("GET /policy = %d, %v", r.Status, err)
	}
	return string(r.Body), r.Header.Get("ETag")
}

func awaitAgent(t *testing.T, h *harness.H, desc string, ok func(config.RegisteredAgent) bool) policySeen {
	t.Helper()
	var seen policySeen
	h.Eventually(desc, func() bool {
		body, etag := fetchPolicy(t, h)
		var p struct {
			RegisteredAgents []config.RegisteredAgent `json:"registeredAgents"`
		}
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatalf("decode /policy: %v", err)
		}
		for _, a := range p.RegisteredAgents {
			if a.ID == "claude-code" && ok(a) {
				seen = policySeen{agent: a, etag: etag, body: body}
				return true
			}
		}
		return false
	})
	return seen
}
