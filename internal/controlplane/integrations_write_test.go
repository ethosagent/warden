package controlplane

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"

	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook sink
)

// TestWriteIntegrations_RoundTripPreservesBlocks asserts WriteIntegrations
// replaces ONLY the integrations block, leaving every other block intact, and
// that an EMPTY list DELETES the key rather than writing `integrations: []`.
func TestWriteIntegrations_RoundTripPreservesBlocks(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	err := srv.WriteIntegrations([]config.IntegrationInstance{{
		Type:   "webhook",
		Name:   "sec-alerts",
		Config: map[string]any{"url": "${WEBHOOK_URL}"},
		Match:  []config.IntegrationMatch{{Category: "security"}},
	}})
	if err != nil {
		t.Fatalf("WriteIntegrations: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload after write: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Integrations) != 1 || p.Integrations[0].Name != "sec-alerts" {
		t.Fatalf("integrations block not persisted: %+v", p.Integrations)
	}
	if p.Integrations[0].Config["url"] != "${WEBHOOK_URL}" {
		t.Errorf("secret ref not preserved verbatim: %+v", p.Integrations[0].Config)
	}
	// Other blocks survive byte-for-byte (semantically): mcp/judge/agents/allowlist.
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Errorf("mcp block clobbered: %+v", p.MCP)
	}
	if !p.Judge.Enabled || p.Judge.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("judge block clobbered: %+v", p.Judge)
	}
	if len(p.Agents) != 1 || p.Agents[0].ID != "agent-1" {
		t.Errorf("agents block clobbered: %+v", p.Agents)
	}
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("allowlist clobbered: %+v", p.Allowlist)
	}

	// Empty list DELETES the key; other blocks remain.
	if err := srv.WriteIntegrations(nil); err != nil {
		t.Fatalf("WriteIntegrations(nil): %v", err)
	}
	prov2, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload after delete: %v", err)
	}
	p2, err := prov2.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Integrations) != 0 {
		t.Errorf("empty write should delete integrations, got %+v", p2.Integrations)
	}
	if !p2.MCP.Enabled {
		t.Error("mcp block lost when integrations key was deleted")
	}
}

// TestReloadRepointsAlertsSource asserts a live reload swaps the manager pointer
// so the alerts + status read paths (which read s.currentManager()) observe the
// NEW manager, and that the store is reused (never reopened) — the reload
// succeeds without a DB error and the new instance reports its honest status.
func TestReloadRepointsAlertsSource(t *testing.T) {
	srv := New(Config{
		PolicyPath:  writePolicyFile(t, "api.openai.com"),
		AlertDBPath: filepath.Join(t.TempDir(), "warden-alerts.db"),
		Integrations: []integration.InstanceConfig{{
			Type: "webhook", Name: "one", Config: map[string]any{"url": "https://a.example/hook"},
			Match: []integration.MatchClause{{Category: "security"}},
		}},
	})
	if srv.integrationsStore == nil {
		t.Fatal("alert store should be built when AlertDBPath is set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx)

	m1 := srv.currentManager()
	if m1 == nil {
		t.Fatal("manager should exist after Start")
	}
	// The alerts closure the dashboard uses reads currentManager().ListAlerts; it
	// must not panic on the shared store (an empty store returns nil or []).
	_ = m1.ListAlerts(10)

	// Reload with a DIFFERENT instance set over the SAME store.
	err := srv.reloadIntegrations([]integration.InstanceConfig{
		{Type: "webhook", Name: "two", Config: map[string]any{"url": "https://b.example/hook"}, Match: []integration.MatchClause{{Category: "security"}}},
		{Type: "slack", Name: "slk", Config: map[string]any{"channel": "#x", "botToken": "${SLACK_BOT_TOKEN}"}},
	})
	if err != nil {
		t.Fatalf("reloadIntegrations: %v", err)
	}

	m2 := srv.currentManager()
	if m2 == m1 {
		t.Fatal("reload must swap the manager pointer (alerts/status would otherwise be stale)")
	}
	// The reloaded manager reads the SAME (still-open) store: a connected webhook
	// below proves the router started over it without the DB being closed.
	_ = m2.ListAlerts(10)

	// Honest per-instance status: webhook connected, slack unavailable (no runtime).
	statuses := srv.integrationStatuses()
	byName := map[string]string{}
	for _, s := range statuses {
		byName[s.Name] = s.Status
	}
	if byName["two"] != integration.StatusConnected {
		t.Errorf("webhook 'two' status = %q, want connected", byName["two"])
	}
	if byName["slk"] != integration.StatusUnavailable {
		t.Errorf("slack 'slk' status = %q, want unavailable", byName["slk"])
	}
	if _, ok := byName["one"]; ok {
		t.Error("old instance 'one' should be gone after reload")
	}
}
