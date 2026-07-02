package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"

	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook sink
)

// deliveredAlert is the subset of the webhook payload the sink asserts on.
type deliveredAlert struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	DedupKey string `json:"dedupKey"`
}

// postIngest posts an ingest envelope of events to the CP's /central/ingest.
func postIngest(t *testing.T, baseURL, proxyID string, events []analytics.Event) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/central/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(analytics.ProxyIDHeader, proxyID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ingest status = %d, want 204", resp.StatusCode)
	}
}

// TestIntegrations_EndToEnd is the money test: a blocked-egress event posted to
// /central/ingest must flow worker→ingest→bridge→bus→alertmanager→store→router→
// webhook and arrive at a real HTTP sink, while an allow-only event delivers
// NOTHING (bridge returns ok=false). Async delivery is synchronized on a channel
// the sink signals — no time.Sleep polling.
func TestIntegrations_EndToEnd(t *testing.T) {
	delivered := make(chan deliveredAlert, 4)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a deliveredAlert
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			t.Errorf("sink decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		delivered <- a
	}))
	defer sink.Close()

	srv := New(Config{
		PolicyPath:  writePolicyFile(t, "api.openai.com"),
		AlertDBPath: filepath.Join(t.TempDir(), "warden-alerts.db"),
		Integrations: []integration.InstanceConfig{{
			Type:   "webhook",
			Name:   "sec-alerts",
			Config: map[string]any{"url": sink.URL},
			Match:  []integration.MatchClause{{Category: "security"}},
		}},
	})
	if srv.integrations == nil {
		t.Fatal("integrations manager should be constructed when configured")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx) // starts the integrations pipeline (router + webhook instance)

	cp := httptest.NewServer(srv.Handler())
	defer cp.Close()

	// A benign allow: bridge returns ok=false ⇒ no finding ⇒ no delivery.
	postIngest(t, cp.URL, "worker-1", []analytics.Event{
		{Domain: "api.openai.com", Decision: "allow", Method: "GET"},
	})
	// A blocked egress: bridge ⇒ egress_blocked / security / medium ⇒ matches.
	postIngest(t, cp.URL, "worker-1", []analytics.Event{
		{Domain: "evil.example.com", Decision: "block", Method: "POST", Reason: "mcp_tool_denied"},
	})

	select {
	case a := <-delivered:
		if a.Category != "security" {
			t.Errorf("delivered category = %q, want security", a.Category)
		}
		if a.Severity != "medium" {
			t.Errorf("delivered severity = %q, want medium", a.Severity)
		}
		if a.DedupKey != "egress_blocked:evil.example.com" {
			t.Errorf("delivered dedupKey = %q", a.DedupKey)
		}
		if a.ID == "" {
			t.Error("delivered alert missing id (idempotency key)")
		}
		if a.Summary == "" {
			t.Error("delivered alert missing summary")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the blocked-egress alert to reach the sink")
	}

	// The allow event must NOT have produced a second delivery. Give the pipeline a
	// brief, bounded moment; the security alert already arrived, so any extra
	// delivery would be the (wrongly) bridged allow event.
	select {
	case a := <-delivered:
		t.Fatalf("unexpected extra delivery (allow event should not alert): %+v", a)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestPolicyWireExcludesIntegrations asserts the CP-local integrations block is
// never projected onto the worker-served /policy wire (which carries allow/deny
// + settings only). The block is CP-consumed; leaking it would ship notification
// credentials-by-reference to workers.
func TestPolicyWireExcludesIntegrations(t *testing.T) {
	// Serve a config that DOES carry an integrations block.
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: api.openai.com\n" +
		"integrations:\n  - type: webhook\n    name: sec\n    config:\n      url: \"${W}\"\n    match:\n      - category: security\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sanity: the config loads and carries the block (so the assertion is meaningful).
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	if pol, _ := prov.GetPolicy(); len(pol.Integrations) != 1 {
		t.Fatalf("test fixture should carry one integration, got %d", len(pol.Integrations))
	}

	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["integrations"]; ok {
		t.Fatal("served /policy wire LEAKED the integrations block across the boundary")
	}
	if _, ok := raw["allowlist"]; !ok {
		t.Error("served policy missing allowlist")
	}
}
