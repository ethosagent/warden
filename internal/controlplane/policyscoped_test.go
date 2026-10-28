package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func scopedEntry(domain string, groups ...string) config.AllowlistEntry {
	return config.AllowlistEntry{Domain: domain, Groups: groups}
}

func scopedMCPWire(aw *config.MCPToolCondition) policyWire {
	return policyWire{
		Allowlist: []config.AllowlistEntry{{Domain: "a.example.com"}},
		Settings: &config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Tools: &config.MCPToolsSettings{
			Allow:       []string{"deploy", "read"},
			Constraints: map[string]config.MCPToolConstraints{"deploy": {AllowWhen: aw}, "read": {AllowWhen: &config.MCPToolCondition{AgentID: "ci"}}},
		}}},
	}
}

// TestPolicyWire_UnscopedUnchanged: an unscoped policy is served byte-for-byte
// as before the projection existed (golden body and ETag captured on main).
func TestPolicyWire_UnscopedUnchanged(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantETag, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag"))
	if err != nil {
		t.Fatal(err)
	}
	ps := newPolicyServer(filepath.Join("testdata", "policy_overlay_none.yaml"), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	ps.Refresh()
	body, etag := servePolicyOnce(t, ps)
	if string(body) != string(wantBody) {
		t.Errorf("body differs from golden\n got: %s\nwant: %s", body, wantBody)
	}
	if strings.Trim(etag, `"`) != strings.Trim(strings.TrimSpace(string(wantETag)), `"`) {
		t.Errorf("ETag = %s, want golden %s", etag, wantETag)
	}
	// An unscoped condition adds no wire field either.
	w := scopedMCPWire(&config.MCPToolCondition{AgentID: "ci"})
	before, _ := json.Marshal(w)
	after, _ := json.Marshal(projectScoped(w))
	if string(before) != string(after) || strings.Contains(string(after), "Scoped") {
		t.Errorf("unscoped wire changed:\n%s\n%s", before, after)
	}
}

func TestProjectScoped_Allow(t *testing.T) {
	in := policyWire{Allowlist: []config.AllowlistEntry{
		{Domain: "a.example.com"}, scopedEntry("b.example.com", "eng"), {Domain: "c.example.com"},
		{Domain: "d.example.com", Users: []string{"bob@example.com"}},
	}}
	out := projectScoped(in)
	if len(out.Allowlist) != 2 || out.Allowlist[0].Domain != "a.example.com" || out.Allowlist[1].Domain != "c.example.com" {
		t.Fatalf("allowlist = %+v", out.Allowlist)
	}
	if len(out.ScopedAllowlist) != 2 || out.ScopedAllowlist[0].Domain != "b.example.com" || out.ScopedAllowlist[1].Domain != "d.example.com" {
		t.Fatalf("scopedAllowlist = %+v", out.ScopedAllowlist)
	}
	if !reflect.DeepEqual(out.ScopedAllowPos, []int{1, 3}) {
		t.Fatalf("pos = %v", out.ScopedAllowPos)
	}
	if len(in.Allowlist) != 4 {
		t.Fatal("projectScoped modified its input")
	}
	// Idempotent: the ETag of a doc equals the ETag of its served projection.
	if !reflect.DeepEqual(projectScoped(out), out) || etagFor(in) != etagFor(out) {
		t.Fatal("projection is not idempotent")
	}
	if etagFor(in) == etagFor(policyWire{Allowlist: []config.AllowlistEntry{{Domain: "a.example.com"}, {Domain: "c.example.com"}}}) {
		t.Fatal("the ETag must cover scoped rules")
	}
}

func TestProjectScoped_MCP(t *testing.T) {
	real := &config.MCPToolCondition{TimeWindow: "09-17", Groups: []string{"eng"}}
	in := scopedMCPWire(real)
	out := projectScoped(in)
	got := out.Settings.MCP.Tools.Constraints["deploy"]
	if got.AllowWhen == nil || got.AllowWhen.AgentID != config.ReservedScopedAgentID || len(got.AllowWhen.Groups) != 0 || got.AllowWhen.TimeWindow != "" {
		t.Fatalf("AllowWhen = %+v, want the bare sentinel", got.AllowWhen)
	}
	if !reflect.DeepEqual(got.AllowWhenScoped, real) {
		t.Fatalf("AllowWhenScoped = %+v", got.AllowWhenScoped)
	}
	if c := out.Settings.MCP.Tools.Constraints["read"]; c.AllowWhen.AgentID != "ci" || c.AllowWhenScoped != nil {
		t.Fatalf("unscoped tool changed: %+v", c)
	}
	if in.Settings.MCP.Tools.Constraints["deploy"].AllowWhen != real || real.AgentID != "" {
		t.Fatal("projectScoped modified its input")
	}
	if !reflect.DeepEqual(projectScoped(out), out) {
		t.Fatal("projection is not idempotent")
	}
}

// Served end to end: one body per ETag hides scoped rules from a lenient
// decode, and a new worker's pull restores them in order.
func TestServePolicy_ScopedRoundTrip(t *testing.T) {
	ps := newPolicyServer(overlayFixture(t), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	if err := ps.addOverlay(wireOverlay{name: "scoped", apply: func(_ context.Context, w *policyWire) (string, error) {
		w.Allowlist = append(w.Allowlist[:1], append([]config.AllowlistEntry{scopedEntry("scoped.example.com", "eng")}, w.Allowlist[1:]...)...)
		w.Settings.MCP.Tools = &config.MCPToolsSettings{Allow: []string{"deploy"}, Constraints: map[string]config.MCPToolConstraints{
			"deploy": {AllowWhen: &config.MCPToolCondition{Groups: []string{"eng"}}},
		}}
		return "s", nil
	}}); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()
	body, _ := servePolicyOnce(t, ps)

	for _, d := range allowDomains(t, body) {
		if d == "scoped.example.com" {
			t.Fatal("scoped host is in the plain allowlist")
		}
	}
	if !strings.Contains(string(body), config.ReservedScopedAgentID) {
		t.Fatal("body lacks the MCP sentinel")
	}
	// The watch (dashboard, audit, diff) keeps the real rules.
	if w, _, _, _ := ps.snapshot(); len(w.Allowlist) != 3 || w.Allowlist[1].Domain != "scoped.example.com" {
		t.Fatalf("snapshot allowlist = %+v", w.Allowlist)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(ps.ServePolicy))
	defer ts.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	rp, err := config.NewRemoteProvider(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatal(err)
	}
	if err := rp.Pull(); err != nil {
		t.Fatalf("pull: %v", err)
	}
	pol, err := rp.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Allowlist) != 3 || pol.Allowlist[1].Domain != "scoped.example.com" || len(pol.Allowlist[1].Groups) != 1 {
		t.Fatalf("worker allowlist = %+v", pol.Allowlist)
	}
	aw := rp.Settings().MCP.Tools.Constraints["deploy"].AllowWhen
	if aw == nil || aw.AgentID != "" || len(aw.Groups) != 1 {
		t.Fatalf("worker AllowWhen = %+v", aw)
	}
}
