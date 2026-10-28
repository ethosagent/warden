package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// scopedAllow is the entry the dashboard editor saves for a scoped rule.
func scopedAllow() []config.AllowlistEntry {
	return []config.AllowlistEntry{
		{Domain: "base.example.com"},
		{Domain: "api.github.com", Groups: []string{"eng"}, Users: []string{"Alice@Corp.Example"}},
	}
}

// TestPolicyWrite_ScopedRoundTrip (W-P1-GPOL-08): a scoped allow entry and an
// MCP allowWhen with groups go through the CP writers and come back
// normalized (users lowercased, lists sorted) from the live policy the
// dashboard reads, and as a scoped wire entry from the served /policy.
func TestPolicyWrite_ScopedRoundTrip(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFileWithSettings(t, "base.example.com")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if err := srv.WritePolicy(context.Background(), config.Policy{Allowlist: scopedAllow()}, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("WritePolicy with groups/users: %v", err)
	}
	wire, _, _, _ := srv.policy.snapshot()
	got := wire.Allowlist[1]
	if !reflect.DeepEqual(got.Groups, []string{"eng"}) || !reflect.DeepEqual(got.Users, []string{"alice@corp.example"}) {
		t.Fatalf("live entry = groups %v users %v, want [eng] [alice@corp.example]", got.Groups, got.Users)
	}

	// The fail-closed wire still hides the scoped entry from old workers.
	raw, _ := fetchPolicyRaw(t, ts.URL)
	if !strings.Contains(string(raw["scopedAllowlist"]), "alice@corp.example") {
		t.Errorf("served scopedAllowlist = %s, want the normalized user", raw["scopedAllowlist"])
	}

	// MCP allowWhen with groups (and an unsorted list) round-trips sorted.
	settings := config.SettingsWire{MCP: &config.MCPSettings{
		Enabled: true, Mode: "enforce",
		Tools: &config.MCPToolsSettings{
			Allow: []string{"deploy"},
			Constraints: map[string]config.MCPToolConstraints{
				"deploy": {AllowWhen: &config.MCPToolCondition{Groups: []string{"sre", "eng"}}},
			},
		},
	}}
	if err := srv.WriteSettings(context.Background(), settings, dashboard.WriteMeta{}); err != nil {
		t.Fatalf("WriteSettings with allowWhen groups: %v", err)
	}
	wire, _, _, _ = srv.policy.snapshot()
	aw := wire.Settings.MCP.Tools.Constraints["deploy"].AllowWhen
	if aw == nil || !reflect.DeepEqual(aw.Groups, []string{"eng", "sre"}) {
		t.Fatalf("live allowWhen = %+v, want groups [eng sre]", aw)
	}
	// The policy edit left the settings alone and the settings edit left the entry alone.
	if len(wire.Allowlist) != 2 || wire.Allowlist[1].Groups[0] != "eng" {
		t.Errorf("allowlist after settings write = %+v", wire.Allowlist)
	}
}

// TestPolicyEdit_ScopedInvalid (W-P1-GPOL-08): an empty group value, an
// over-long list and a blank MCP user are refused with the loader's error, and
// the served policy and ETag stay as they were.
func TestPolicyEdit_ScopedInvalid(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFileWithSettings(t, "base.example.com")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	_, etag := fetchPolicyRaw(t, ts.URL)

	tooMany := make([]string, 300)
	for i := range tooMany {
		tooMany[i] = "g" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + json.Number(strings.Repeat("1", i/26+1)).String()
	}
	for name, allow := range map[string][]config.AllowlistEntry{
		"empty group": {{Domain: "api.github.com", Groups: []string{"eng", " "}}},
		"empty user":  {{Domain: "api.github.com", Users: []string{""}}},
		"over limit":  {{Domain: "api.github.com", Groups: tooMany}},
	} {
		err := srv.WritePolicy(context.Background(), config.Policy{Allowlist: allow}, dashboard.WriteMeta{})
		if err == nil || !strings.Contains(err.Error(), "groups") && !strings.Contains(err.Error(), "users") {
			t.Errorf("%s: err = %v, want a groups/users validation error", name, err)
		}
		if _, now := fetchPolicyRaw(t, ts.URL); now != etag {
			t.Errorf("%s: ETag changed to %s after a rejected edit, want %s", name, now, etag)
		}
	}

	bad := config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Tools: &config.MCPToolsSettings{
		Allow:       []string{"deploy"},
		Constraints: map[string]config.MCPToolConstraints{"deploy": {AllowWhen: &config.MCPToolCondition{Users: []string{""}}}},
	}}}
	if err := srv.WriteSettings(context.Background(), bad, dashboard.WriteMeta{}); err == nil {
		t.Error("empty MCP allowWhen user was accepted")
	}
	if _, now := fetchPolicyRaw(t, ts.URL); now != etag {
		t.Errorf("ETag changed to %s after a rejected settings edit, want %s", now, etag)
	}
}
