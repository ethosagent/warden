package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
)

func testIdentity() *config.IdentitySettings {
	return &config.IdentitySettings{
		DefaultMode: "attribute", Issuer: "http://localhost:5556/dex", Audience: "warden",
		AllowedAZP: []string{"agent-harness", "warden-cli"}, GroupsClaim: "groups", JWKSURL: "http://dex:5556/keys",
		ClockSkewSeconds: 30, MaxTokenTTLSeconds: 600, InternalIssuerURL: "http://dex:5556",
	}
}

// identityNode returns the raw bytes of the on-disk `identity:` node.
func identityNode(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]yaml.Node{}
	if err := yaml.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	n, ok := root["identity"]
	if !ok {
		return ""
	}
	out, err := yaml.Marshal(&n)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestWriteSettingsIdentity(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	in := config.SettingsWire{
		Identity: testIdentity(),
		Agents:   []config.AgentSettings{{ID: "agent-a", Policy: "p", Identity: "attribute"}, {ID: "agent-b", Identity: "off"}},
	}
	if err := srv.writeSettings(in); err != nil {
		t.Fatalf("WriteSettings: %v", err)
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Identity, *in.Identity) {
		t.Errorf("identity not round-tripped: %+v", p.Identity)
	}
	if len(p.Agents) != 2 || p.Agents[0].Identity != "attribute" || p.Agents[1].Identity != "off" {
		t.Errorf("per-agent identity not round-tripped: %+v", p.Agents)
	}

	// A nil identity removes the block.
	if err := srv.writeSettings(config.SettingsWire{}); err != nil {
		t.Fatalf("WriteSettings(nil identity): %v", err)
	}
	if got := identityNode(t, path); got != "" {
		t.Errorf("identity block should be removed, got:\n%s", got)
	}
}

func TestWritersPreserveIdentityBlock(t *testing.T) {
	cfg := detectionEditorConfig(t)
	path := cfg.PolicyPath
	srv := New(cfg)
	if err := srv.writeSettings(config.SettingsWire{Identity: testIdentity()}); err != nil {
		t.Fatal(err)
	}
	before := identityNode(t, path)
	if before == "" {
		t.Fatal("identity block missing after WriteSettings")
	}

	writers := map[string]func() error{
		"WritePolicy": func() error {
			prov, err := config.NewLocalYAMLProvider(path)
			if err != nil {
				return err
			}
			p, err := prov.GetPolicy()
			if err != nil {
				return err
			}
			return srv.writePolicy(p)
		},
		"WriteIntegrations": func() error {
			return srv.WriteIntegrations([]config.IntegrationInstance{{
				Type: "webhook", Name: "x", Config: map[string]any{"url": "${WEBHOOK_URL}"},
				Match: []config.IntegrationMatch{{Category: "security"}},
			}})
		},
		"WriteDetection": func() error { return srv.WriteDetection(config.DetectionConfig{Enabled: false}) },
	}
	for name, w := range writers {
		if err := w(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if after := identityNode(t, path); after != before {
			t.Errorf("%s changed the identity block:\n%s\nvs\n%s", name, before, after)
		}
	}
}

func TestPolicyServedIncludesIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: api.openai.com\n" +
		"identity:\n  defaultMode: attribute\n  issuer: https://idp.example.com\n  audience: warden\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	raw, etagA := fetchPolicyRaw(t, ts.URL)
	var settings config.SettingsWire
	if err := json.Unmarshal(raw["settings"], &settings); err != nil {
		t.Fatalf("settings missing or invalid: %v", err)
	}
	if settings.Identity == nil || settings.Identity.Issuer != "https://idp.example.com" || settings.Identity.DefaultMode != "attribute" {
		t.Fatalf("served settings lack identity: %+v", settings.Identity)
	}

	body = "policy:\n  allowlist:\n    - domain: api.openai.com\n" +
		"identity:\n  defaultMode: attribute\n  issuer: https://other.example.com\n  audience: warden\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.refresh()
	_, etagB := fetchPolicyRaw(t, ts.URL)
	if etagA == etagB {
		t.Fatal("ETag did not change when the identity block changed")
	}
}

func TestWriteSettingsIdentityRejectsInvalid(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = srv.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{
		DefaultMode: "require", Issuer: "https://idp.example.com", Audience: "warden",
	}})
	if err == nil || !strings.Contains(err.Error(), "Phase 2") {
		t.Fatalf("want a Phase 2 rejection, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("a rejected write must leave the file unchanged")
	}
}
