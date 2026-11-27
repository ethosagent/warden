package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
)

const consentBlockYAML = `consent:
  enabled: true
  oidc:
    issuer: https://idp.example.com
    clientSecretEnv: WARDEN_PORTAL_DEX_CLIENT_SECRET
    redirectURL: https://warden.example.com/portal/callback
  allowedGroups: [staff]
`

func fullConsent() config.ConsentConfig {
	return config.ConsentConfig{
		Enabled: true,
		OIDC: config.ConsentOIDC{
			Issuer: "https://idp.example.com", ClientID: "warden-portal", ClientSecretEnv: "WARDEN_PORTAL_DEX_CLIENT_SECRET",
			RedirectURL: "https://warden.example.com/portal/callback", InternalIssuerURL: "http://dex:5556",
		},
		AllowedGroups: []string{"staff"},
		Session:       config.ConsentSession{Idle: 30 * time.Minute, Absolute: 8 * time.Hour},
		IdPLink:       config.ConsentIdPLink{Enabled: true, RefreshLifetime: 720 * time.Hour},
	}
}

func TestConsentNotOnWire(t *testing.T) {
	p := config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.example.com"}},
		Consent:   fullConsent(),
		// Give the settings projection something to emit so the check is not vacuous.
		Identity: config.IdentitySettings{DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden"},
	}
	sw := config.SettingsWireFromPolicy(p)
	if sw == nil {
		t.Fatal("SettingsWireFromPolicy returned nil; the check would be vacuous")
	}
	pw, err := json.Marshal(policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist, Settings: sw})
	if err != nil {
		t.Fatal(err)
	}
	sj, err := json.Marshal(sw)
	if err != nil {
		t.Fatal(err)
	}
	pj, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"policyWire": pw, "SettingsWire": sj, "Policy": pj} {
		for _, banned := range []string{"consent", "clientSecretEnv", "warden-portal", "WARDEN_PORTAL_DEX_CLIENT_SECRET", "allowedGroups", "idpLink"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s JSON contains %q: %s", name, banned, b)
			}
		}
	}
}

// consentNode returns the re-marshalled on-disk `consent:` node.
func consentNode(t *testing.T, path string) string {
	t.Helper()
	root := map[string]yaml.Node{}
	if err := yaml.Unmarshal([]byte(readFile(t, path)), &root); err != nil {
		t.Fatal(err)
	}
	n, ok := root["consent"]
	if !ok {
		t.Fatal("consent node missing")
	}
	out, err := yaml.Marshal(&n)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestWritersPreserveConsentBlock(t *testing.T) {
	cfg := detectionEditorConfig(t)
	path := cfg.PolicyPath
	if err := os.WriteFile(path, []byte(readFile(t, path)+consentBlockYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	before := consentNode(t, path)
	srv := New(cfg)

	writers := []struct {
		name string
		fn   func() error
	}{
		{"WritePolicy", func() error {
			prov, err := config.NewLocalYAMLProvider(path)
			if err != nil {
				return err
			}
			p, err := prov.GetPolicy()
			if err != nil {
				return err
			}
			p.Allowlist = append(p.Allowlist, config.AllowlistEntry{Domain: "added.example.com"})
			return srv.writePolicy(p)
		}},
		{"WriteSettings", func() error {
			return srv.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{
				DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden",
			}})
		}},
		{"WriteIntegrations", func() error {
			return srv.WriteIntegrations([]config.IntegrationInstance{{
				Type: "webhook", Name: "x", Config: map[string]any{"url": "${WEBHOOK_URL}"},
				Match: []config.IntegrationMatch{{Category: "security"}},
			}})
		}},
		{"WriteDetection", func() error { return srv.WriteDetection(config.DetectionConfig{Enabled: false}) }},
	}
	for _, w := range writers {
		if err := w.fn(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if after := consentNode(t, path); after != before {
			t.Errorf("%s changed the consent block:\n%s\nvs\n%s", w.name, before, after)
		}
	}
}

// TestConsentIssuerBinding: while consent is enabled the settings writer
// rejects an identity.issuer that differs from consent.oidc.issuer.
func TestConsentIssuerBinding(t *testing.T) {
	cfg := detectionEditorConfig(t)
	c := fullConsent()
	cfg.Consent = &c
	srv := New(cfg)

	err := srv.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{
		DefaultMode: "attribute", Issuer: "https://other.example.com", Audience: "warden",
	}})
	wantMismatch(t, "mismatched issuer", err)
	// A trailing slash or case change names the same issuer.
	if err := srv.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{
		DefaultMode: "attribute", Issuer: "https://IDP.example.com/", Audience: "warden",
	}}); err != nil {
		t.Fatalf("same issuer rejected: %v", err)
	}
	// With consent off the same change is accepted.
	off := New(detectionEditorConfig(t))
	if err := off.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{
		DefaultMode: "attribute", Issuer: "https://other.example.com", Audience: "warden",
	}}); err != nil {
		t.Fatalf("consent off: %v", err)
	}
}

func consentConfigFile(t *testing.T, dir, consent string) string {
	t.Helper()
	p := filepath.Join(dir, "config.yaml")
	writeFileT(t, p, basePolicy+consoleBlock+consent)
	return p
}

func TestResolveConsent(t *testing.T) {
	const secret = "portal-s3cret-value"
	const issuer = "https://idp.example.com"
	env := func(v string) func(string) string {
		return func(string) string { return v }
	}
	oidcConsole := fullConsole()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := consentConfigFile(t, dir, consentBlockYAML)

	cases := []struct {
		name     string
		console  config.ConsoleConfig
		state    string
		issuer   string
		getenv   func(string) string
		wantErr  string
		wantNil  bool
		consent  string // overrides the file's consent block when set
		useBlock bool
	}{
		{name: "ok", console: oidcConsole, state: state, issuer: issuer, getenv: env(secret)},
		{name: "ok trailing slash issuer", console: oidcConsole, state: state, issuer: issuer + "/", getenv: env(secret)},
		{name: "empty secret", console: oidcConsole, state: state, issuer: issuer, getenv: env("  "), wantErr: "WARDEN_PORTAL_DEX_CLIENT_SECRET"},
		{name: "missing state dir", console: oidcConsole, state: "", issuer: issuer, getenv: env(secret), wantErr: "--state-dir"},
		{name: "console auth none", console: config.ConsoleConfig{Auth: config.ConsoleAuthNone}, state: state, issuer: issuer, getenv: env(secret), wantErr: "console.auth oidc"},
		{name: "issuer differs", console: oidcConsole, state: state, issuer: "https://other.example.com", getenv: env(secret), wantErr: "must equal identity.issuer"},
		{name: "no identity issuer", console: oidcConsole, state: state, issuer: "", getenv: env(secret), wantErr: "requires identity.issuer"},
		{name: "disabled", console: config.ConsoleConfig{}, state: "", issuer: "", getenv: env(""), wantNil: true, useBlock: true, consent: "consent:\n  enabled: false\n"},
		{name: "absent", console: config.ConsoleConfig{}, state: "", issuer: "", getenv: env(""), wantNil: true, useBlock: true, consent: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := cfg
			if tc.useBlock {
				path = consentConfigFile(t, t.TempDir(), tc.consent)
			}
			logger, logs := testLogger()
			got, err := resolveConsent(logger, path, path, tc.state, tc.console, tc.issuer, tc.getenv)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("unexpected error %v", err)
			case tc.wantNil && got != nil:
				t.Fatalf("got %+v, want nil", got)
			case !tc.wantNil && (got == nil || got.OIDC.ClientID != "warden-portal"):
				t.Fatalf("got %+v, want the enabled block", got)
			}
			if strings.Contains(logs.String(), secret) || (err != nil && strings.Contains(err.Error(), secret)) {
				t.Error("log or error contains the secret value")
			}
		})
	}
}

// TestResolveConsentServedCopyWarns: a served copy with a different consent
// block is ignored with a warning, and --config wins.
func TestResolveConsentServedCopyWarns(t *testing.T) {
	dir := t.TempDir()
	cfg := consentConfigFile(t, dir, consentBlockYAML)
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(state, "config.yaml")
	writeFileT(t, served, basePolicy)
	logger, logs := testLogger()
	got, err := resolveConsent(logger, cfg, served, state, fullConsole(), "https://idp.example.com", func(string) string { return "x" })
	if err != nil || got == nil || got.AllowedGroups[0] != "staff" {
		t.Fatalf("got %+v, %v; want the --config block", got, err)
	}
	if !strings.Contains(logs.String(), "different consent block") {
		t.Errorf("expected a warning about the differing served copy, logs: %s", logs)
	}
}

// TestWritersPreserveConsentBlockVersioned: in --policy-store=versioned the
// served YAML is the only home of the CP-local blocks. A versioned settings
// save (publishSettings -> writeMirror) and a save that changes the credential
// (writeCredential) leave the consent node byte-identical, over a served file
// and head that already hold it.
func TestWritersPreserveConsentBlockVersioned(t *testing.T) {
	t.Run("publishSettings mirror", func(t *testing.T) {
		path := consentPolicyFile(t, "")
		srv := newConsentVersioned(t, path)
		before := consentNode(t, path)
		if err := srv.writeSettings(config.SettingsWire{
			Identity: matchingIdentity(), Logging: &config.LoggingSettings{Level: "debug", Format: "json"},
		}); err != nil {
			t.Fatal(err)
		}
		if h := mustHead(t, srv.versions); h != 2 {
			t.Fatalf("head = %d, want 2 (the save must publish)", h)
		}
		if after := consentNode(t, path); after != before {
			t.Errorf("publishSettings changed the consent block:\n%s\nvs\n%s", before, after)
		}
	})
	t.Run("writeCredential", func(t *testing.T) {
		path := consentPolicyFile(t, writeCredentialPolicyFile(t))
		srv := newConsentVersioned(t, path)
		before := consentNode(t, path)
		in := awsSettings("a-brand-new-secret-access-key")
		in.Identity = matchingIdentity()
		if err := srv.writeSettings(in); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readFile(t, path), "a-brand-new-secret-access-key") {
			t.Fatal("the new credential was not written to the served file")
		}
		if after := consentNode(t, path); after != before {
			t.Errorf("writeCredential changed the consent block:\n%s\nvs\n%s", before, after)
		}
	})
}
