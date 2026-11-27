package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConsent = `consent:
  enabled: true
  oidc:
    issuer: https://idp.example.com
    clientSecretEnv: WARDEN_PORTAL_DEX_CLIENT_SECRET
    redirectURL: https://warden.example.com/portal/callback
`

func consentBlock(oidc, extra string) string {
	return "consent:\n  enabled: true\n  oidc:\n" + oidc + extra
}

const (
	cIssuer = "    issuer: https://idp.example.com\n"
	cSecret = "    clientSecretEnv: WARDEN_PORTAL_DEX_CLIENT_SECRET\n"
	cRedir  = "    redirectURL: https://warden.example.com/portal/callback\n"
)

func TestConsentConfigDefaults(t *testing.T) {
	prov, err := parse(consoleYAML(""))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	if p.Consent.Enabled {
		t.Error("absent block must be disabled")
	}

	prov, err = parse(consoleYAML(validConsent))
	if err != nil {
		t.Fatal(err)
	}
	p, _ = prov.GetPolicy()
	c := p.Consent
	if !c.Enabled || c.OIDC.ClientID != "warden-portal" {
		t.Errorf("ClientID = %q enabled=%v", c.OIDC.ClientID, c.Enabled)
	}
	if c.Session.Idle != 30*time.Minute || c.Session.Absolute != 8*time.Hour {
		t.Errorf("Session = %+v, want idle 30m absolute 8h", c.Session)
	}
	if !c.IdPLink.Enabled || c.IdPLink.RefreshLifetime != 720*time.Hour {
		t.Errorf("IdPLink = %+v, want enabled 720h", c.IdPLink)
	}
	if len(c.AllowedGroups) != 0 {
		t.Errorf("AllowedGroups = %v, want empty", c.AllowedGroups)
	}
}

func TestConsentConfig(t *testing.T) {
	cases := []struct {
		name    string
		block   string
		wantErr string // "" = valid
	}{
		{"valid", validConsent, ""},
		{"valid explicit", consentBlock(cIssuer+cSecret+"    clientID: custom\n"+cRedir,
			"  allowedGroups: [staff]\n  session:\n    idle: 10m\n    absolute: 24h\n  idpLink:\n    enabled: false\n    refreshLifetime: 24h\n"), ""},
		{"disabled block is not validated", "consent:\n  enabled: false\n  oidc:\n    issuer: nonsense\n", ""},
		{"missing issuer", consentBlock(cSecret+cRedir, ""), "consent.oidc.issuer is required"},
		{"missing clientSecretEnv", consentBlock(cIssuer+cRedir, ""), "consent.oidc.clientSecretEnv is required"},
		{"missing redirectURL", consentBlock(cIssuer+cSecret, ""), "consent.oidc.redirectURL is required"},
		{"http issuer without internal", consentBlock("    issuer: http://dex:5556/dex\n"+cSecret+cRedir, ""), "plain http"},
		{"http issuer with internal", consentBlock("    issuer: http://localhost:5556/dex\n    internalIssuerURL: http://dex:5556\n"+cSecret+cRedir, ""), ""},
		{"internal url with path", consentBlock("    issuer: http://localhost:5556/dex\n    internalIssuerURL: http://dex:5556/x\n"+cSecret+cRedir, ""), "origin only"},
		{"internal url not absolute", consentBlock(cIssuer+"    internalIssuerURL: dex\n"+cSecret+cRedir, ""), "internalIssuerURL"},
		{"wrong redirect path", consentBlock(cIssuer+cSecret+"    redirectURL: https://warden.example.com/auth/callback\n", ""), "exactly /portal/callback"},
		{"redirect path suffix only", consentBlock(cIssuer+cSecret+"    redirectURL: https://warden.example.com/x/portal/callback\n", ""), "exactly /portal/callback"},
		{"http redirect non-loopback", consentBlock(cIssuer+cSecret+"    redirectURL: http://warden.example.com/portal/callback\n", ""), "https unless"},
		{"http redirect loopback", consentBlock(cIssuer+cSecret+"    redirectURL: http://localhost:7070/portal/callback\n", ""), ""},
		{"idle greater than absolute", consentBlock(cIssuer+cSecret+cRedir, "  session:\n    idle: 9h\n    absolute: 8h\n"), "consent.session"},
		{"absolute over 24h", consentBlock(cIssuer+cSecret+cRedir, "  session:\n    idle: 1h\n    absolute: 25h\n"), "consent.session"},
		{"zero idle", consentBlock(cIssuer+cSecret+cRedir, "  session:\n    idle: 0s\n"), "consent.session"},
		{"bad duration", consentBlock(cIssuer+cSecret+cRedir, "  session:\n    idle: soon\n"), "not a valid duration"},
		{"zero refresh lifetime", consentBlock(cIssuer+cSecret+cRedir, "  idpLink:\n    refreshLifetime: 0s\n"), "refreshLifetime"},
		{"empty group", consentBlock(cIssuer+cSecret+cRedir, "  allowedGroups: [\"\"]\n"), "allowedGroups"},
		{"unknown key", consentBlock(cIssuer+cSecret+cRedir, "  bogus: 1\n"), "bogus"},
		{"unknown oidc key", consentBlock(cIssuer+cSecret+cRedir+"    scopes: [openid]\n", ""), "scopes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, perr := parse(consoleYAML(tc.block))
			path := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(path, consoleYAML(tc.block), 0o600); err != nil {
				t.Fatal(err)
			}
			_, lerr := LoadConsent(path)
			for what, err := range map[string]error{"parse": perr, "LoadConsent": lerr} {
				if tc.wantErr == "" {
					if err != nil {
						t.Errorf("%s: unexpected error %v", what, err)
					}
					continue
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("%s: error = %v, want containing %q", what, err, tc.wantErr)
				}
			}
		})
	}
}

func TestConsentConfigLoadConsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, consoleYAML(validConsent), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConsent(path)
	if err != nil || !c.Enabled || c.OIDC.Issuer != "https://idp.example.com" {
		t.Fatalf("LoadConsent = %+v, %v", c, err)
	}
	if err := os.WriteFile(path, consoleYAML(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = LoadConsent(path); err != nil || c.Enabled {
		t.Fatalf("absent block = %+v, %v; want disabled", c, err)
	}
	if _, err := LoadConsent(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file must error")
	}
}

// The console's own validation already pins its redirect to /auth/callback, so
// the equality guard is defence in depth; exercise it directly.
func TestConsentConfigRedirectDiffersFromConsole(t *testing.T) {
	c := defaultConsent()
	c.Enabled = true
	c.OIDC.Issuer = "https://idp.example.com"
	c.OIDC.ClientSecretEnv = "X"
	c.OIDC.RedirectURL = "https://warden.example.com/portal/callback"
	if err := validateConsent(c, "https://warden.example.com/portal/callback/"); err == nil || !strings.Contains(err.Error(), "must differ from console") {
		t.Errorf("err = %v, want redirect-equals-console rejection", err)
	}
	if err := validateConsent(c, "https://warden.example.com/auth/callback"); err != nil {
		t.Errorf("distinct redirects rejected: %v", err)
	}
}
