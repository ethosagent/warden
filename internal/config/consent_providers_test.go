package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const provBase = cIssuer + cSecret + cRedir

func provBlock(extra string) string {
	return consentBlock(provBase, extra)
}

const googleOK = `  providers:
    - id: google
      type: google
      clientID: cid
      clientSecretKey: oauth-clients/google
      allowedScopes: [openid, "https://www.googleapis.com/auth/drive.readonly"]
      defaultScopes: [openid]
`

func TestConsentProvidersValidate(t *testing.T) {
	prov := func(body string) string {
		return "  providers:\n    - id: p1\n      clientID: cid\n      clientSecretEnv: P_SECRET\n" + body
	}
	cases := []struct {
		name    string
		extra   string
		wantErr string // "" = valid
	}{
		{"google ok", googleOK, ""},
		{"github minimal", prov("      type: github\n"), ""},
		{"generic ok", prov("      type: generic\n      authURL: https://a.example.com/auth\n      tokenURL: https://a.example.com/token\n"), ""},
		{"generic loopback http", prov("      type: generic\n      authURL: http://127.0.0.1:9/auth\n      tokenURL: http://localhost:9/token\n"), ""},
		{"githubApp ok", prov("      type: githubApp\n"), ""},
		{"no providers", "", ""},
		{"generic without tokenURL", prov("      type: generic\n      authURL: https://a.example.com/auth\n"), "consent.providers[0].tokenURL"},
		{"generic account rule without userinfoURL", prov("      type: generic\n      authURL: https://a.example.com/auth\n      tokenURL: https://a.example.com/token\n      requireEmailMatch: true\n"), "consent.providers[0].userinfoURL"},
		{"generic account rule with userinfoURL ok", prov("      type: generic\n      authURL: https://a.example.com/auth\n      tokenURL: https://a.example.com/token\n      userinfoURL: https://a.example.com/userinfo\n      allowedAccountDomains: [example.com]\n"), ""},
		{"generic without authURL", prov("      type: generic\n      tokenURL: https://a.example.com/token\n"), "consent.providers[0].authURL"},
		{"duplicate id", prov("      type: github\n") + "    - id: p1\n      type: github\n      clientID: c\n      clientSecretEnv: X\n", "consent.providers[1].id"},
		{"id starts with underscore", strings.Replace(prov("      type: github\n"), "id: p1", "id: _p1", 1), "consent.providers[0].id"},
		{"id uppercase", strings.Replace(prov("      type: github\n"), "id: p1", "id: P1", 1), "consent.providers[0].id"},
		{"unknown type", prov("      type: facebook\n"), "consent.providers[0].type"},
		{"missing type", prov(""), "consent.providers[0].type"},
		{"http token url", prov("      type: github\n      tokenURL: http://ghe.example.com/token\n"), "consent.providers[0].tokenURL"},
		{"http auth url", prov("      type: github\n      authURL: http://ghe.example.com/auth\n"), "consent.providers[0].authURL"},
		{"http revoke url", prov("      type: github\n      revokeURL: http://ghe.example.com/revoke\n"), "consent.providers[0].revokeURL"},
		{"http userinfo url", prov("      type: github\n      userinfoURL: http://ghe.example.com/user\n"), "consent.providers[0].userinfoURL"},
		{"ftp url", prov("      type: github\n      tokenURL: ftp://x.example.com/t\n"), "consent.providers[0].tokenURL"},
		{"url with userinfo", prov("      type: github\n      tokenURL: https://u:p@x.example.com/t\n"), "consent.providers[0].tokenURL"},
		{"relative url", prov("      type: github\n      tokenURL: /token\n"), "consent.providers[0].tokenURL"},
		{"ghes tokenURL without revokeURL", prov("      type: github\n      authURL: https://ghe.example.com/auth\n      tokenURL: https://ghe.example.com/token\n"), "consent.providers[0].revokeURL"},
		{"ghes githubApp tokenURL without revokeURL", prov("      type: githubApp\n      tokenURL: https://ghe.example.com/token\n"), "revokeURL is required for GitHub Enterprise"},
		{"github revokeURL wrong path", prov("      type: github\n      revokeURL: https://api.github.com/applications/grant\n"), "must end in /applications/{client_id}/grant"},
		{"githubApp revokeURL wrong path", prov("      type: githubApp\n      revokeURL: https://ghe.example.com/revoke\n"), "consent.providers[0].revokeURL"},
		{"ghes with revokeURL ok", prov("      type: github\n      tokenURL: https://ghe.example.com/token\n      revokeURL: https://ghe.example.com/api/v3/applications/{client_id}/grant\n"), ""},
		{"github.com explicit urls ok", prov("      type: github\n      tokenURL: https://github.com/login/oauth/access_token\n"), ""},
		{"revoke template ok", prov("      type: github\n      revokeURL: https://ghe.example.com/applications/{client_id}/grant\n"), ""},
		{"redirect_uri extra param", prov("      type: github\n      extraAuthParams:\n        redirect_uri: https://evil.example.com\n"), "extraAuthParams.redirect_uri"},
		{"include_granted_scopes extra param", prov("      type: google\n      extraAuthParams:\n        include_granted_scopes: \"true\"\n"), "extraAuthParams.include_granted_scopes"},
		{"mixed-case forbidden param", prov("      type: github\n      extraAuthParams:\n        State: x\n"), "extraAuthParams.State"},
		{"allowed extra param", prov("      type: github\n      extraAuthParams:\n        login: octocat\n"), ""},
		{"githubApp with allowedScopes", prov("      type: githubApp\n      allowedScopes: [repo]\n"), "consent.providers[0].allowedScopes"},
		{"scope with space", prov("      type: github\n      allowedScopes: [\"repo read\"]\n"), "allowedScopes[0]"},
		{"scope with comma", prov("      type: github\n      allowedScopes: [\"a,b\"]\n"), "allowedScopes[0]"},
		{"empty scope", prov("      type: github\n      allowedScopes: [\"\"]\n"), "allowedScopes[0]"},
		{"defaults not subset", prov("      type: github\n      allowedScopes: [repo]\n      defaultScopes: [admin]\n"), "defaultScopes[0]"},
		{"missing clientID", "  providers:\n    - id: p1\n      type: github\n      clientSecretEnv: X\n", "consent.providers[0].clientID"},
		{"no secret source", "  providers:\n    - id: p1\n      type: github\n      clientID: c\n", "exactly one of"},
		{"both secret sources", prov("      type: github\n      clientSecretKey: oauth-clients/p1\n"), "mutually exclusive"},
		{"secret key for another provider", "  providers:\n    - id: p1\n      type: github\n      clientID: c\n      clientSecretKey: oauth-clients/p2\n", "must equal \"oauth-clients/p1\""},
		{"secret key outside namespace", "  providers:\n    - id: p1\n      type: github\n      clientID: c\n      clientSecretKey: users/x\n", "must equal"},
		{"bad env name", strings.Replace(prov("      type: github\n"), "P_SECRET", "p secret", 1), "clientSecretEnv"},
		{"bad account domain", prov("      type: github\n      allowedAccountDomains: [\"@example.com\"]\n"), "allowedAccountDomains[0]"},
		{"account domain ok", prov("      type: github\n      allowedAccountDomains: [Example.com]\n      requireEmailMatch: true\n"), ""},
		{"unknown provider key", prov("      type: github\n      bogus: 1\n"), "bogus"},
		{"ttl too short", googleOK + "  connect:\n    pendingTTL: 30s\n", "pendingTTL"},
		{"ttl too long", googleOK + "  connect:\n    pendingTTL: 2h\n", "pendingTTL"},
		{"ttl bad", googleOK + "  connect:\n    pendingTTL: soon\n", "not a valid duration"},
		{"ttl ok", googleOK + "  connect:\n    pendingTTL: 1h\n", ""},
		{"redirect wrong path", googleOK + "  connect:\n    redirectURL: https://warden.example.com/portal/callback\n", "exactly /connect/callback"},
		{"redirect http non-loopback", googleOK + "  connect:\n    redirectURL: http://warden.example.com/connect/callback\n", "https unless"},
		{"redirect other origin", googleOK + "  connect:\n    redirectURL: https://other.example.com/connect/callback\n", "same origin"},
		{"redirect same origin explicit", googleOK + "  connect:\n    redirectURL: https://warden.example.com/connect/callback\n", ""},
		{"authURL with query", prov("      type: generic\n      authURL: https://a.example.com/auth?redirect_uri=https://evil\n      tokenURL: https://a.example.com/token\n"), "authURL"},
		{"tokenURL with query", prov("      type: generic\n      authURL: https://a.example.com/auth\n      tokenURL: https://a.example.com/token?x=1\n"), "tokenURL"},
		{"authURL empty query", prov("      type: generic\n      authURL: https://a.example.com/auth?\n      tokenURL: https://a.example.com/token\n"), "authURL"},
		{"empty host", prov("      type: github\n      tokenURL: https://:443/x\n"), "tokenURL"},
		{"empty fragment", prov("      type: github\n      userinfoURL: https://a.example.com/u#\n"), "userinfoURL"},
		{"request param", prov("      type: github\n      extraAuthParams:\n        request: x\n"), "extraAuthParams.request"},
		{"request_uri param", prov("      type: github\n      extraAuthParams:\n        Request_URI: x\n"), "extraAuthParams.Request_URI"},
		{"response_mode param", prov("      type: github\n      extraAuthParams:\n        response_mode: fragment\n"), "extraAuthParams.response_mode"},
		{"claims param", prov("      type: github\n      extraAuthParams:\n        claims: x\n"), "extraAuthParams.claims"},
		{"unknown connect key", googleOK + "  connect:\n    bogus: 1\n", "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := provBlock(tc.extra)
			_, perr := parse(consoleYAML(block))
			path := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(path, consoleYAML(block), 0o600); err != nil {
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

func TestConsentProvidersDefaults(t *testing.T) {
	c, err := loadConsentYAML(t, provBlock(googleOK))
	if err != nil {
		t.Fatal(err)
	}
	if c.Connect.RedirectURL != "https://warden.example.com/connect/callback" {
		t.Errorf("RedirectURL = %q, want origin of oidc redirect + /connect/callback", c.Connect.RedirectURL)
	}
	if c.Connect.PendingTTL != 15*time.Minute {
		t.Errorf("PendingTTL = %s, want 15m", c.Connect.PendingTTL)
	}
	if len(c.Providers) != 1 || c.Providers[0].ID != "google" || c.Providers[0].ClientSecretKey != "oauth-clients/google" {
		t.Errorf("Providers = %+v", c.Providers)
	}
	// Domains are lowercased; extra params and scopes survive.
	c, err = loadConsentYAML(t, provBlock("  providers:\n    - id: gh\n      type: github\n      clientID: c\n      clientSecretEnv: X\n      allowedAccountDomains: [Example.COM]\n"))
	if err != nil || c.Providers[0].AllowedAccountDomains[0] != "example.com" {
		t.Errorf("domains = %+v, %v", c.Providers, err)
	}
}

// A disabled block is never validated, so a half-written providers list cannot
// stop a start that does not use the broker.
func TestConsentProvidersDisabledNotValidated(t *testing.T) {
	block := "consent:\n  enabled: false\n  providers:\n    - id: _bad\n      type: nope\n"
	if _, err := loadConsentYAML(t, block); err != nil {
		t.Errorf("disabled block rejected: %v", err)
	}
}

func loadConsentYAML(t *testing.T, block string) (ConsentConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, consoleYAML(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConsent(path)
}

// consent.providers never reaches the worker wire.
func TestConsentProvidersNotOnWire(t *testing.T) {
	prov, err := parse(consoleYAML(provBlock(googleOK)))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"providers", "oauth-clients", "clientSecret", "connect"} {
		if strings.Contains(string(b), s) {
			t.Errorf("policy JSON contains %q: %s", s, b)
		}
	}
}
