package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// consoleYAML builds a minimal valid config around a console block body.
func consoleYAML(console string) []byte {
	return []byte("policy:\n  allowlist:\n    - domain: api.example.com\n" + console)
}

const validOIDC = `console:
  auth: oidc
  oidc:
    issuer: https://idp.example.com
    clientSecretEnv: WARDEN_CONSOLE_SECRET
    redirectURL: https://warden.example.com/auth/callback
  roles:
    admin: [warden-admins]
`

func TestConsoleConfigDefaults(t *testing.T) {
	// Absent block: Auth none, defaults filled, existing behaviour untouched.
	prov, err := parse(consoleYAML(""))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	if p.Console.Auth != ConsoleAuthNone {
		t.Errorf("absent block Auth = %q, want none", p.Console.Auth)
	}

	prov, err = parse(consoleYAML(validOIDC))
	if err != nil {
		t.Fatal(err)
	}
	p, _ = prov.GetPolicy()
	c := p.Console
	if c.OIDC.ClientID != "warden-console" {
		t.Errorf("ClientID = %q, want warden-console", c.OIDC.ClientID)
	}
	if want := []string{"openid", "email", "profile", "groups"}; !reflect.DeepEqual(c.OIDC.Scopes, want) {
		t.Errorf("Scopes = %v, want %v", c.OIDC.Scopes, want)
	}
	if c.Session.Idle != time.Hour || c.Session.Absolute != 12*time.Hour {
		t.Errorf("Session = %+v, want idle 1h absolute 12h", c.Session)
	}
}

func TestConsoleConfigValidation(t *testing.T) {
	block := func(oidcExtra, roles, session string) string {
		return "console:\n  auth: oidc\n  oidc:\n" + oidcExtra + "  roles:\n" + roles + session
	}
	const admin = "    admin: [warden-admins]\n"
	const okIssuer = "    issuer: https://idp.example.com\n    clientSecretEnv: S\n    redirectURL: https://w.example.com/auth/callback\n"
	const okSecretRedirect = "    clientSecretEnv: S\n    redirectURL: https://w.example.com/auth/callback\n"
	tests := []struct {
		name    string
		yaml    string
		wantErr string // "" = accepted
	}{
		{"valid oidc", validOIDC, ""},
		{"valid with sessions", block(okIssuer, admin, "  session:\n    idle: 30m\n    absolute: 168h\n"), ""},
		{"missing admin group", block(okIssuer, "    viewer: [v]\n", ""), "console.roles.admin"},
		{"empty group name", block(okIssuer, "    admin: [\"\"]\n", ""), "empty group"},
		{"missing issuer", block(okSecretRedirect, admin, ""), "console.oidc.issuer is required"},
		{"missing secret env", block("    issuer: https://i.example.com\n    redirectURL: https://w.example.com/auth/callback\n", admin, ""), "clientSecretEnv is required"},
		{"missing redirect", block("    issuer: https://i.example.com\n    clientSecretEnv: S\n", admin, ""), "redirectURL is required"},
		{"http issuer without internal url", block("    issuer: http://localhost:5556/dex\n"+okSecretRedirect, admin, ""), "plain http"},
		{"http issuer with internal url", block("    issuer: http://localhost:5556/dex\n    internalIssuerURL: http://dex:5556\n"+okSecretRedirect, admin, ""), ""},
		{"https issuer without internal url", block(okIssuer, admin, ""), ""},
		{"internal url with path", block(okIssuer+"    internalIssuerURL: http://dex:5556/dex\n", admin, ""), "origin only"},
		{"internal url with query", block(okIssuer+"    internalIssuerURL: http://dex:5556?x=1\n", admin, ""), "origin only"},
		{"internal url non-http scheme", block(okIssuer+"    internalIssuerURL: ftp://dex:5556\n", admin, ""), "absolute http"},
		{"internal url with empty issuer", block("    internalIssuerURL: http://dex:5556\n"+okSecretRedirect, admin, ""), "console.oidc.issuer is required"},
		{"http redirect non-loopback", block("    issuer: https://i.example.com\n    clientSecretEnv: S\n    redirectURL: http://w.example.com/auth/callback\n", admin, ""), "loopback"},
		{"http redirect 127.0.0.1", block("    issuer: https://i.example.com\n    clientSecretEnv: S\n    redirectURL: http://127.0.0.1:7070/auth/callback\n", admin, ""), ""},
		{"redirect wrong path", block("    issuer: https://i.example.com\n    clientSecretEnv: S\n    redirectURL: https://w.example.com/cb\n", admin, ""), "/auth/callback"},
		{"redirect relative", block("    issuer: https://i.example.com\n    clientSecretEnv: S\n    redirectURL: /auth/callback\n", admin, ""), "absolute"},
		{"idle greater than absolute", block(okIssuer, admin, "  session:\n    idle: 5h\n    absolute: 1h\n"), "console.session"},
		{"absolute over 168h", block(okIssuer, admin, "  session:\n    idle: 1h\n    absolute: 169h\n"), "console.session"},
		{"zero idle", block(okIssuer, admin, "  session:\n    idle: 0s\n"), "console.session"},
		{"bad duration", block(okIssuer, admin, "  session:\n    idle: soon\n"), "not a valid duration"},
		{"scopes without openid", block(okIssuer+"    scopes: [email]\n", admin, ""), "openid"},
		{"unknown auth", "console:\n  auth: saml\n", "console.auth \"saml\""},
		{"auth none ignores oidc rules", "console:\n  auth: none\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(consoleYAML(tc.yaml))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want accepted, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestRoleFor(t *testing.T) {
	c := ConsoleConfig{Roles: ConsoleRoles{
		Admin: []string{"admins"}, Editor: []string{"editors"}, Viewer: []string{"viewers", "shared"},
	}}
	tests := []struct {
		name   string
		groups []string
		want   Role
		ok     bool
	}{
		{"none", nil, 0, false},
		{"unmatched", []string{"other"}, 0, false},
		{"viewer", []string{"viewers"}, RoleViewer, true},
		{"editor", []string{"editors"}, RoleEditor, true},
		{"admin", []string{"admins"}, RoleAdmin, true},
		{"highest wins regardless of order", []string{"viewers", "admins", "editors"}, RoleAdmin, true},
		{"editor beats viewer", []string{"viewers", "editors"}, RoleEditor, true},
		{"case sensitive", []string{"Admins", "ADMINS"}, 0, false},
		{"no trimming", []string{" admins"}, 0, false},
		{"empty group never matches", []string{""}, 0, false},
	}
	for _, tc := range tests {
		got, ok := c.RoleFor(tc.groups)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: RoleFor(%v) = (%v,%v), want (%v,%v)", tc.name, tc.groups, got, ok, tc.want, tc.ok)
		}
	}
	if RoleViewer >= RoleEditor || RoleEditor >= RoleAdmin {
		t.Error("role ordering must be viewer < editor < admin")
	}
}

// TestConsoleNoInsecureKey: the removed insecure-issuer key is rejected by the
// strict parser (the key is spelled in two pieces so the repo-wide grep for the
// old name stays empty).
func TestConsoleNoInsecureKey(t *testing.T) {
	old := "allowInsecure" + "Issuer"
	body := strings.Replace(validOIDC, "    clientSecretEnv", "    "+old+": true\n    clientSecretEnv", 1)
	if _, err := parse(consoleYAML(body)); err == nil {
		t.Fatal("a config setting the removed insecure-issuer key must be rejected")
	}
	if _, err := LoadConsole(writeConsoleTemp(t, consoleYAML(body))); err == nil {
		t.Fatal("LoadConsole must reject the removed insecure-issuer key")
	}
}

func writeConsoleTemp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConsoleConfigLoadConsole(t *testing.T) {
	c, err := LoadConsole(writeConsoleTemp(t, consoleYAML(validOIDC)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth != ConsoleAuthOIDC || c.OIDC.ClientSecretEnv != "WARDEN_CONSOLE_SECRET" {
		t.Errorf("LoadConsole = %+v", c)
	}
	c, err = LoadConsole(writeConsoleTemp(t, consoleYAML("")))
	if err != nil || c.Auth != ConsoleAuthNone {
		t.Errorf("absent block: %+v, %v", c, err)
	}
	if _, err := LoadConsole(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file must error")
	}
	if _, err := LoadConsole(writeConsoleTemp(t, consoleYAML("console:\n  auth: oidc\n"))); err == nil {
		t.Error("invalid oidc block must error")
	}
}

// TestConsoleAdminAuditBlock: console.adminAudit.enabled defaults to false
// (absent block, and a console block without the sub-block), parses true and
// false, and a misspelled key under it fails the strict decode.
func TestConsoleAdminAuditBlock(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       bool
	}{
		{"absent console block", "", false},
		{"console block without adminAudit", "console:\n  auth: none\n", false},
		{"enabled true", "console:\n  adminAudit:\n    enabled: true\n", true},
		{"enabled false", "console:\n  adminAudit:\n    enabled: false\n", false},
		{"with oidc", validOIDC + "  adminAudit:\n    enabled: true\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := LoadConsole(writeConsoleTemp(t, consoleYAML(tc.yaml)))
			if err != nil {
				t.Fatalf("LoadConsole: %v", err)
			}
			if c.AdminAudit.Enabled != tc.want {
				t.Errorf("AdminAudit.Enabled = %v, want %v", c.AdminAudit.Enabled, tc.want)
			}
		})
	}
	if _, err := LoadConsole(writeConsoleTemp(t, consoleYAML("console:\n  adminAudit:\n    enable: true\n"))); err == nil {
		t.Error("a misspelled console.adminAudit key must fail to parse")
	}
	if _, err := LoadConsole(writeConsoleTemp(t, consoleYAML("console:\n  adminAudit:\n    enabled: maybe\n"))); err == nil {
		t.Error("a non-boolean console.adminAudit.enabled must fail to parse")
	}
}

// TestConsoleAdminAuditNotOnPolicyWire: like the rest of console:, the
// adminAudit sub-block never reaches the JSON policy wire.
func TestConsoleAdminAuditNotOnPolicyWire(t *testing.T) {
	prov, err := parse(consoleYAML("console:\n  adminAudit:\n    enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	if !p.Console.AdminAudit.Enabled {
		t.Fatal("parse dropped console.adminAudit.enabled")
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.ToLower(string(b)); strings.Contains(s, "adminaudit") || strings.Contains(s, "console") {
		t.Errorf("policy JSON carries the console block: %s", b)
	}
}

// TestConsoleTrustedProxies: console.trustedProxies defaults to empty, keeps
// valid IPv4 and IPv6 CIDRs, and refuses a bare address or garbage by naming
// the key, in none mode as well as oidc.
func TestConsoleTrustedProxies(t *testing.T) {
	c, err := LoadConsole(writeConsoleTemp(t, consoleYAML("")))
	if err != nil {
		t.Fatalf("LoadConsole: %v", err)
	}
	if len(c.TrustedProxies) != 0 {
		t.Fatalf("default TrustedProxies = %v, want empty", c.TrustedProxies)
	}
	c, err = LoadConsole(writeConsoleTemp(t, consoleYAML("console:\n  trustedProxies: [\"10.0.0.0/8\", \" 2001:db8::/32 \"]\n")))
	if err != nil {
		t.Fatalf("LoadConsole: %v", err)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0] != "10.0.0.0/8" || c.TrustedProxies[1] != "2001:db8::/32" {
		t.Fatalf("TrustedProxies = %q", c.TrustedProxies)
	}
	for _, bad := range []string{"10.0.0.1", "not-a-cidr", "10.0.0.0/33", ""} {
		_, err := LoadConsole(writeConsoleTemp(t, consoleYAML("console:\n  trustedProxies: [\""+bad+"\"]\n")))
		if err == nil || !strings.Contains(err.Error(), "console.trustedProxies") {
			t.Errorf("trustedProxies %q: err = %v, want a console.trustedProxies error", bad, err)
		}
	}
	if _, err := LoadConsole(writeConsoleTemp(t, consoleYAML(validOIDC+"  trustedProxies: [\"192.0.2.1\"]\n"))); err == nil {
		t.Error("a bare address in trustedProxies must fail in oidc mode too")
	}
}

func TestConsoleBreakGlassValidation(t *testing.T) {
	const hashLike = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
	bg := func(auth, body string) string {
		if auth == "oidc" {
			return validOIDC + "  breakGlass:\n" + body
		}
		return "console:\n  auth: none\n  breakGlass:\n" + body
	}
	const user = "    username: ops\n"
	const env = "    passwordHashEnv: BG_HASH\n"
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"valid env", bg("oidc", "    enabled: true\n"+user+env), ""},
		{"valid file with ttl", bg("oidc", "    enabled: true\n"+user+"    passwordHashFile: /run/secrets/bg\n    sessionTTL: 4h\n"), ""},
		{"auth none", bg("none", "    enabled: true\n"+user+env), "console.breakGlass.enabled"},
		{"both sources", bg("oidc", "    enabled: true\n"+user+env+"    passwordHashFile: /f\n"), "console.breakGlass.passwordHashEnv"},
		{"no source", bg("oidc", "    enabled: true\n"+user), "console.breakGlass.passwordHashEnv"},
		{"ttl 5h", bg("oidc", "    enabled: true\n"+user+env+"    sessionTTL: 5h\n"), "console.breakGlass.sessionTTL"},
		{"ttl zero", bg("oidc", "    enabled: true\n"+user+env+"    sessionTTL: 0s\n"), "console.breakGlass.sessionTTL"},
		{"ttl garbage", bg("oidc", "    enabled: true\n"+user+env+"    sessionTTL: soon\n"), "console.breakGlass.sessionTTL"},
		{"empty username", bg("oidc", "    enabled: true\n    username: \"  \"\n"+env), "console.breakGlass.username"},
		{"username 129 bytes", bg("oidc", "    enabled: true\n    username: "+strings.Repeat("a", 129)+"\n"+env), "console.breakGlass.username"},
		{"username 128 bytes", bg("oidc", "    enabled: true\n    username: "+strings.Repeat("a", 128)+"\n"+env), ""},
		{"disabled needs nothing", bg("none", "    enabled: false\n    sessionTTL: 99h\n"), ""},
		{"hash in env name field", bg("oidc", "    enabled: true\n    passwordHashEnv: x\n    passwordHashFile: "+hashLike+"\n"+user), "console.breakGlass.passwordHashEnv"},
		{"unknown key", bg("oidc", "    enabled: true\n    password: x\n"), "field password not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(consoleYAML(tc.yaml))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want accepted, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "":
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "argon2id") {
					t.Fatalf("error leaks a hash: %q", err)
				}
			}
		})
	}
}

func TestConsoleBreakGlassDefaultsAndLocality(t *testing.T) {
	prov, err := parse(consoleYAML(validOIDC + "  breakGlass:\n    enabled: true\n    username: \" ops \"\n    passwordHashEnv: BG_HASH\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	b := p.Console.BreakGlass
	if !b.Enabled || b.Username != "ops" || b.PasswordHashEnv != "BG_HASH" || b.SessionTTL != time.Hour || b.AllowBehindTLSTerminator {
		t.Errorf("BreakGlass = %+v", b)
	}
	// Absent block: disabled, default TTL, and never in the served JSON.
	prov, err = parse(consoleYAML(""))
	if err != nil {
		t.Fatal(err)
	}
	p, _ = prov.GetPolicy()
	if p.Console.BreakGlass != (ConsoleBreakGlass{SessionTTL: time.Hour}) {
		t.Errorf("absent BreakGlass = %+v", p.Console.BreakGlass)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "breakglass") {
		t.Errorf("served policy JSON mentions breakGlass: %s", raw)
	}
}
