package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveConsentRequiresPersistentStore: the control-plane command refuses
// to start with consent and consent.idpLink enabled unless consent.store is a
// persistent backend (W-P3-CSIG-03): no consent.store and the echo store (even
// with --dev) are refused with an error naming the backend; the same block
// with the IdP link off starts, and so does an aws consent.store.
func TestResolveConsentRequiresPersistentStore(t *testing.T) {
	const issuer = "https://127.0.0.1:1/dex"
	const base = "identity:\n  defaultMode: attribute\n  issuer: " + issuer + "\n  audience: warden\n" +
		"console:\n  auth: oidc\n  oidc:\n    issuer: " + issuer + "\n    clientSecretEnv: WARDEN_CONSENT_TEST_CONSOLE\n" +
		"    redirectURL: https://warden.example.com/auth/callback\n  roles:\n    admin: [admins]\n" +
		"consent:\n  enabled: true\n  oidc:\n    issuer: " + issuer + "\n    clientSecretEnv: WARDEN_CONSENT_TEST_PORTAL\n" +
		"    redirectURL: https://warden.example.com/portal/callback\n"
	t.Setenv("WARDEN_CONSENT_TEST_CONSOLE", "console-secret")
	t.Setenv("WARDEN_CONSENT_TEST_PORTAL", "portal-secret")
	run := func(cfg string, extra ...string) error {
		args := append([]string{"control-plane", "--config", writeTempConfig(t, minimalConfig+base+cfg),
			"--listen", "127.0.0.1:0", "--analytics-provider", "memory",
			"--alerts-db", filepath.Join(t.TempDir(), "a.db"),
			"--state-dir", filepath.Join(t.TempDir(), "state")}, extra...)
		return executeRoot(t, args...)
	}
	for name, tc := range map[string]struct {
		cfg   string
		extra []string
		want  string
	}{
		"no consent.store":   {"", nil, "(none: consent.store is not configured)"},
		"echo with --dev":    {"  store:\n    backend: echo\n", []string{"--dev"}, "consent.store.backend is echo"},
		"echo without --dev": {"  store:\n    backend: echo\n", nil, "echo"},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(tc.cfg, tc.extra...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "consent.") {
				t.Fatalf("control-plane = %v, want a refusal naming %q", err, tc.want)
			}
			if name != "echo without --dev" && !strings.Contains(err.Error(), "consent.idpLink.enabled") {
				t.Fatalf("control-plane = %v, want it to name consent.idpLink.enabled", err)
			}
		})
	}
	t.Run("idpLink disabled starts", func(t *testing.T) {
		if err := run("  idpLink:\n    enabled: false\n"); err != nil {
			t.Fatalf("control-plane with the IdP link off = %v, want a clean start", err)
		}
	})
	t.Run("aws starts", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")
		if err := run("  store:\n    backend: aws\n    aws:\n      region: us-east-1\n"); err != nil {
			t.Fatalf("control-plane with an aws consent.store = %v, want a clean start", err)
		}
	})
}
