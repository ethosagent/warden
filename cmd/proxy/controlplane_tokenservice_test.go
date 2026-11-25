package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

const (
	tokenSvcIdentity = `
identity:
  defaultMode: attribute
  issuer: http://127.0.0.1:9
  internalIssuerURL: http://127.0.0.1:9
  audience: warden
`
	tokenSvcKeys  = "\nkeys:\n  enabled: true\n"
	tokenSvcBlock = "\ntokenService:\n  enabled: true\n  issuer: https://warden.example.com\n"
)

// runTokenSvcCP runs `control-plane` on cfg for a moment (executeRoot cancels
// it) and returns its error and the state dir.
func runTokenSvcCP(t *testing.T, cfg string, withState bool) (string, error) {
	t.Helper()
	d := t.TempDir()
	state := filepath.Join(d, "state")
	args := []string{"control-plane", "--config", writeTempConfig(t, cfg), "--listen", "127.0.0.1:0",
		"--analytics-db", filepath.Join(d, "f.db"), "--alerts-db", filepath.Join(d, "a.db")}
	if withState {
		args = append(args, "--state-dir", state)
	}
	return state, executeRoot(t, args...)
}

// tableExists opens the control plane's state database read-only and reports
// whether table exists.
func tableExists(t *testing.T, state, table string) bool {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(state, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = ?`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// TestControlPlaneTokenService: the tokenService block is the only switch. A
// broken or incomplete block stops startup with the setting named, a complete
// one starts, and disabled creates no tokensvc table.
func TestControlPlaneTokenService(t *testing.T) {
	fails := []struct {
		name, cfg, want string
		state           bool
	}{
		{"enabled without --state-dir", minimalConfig + tokenSvcIdentity + tokenSvcKeys + tokenSvcBlock, "--state-dir", false},
		{"enabled without an identity issuer", minimalConfig + tokenSvcKeys + tokenSvcBlock, "identity", true},
		{"enabled without keys", minimalConfig + tokenSvcIdentity + tokenSvcBlock, "keys.enabled", true},
		{"ttl above 15m", minimalConfig + tokenSvcIdentity + tokenSvcKeys + tokenSvcBlock + "  ttl: 16m\n", "tokenService.ttl", true},
		{"non-loopback http issuer", minimalConfig + tokenSvcIdentity + tokenSvcKeys + "\ntokenService:\n  enabled: true\n  issuer: http://warden.example.com\n", "loopback", true},
		{"issuer with a trailing slash", minimalConfig + tokenSvcIdentity + tokenSvcKeys + "\ntokenService:\n  enabled: true\n  issuer: https://warden.example.com/\n", "trailing slash", true},
		{"key overlap below ttl + 2m", minimalConfig + tokenSvcIdentity + "\nkeys:\n  enabled: true\n  token:\n    overlap: 16m\n" + tokenSvcBlock, "keys.token.overlap", true},
	}
	for _, f := range fails {
		t.Run(f.name, func(t *testing.T) {
			_, err := runTokenSvcCP(t, f.cfg, f.state)
			if err == nil || !strings.Contains(err.Error(), f.want) {
				t.Fatalf("err = %v, want one naming %q", err, f.want)
			}
		})
	}

	t.Run("enabled and complete starts", func(t *testing.T) {
		state, err := runTokenSvcCP(t, minimalConfig+tokenSvcIdentity+tokenSvcKeys+tokenSvcBlock, true)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		for _, table := range []string{"token_assertion_jti", "token_sessions"} {
			if !tableExists(t, state, table) {
				t.Errorf("enabled but %s was not created", table)
			}
		}
	})
	t.Run("disabled creates no tokensvc table", func(t *testing.T) {
		for _, cfg := range []string{
			minimalConfig + tokenSvcIdentity + tokenSvcKeys,
			minimalConfig + tokenSvcIdentity + tokenSvcKeys + "\ntokenService:\n  enabled: false\n  issuer: https://warden.example.com\n",
		} {
			state, err := runTokenSvcCP(t, cfg, true)
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			for _, table := range []string{"token_assertion_jti", "token_sessions"} {
				if tableExists(t, state, table) {
					t.Errorf("disabled but %s exists", table)
				}
			}
		}
	})
}
