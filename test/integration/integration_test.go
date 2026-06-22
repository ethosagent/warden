//go:build integration

// Package integration holds cross-package / end-to-end tests that run only
// under the `integration` build tag (via `scripts/check.sh --integration`).
// M1 fills this with a real agent→proxy→upstream flow; this placeholder keeps
// the tag and target wired from milestone 0.
package integration

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// TestPlaceholder asserts the integration target builds and the core packages
// link together. Replace with a real end-to-end flow in M1.
func TestPlaceholder(t *testing.T) {
	e := policy.NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.openai.com"}},
	})
	if e.Evaluate("api.openai.com", 443, policy.SchemeHTTPS) != policy.Allow {
		t.Fatal("expected allowlisted destination to be allowed")
	}
	if e.Evaluate("evil.example.com", 443, policy.SchemeHTTPS) != policy.Deny {
		t.Fatal("expected non-allowlisted destination to be denied (default-deny)")
	}
}
