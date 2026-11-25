package scenarios

import (
	"context"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// Approvals default off (W-P2-APPR-01): a control plane without
// console.approvals.enabled creates no approvals table, applies no approvals
// migration, and serves /policy as before.

func approvalsOffOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

// approvalsOffByDefault: on a versioned control plane with the approvals block
// absent, the state database holds no change_* table and no approvals
// migration, while the policy store itself is live and /policy still serves.
func approvalsOffByDefault(t *testing.T, h *harness.H) {
	ctx := context.Background()
	var served map[string]any
	if err := h.CP().GetJSON("/policy", &served); err != nil {
		t.Fatalf("GET /policy: %v", err)
	}
	if _, ok := served["allowlist"]; !ok {
		t.Fatalf("/policy = %v, want an allowlist", served)
	}

	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var tables int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'change_%'").Scan(&tables); err != nil {
		t.Fatalf("inspect the state db: %v", err)
	}
	if tables != 0 {
		t.Errorf("a control plane without console.approvals has %d change_* tables, want none", tables)
	}
	var applied int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE id LIKE 'approvals/%'").Scan(&applied); err != nil {
		t.Fatalf("inspect schema_migrations: %v", err)
	}
	if applied != 0 {
		t.Errorf("approvals migration applied %d times without console.approvals.enabled", applied)
	}
	var policyTables int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name = 'policy_versions'").Scan(&policyTables); err != nil || policyTables != 1 {
		t.Errorf("policy_versions tables = %d, %v; want the versioned store live", policyTables, err)
	}
}
