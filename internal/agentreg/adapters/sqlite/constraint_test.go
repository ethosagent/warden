package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/cpstate"
)

// The store maps constraint violations by the driver's typed extended result
// code, not by its message. This pins the codes the mapping relies on.
func TestConstraintCodes(t *testing.T) {
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "warden-cp.db"), Migrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	const ins = `INSERT INTO agents (id, display_name, owner_iss, owner_sub, owner_email, allowed_groups_json,
        allowed_scopes_json, status, revision, created_at, created_by, updated_at, updated_by)
        VALUES (?, '', '', '', '', '[]', '[]', 'active', 1, 0, 'a', 0, 'a')`
	if _, err := db.SQL().ExecContext(ctx, ins, "x"); err != nil {
		t.Fatal(err)
	}
	_, err = db.SQL().ExecContext(ctx, ins, "x")
	if code, ok := constraintCode(err); !ok || code != codePrimaryKey {
		t.Fatalf("duplicate agent id: code=%d ok=%v err=%v", code, ok, err)
	}
	const key = `INSERT INTO agent_keys (jkt, agent_id, kid, alg, jwk_json) VALUES (?, 'x', ?, 'EdDSA', '{}')`
	if _, err := db.SQL().ExecContext(ctx, key, "j1", "k1"); err != nil {
		t.Fatal(err)
	}
	_, err = db.SQL().ExecContext(ctx, key, "j1", "k2")
	if code, ok := constraintCode(err); !ok || code != codePrimaryKey {
		t.Fatalf("duplicate jkt: code=%d ok=%v err=%v", code, ok, err)
	}
	_, err = db.SQL().ExecContext(ctx, key, "j2", "k1")
	if code, ok := constraintCode(err); !ok || code != codeUnique {
		t.Fatalf("duplicate (agent, kid): code=%d ok=%v err=%v", code, ok, err)
	}
	if _, ok := constraintCode(nil); ok {
		t.Fatal("nil is not a constraint error")
	}
}
