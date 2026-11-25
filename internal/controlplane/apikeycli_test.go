package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The argument and state-dir guards of the offline API key commands; the
// commands themselves run end to end in cmd/proxy and the apikey_cli_revoke
// scenario.
func TestAPIKeyCLIGuards(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	for name, target := range map[string]APIKeyRevokeTarget{
		"none": {}, "both": {ID: "a", OwnerSub: "b"},
	} {
		if _, err := RunAPIKeyRevoke(ctx, dir, "", target, nil); err == nil {
			t.Errorf("%s: want an error for %+v", name, target)
		}
	}
	if _, err := RunAPIKeyRevoke(ctx, "", "", APIKeyRevokeTarget{ID: "a"}, nil); err == nil {
		t.Error("an empty state dir must be refused")
	}
	if _, err := RunAPIKeyRevoke(ctx, filepath.Join(dir, "absent"), "", APIKeyRevokeTarget{ID: "a"}, nil); err == nil {
		t.Error("a missing state dir must be refused")
	}
	if _, err := RunAPIKeyRevoke(ctx, dir, "", APIKeyRevokeTarget{ID: "a"}, nil); err == nil {
		t.Error("a state dir without a database must be refused, and must not create one")
	}
	if _, err := os.Stat(filepath.Join(dir, adminaudit.StateDBFileName)); err == nil {
		t.Error("the CLI created a database")
	}
	if _, err := ListAPIKeysOffline(ctx, ""); err == nil {
		t.Error("list needs a state dir")
	}
	if _, err := ListAPIKeysOffline(ctx, dir); err == nil {
		t.Error("list needs a database")
	}

	// A database that never enabled API keys: nothing to list, nothing to
	// revoke, and the table is not created.
	db, err := cpstate.Open(ctx, filepath.Join(dir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if keys, err := ListAPIKeysOffline(ctx, dir); err != nil || len(keys) != 0 {
		t.Errorf("list on a keyless db = %v, %v", keys, err)
	}
	if _, err := RunAPIKeyRevoke(ctx, dir, "", APIKeyRevokeTarget{ID: "a"}, nil); !errors.Is(err, ErrNoAPIKeyTable) {
		t.Errorf("revoke on a keyless db = %v, want ErrNoAPIKeyTable", err)
	}
	ro, err := cpstate.OpenReadOnly(ctx, filepath.Join(dir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	for _, id := range ro.Applied() {
		if id == sqlitestore.MigrationID {
			t.Error("the CLI applied the api_keys migration")
		}
	}
}

// TestAPIKeyCLIRevokeWithoutAudit: with no admin audit chain a revoke still
// happens, says so on the notice writer and reports Audited false.
func TestAPIKeyCLIRevokeWithoutAudit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := cpstate.Open(ctx, filepath.Join(dir, adminaudit.StateDBFileName),
		cpstate.Enable(StateMigrations(), sqlitestore.MigrationID))
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	_, k, err := st.Create(ctx, apikeys.CreateParams{
		Name: "ci", OwnerIss: "https://idp", OwnerSub: "alice", Scopes: []apikeys.Scope{"policy:read"},
		TTL: 2 * apikeys.MinTTL, MaxTTL: 24 * apikeys.MinTTL, MaxActive: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	var notice syncBuf
	res, err := RunAPIKeyRevoke(ctx, dir, "", APIKeyRevokeTarget{ID: k.ID}, &notice)
	if err != nil || res.Audited || len(res.Revoked) != 1 {
		t.Fatalf("RunAPIKeyRevoke = %+v, %v", res, err)
	}
	if notice.String() == "" {
		t.Error("no notice that admin audit is off")
	}
	keys, err := ListAPIKeysOffline(ctx, dir)
	if err != nil || len(keys) != 1 || keys[0].RevokedBy == "" {
		t.Fatalf("listed = %v, %v; want the revoked key", keys, err)
	}
}
