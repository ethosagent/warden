package keys_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
)

// testGenerate makes an importable Ed25519 key.
func testGenerate(t *testing.T, _ string) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestResetReplacesAPurpose: `keys reset` deletes every row and every piece of
// material of the purpose — including the retired key a rotation left — and
// generates a fresh active and next key attributed to the acting operator, so
// a restore that lost the key directory ends with a purpose that signs again.
func TestResetReplacesAPurpose(t *testing.T) {
	e := newEnv(t)
	m := e.manager()
	m.Init(context.Background())

	before := e.rows()
	if len(before) != 4 {
		t.Fatalf("rows before the reset = %d, want an active and a next for token and bundle", len(before))
	}
	// A rotation leaves a retired row whose material is already gone; the
	// reset removes it too.
	e.clk.Advance(2 * time.Hour) // the next key's prepublish window
	if err := m.Rotate(context.Background(), keys.PurposeToken, keys.RotateOpts{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	auditLenBefore := len(e.audit.events())

	res, err := m.Reset(context.Background(), keys.PurposeToken, keys.Actor{Subject: "cli:op", AuthMethod: "cli"})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	audited := e.audit.events()[auditLenBefore:]
	if res.Removed != 3 {
		t.Errorf("removed = %d, want the purpose's 3 rows (active, next, retired)", res.Removed)
	}
	rows := e.rows()
	if got := kidsByState(rows, keys.PurposeToken, keys.StateActive); len(got) != 1 {
		t.Fatalf("token rows after the reset = %+v, want exactly one active", rows)
	}
	if got := kidsByState(rows, keys.PurposeToken, keys.StateActive)[0]; got != res.ActiveKID || res.ActiveKID == "" {
		t.Errorf("active kid = %q, want the reset's %q", got, res.ActiveKID)
	}
	if got := kidsByState(rows, keys.PurposeToken, keys.StateNext); len(got) != 1 || slices.Contains(beforeKeys(before, keys.PurposeToken), got[0]) {
		t.Errorf("next rows after the reset = %v, want one fresh kid", got)
	}
	for _, r := range rows {
		if r.Purpose != keys.PurposeToken {
			continue
		}
		if r.CreatedBy != "cli:op" {
			t.Errorf("row %s created_by = %q, want the acting operator", r.KID, r.CreatedBy)
		}
		if _, err := os.Stat(filepath.Join(e.dir, r.Purpose, r.KID+".pem")); err != nil {
			t.Errorf("material for the fresh %s key %s: %v", r.State, r.KID, err)
		}
	}
	// The old material is gone from the store.
	for _, kid := range beforeKeys(before, keys.PurposeToken) {
		if _, err := e.store.Get(context.Background(), keys.PurposeToken, kid); !errors.Is(err, keys.ErrKeyNotFound) {
			t.Errorf("material of the removed key %s survived: %v", kid, err)
		}
	}
	// The other purpose is untouched, and the audit trail names the operator.
	if got := kidsByState(rows, keys.PurposeBundle, keys.StateActive); len(got) != 1 || got[0] != kidsByState(before, keys.PurposeBundle, keys.StateActive)[0] {
		t.Errorf("bundle rows changed: %+v", rows)
	}
	for _, ev := range audited {
		if ev.Purpose == keys.PurposeToken && ev.Action == keys.ActionGenerated && ev.Actor.Subject != "cli:op" {
			t.Errorf("generated event %+v does not name the operator", ev)
		}
	}
	// The reset purpose loads and signs.
	if err := m.LoadKeySet(context.Background(), keys.PurposeToken); err != nil {
		t.Errorf("load after the reset: %v", err)
	}
}

// TestResetClearsCA: the ca purpose is only cleared — its key is imported
// (ImportKey), so a reset leaves the generation to the importer.
func TestResetClearsCA(t *testing.T) {
	e := newEnv(t)
	m := e.manager()
	m.Init(context.Background())
	if _, err := m.ImportKey(context.Background(), keys.PurposeCA, testGenerate(t, keys.AlgEdDSA), keys.SystemActor); err != nil {
		t.Fatalf("import: %v", err)
	}
	caRows := kidsByState(e.rows(), keys.PurposeCA, keys.StateActive)
	if len(caRows) != 1 {
		t.Fatalf("ca rows = %+v", e.rows())
	}

	res, err := m.Reset(context.Background(), keys.PurposeCA, keys.SystemActor)
	if err != nil {
		t.Fatalf("reset ca: %v", err)
	}
	if res.Removed != 1 || res.ActiveKID != "" {
		t.Errorf("reset result = %+v, want one removed row and no generated key", res)
	}
	if rows := e.rows(); len(rows) != 4 {
		t.Errorf("rows after clearing ca = %d, want the 4 token and bundle rows", len(rows))
	}
	if _, err := e.store.Get(context.Background(), keys.PurposeCA, caRows[0]); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("ca material survived the reset: %v", err)
	}
	// The importer can start over.
	if _, err := m.ImportKey(context.Background(), keys.PurposeCA, testGenerate(t, keys.AlgEdDSA), keys.SystemActor); err != nil {
		t.Errorf("import after the reset: %v", err)
	}
}

// TestResetRefusesUnknownPurpose: an unknown purpose is ErrInvalidPurpose and
// changes nothing.
func TestResetRefusesUnknownPurpose(t *testing.T) {
	e := newEnv(t)
	m := e.manager()
	m.Init(context.Background())
	before := e.rows()

	if _, err := m.Reset(context.Background(), "tokens", keys.SystemActor); !errors.Is(err, keys.ErrInvalidPurpose) {
		t.Fatalf("reset an unknown purpose = %v, want ErrInvalidPurpose", err)
	}
	after := e.rows()
	if len(after) != len(before) {
		t.Errorf("a refused reset changed the rows: %d -> %d", len(before), len(after))
	}
}

// TestResetEmptyPurpose: a purpose with no rows (the restore brought none
// back) still ends with a fresh active and next key.
func TestResetEmptyPurpose(t *testing.T) {
	e := newEnv(t)
	m := e.manager()
	m.Init(context.Background())
	if _, err := m.Reset(context.Background(), keys.PurposeBundle, keys.SystemActor); err != nil {
		t.Fatalf("reset: %v", err)
	}
	rows := e.rows()
	if got := kidsByState(rows, keys.PurposeBundle, keys.StateActive); len(got) != 1 {
		t.Fatalf("bundle rows after resetting an empty purpose = %+v", rows)
	}
	if got := kidsByState(rows, keys.PurposeBundle, keys.StateNext); len(got) != 1 {
		t.Errorf("no fresh next key: %+v", rows)
	}
}

func beforeKeys(rows []keys.Record, purpose string) []string {
	var out []string
	for _, r := range rows {
		if r.Purpose == purpose {
			out = append(out, r.KID)
		}
	}
	return out
}
