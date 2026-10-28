package cpstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrityCheck(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "warden-cp.db")
	d, err := Open(ctx, path, []Migration{{ID: "t/0001", SQL: "CREATE TABLE t (a TEXT)"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := IntegrityCheck(ctx, path); err != nil {
		t.Fatalf("healthy database: %v", err)
	}

	junk := filepath.Join(dir, "junk.db")
	if err := os.WriteFile(junk, []byte("this is not a database, just text padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := IntegrityCheck(ctx, junk); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("junk file: err = %v, want ErrIntegrity", err)
	}
	if err := IntegrityCheck(ctx, filepath.Join(dir, "missing.db")); err == nil || errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing file: err = %v, want a plain stat error", err)
	}
}
