package cpstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite"
)

func openCopy(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open copy: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestBackupTo_ConsistentUnderWrites(t *testing.T) {
	d := openT(t, dbPath(t), mig1, mig2)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if _, err := d.SQL().ExecContext(ctx, "INSERT INTO t1 (id, v) VALUES (?, 'seed')", i); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var next atomic.Int64
	next.Store(1000)
	var committed atomic.Int64 // inserts acknowledged so far
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errc := make(chan error, 8)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				id := next.Add(1)
				if _, err := d.SQL().ExecContext(ctx, "INSERT INTO t1 (id, v) VALUES (?, 'w')", id); err != nil {
					errc <- err
					return
				}
				committed.Add(1)
			}
		}()
	}
	for committed.Load() < 20 {
	}
	before := committed.Load()
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := d.BackupTo(ctx, dst); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	close(stop)
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatalf("writer failed during backup: %v", err)
	}

	cp := openCopy(t, dst)
	var res string
	if err := cp.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil || res != "ok" {
		t.Fatalf("integrity_check = %q, %v", res, err)
	}
	var n int64
	if err := cp.QueryRow("SELECT count(*) FROM t1").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n < 100+before {
		t.Fatalf("copy has %d rows, want at least %d (seed + committed before the call)", n, 100+before)
	}
	// Every registered table is copied, not just one.
	if err := cp.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('t1','t2','schema_migrations')").Scan(&n); err != nil || n != 3 {
		t.Fatalf("tables in copy = %d, %v", n, err)
	}
}

func TestBackupTo_Destination(t *testing.T) {
	d := openT(t, dbPath(t), mig1)
	ctx := context.Background()
	dir := t.TempDir()

	existing := filepath.Join(dir, "exists.db")
	if err := os.WriteFile(existing, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.BackupTo(ctx, existing); !errors.Is(err, ErrBackupDestExists) {
		t.Fatalf("existing dst: err = %v, want ErrBackupDestExists", err)
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me" {
		t.Fatalf("existing dst modified: %q", b)
	}

	missing := filepath.Join(dir, "nodir", "copy.db")
	if err := d.BackupTo(ctx, missing); err == nil {
		t.Fatal("missing parent: want error")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatalf("missing parent was created: %v", err)
	}

	if err := d.BackupTo(ctx, ""); err == nil {
		t.Fatal("empty dst: want error")
	}
	if err := d.BackupTo(ctx, existing+"/x"); err == nil {
		t.Fatal("parent that is a file: want error")
	}
}

func TestBackupTo_Cancel(t *testing.T) {
	d := openT(t, dbPath(t), mig1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := d.BackupTo(ctx, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("dst left behind: %v", err)
	}
}

func TestBackupTo_FailureRemovesPartial(t *testing.T) {
	d := openT(t, dbPath(t), mig1)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := d.BackupTo(context.Background(), dst); err == nil {
		t.Fatal("closed db: want error")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("partial dst left behind: %v", err)
	}
}

func TestBackupTo_Mode(t *testing.T) {
	d := openT(t, dbPath(t), mig1)
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := d.BackupTo(context.Background(), dst); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestSchemaVersion_CountsAppliedMigrations(t *testing.T) {
	ctx := context.Background()
	path := dbPath(t)
	d := openT(t, path, mig1)
	if v, err := d.SchemaVersion(ctx); err != nil || v != 1 {
		t.Fatalf("SchemaVersion = %d, %v; want 1", v, err)
	}
	_ = d.Close()
	d = openT(t, path, mig1, mig2)
	if v, err := d.SchemaVersion(ctx); err != nil || v != 2 {
		t.Fatalf("SchemaVersion after a second migration = %d, %v; want 2", v, err)
	}
}
