package cpstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	mig1 = Migration{ID: "t/0001", SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY, v TEXT)"}
	mig2 = Migration{ID: "t/0002", SQL: "CREATE TABLE t2 (id INTEGER PRIMARY KEY)"}
	mig3 = Migration{ID: "t/0003", SQL: "CREATE TABLE t3 (id INTEGER PRIMARY KEY)"}
)

func dbPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "warden-cp.db")
}

func openT(t *testing.T, path string, migs ...Migration) *DB {
	t.Helper()
	d, err := Open(context.Background(), path, migs)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func tableExists(t *testing.T, d *DB, name string) bool {
	t.Helper()
	var n int
	err := d.SQL().QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	if err != nil {
		t.Fatalf("sqlite_master: %v", err)
	}
	return n == 1
}

func recordedIDs(t *testing.T, d *DB) []string {
	t.Helper()
	ids, err := d.appliedIDs(context.Background())
	if err != nil {
		t.Fatalf("appliedIDs: %v", err)
	}
	return ids
}

func TestMigrateAppliesOnlyNew(t *testing.T) {
	path := dbPath(t)
	d := openT(t, path, mig1)
	if got := d.Applied(); !slices.Equal(got, []string{"t/0001"}) {
		t.Fatalf("first Applied = %v, want [t/0001]", got)
	}
	if _, err := d.SQL().Exec("INSERT INTO t1 (v) VALUES ('keep')"); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// t/0001 would fail if re-run (table exists); only t/0002 may be applied.
	d2 := openT(t, path, mig1, mig2)
	if got := d2.Applied(); !slices.Equal(got, []string{"t/0002"}) {
		t.Fatalf("second Applied = %v, want [t/0002]", got)
	}
	if got := recordedIDs(t, d2); !slices.Equal(got, []string{"t/0001", "t/0002"}) {
		t.Fatalf("schema_migrations = %v", got)
	}
	var v string
	if err := d2.SQL().QueryRow("SELECT v FROM t1").Scan(&v); err != nil || v != "keep" {
		t.Fatalf("t1 row lost: %q, %v", v, err)
	}

	d3 := openT(t, path, mig1, mig2)
	if got := d3.Applied(); len(got) != 0 {
		t.Fatalf("third Applied = %v, want none", got)
	}
}

func TestMigrateRefusesUnknownID(t *testing.T) {
	path := dbPath(t)
	d := openT(t, path, mig1, mig2, mig3)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open(context.Background(), path, []Migration{mig1, mig2})
	if err == nil {
		t.Fatal("Open succeeded against a DB holding an unregistered migration")
	}
	if !strings.Contains(err.Error(), "t/0003") {
		t.Errorf("error %q does not name t/0003", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("database bytes changed after a refused Open")
	}

	// The read-only opener enforces the same guard.
	if _, err := OpenReadOnly(context.Background(), path, []Migration{mig1, mig2}); err == nil ||
		!strings.Contains(err.Error(), "t/0003") {
		t.Errorf("OpenReadOnly err = %v, want one naming t/0003", err)
	}
}

func TestMigrateFailureRollsBack(t *testing.T) {
	path := dbPath(t)
	bad := Migration{ID: "t/0002", SQL: "CREATE TABLE half (id INTEGER); CREATE TABLE half (id INTEGER)"}
	_, err := Open(context.Background(), path, []Migration{mig1, bad})
	if err == nil || !strings.Contains(err.Error(), "t/0002") {
		t.Fatalf("Open err = %v, want one naming t/0002", err)
	}

	d := openT(t, path, mig1)
	if got := recordedIDs(t, d); !slices.Equal(got, []string{"t/0001"}) {
		t.Fatalf("schema_migrations = %v, want only t/0001", got)
	}
	if !tableExists(t, d, "t1") {
		t.Error("earlier migration's table was lost")
	}
	if tableExists(t, d, "half") {
		t.Error("failed migration left a table behind")
	}
}

func TestMigrationValidation(t *testing.T) {
	cases := map[string][]Migration{
		"empty id":  {{ID: "", SQL: "SELECT 1"}},
		"empty sql": {{ID: "t/1", SQL: ""}},
		"duplicate": {mig1, mig1},
	}
	for name, migs := range cases {
		t.Run(name, func(t *testing.T) {
			path := dbPath(t)
			if _, err := Open(context.Background(), path, migs); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := os.Stat(path); err == nil {
				t.Error("invalid migrations still created the database file")
			}
		})
	}
}

func TestOpenCreatesFileMode0600(t *testing.T) {
	path := dbPath(t)
	d := openT(t, path, mig1)
	// Force WAL sidecars into existence, then check every file.
	if _, err := d.SQL().Exec("INSERT INTO t1 (v) VALUES ('x')"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", filepath.Base(p), perm)
		}
	}
}

func TestOpenPragmas(t *testing.T) {
	d := openT(t, dbPath(t), mig1)
	var mode string
	if err := d.SQL().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v; want wal", mode, err)
	}
	var fk, busy int
	if err := d.SQL().QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d, %v; want 1", fk, err)
	}
	if err := d.SQL().QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil || busy != 5000 {
		t.Errorf("busy_timeout = %d, %v; want 5000", busy, err)
	}
	if got := d.SQL().Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestOpenPathWithURISyntax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a b?c#d%e", "warden-cp.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	d := openT(t, path, mig1)
	if !tableExists(t, d, "t1") {
		t.Error("migration did not run in the intended file")
	}
}

func TestOpenGarbageFile(t *testing.T) {
	path := dbPath(t)
	garbage := make([]byte, 4096)
	if _, err := rand.Read(garbage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), path, []Migration{mig1})
	if err == nil {
		t.Fatal("Open succeeded on a garbage file")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the path", err)
	}
	if !strings.Contains(err.Error(), "backup") {
		t.Errorf("error %q lacks the recovery hint", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, garbage) {
		t.Error("garbage file was modified")
	}
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(context.Background(), "", nil); err == nil {
		t.Error("expected error for an empty path")
	}
}

func TestOpenReadOnly(t *testing.T) {
	path := dbPath(t)
	d := openT(t, path, mig1)
	if _, err := d.SQL().Exec("INSERT INTO t1 (v) VALUES ('a')"); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fiBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure a rewritten mtime would be observable.
	past := fiBefore.ModTime().Add(-time.Hour)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(context.Background(), path, []Migration{mig1})
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	var v string
	if err := ro.SQL().QueryRow("SELECT v FROM t1").Scan(&v); err != nil || v != "a" {
		t.Fatalf("read via read-only handle = %q, %v", v, err)
	}
	if _, err := ro.SQL().Exec("INSERT INTO t1 (v) VALUES ('b')"); err == nil {
		t.Fatal("write through a read-only handle succeeded")
	}
	if _, err := ro.SQL().Exec("CREATE TABLE evil (id INTEGER)"); err == nil {
		t.Fatal("DDL through a read-only handle succeeded")
	}
	if got := ro.Applied(); !slices.Equal(got, []string{"t/0001"}) {
		t.Errorf("Applied = %v", got)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("file bytes changed")
	}
	fiAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fiAfter.ModTime().Equal(past) {
		t.Errorf("mtime changed: %v -> %v", past, fiAfter.ModTime())
	}
}

func TestOpenReadOnlyMissingFile(t *testing.T) {
	path := dbPath(t)
	if _, err := OpenReadOnly(context.Background(), path, nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("OpenReadOnly created the file")
	}
}

func TestOpenReadOnlyGarbage(t *testing.T) {
	path := dbPath(t)
	if err := os.WriteFile(path, bytes.Repeat([]byte("not a database "), 300), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenReadOnly(context.Background(), path, nil)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want one naming the path", err)
	}
}

func TestConcurrentWriters(t *testing.T) {
	d := openT(t, dbPath(t), mig1)
	const writers, perWriter = 50, 100
	errCh := make(chan error, writers)
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				if _, err := d.SQL().Exec("INSERT INTO t1 (v) VALUES (?)", fmt.Sprintf("w%d-%d", w, i)); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("writer failed: %v", err)
	}
	var n int
	if err := d.SQL().QueryRow("SELECT count(*) FROM t1").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != writers*perWriter {
		t.Errorf("rows = %d, want %d", n, writers*perWriter)
	}
}

// A second handle on the same file (as an offline CLI would hold while the CP
// runs) waits on busy_timeout instead of failing.
func TestSecondHandleSeesCommittedRows(t *testing.T) {
	path := dbPath(t)
	d := openT(t, path, mig1)
	if _, err := d.SQL().Exec("INSERT INTO t1 (v) VALUES ('live')"); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(context.Background(), path, []Migration{mig1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	var v string
	if err := ro.SQL().QueryRow("SELECT v FROM t1").Scan(&v); err != nil || v != "live" {
		t.Fatalf("read = %q, %v", v, err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	d, err := Open(context.Background(), dbPath(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
}

// TestOpenReadOnlyAllowNewer: a reader that only reads its own tables may
// tolerate IDs a newer binary applied. AllowNewer decides per unknown ID; an
// ID it refuses still trips the guard, and the file is never modified.
func TestOpenReadOnlyAllowNewer(t *testing.T) {
	path := dbPath(t)
	d := openT(t, path, mig1, mig2, mig3)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnlyWith(context.Background(), path, []Migration{mig1}, ReadOnlyOptions{
		AllowNewer: func(id string) bool { return id != "t/0001" },
	})
	if err != nil {
		t.Fatalf("OpenReadOnlyWith tolerating newer IDs: %v", err)
	}
	if got := ro.Applied(); !slices.Equal(got, []string{"t/0001", "t/0002", "t/0003"}) {
		t.Errorf("Applied = %v, want every ID the file holds", got)
	}
	if _, err := ro.SQL().Exec("INSERT INTO t1 (v) VALUES ('x')"); err == nil {
		t.Error("write through the tolerant read-only handle succeeded")
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = OpenReadOnlyWith(context.Background(), path, []Migration{mig1}, ReadOnlyOptions{
		AllowNewer: func(id string) bool { return id != "t/0003" },
	})
	if err == nil || !strings.Contains(err.Error(), "t/0003") {
		t.Errorf("OpenReadOnlyWith refusing t/0003 = %v, want an error naming it", err)
	}
	// A nil AllowNewer is plain OpenReadOnly.
	if _, err := OpenReadOnlyWith(context.Background(), path, []Migration{mig1}, ReadOnlyOptions{}); err == nil {
		t.Error("OpenReadOnlyWith without AllowNewer accepted unknown IDs")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("database bytes changed")
	}
}
