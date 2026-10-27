package adminaudit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/cpstate"
)

// otherMigration stands in for a migration another CP feature (sessions,
// policy versions, ...) applied to the same file.
var otherMigration = cpstate.Migration{ID: "other/0001", SQL: "CREATE TABLE other_feature (id INTEGER PRIMARY KEY)"}

// cpMigrations is the full list a CP binary registers in these tests.
func cpMigrations() []cpstate.Migration {
	return append([]cpstate.Migration{otherMigration}, Migrations()...)
}

// stateDirWith creates a state dir whose warden-cp.db was migrated with migs.
func stateDirWith(t *testing.T, migs []cpstate.Migration) (string, *cpstate.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := cpstate.Open(context.Background(), filepath.Join(dir, StateDBFileName), migs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return dir, db
}

// seededStateDir is a state dir on which the CP ran with audit enabled: a
// genesis row, n entries and the default key files.
func seededStateDir(t *testing.T, n int) (string, *cpstate.DB, *Store) {
	t.Helper()
	dir, db := stateDirWith(t, cpMigrations())
	s := mustOpenKeyed(t, db, DefaultKeyPath(dir), "")
	record(t, s, n)
	return dir, db, s
}

func openCLI(t *testing.T, stateDir, keyFile string) (Recorder, error) {
	t.Helper()
	rec, closeFn, err := OpenForCLI(context.Background(), stateDir, keyFile, cpMigrations())
	if closeFn != nil {
		t.Cleanup(func() { _ = closeFn() })
	}
	return rec, err
}

func cliInput() Input {
	return Input{Action: "worker_token.create", Target: "worker_token", TargetRef: "token:w1", Outcome: OutcomeOK}
}

func setCLIUser(t *testing.T, name string) {
	t.Helper()
	old := osUserName
	osUserName = func() string { return name }
	t.Cleanup(func() { osUserName = old })
}

// TestOpenForCLI covers the opener's cases: no DB file, no table, an empty
// table, a seeded chain, and a seeded chain whose key is missing or wrong.
func TestOpenForCLI(t *testing.T) {
	t.Run("no database file", func(t *testing.T) {
		dir := t.TempDir()
		rec, err := openCLI(t, dir, "")
		if rec != nil || err != nil {
			t.Fatalf("OpenForCLI = %v, %v; want nil, nil", rec, err)
		}
		if _, serr := os.Stat(filepath.Join(dir, StateDBFileName)); !errors.Is(serr, os.ErrNotExist) {
			t.Error("OpenForCLI created warden-cp.db")
		}
		if _, serr := os.Stat(DefaultKeyPath(dir)); !errors.Is(serr, os.ErrNotExist) {
			t.Error("OpenForCLI created a key file")
		}
	})
	t.Run("no admin_audit table", func(t *testing.T) {
		dir, db := stateDirWith(t, []cpstate.Migration{otherMigration})
		rec, err := openCLI(t, dir, "")
		if rec != nil || err != nil {
			t.Fatalf("OpenForCLI = %v, %v; want nil, nil", rec, err)
		}
		var n int
		if err := db.SQL().QueryRow("SELECT count(*) FROM sqlite_master WHERE name='admin_audit'").Scan(&n); err != nil || n != 0 {
			t.Errorf("admin_audit table created by the CLI (n=%d, %v)", n, err)
		}
		if _, serr := os.Stat(DefaultKeyPath(dir)); !errors.Is(serr, os.ErrNotExist) {
			t.Error("OpenForCLI created a key file")
		}
	})
	t.Run("empty table", func(t *testing.T) {
		dir, db := stateDirWith(t, cpMigrations())
		rec, err := openCLI(t, dir, "")
		if rec != nil || err != nil {
			t.Fatalf("OpenForCLI = %v, %v; want nil, nil", rec, err)
		}
		if n := rowCount(t, db, "admin_audit"); n != 0 {
			t.Errorf("rows = %d, want 0", n)
		}
		if _, serr := os.Stat(DefaultKeyPath(dir)); !errors.Is(serr, os.ErrNotExist) {
			t.Error("OpenForCLI created a key file")
		}
	})
	t.Run("seeded chain appends one cli row", func(t *testing.T) {
		setCLIUser(t, "alice")
		dir, db, s := seededStateDir(t, 1)
		rec, err := openCLI(t, dir, "")
		if err != nil || rec == nil {
			t.Fatalf("OpenForCLI = %v, %v; want a recorder", rec, err)
		}
		e, err := rec.Record(context.Background(), cliInput())
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if e.AuthMethod != AuthMethodCLI || e.ActorID != s.actorID("cli:alice") || e.KeyID != s.KeyID() {
			t.Errorf("cli entry = auth %s actor %s key %s; want cli, HMAC(cli:alice), %s", e.AuthMethod, e.ActorID, e.KeyID, s.KeyID())
		}
		items, err := s.List(context.Background(), Filter{Actor: "cli:alice"}, 10, 0)
		if err != nil || len(items) != 1 || items[0].Actor.Sub != "cli:alice" {
			t.Errorf("List(cli:alice) = %+v, %v; want one row with sub cli:alice", items, err)
		}
		if n := rowCount(t, db, "admin_audit"); n != 3 {
			t.Errorf("rows = %d, want 3", n)
		}
		if res := verify(t, s, VerifyOptions{HMACKey: s.hmacKey}); !res.OK {
			t.Errorf("Verify = %+v", res)
		}
	})
	t.Run("caller fields cannot override actor or auth method", func(t *testing.T) {
		setCLIUser(t, "")
		dir, _, s := seededStateDir(t, 0)
		rec, err := openCLI(t, dir, DefaultKeyPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		in := cliInput()
		in.Actor = Actor{Sub: "someone-else"}
		in.AuthMethod = AuthMethodOIDC
		e, err := rec.Record(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if e.AuthMethod != AuthMethodCLI || e.ActorID != s.actorID("cli:unknown") {
			t.Errorf("entry = auth %s actor %s; want cli and HMAC(cli:unknown)", e.AuthMethod, e.ActorID)
		}
	})
	t.Run("missing key file", func(t *testing.T) {
		dir, db, s := seededStateDir(t, 1)
		if err := os.Remove(DefaultKeyPath(dir)); err != nil {
			t.Fatal(err)
		}
		rec, err := openCLI(t, dir, "")
		if rec != nil || !errors.Is(err, ErrKeyFileMissing) || !strings.Contains(err.Error(), s.KeyID()) {
			t.Fatalf("OpenForCLI = %v, %v; want nil and ErrKeyFileMissing naming %s", rec, err, s.KeyID())
		}
		if _, serr := os.Stat(DefaultKeyPath(dir)); !errors.Is(serr, os.ErrNotExist) {
			t.Error("OpenForCLI minted a key while rows exist")
		}
		if n := rowCount(t, db, "admin_audit"); n != 2 {
			t.Errorf("rows = %d, want 2 (nothing written)", n)
		}
	})
	t.Run("wrong key file", func(t *testing.T) {
		dir, db, _ := seededStateDir(t, 1)
		other, _ := otherKey(t, DefaultKeyPath(dir))
		rec, err := openCLI(t, dir, other)
		if rec != nil || !errors.Is(err, ErrKeyIDMismatch) {
			t.Fatalf("OpenForCLI = %v, %v; want nil and ErrKeyIDMismatch", rec, err)
		}
		if n := rowCount(t, db, "admin_audit"); n != 2 {
			t.Errorf("rows = %d, want 2", n)
		}
	})
	t.Run("empty state dir", func(t *testing.T) {
		if _, _, err := OpenForCLI(context.Background(), "", "", cpMigrations()); err == nil {
			t.Error("OpenForCLI with an empty state dir must fail")
		}
	})
	t.Run("unreadable database", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, StateDBFileName), []byte(strings.Repeat("not a db ", 512)), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec, err := openCLI(t, dir, ""); rec != nil || err == nil {
			t.Errorf("OpenForCLI on a corrupt db = %v, %v; want an error", rec, err)
		}
	})
}

// TestOpenForCLIMigrationList: the opener registers the caller's full
// migration list, so a DB another CP feature migrated opens; a partial list
// trips the cpstate downgrade guard and writes nothing.
func TestOpenForCLIMigrationList(t *testing.T) {
	dir, db, _ := seededStateDir(t, 1)
	rec, closeFn, err := OpenForCLI(context.Background(), dir, "", Migrations())
	if closeFn != nil {
		_ = closeFn()
	}
	if rec != nil || err == nil || !strings.Contains(err.Error(), otherMigration.ID) {
		t.Fatalf("OpenForCLI with a partial list = %v, %v; want an error naming %s", rec, err, otherMigration.ID)
	}
	// The full list without adminaudit's own still works: the opener adds them.
	rec, err = openCLIWith(t, dir, []cpstate.Migration{otherMigration})
	if err != nil || rec == nil {
		t.Fatalf("OpenForCLI without adminaudit's migrations = %v, %v", rec, err)
	}
	if _, err := rec.Record(context.Background(), cliInput()); err != nil {
		t.Fatal(err)
	}
	if n := rowCount(t, db, "admin_audit"); n != 3 {
		t.Errorf("rows = %d, want 3", n)
	}
}

func openCLIWith(t *testing.T, dir string, migs []cpstate.Migration) (Recorder, error) {
	t.Helper()
	rec, closeFn, err := OpenForCLI(context.Background(), dir, "", migs)
	if closeFn != nil {
		t.Cleanup(func() { _ = closeFn() })
	}
	return rec, err
}

// TestOpenForCLIInterleaved: the CP store and a CLI recorder on separate
// handles to one file append concurrently; the chain verifies with no seq gap.
func TestOpenForCLIInterleaved(t *testing.T) {
	setCLIUser(t, "bob")
	dir, db, cp := seededStateDir(t, 0)
	cli, err := openCLI(t, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	const each = 20
	var wg sync.WaitGroup
	errs := make(chan error, 2*each)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range each {
			if _, err := cp.Record(context.Background(), input(i)); err != nil {
				errs <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range each {
			if _, err := cli.Record(context.Background(), cliInput()); err != nil {
				errs <- err
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Record: %v", err)
	}
	if n := rowCount(t, db, "admin_audit"); n != 1+2*each {
		t.Fatalf("rows = %d, want %d", n, 1+2*each)
	}
	res := verify(t, cp, VerifyOptions{HMACKey: cp.hmacKey})
	if !res.OK || res.HeadSeq != 1+2*each {
		t.Errorf("Verify = %+v, want ok with head %d", res, 1+2*each)
	}
}
