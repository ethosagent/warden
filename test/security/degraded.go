package security

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Helpers of the degraded-mode and restart cases (W-P2-SECT-07). Stopping and
// restarting the control plane and a worker is in lifecycle.go; what is here
// breaks a dependency of a running component (a table of the control plane's
// state database) and forges what a restarting worker finds on its disk.

// stateSQL opens a second, writable handle on the control plane's state
// database, the way an operator's offline tool (or a failing disk) would reach
// it. The control plane keeps its own handle; both see every committed change.
func (s *Stack) stateSQL(tb testing.TB) *sql.DB {
	tb.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(s.CP.StateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		tb.Fatalf("security: open the CP state db for writing: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return db.SQL()
}

func (s *Stack) execState(tb testing.TB, db *sql.DB, stmt string) {
	tb.Helper()
	if _, err := db.ExecContext(context.Background(), stmt); err != nil {
		tb.Fatalf("security: %s: %v", stmt, err)
	}
}

// FailWrites makes every INSERT and UPDATE on table fail inside the control
// plane's state database, as a full disk or a read-only mount would, and
// returns the function that brings the table back. Reads keep working. The
// failure is a pair of triggers on the table: nothing in the control plane
// knows about them, so the code that answers the failure is the shipped code.
// The restore function is also registered as a cleanup and is idempotent.
func (s *Stack) FailWrites(tb testing.TB, table string) (restore func()) {
	tb.Helper()
	db := s.stateSQL(tb)
	ins, upd := "sect_down_ins_"+table, "sect_down_upd_"+table
	s.execState(tb, db, `CREATE TRIGGER `+ins+` BEFORE INSERT ON `+table+` BEGIN SELECT RAISE(ABORT, 'store down'); END`)
	s.execState(tb, db, `CREATE TRIGGER `+upd+` BEFORE UPDATE ON `+table+` BEGIN SELECT RAISE(ABORT, 'store down'); END`)
	restore = func() {
		tb.Helper()
		s.execState(tb, db, `DROP TRIGGER IF EXISTS `+ins)
		s.execState(tb, db, `DROP TRIGGER IF EXISTS `+upd)
	}
	tb.Cleanup(restore)
	return restore
}

// HideTable renames table away in the control plane's state database, so every
// read and write of it fails with "no such table", and returns the function that
// renames it back. It works on a running control plane (the rename commits from
// a second connection) and on a stopped one (the next boot finds it missing).
// The restore function is also registered as a cleanup and renames only once.
func (s *Stack) HideTable(tb testing.TB, table string) (restore func()) {
	tb.Helper()
	db := s.stateSQL(tb)
	s.execState(tb, db, `ALTER TABLE `+table+` RENAME TO `+table+`_hidden`)
	done := false
	restore = func() {
		tb.Helper()
		if done {
			return
		}
		done = true
		s.execState(tb, db, `ALTER TABLE `+table+`_hidden RENAME TO `+table)
	}
	tb.Cleanup(restore)
	return restore
}

// CachePath is where w keeps its last-known-good bundle.
func CachePath(w *Worker) string { return config.BundleCachePath(w.StateDir) }

// CachedBundle reads w's bundle cache.
func (s *Stack) CachedBundle(tb testing.TB, w *Worker) []byte {
	tb.Helper()
	raw, err := os.ReadFile(CachePath(w))
	if err != nil {
		tb.Fatalf("security: read %s's bundle cache: %v", w.Name, err)
	}
	return raw
}

// WriteBundleCache replaces w's bundle cache with raw, as a process with
// access to the worker's state directory would. w must not be running.
func (s *Stack) WriteBundleCache(tb testing.TB, w *Worker, raw []byte) {
	tb.Helper()
	if w.cancel != nil {
		tb.Fatalf("security: %s is running; stop it before changing its bundle cache", w.Name)
	}
	if err := os.WriteFile(CachePath(w), raw, 0o600); err != nil {
		tb.Fatalf("security: write %s's bundle cache: %v", w.Name, err)
	}
}

// CachedBundleValue verifies w's cache against the pins and returns the bundle.
func (s *Stack) CachedBundleValue(tb testing.TB, w *Worker) bundle.Bundle {
	tb.Helper()
	v, err := bundle.Verify(s.CachedBundle(tb, w), s.pins(), bundle.State{},
		bundle.Options{Now: s.Clock.Now(), Skew: bundleSkew, AllowMissingCredentials: true})
	if err != nil {
		tb.Fatalf("security: %s's bundle cache does not verify: %v", w.Name, err)
	}
	return v.Bundle
}

// LogMark is the length of the logs so far; LogsSince returns what was logged
// after it.
func (s *Stack) LogMark() int { return len(s.logs.String()) }

// LogsSince returns the log output written after mark.
func (s *Stack) LogsSince(mark int) string { return s.logs.String()[mark:] }

// AwaitWorkerSeq waits until w reports a bundle seq of at least min. The gauge
// follows the worker's clock, so the wait advances the shared clock.
func (s *Stack) AwaitWorkerSeq(tb testing.TB, w *Worker, min float64) {
	tb.Helper()
	s.EventuallyAdvance(w.Name+" to report warden_bundle_seq >= "+itoa(int(min)), time.Second, func() bool {
		v, ok := s.TryMetric(w, "warden_bundle_seq", nil)
		return ok && v >= min
	})
}

// decodeAccessToken is the access token of a 200 token reply, registered with
// the leak invariant ("" when the reply carries none).
func decodeAccessToken(tb testing.TB, s *Stack, r Reply) string {
	tb.Helper()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if !decodeJSON(r.Body, &out) || out.AccessToken == "" {
		return ""
	}
	s.Track("warden token", out.AccessToken)
	return out.AccessToken
}
