// Package cpstate is the control plane's durable state store: one SQLite
// database at <state-dir>/warden-cp.db plus a forward-only migration runner.
//
// The package owns no tables. Each feature store (sessions, pending logins,
// admin audit, policy versions, worker tokens, ...) declares its own
// Migration values with a globally unique ID such as "sessions/0001" and
// passes them to Open; the runner applies the ones the file does not have yet,
// in the order given, one transaction each. Opening a file that holds a
// migration this binary does not register fails (downgrade guard), so an older
// binary can never run against a schema it does not understand.
package cpstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// fileMode is the mode of a newly created database file. The file holds
// session hashes and other control-plane secrets-adjacent state, so only the
// owner may read it. SQLite gives the -wal and -shm files the same mode.
const fileMode os.FileMode = 0o600

// corruptHint is appended to every error that means the file is unusable, so
// the operator knows the safe next step instead of deleting state blindly.
const corruptHint = "restore warden-cp.db from backup or move the file aside to start with empty state"

// Migration is one forward-only schema step. ID must be unique across every
// feature that registers migrations (convention: "<feature>/<nnnn>"); SQL may
// hold several statements and runs in a single transaction together with the
// schema_migrations row that records it.
type Migration struct {
	ID  string
	SQL string
	// Optional marks a feature-gated migration: the downgrade guard knows its
	// ID (a file that holds it opens fine) but Open does not apply it, so a
	// feature that is off creates no table. The feature turns it on for its
	// own Open with Enable. Applying is forward-only: once applied, the
	// migration stays recorded whatever a later Open passes.
	Optional bool
}

// Enable returns migs with the Optional flag cleared on the migrations whose
// IDs are given, so Open applies them. migs is not modified; an ID that matches
// nothing is ignored.
func Enable(migs []Migration, ids ...string) []Migration {
	out := make([]Migration, len(migs))
	copy(out, migs)
	for i := range out {
		for _, id := range ids {
			if out[i].ID == id {
				out[i].Optional = false
			}
		}
	}
	return out
}

// DB is an open control-plane state database. It wraps a single-connection
// *sql.DB (SetMaxOpenConns(1)), so every statement is serialised in-process
// and writers never see SQLITE_BUSY from each other.
type DB struct {
	db      *sql.DB
	path    string
	applied []string
	once    sync.Once
	err     error
}

// Open opens (creating it with mode 0600 when absent) the database at path,
// verifies it with PRAGMA quick_check, refuses it if it holds a migration ID
// not in migs, and applies every missing migration in the order given. A nil
// migs only ensures the schema_migrations table exists.
//
// Open is fail-closed: a file that is not a database or fails quick_check
// returns an error naming path, and the file is left as found. (Files cpstate
// created are already in WAL mode; a file switched to another journal mode by
// an external tool has its header switched back to WAL on connect, before the
// checks run, but its content is never altered.)
func Open(ctx context.Context, path string, migs []Migration) (*DB, error) {
	if err := validateMigrations(migs); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("cpstate: empty database path")
	}
	if err := createIfAbsent(path); err != nil {
		return nil, err
	}
	d, err := openSQL(path, false)
	if err != nil {
		return nil, err
	}
	if err := d.verify(ctx); err != nil {
		_ = d.db.Close()
		return nil, err
	}
	known, err := d.appliedIDs(ctx)
	if err != nil {
		_ = d.db.Close()
		return nil, err
	}
	if err := checkKnown(path, known, migs); err != nil {
		_ = d.db.Close()
		return nil, err
	}
	if err := d.migrate(ctx, migs, known); err != nil {
		_ = d.db.Close()
		return nil, err
	}
	return d, nil
}

// OpenReadOnly opens an existing database with mode=ro for offline readers
// (for example the admin-audit verifier). It applies no migrations and never
// writes, but still runs quick_check and the unknown-ID check against migs, so
// a reader built from an older schema refuses a newer file. A missing file is
// an error: read-only never creates one.
func OpenReadOnly(ctx context.Context, path string, migs []Migration) (*DB, error) {
	return OpenReadOnlyWith(ctx, path, migs, ReadOnlyOptions{})
}

// ReadOnlyOptions relaxes OpenReadOnlyWith.
type ReadOnlyOptions struct {
	// AllowNewer, when set, is asked about each ID the file holds that migs
	// does not register; true tolerates it. The downgrade guard exists so an
	// older binary never writes against a schema it does not understand; a
	// read-only reader that touches only its own tables can safely open a
	// file a newer binary migrated, as long as no newer migration changed
	// those tables (the reader refuses IDs in its own namespace). Nil keeps
	// the guard strict.
	AllowNewer func(id string) bool
}

// OpenReadOnlyWith is OpenReadOnly with options.
func OpenReadOnlyWith(ctx context.Context, path string, migs []Migration, o ReadOnlyOptions) (*DB, error) {
	if err := validateMigrations(migs); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("cpstate: open %s read-only: %w", path, err)
	}
	d, err := openSQL(path, true)
	if err != nil {
		return nil, err
	}
	if err := d.verify(ctx); err != nil {
		_ = d.db.Close()
		return nil, err
	}
	known, err := d.appliedIDs(ctx)
	if err != nil {
		_ = d.db.Close()
		return nil, err
	}
	if err := checkKnown(path, unknownToCheck(known, o.AllowNewer), migs); err != nil {
		_ = d.db.Close()
		return nil, err
	}
	d.applied = known
	return d, nil
}

// unknownToCheck drops the IDs allow tolerates (all IDs are kept with a nil
// allow). Registered IDs pass checkKnown either way, so asking allow about
// them is harmless.
func unknownToCheck(applied []string, allow func(string) bool) []string {
	if allow == nil {
		return applied
	}
	var out []string
	for _, id := range applied {
		if !allow(id) {
			out = append(out, id)
		}
	}
	return out
}

// SQL returns the underlying single-connection handle for feature stores to
// build their statements on. Callers must not Close it; use (*DB).Close.
func (d *DB) SQL() *sql.DB { return d.db }

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// Applied returns the IDs of the migrations this Open applied, in order. For
// OpenReadOnly it returns every ID the file holds. The result is a copy.
func (d *DB) Applied() []string { return append([]string(nil), d.applied...) }

// Close releases the database. It is safe to call more than once.
func (d *DB) Close() error {
	d.once.Do(func() { d.err = d.db.Close() })
	return d.err
}

// createIfAbsent creates an empty file with the final mode before SQLite
// touches it, so the database is never briefly world-readable. An existing
// file is left untouched (its mode and bytes are the operator's).
func createIfAbsent(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("cpstate: create %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cpstate: create %s: %w", path, err)
	}
	// The umask can only remove bits from the requested mode; make it exact.
	if err := os.Chmod(path, fileMode); err != nil {
		return fmt.Errorf("cpstate: chmod %s: %w", path, err)
	}
	return nil
}

func openSQL(path string, readOnly bool) (*DB, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
	}
	u := url.URL{Scheme: "file", Opaque: escapePath(path), RawQuery: q.Encode()}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("cpstate: open %s: %w", path, err)
	}
	// One connection: statements serialise in-process, matching
	// internal/integration and internal/analytics.
	db.SetMaxOpenConns(1)
	return &DB{db: db, path: path}, nil
}

// escapePath makes a filesystem path safe inside a file: URI (the characters
// ?, # and % would otherwise be read as URI syntax).
func escapePath(p string) string {
	u := url.URL{Path: p}
	return u.EscapedPath()
}

// verify runs PRAGMA quick_check. A file that is not a database fails on the
// first statement; either way the error names the path and the recovery hint.
func (d *DB) verify(ctx context.Context) error {
	rows, err := d.db.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return fmt.Errorf("cpstate: %s is not a usable database: %w (%s)", d.path, err, corruptHint)
	}
	defer func() { _ = rows.Close() }()
	var first string
	var n int
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("cpstate: quick_check %s: %w (%s)", d.path, err, corruptHint)
		}
		if n == 0 {
			first = line
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cpstate: quick_check %s: %w (%s)", d.path, err, corruptHint)
	}
	if n != 1 || first != "ok" {
		return fmt.Errorf("cpstate: quick_check failed for %s: %s (%s)", d.path, first, corruptHint)
	}
	return nil
}
