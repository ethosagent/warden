package adminaudit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/ethosagent/warden/internal/cpstate"
)

// StateDBFileName is the control plane's state database inside --state-dir.
const StateDBFileName = "warden-cp.db"

// cliActorPrefix prefixes the OS user in a CLI entry's actor.
const cliActorPrefix = "cli:"

// osUserName returns the OS user running the CLI ("" when unknown). Tests
// replace it.
var osUserName = func() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// OpenForCLI is the shared opener of the offline CLIs that write admin
// changes (policy import, worker tokens, block list). It opens
// <stateDir>/warden-cp.db through cpstate with migs (the caller's full CP
// migration list, so the downgrade guard sees every feature's migrations;
// Migrations() is added when absent).
//
// It returns a nil Recorder and a nil error, creating nothing, when there is
// no database file, no admin_audit table (a state dir from an older binary)
// or no rows (admin audit was never enabled here): the caller prints a
// one-line notice and skips the append. Otherwise it loads the signing key
// from keyFile (default <stateDir>/cp-audit.key) and the HMAC key beside it,
// never creating either, and runs the control plane's key check; any failure
// is an error, so the CLI exits non-zero and writes nothing. The Recorder
// stamps actor cli:<os user> (cli:unknown when the user is unknown) and
// auth_method cli on every entry. closeFn closes the database.
func OpenForCLI(ctx context.Context, stateDir, keyFile string, migs []cpstate.Migration) (rec Recorder, closeFn func() error, err error) {
	if stateDir == "" {
		return nil, nil, errors.New("adminaudit: OpenForCLI needs a state dir")
	}
	path := filepath.Join(stateDir, StateDBFileName)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("adminaudit: stat %s: %w", path, err)
	}
	all := withOwnMigrations(migs)
	// Probe read-only first so a state dir without audit is left untouched.
	has, err := hasRows(ctx, path, all)
	if err != nil || !has {
		return nil, nil, err
	}
	db, err := cpstate.Open(ctx, path, all)
	if err != nil {
		return nil, nil, err
	}
	if keyFile == "" {
		keyFile = DefaultKeyPath(stateDir)
	}
	// The chain has rows, so Open never creates a key file here.
	s, err := Open(ctx, db, OpenOptions{KeyFile: keyFile})
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return &cliRecorder{store: s, actor: CLIActor()}, db.Close, nil
}

// CLIActor is the identity an offline CLI acts as: cli:<os user>, or
// cli:unknown when the user is unknown. It is the actor of every entry the
// OpenForCLI Recorder writes; CLIs stamp it on what else they write (a policy
// version's author) so both name the same person.
func CLIActor() string {
	name := osUserName()
	if name == "" {
		name = "unknown"
	}
	return cliActorPrefix + name
}

// withOwnMigrations returns migs plus any adminaudit migration it lacks.
func withOwnMigrations(migs []cpstate.Migration) []cpstate.Migration {
	have := make(map[string]bool, len(migs))
	for _, m := range migs {
		have[m.ID] = true
	}
	out := append([]cpstate.Migration(nil), migs...)
	for _, m := range Migrations() {
		if !have[m.ID] {
			out = append(out, m)
		}
	}
	return out
}

// hasRows reports whether the database at path has an admin_audit table with
// at least one row, opening it read-only.
func hasRows(ctx context.Context, path string, migs []cpstate.Migration) (bool, error) {
	ro, err := cpstate.OpenReadOnly(ctx, path, migs)
	if err != nil {
		return false, err
	}
	defer func() { _ = ro.Close() }()
	var tables int
	if err := ro.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='admin_audit'").Scan(&tables); err != nil {
		return false, fmt.Errorf("adminaudit: inspect %s: %w", path, err)
	}
	if tables == 0 {
		return false, nil
	}
	var rows int
	if err := ro.SQL().QueryRowContext(ctx, "SELECT count(*) FROM (SELECT 1 FROM admin_audit LIMIT 1)").Scan(&rows); err != nil {
		return false, fmt.Errorf("adminaudit: read %s: %w", path, err)
	}
	return rows > 0, nil
}

// cliRecorder records through the store with the CLI's actor and auth method.
type cliRecorder struct {
	store *Store
	actor string
}

func (r *cliRecorder) Record(ctx context.Context, in Input) (Entry, error) {
	in.Actor = Actor{Sub: r.actor}
	in.AuthMethod = AuthMethodCLI
	if in.ActorRole == "" {
		in.ActorRole = AuthMethodCLI
	}
	return r.store.Record(ctx, in)
}
