package cpstate

import (
	"context"
	"fmt"
	"time"
)

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
    id         TEXT    PRIMARY KEY,
    applied_at INTEGER NOT NULL
)`

func validateMigrations(migs []Migration) error {
	seen := make(map[string]struct{}, len(migs))
	for _, m := range migs {
		if m.ID == "" {
			return fmt.Errorf("cpstate: migration with empty ID")
		}
		if m.SQL == "" {
			return fmt.Errorf("cpstate: migration %s has no SQL", m.ID)
		}
		if _, dup := seen[m.ID]; dup {
			return fmt.Errorf("cpstate: duplicate migration ID %s", m.ID)
		}
		seen[m.ID] = struct{}{}
	}
	return nil
}

// appliedIDs returns the IDs recorded in schema_migrations, oldest first. A
// file without that table (brand new, or created by nothing yet) reports none.
// It only reads, so the unknown-ID check never alters the file.
func (d *DB) appliedIDs(ctx context.Context) ([]string, error) {
	var n int
	err := d.db.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&n)
	if err != nil {
		return nil, fmt.Errorf("cpstate: inspect %s: %w", d.path, err)
	}
	if n == 0 {
		return nil, nil
	}
	rows, err := d.db.QueryContext(ctx, "SELECT id FROM schema_migrations ORDER BY applied_at, rowid")
	if err != nil {
		return nil, fmt.Errorf("cpstate: read schema_migrations in %s: %w", d.path, err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("cpstate: read schema_migrations in %s: %w", d.path, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cpstate: read schema_migrations in %s: %w", d.path, err)
	}
	return ids, nil
}

// checkKnown is the downgrade guard: every ID the file holds must be one this
// binary registers.
func checkKnown(path string, applied []string, migs []Migration) error {
	reg := make(map[string]struct{}, len(migs))
	for _, m := range migs {
		reg[m.ID] = struct{}{}
	}
	for _, id := range applied {
		if _, ok := reg[id]; !ok {
			return fmt.Errorf("cpstate: %s holds migration %q that this binary does not register; "+
				"run a Warden version that includes it (the file was not modified)", path, id)
		}
	}
	return nil
}

// migrate applies each migration in migs that the file lacks, in order. Each
// migration and its schema_migrations row commit in one transaction, so a
// failure rolls back both and earlier migrations stay intact.
func (d *DB) migrate(ctx context.Context, migs []Migration, applied []string) error {
	if _, err := d.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("cpstate: create schema_migrations in %s: %w", d.path, err)
	}
	have := make(map[string]struct{}, len(applied))
	for _, id := range applied {
		have[id] = struct{}{}
	}
	d.applied = nil
	for _, m := range migs {
		if _, ok := have[m.ID]; ok {
			continue
		}
		if err := d.apply(ctx, m); err != nil {
			return err
		}
		d.applied = append(d.applied, m.ID)
	}
	return nil
}

func (d *DB) apply(ctx context.Context, m Migration) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cpstate: migration %s: begin: %w", m.ID, err)
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("cpstate: migration %s: %w", m.ID, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)", m.ID, time.Now().Unix()); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("cpstate: migration %s: record: %w", m.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cpstate: migration %s: commit: %w", m.ID, err)
	}
	return nil
}

// SchemaVersion reports the schema version of the open database: the number of
// migrations recorded in schema_migrations. Migrations are append-only and
// identified by ID, so the count grows by one per applied migration and a
// restore can compare it with the binary's StateMigrations. A file with no
// migrations reports 0.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	ids, err := d.appliedIDs(ctx)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}
