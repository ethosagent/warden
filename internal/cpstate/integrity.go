package cpstate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrIntegrity is returned (wrapped) by IntegrityCheck when SQLite reports a
// problem with the file, or the file is not a database at all.
var ErrIntegrity = errors.New("database integrity check failed")

// IntegrityCheck runs the full `PRAGMA integrity_check` (not the cheaper
// quick_check Open uses) on the SQLite file at path, opened read-only so it
// never writes to the file. It applies no migrations and does not care which
// feature owns the tables, so restore can vet the alert and fleet databases
// as well as warden-cp.db. A missing file is an error; any result other than
// a single "ok" row returns ErrIntegrity naming path and the first finding.
func IntegrityCheck(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cpstate: integrity check %s: %w", path, err)
	}
	d, err := openSQL(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = d.db.Close() }()
	rows, err := d.db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("cpstate: %s: %w: %v", path, ErrIntegrity, err)
	}
	defer func() { _ = rows.Close() }()
	var first string
	n := 0
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("cpstate: %s: %w: %v", path, ErrIntegrity, err)
		}
		if n == 0 {
			first = line
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cpstate: %s: %w: %v", path, ErrIntegrity, err)
	}
	if n != 1 || !strings.EqualFold(first, "ok") {
		return fmt.Errorf("cpstate: %s: %w: %s", path, ErrIntegrity, first)
	}
	return nil
}
