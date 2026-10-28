package cpstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrBackupDestExists is returned (wrapped) when the backup destination is
// already present. The existing file is never touched.
var ErrBackupDestExists = errors.New("backup destination exists")

// BackupTo writes a consistent, compacted copy of the whole database
// (every table, whichever feature registered it) to dst with VACUUM INTO. See
// VacuumInto for the destination rules.
func (d *DB) BackupTo(ctx context.Context, dst string) error {
	return VacuumInto(ctx, d.db, dst)
}

// VacuumInto copies the database behind db to dst with `VACUUM INTO ?` on db
// itself. The stores that share this helper (cpstate, the alert store, the
// fleet store) hold a single connection, so a copy in progress makes
// concurrent writers queue behind it instead of failing with SQLITE_BUSY, and
// the connection is held only for the duration of the statement.
//
// dst must be a non-empty path whose parent directory exists and that does
// not exist yet. It is claimed exclusively with mode 0600 before any SQL runs;
// on any failure the partial dst is removed. Errors name dst, never row
// contents.
func VacuumInto(ctx context.Context, db *sql.DB, dst string) error {
	if dst == "" {
		return errors.New("cpstate: backup: empty destination path")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cpstate: backup %s: %w", dst, err)
	}
	if fi, err := os.Stat(filepath.Dir(dst)); err != nil {
		return fmt.Errorf("cpstate: backup %s: parent directory: %w", dst, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("cpstate: backup %s: parent is not a directory", dst)
	}
	// O_EXCL claims the name atomically; SQLite accepts an empty existing file.
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("cpstate: backup %s: %w", dst, ErrBackupDestExists)
		}
		return fmt.Errorf("cpstate: backup %s: %w", dst, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("cpstate: backup %s: %w", dst, err)
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("cpstate: backup %s: %w", dst, err)
	}
	// The umask can only remove bits from the requested mode; make it exact.
	if err := os.Chmod(dst, fileMode); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("cpstate: backup %s: chmod: %w", dst, err)
	}
	return nil
}
