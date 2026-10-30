// Package metastore is the SQLite keys.MetaStore: the signing_keys table on
// the control plane's state database (cpstate). It holds public metadata only
// — kid, purpose, algorithm, state, the public JWK, timestamps — never private
// key bytes; those live in the keys.PrivateKeyStore. Every write runs in a
// BEGIN IMMEDIATE transaction, so concurrent writers in this process or
// another (the CLI) are serialised by the database.
package metastore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
)

// MigrationID is the id of the signing_keys migration.
const MigrationID = "signing_keys/0001"

// Migrations returns the signing_keys migration. It is Optional: the
// control plane registers it always (so the downgrade guard knows it) and
// applies it only with keys.enabled, via cpstate.Enable(…, MigrationID). A
// control plane without keys creates no table.
//
// The partial unique indexes allow at most one active and one next row per
// purpose, which is what keeps two writers from forking the lifecycle.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID:       MigrationID,
		Optional: true,
		SQL: `CREATE TABLE signing_keys (
  kid           TEXT PRIMARY KEY,
  purpose       TEXT NOT NULL,
  alg           TEXT NOT NULL,
  state         TEXT NOT NULL CHECK (state IN ('next','active','retired','revoked','destroyed')),
  public_jwk    TEXT NOT NULL,
  store_backend TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  publish_at    INTEGER NULL,
  activate_at   INTEGER NULL,
  retire_at     INTEGER NULL,
  destroyed_at  INTEGER NULL,
  created_by    TEXT NOT NULL
);
CREATE INDEX signing_keys_purpose ON signing_keys (purpose);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (purpose) WHERE state = 'active';
CREATE UNIQUE INDEX signing_keys_one_next ON signing_keys (purpose) WHERE state = 'next';`,
	}}
}

// Store implements keys.MetaStore over a cpstate database opened with the
// signing_keys migration enabled.
type Store struct {
	db *sql.DB
}

var _ keys.MetaStore = (*Store)(nil)

// New returns a Store over db. The signing_keys table must exist.
func New(db *cpstate.DB) *Store { return &Store{db: db.SQL()} }

const columns = `kid, purpose, alg, state, public_jwk, store_backend, created_at, publish_at, activate_at, retire_at, destroyed_at, created_by`

// List returns every row, oldest first.
func (s *Store) List(ctx context.Context) ([]keys.Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM signing_keys ORDER BY created_at, rowid`)
	if err != nil {
		return nil, fmt.Errorf("metastore: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []keys.Record
	for rows.Next() {
		rec, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metastore: list: %w", err)
	}
	return out, nil
}

func scan(r *sql.Rows) (keys.Record, error) {
	var (
		rec                                  keys.Record
		state, jwk                           string
		created                              int64
		publish, activate, retire, destroyed sql.NullInt64
	)
	if err := r.Scan(&rec.KID, &rec.Purpose, &rec.Alg, &state, &jwk, &rec.StoreBackend,
		&created, &publish, &activate, &retire, &destroyed, &rec.CreatedBy); err != nil {
		return keys.Record{}, fmt.Errorf("metastore: scan: %w", err)
	}
	pub, err := keys.ParseJWK([]byte(jwk))
	if err != nil {
		return keys.Record{}, fmt.Errorf("metastore: row %s: public_jwk: %w", rec.KID, err)
	}
	rec.State = keys.State(state)
	rec.PublicJWK = pub
	rec.CreatedAt = time.Unix(created, 0).UTC()
	rec.PublishAt = fromNull(publish)
	rec.ActivateAt = fromNull(activate)
	rec.RetireAt = fromNull(retire)
	rec.DestroyedAt = fromNull(destroyed)
	return rec, nil
}

func toNull(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

func fromNull(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0).UTC()
}

// Insert adds one row; a duplicate kid or a second active/next row for the
// purpose is keys.ErrConflict.
func (s *Store) Insert(ctx context.Context, rec keys.Record) error {
	return s.immediate(ctx, func(conn *sql.Conn) error { return insert(ctx, conn, rec) })
}

// InsertIfEmpty adds recs only when purpose has no rows, in one transaction.
func (s *Store) InsertIfEmpty(ctx context.Context, purpose string, recs []keys.Record) (bool, error) {
	inserted := false
	err := s.immediate(ctx, func(conn *sql.Conn) error {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM signing_keys WHERE purpose = ?`, purpose).Scan(&n); err != nil {
			return fmt.Errorf("metastore: count %s rows: %w", purpose, err)
		}
		if n > 0 {
			return nil
		}
		for _, r := range recs {
			if r.Purpose != purpose {
				return fmt.Errorf("metastore: row %s is purpose %s, not %s", r.KID, r.Purpose, purpose)
			}
			if err := insert(ctx, conn, r); err != nil {
				return err
			}
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

func insert(ctx context.Context, conn *sql.Conn, rec keys.Record) error {
	jwk, err := json.Marshal(rec.PublicJWK)
	if err != nil {
		return fmt.Errorf("metastore: encode public_jwk: %w", err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO signing_keys (`+columns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.KID, rec.Purpose, rec.Alg, string(rec.State), string(jwk), rec.StoreBackend,
		rec.CreatedAt.Unix(), toNull(rec.PublishAt), toNull(rec.ActivateAt), toNull(rec.RetireAt), toNull(rec.DestroyedAt), rec.CreatedBy)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s %s", keys.ErrConflict, rec.Purpose, rec.State)
		}
		return fmt.Errorf("metastore: insert %s: %w", rec.KID, err)
	}
	return nil
}

// UpdateState is a compare-and-swap on the state column; it stamps the
// timestamp that belongs to the new state. A row that is not in from, or is
// absent, changes nothing and reports false. A change that would break the
// one-active / one-next invariant is keys.ErrConflict.
func (s *Store) UpdateState(ctx context.Context, kid string, from, to keys.State, at time.Time) (bool, error) {
	col, ok := stampColumn[to]
	if !ok {
		return false, fmt.Errorf("metastore: no timestamp for state %q", to)
	}
	changed := false
	err := s.immediate(ctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx, `UPDATE signing_keys SET state = ?, `+col+` = ? WHERE kid = ? AND state = ?`,
			string(to), at.Unix(), kid, string(from))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				return fmt.Errorf("%w: %s", keys.ErrConflict, to)
			}
			return fmt.Errorf("metastore: update %s: %w", kid, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("metastore: update %s: %w", kid, err)
		}
		changed = n == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

// stampColumn is the timestamp column each target state writes.
var stampColumn = map[keys.State]string{
	keys.StateNext:      "publish_at",
	keys.StateActive:    "activate_at",
	keys.StateRetired:   "retire_at",
	keys.StateRevoked:   "retire_at",
	keys.StateDestroyed: "destroyed_at",
}

// DataVersion returns the database's data version: a counter SQLite bumps on
// every committed write, including writes made by other processes through their
// own connections. The key manager polls it to notice the keys CLI's writes
// without re-reading the table every two seconds.
func (s *Store) DataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("metastore: data_version: %w", err)
	}
	return v, nil
}

// immediate runs fn in a BEGIN IMMEDIATE transaction on one connection, so its
// reads and writes see no other writer. It commits when fn returns nil and
// rolls back otherwise.
func (s *Store) immediate(ctx context.Context, fn func(conn *sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("metastore: connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("metastore: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("metastore: commit: %w", err)
	}
	committed = true
	return nil
}
