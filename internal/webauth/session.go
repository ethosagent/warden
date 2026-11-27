package webauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
)

// TouchInterval bounds how often a session's last_seen_at is written: at most
// once per interval per session, so a busy front door does not turn every read
// into a SQLite write.
const TouchInterval = time.Minute

// SessionSweepInterval is how often a consumer sweeps expired sessions.
const SessionSweepInterval = time.Minute

// AuthMethodBreakglass is the auth_method of a break-glass session. Such a
// session has no idle timeout: its absolute expiry is its only limit, so
// activity never extends it. It applies only to a table with an auth_method
// column.
const AuthMethodBreakglass = "breakglass"

// validTableName reports whether name is a plain lowercase SQL identifier
// ([a-z][a-z0-9_]*). The name is spliced into SQL, so it is checked, never
// taken from input.
func validTableName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// SessionTable names one front door's session table.
type SessionTable struct {
	// Name is the SQL table ("sessions", "portal_sessions").
	Name string
	// MigrationID is the cpstate migration that creates it ("sessions/0001").
	MigrationID string
	// AuthMethod adds the auth_method column (console sessions are oidc or
	// breakglass). Without it every session has an idle timeout and
	// Session.AuthMethod reads back empty.
	AuthMethod bool
}

func (t SessionTable) check() {
	if !validTableName(t.Name) {
		panic(fmt.Sprintf("webauth: invalid session table name %q", t.Name))
	}
}

// Migrations are the cpstate migrations that create the table, with an index
// on expires_at and one on sub.
func (t SessionTable) Migrations() []cpstate.Migration {
	t.check()
	authMethod := ""
	if t.AuthMethod {
		authMethod = "\n  auth_method  TEXT NOT NULL,"
	}
	return []cpstate.Migration{{
		ID: t.MigrationID,
		SQL: `CREATE TABLE ` + t.Name + ` (
  id_hash      TEXT PRIMARY KEY,
  iss          TEXT NOT NULL,
  sub          TEXT NOT NULL,
  email        TEXT NOT NULL,
  groups_json  TEXT NOT NULL,` + authMethod + `
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX ` + t.Name + `_expires_at ON ` + t.Name + ` (expires_at);
CREATE INDEX ` + t.Name + `_sub ON ` + t.Name + ` (sub);`,
	}}
}

// Session is one stored session. It never holds the raw id: IDHash is the hex
// sha256 of it.
type Session struct {
	IDHash     string
	Iss, Sub   string
	Email      string
	Groups     []string
	AuthMethod string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// CreateOptions tune one Create call. The zero value is the store's defaults.
type CreateOptions struct {
	// AbsoluteTTL, when positive, replaces the store's absolute lifetime for
	// this session.
	AbsoluteTTL time.Duration
}

// SessionInput is what Create records about the signed-in user. AuthMethod is
// stored only in a table with an auth_method column.
type SessionInput struct {
	Iss, Sub, Email string
	Groups          []string
	AuthMethod      string
}

// SessionStore keeps server-side sessions in one table of the cpstate
// database. Only sha256(id) is stored; the raw id lives in the browser cookie.
// Time comes from the injected clock, so expiry follows the control plane's
// clock, never the client's. Two stores on different tables never see each
// other's rows.
type SessionStore struct {
	db       *sql.DB
	table    SessionTable
	idle     time.Duration
	absolute time.Duration
	now      func() time.Time
	cols     string // the selected columns, in scanSession order
}

// NewSessionStore builds a store over table in db (a cpstate DB opened with
// table.Migrations()). A nil now uses time.Now. It panics on a table name that
// is not a plain lowercase identifier.
func NewSessionStore(db *sql.DB, table SessionTable, idle, absolute time.Duration, now func() time.Time) *SessionStore {
	table.check()
	if now == nil {
		now = time.Now
	}
	am := "''"
	if table.AuthMethod {
		am = "auth_method"
	}
	return &SessionStore{
		db: db, table: table, idle: idle, absolute: absolute, now: now,
		cols: "id_hash, iss, sub, email, groups_json, " + am + ", created_at, last_seen_at, expires_at",
	}
}

// HashID returns the hex sha256 of a raw session id.
func HashID(rawID string) string {
	sum := sha256.Sum256([]byte(rawID))
	return hex.EncodeToString(sum[:])
}

// ShortHash is the only form of a session id that may appear in logs: the
// first 8 hex characters of its hash.
func ShortHash(idHash string) string {
	if len(idHash) > 8 {
		return idHash[:8]
	}
	return idHash
}

// Table is the store's table.
func (s *SessionStore) Table() SessionTable { return s.table }

// Absolute is the store's default absolute session lifetime.
func (s *SessionStore) Absolute() time.Duration { return s.absolute }

// Idle is the store's idle timeout.
func (s *SessionStore) Idle() time.Duration { return s.idle }

// Create mints a session with a fresh 32-byte random id and returns the raw id
// for the cookie. The id is never taken from a request.
func (s *SessionStore) Create(ctx context.Context, in SessionInput, opts ...CreateOptions) (string, Session, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", Session{}, fmt.Errorf("sessions: random id: %w", err)
	}
	rawID := base64.RawURLEncoding.EncodeToString(b[:])
	groups := in.Groups
	if groups == nil {
		groups = []string{}
	}
	gj, err := json.Marshal(groups)
	if err != nil {
		return "", Session{}, fmt.Errorf("sessions: encode groups: %w", err)
	}
	now := s.now()
	absolute := s.absolute
	for _, o := range opts {
		if o.AbsoluteTTL > 0 {
			absolute = o.AbsoluteTTL
		}
	}
	authMethod := in.AuthMethod
	if !s.table.AuthMethod {
		authMethod = ""
	}
	sess := Session{
		IDHash: HashID(rawID), Iss: in.Iss, Sub: in.Sub, Email: in.Email,
		Groups: groups, AuthMethod: authMethod,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(absolute),
	}
	if s.table.AuthMethod {
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO `+s.table.Name+` (id_hash, iss, sub, email, groups_json, auth_method, created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sess.IDHash, sess.Iss, sess.Sub, sess.Email, string(gj), sess.AuthMethod,
			now.Unix(), now.Unix(), sess.ExpiresAt.Unix())
	} else {
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO `+s.table.Name+` (id_hash, iss, sub, email, groups_json, created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sess.IDHash, sess.Iss, sess.Sub, sess.Email, string(gj),
			now.Unix(), now.Unix(), sess.ExpiresAt.Unix())
	}
	if err != nil {
		return "", Session{}, fmt.Errorf("sessions: insert: %w", err)
	}
	return rawID, sess, nil
}

// Now is the store's clock.
func (s *SessionStore) Now() time.Time { return s.now() }

// SetNow replaces the store's clock (nil restores time.Now). Tests use it to
// drive expiry; call it only while no request uses the store.
func (s *SessionStore) SetNow(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// expired reports whether sess is past its idle or absolute limit at now.
func (s *SessionStore) expired(sess Session, now time.Time) bool {
	if !now.Before(sess.ExpiresAt) {
		return true
	}
	return sess.AuthMethod != AuthMethodBreakglass && !now.Before(sess.LastSeenAt.Add(s.idle))
}

// Lookup returns the live session for rawID. An unknown or expired id returns
// false with no error; an expired row is deleted on the way.
func (s *SessionStore) Lookup(ctx context.Context, rawID string) (Session, bool, error) {
	if rawID == "" {
		return Session{}, false, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT `+s.cols+` FROM `+s.table.Name+` WHERE id_hash = ?`, HashID(rawID))
	sess, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	if s.expired(sess, s.now()) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM `+s.table.Name+` WHERE id_hash = ?`, sess.IDHash)
		return Session{}, false, nil
	}
	return sess, true, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanSession(r rowScanner) (Session, error) {
	var (
		sess                      Session
		gj                        string
		created, lastSeen, expiry int64
	)
	if err := r.Scan(&sess.IDHash, &sess.Iss, &sess.Sub, &sess.Email, &gj, &sess.AuthMethod, &created, &lastSeen, &expiry); err != nil {
		return Session{}, err
	}
	if err := json.Unmarshal([]byte(gj), &sess.Groups); err != nil {
		return Session{}, fmt.Errorf("sessions: decode groups: %w", err)
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = time.Unix(created, 0), time.Unix(lastSeen, 0), time.Unix(expiry, 0)
	return sess, nil
}

// TouchDue reports whether sess's last_seen_at is old enough (TouchInterval)
// for Touch to write, as seen at now.
func TouchDue(sess Session, now time.Time) bool {
	return !sess.LastSeenAt.After(now.Add(-TouchInterval))
}

// Touch records activity: it advances last_seen_at to now, but only when the
// stored value is at least TouchInterval old. It reports whether it wrote.
func (s *SessionStore) Touch(ctx context.Context, rawID string) (bool, error) {
	now := s.now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE `+s.table.Name+` SET last_seen_at = ? WHERE id_hash = ? AND last_seen_at <= ?`,
		now.Unix(), HashID(rawID), now.Add(-TouchInterval).Unix())
	if err != nil {
		return false, fmt.Errorf("sessions: touch: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Delete removes the session for rawID. A missing session is not an error.
func (s *SessionStore) Delete(ctx context.Context, rawID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table.Name+` WHERE id_hash = ?`, HashID(rawID)); err != nil {
		return fmt.Errorf("sessions: delete: %w", err)
	}
	return nil
}

// DeleteByHash removes the session whose id hash is idHash (the admin
// "handle") and reports whether one existed.
func (s *SessionStore) DeleteByHash(ctx context.Context, idHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table.Name+` WHERE id_hash = ?`, idHash)
	if err != nil {
		return false, fmt.Errorf("sessions: delete by hash: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteBySub removes every session of sub and returns how many it removed.
func (s *SessionStore) DeleteBySub(ctx context.Context, sub string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table.Name+` WHERE sub = ?`, sub)
	if err != nil {
		return 0, fmt.Errorf("sessions: delete by sub: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DeleteByEmail removes every session whose login email equals email,
// compared case-insensitively, and returns how many it removed. It serves a
// block-list entry that has an email and no sub.
func (s *SessionStore) DeleteByEmail(ctx context.Context, email string) (int, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table.Name+` WHERE lower(email) = ?`, email)
	if err != nil {
		return 0, fmt.Errorf("sessions: delete by email: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DeleteBySubExcept removes every session of sub except the one whose id hash
// is keepHash and returns how many it removed.
func (s *SessionStore) DeleteBySubExcept(ctx context.Context, sub, keepHash string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table.Name+` WHERE sub = ? AND id_hash <> ?`, sub, keepHash)
	if err != nil {
		return 0, fmt.Errorf("sessions: delete by sub: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// List returns the live sessions, newest first. Rows carry only the id hash.
func (s *SessionStore) List(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+s.cols+` FROM `+s.table.Name+` ORDER BY created_at DESC, id_hash`)
	if err != nil {
		return nil, fmt.Errorf("sessions: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	now := s.now()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		if !s.expired(sess, now) {
			out = append(out, sess)
		}
	}
	return out, rows.Err()
}

// SweepExpired deletes every session past its idle or absolute limit and
// returns how many it removed.
func (s *SessionStore) SweepExpired(ctx context.Context) (int, error) {
	now := s.now()
	var (
		res sql.Result
		err error
	)
	if s.table.AuthMethod {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM `+s.table.Name+` WHERE expires_at <= ? OR (last_seen_at <= ? AND auth_method <> ?)`,
			now.Unix(), now.Add(-s.idle).Unix(), AuthMethodBreakglass)
	} else {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM `+s.table.Name+` WHERE expires_at <= ? OR last_seen_at <= ?`,
			now.Unix(), now.Add(-s.idle).Unix())
	}
	if err != nil {
		return 0, fmt.Errorf("sessions: sweep: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
