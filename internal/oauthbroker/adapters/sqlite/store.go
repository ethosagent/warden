package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/oauthbroker"
)

// idBytes is the entropy of a pending id and a grant id (128 bits).
const idBytes = 16

// maxIDAttempts bounds retries on a generated-id collision; reaching it means
// the random source is broken.
const maxIDAttempts = 4

// subscribeReadTimeout bounds the row read Subscribe does after registering.
const subscribeReadTimeout = 5 * time.Second

// maxTouchEntries bounds the in-memory TouchLastUsed throttle; past it, stale
// entries are dropped.
const maxTouchEntries = 4096

// Options configures a Store.
type Options struct {
	// Clock is the time source; nil uses the real clock.
	Clock clock.Clock
	// Rand is the entropy for ids; nil uses crypto/rand.
	Rand io.Reader
	// Limits are the caps; zero fields take the oauthbroker defaults.
	Limits oauthbroker.Limits
}

// Store is the oauthbroker.GrantStore over cpstate. Every method is one SQL
// statement (plus a read to tell ErrNotFound from a state conflict), so the
// single-connection cpstate DB serialises writers and the limits hold across
// processes that share the file.
type Store struct {
	db     *sql.DB
	clk    clock.Clock
	rand   io.Reader
	limits oauthbroker.Limits
	notify oauthbroker.Notifier

	touchMu sync.Mutex
	touched map[string]time.Time
}

var _ oauthbroker.GrantStore = (*Store)(nil)

// New builds a Store over db, which must have been opened with the broker
// migrations enabled (cpstate.Enable(migs, EnabledMigrationIDs()...)).
func New(db *cpstate.DB, o Options) *Store {
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	return &Store{db: db.SQL(), clk: o.Clock, rand: o.Rand, limits: o.Limits.WithDefaults(), touched: map[string]time.Time{}}
}

func (s *Store) newID() (string, error) {
	var b [idBytes]byte
	if _, err := io.ReadFull(s.rand, b[:]); err != nil {
		return "", fmt.Errorf("oauthbroker store: random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func sqliteCode(err error) int {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code()
	}
	return 0
}

func isConstraint(err error) bool {
	switch sqliteCode(err) {
	case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY, sqlite3.SQLITE_CONSTRAINT_UNIQUE:
		return true
	}
	return false
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMilli(v.Int64).UTC()
}

func null(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func scopesJSON(scopes []string) string {
	b, err := json.Marshal(oauthbroker.CanonicalScopes(scopes))
	if err != nil { // a []string always marshals
		return "[]"
	}
	return string(b)
}

func parseScopes(raw string) ([]string, error) {
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("oauthbroker store: scopes_json: %w", err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

type rowScanner interface{ Scan(dest ...any) error }

// --- pending_authorizations ---

const pendingCols = `id, iss, sub, user_key, agent_id, provider, scopes_json, message,
  request_method, request_host, request_path, mcp_tool, status, reason, created_at, expires_at, completed_at`

func scanPending(r rowScanner) (oauthbroker.Pending, error) {
	var (
		p                                    oauthbroker.Pending
		agent, msg, method, host, path, tool sql.NullString
		reason                               sql.NullString
		scopes, status                       string
		created, expires                     int64
		completed                            sql.NullInt64
	)
	if err := r.Scan(&p.ID, &p.Iss, &p.Sub, &p.UserKey, &agent, &p.Provider, &scopes, &msg,
		&method, &host, &path, &tool, &status, &reason, &created, &expires, &completed); err != nil {
		return oauthbroker.Pending{}, err
	}
	sc, err := parseScopes(scopes)
	if err != nil {
		return oauthbroker.Pending{}, err
	}
	p.AgentID, p.Scopes, p.Message = agent.String, sc, msg.String
	p.Request = oauthbroker.RequestInfo{Method: method.String, Host: host.String, Path: path.String, MCPTool: tool.String}
	p.Status, p.Reason = oauthbroker.PendingStatus(status), reason.String
	p.CreatedAt, p.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	p.CompletedAt = fromMS(completed)
	return p, nil
}

// CreatePending implements oauthbroker.GrantStore. The open-pending cap and
// the insert are one statement, so concurrent creators cannot both pass it.
func (s *Store) CreatePending(ctx context.Context, p oauthbroker.Pending, ttl time.Duration) (oauthbroker.Pending, error) {
	if err := oauthbroker.ValidatePending(p, ttl); err != nil {
		return oauthbroker.Pending{}, err
	}
	now := s.clk.Now()
	for range maxIDAttempts {
		id, err := s.newID()
		if err != nil {
			return oauthbroker.Pending{}, err
		}
		res, err := s.db.ExecContext(ctx, `INSERT INTO pending_authorizations (`+pendingCols+`)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, ?, NULL
WHERE (SELECT count(*) FROM pending_authorizations
       WHERE user_key = ? AND status = 'pending' AND expires_at > ?) < ?`,
			id, p.Iss, p.Sub, p.UserKey, null(p.AgentID), p.Provider, scopesJSON(p.Scopes), null(p.Message),
			null(p.Request.Method), null(p.Request.Host), null(p.Request.Path), null(p.Request.MCPTool),
			ms(now), ms(now.Add(ttl)),
			p.UserKey, ms(now), s.limits.MaxOpenPendingsPerUser)
		if isConstraint(err) {
			continue
		}
		if err != nil {
			return oauthbroker.Pending{}, fmt.Errorf("oauthbroker store: create pending: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return oauthbroker.Pending{}, oauthbroker.ErrTooMany
		}
		return s.readPending(ctx, id)
	}
	return oauthbroker.Pending{}, errors.New("oauthbroker store: create pending: id collisions; the random source is broken")
}

func (s *Store) readPending(ctx context.Context, id string) (oauthbroker.Pending, error) {
	p, err := scanPending(s.db.QueryRowContext(ctx, `SELECT `+pendingCols+` FROM pending_authorizations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return oauthbroker.Pending{}, oauthbroker.ErrNotFound
	}
	if err != nil {
		return oauthbroker.Pending{}, fmt.Errorf("oauthbroker store: read pending: %w", err)
	}
	return p, nil
}

// GetPending implements oauthbroker.GrantStore. Expiry is computed on read.
func (s *Store) GetPending(ctx context.Context, id string) (oauthbroker.Pending, error) {
	p, err := s.readPending(ctx, id)
	if err != nil {
		return p, err
	}
	if p.Status == oauthbroker.StatusPending && !p.ExpiresAt.After(s.clk.Now()) {
		p.Status, p.Reason = oauthbroker.StatusExpired, oauthbroker.ReasonExpired
	}
	return p, nil
}

// CompletePending implements oauthbroker.GrantStore as one compare-and-set
// UPDATE.
func (s *Store) CompletePending(ctx context.Context, id string, status oauthbroker.PendingStatus, reason string) error {
	if !status.Terminal() {
		return fmt.Errorf("%w: complete with status %q", oauthbroker.ErrInvalid, status)
	}
	now := s.clk.Now()
	res, err := s.db.ExecContext(ctx, `UPDATE pending_authorizations
SET status = ?, reason = ?, completed_at = ?
WHERE id = ? AND status = 'pending' AND expires_at > ?`,
		string(status), null(reason), ms(now), id, ms(now))
	if err != nil {
		return fmt.Errorf("oauthbroker store: complete pending: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		s.notify.Complete(id, status)
		return nil
	}
	if _, err := s.readPending(ctx, id); err != nil {
		return err
	}
	return oauthbroker.ErrNotPending
}

// Subscribe implements oauthbroker.GrantStore. It registers first and reads the
// row second, so a completion between the two is never missed.
func (s *Store) Subscribe(id string) (<-chan oauthbroker.PendingStatus, func()) {
	ch, cancel := s.notify.Subscribe(id)
	ctx, done := context.WithTimeout(context.Background(), subscribeReadTimeout)
	defer done()
	p, err := s.GetPending(ctx, id)
	switch {
	case errors.Is(err, oauthbroker.ErrNotFound):
		cancel()
		return oauthbroker.Closed(""), func() {}
	case err != nil:
		// A read error leaves the waiter registered; it re-reads on its own
		// timer and Sweep or CompletePending still wakes it.
		return ch, cancel
	case p.Status.Terminal():
		cancel()
		return oauthbroker.Closed(p.Status), func() {}
	}
	return ch, cancel
}

// --- connect_attempts ---

const attemptCols = `state_hash, pending_id, iss, sub, user_key, provider, scopes_json, verifier, browser_hash, created_at, expires_at`

func scanAttempt(r rowScanner) (oauthbroker.Attempt, error) {
	var (
		a                oauthbroker.Attempt
		pending          sql.NullString
		scopes           string
		created, expires int64
	)
	if err := r.Scan(&a.StateHash, &pending, &a.Iss, &a.Sub, &a.UserKey, &a.Provider, &scopes,
		&a.Verifier, &a.BrowserHash, &created, &expires); err != nil {
		return oauthbroker.Attempt{}, err
	}
	sc, err := parseScopes(scopes)
	if err != nil {
		return oauthbroker.Attempt{}, err
	}
	a.PendingID, a.Scopes = pending.String, sc
	a.CreatedAt, a.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	return a, nil
}

// CreateAttempt implements oauthbroker.GrantStore. Both caps and the insert are
// one statement.
func (s *Store) CreateAttempt(ctx context.Context, a oauthbroker.Attempt) (oauthbroker.Attempt, error) {
	if err := oauthbroker.ValidateAttempt(a); err != nil {
		return oauthbroker.Attempt{}, err
	}
	now := s.clk.Now()
	a.Scopes = oauthbroker.CanonicalScopes(a.Scopes)
	a.CreatedAt, a.ExpiresAt = time.UnixMilli(ms(now)).UTC(), time.UnixMilli(ms(now.Add(oauthbroker.AttemptTTL))).UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO connect_attempts (`+attemptCols+`)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
WHERE (SELECT count(*) FROM connect_attempts WHERE user_key = ? AND expires_at > ?) < ?
  AND (SELECT count(*) FROM connect_attempts WHERE expires_at > ?) < ?`,
		a.StateHash, null(a.PendingID), a.Iss, a.Sub, a.UserKey, a.Provider, scopesJSON(a.Scopes),
		a.Verifier, a.BrowserHash, ms(a.CreatedAt), ms(a.ExpiresAt),
		a.UserKey, ms(now), s.limits.MaxOpenAttemptsPerUser,
		ms(now), s.limits.MaxLiveAttempts)
	if isConstraint(err) {
		return oauthbroker.Attempt{}, oauthbroker.ErrExists
	}
	if err != nil {
		return oauthbroker.Attempt{}, fmt.Errorf("oauthbroker store: create attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return oauthbroker.Attempt{}, oauthbroker.ErrTooMany
	}
	return a, nil
}

// ConsumeAttempt implements oauthbroker.GrantStore with DELETE ... RETURNING.
func (s *Store) ConsumeAttempt(ctx context.Context, stateHash string) (oauthbroker.Attempt, error) {
	a, err := scanAttempt(s.db.QueryRowContext(ctx,
		`DELETE FROM connect_attempts WHERE state_hash = ? RETURNING `+attemptCols, stateHash))
	if errors.Is(err, sql.ErrNoRows) {
		return oauthbroker.Attempt{}, oauthbroker.ErrNotFound
	}
	if err != nil {
		return oauthbroker.Attempt{}, fmt.Errorf("oauthbroker store: consume attempt: %w", err)
	}
	if !a.ExpiresAt.After(s.clk.Now()) {
		return oauthbroker.Attempt{}, oauthbroker.ErrNotFound
	}
	return a, nil
}

// --- oauth_grants ---

const grantCols = `user_key, iss, sub, provider, grant_id, prev_grant_id, state, scopes_json, provider_account_id,
  provider_account_login, granted_at, updated_at, last_used_at, revoked_at`

func scanGrant(r rowScanner) (oauthbroker.Grant, error) {
	var (
		g                 oauthbroker.Grant
		state, scopes     string
		accID, accLogin   sql.NullString
		prev              sql.NullString
		granted, updated  int64
		lastUsed, revoked sql.NullInt64
	)
	if err := r.Scan(&g.UserKey, &g.Iss, &g.Sub, &g.Provider, &g.GrantID, &prev, &state, &scopes,
		&accID, &accLogin, &granted, &updated, &lastUsed, &revoked); err != nil {
		return oauthbroker.Grant{}, err
	}
	sc, err := parseScopes(scopes)
	if err != nil {
		return oauthbroker.Grant{}, err
	}
	g.State, g.Scopes, g.PrevGrantID = oauthbroker.GrantState(state), sc, prev.String
	g.Account = oauthbroker.Account{ID: accID.String, Login: accLogin.String}
	g.GrantedAt, g.UpdatedAt = time.UnixMilli(granted).UTC(), time.UnixMilli(updated).UTC()
	g.LastUsedAt, g.RevokedAt = fromMS(lastUsed), fromMS(revoked)
	return g, nil
}

// grantRow runs a statement that returns at most one grant row; no row is
// sql.ErrNoRows.
func (s *Store) grantRow(ctx context.Context, op, query string, args ...any) (oauthbroker.Grant, error) {
	g, err := scanGrant(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return oauthbroker.Grant{}, sql.ErrNoRows
	}
	if err != nil {
		return oauthbroker.Grant{}, fmt.Errorf("oauthbroker store: %s: %w", op, err)
	}
	return g, nil
}

// BeginGrant implements oauthbroker.GrantStore as one upsert.
func (s *Store) BeginGrant(ctx context.Context, ref oauthbroker.GrantRef) (oauthbroker.Grant, error) {
	if err := oauthbroker.ValidateGrantRef(ref); err != nil {
		return oauthbroker.Grant{}, err
	}
	now := ms(s.clk.Now())
	for range maxIDAttempts {
		id, err := s.newID()
		if err != nil {
			return oauthbroker.Grant{}, err
		}
		g, err := s.grantRow(ctx, "begin grant", `INSERT INTO oauth_grants
  (user_key, iss, sub, provider, grant_id, state, scopes_json, granted_at, updated_at)
VALUES (?, ?, ?, ?, ?, 'connecting', '[]', ?, ?)
ON CONFLICT (user_key, provider) DO UPDATE SET
  iss = excluded.iss, sub = excluded.sub, grant_id = excluded.grant_id,
  prev_grant_id = CASE oauth_grants.state
    WHEN 'active' THEN oauth_grants.grant_id
    WHEN 'connecting' THEN oauth_grants.prev_grant_id
    ELSE NULL END,
  state = 'connecting', updated_at = excluded.updated_at, revoked_at = NULL
RETURNING `+grantCols,
			ref.UserKey, ref.Iss, ref.Sub, ref.Provider, id, now, now)
		if isConstraint(err) {
			continue // grant_id collision
		}
		return g, err
	}
	return oauthbroker.Grant{}, errors.New("oauthbroker store: begin grant: id collisions; the random source is broken")
}

// ActivateGrant implements oauthbroker.GrantStore as a compare-and-set on
// (grant_id, state = connecting).
func (s *Store) ActivateGrant(ctx context.Context, grantID string, scopes []string, account oauthbroker.Account) (oauthbroker.Grant, error) {
	if err := oauthbroker.ValidateAccount(scopes, account); err != nil {
		return oauthbroker.Grant{}, err
	}
	now := ms(s.clk.Now())
	g, err := s.grantRow(ctx, "activate grant", `UPDATE oauth_grants SET
  state = 'active', prev_grant_id = NULL, scopes_json = ?, provider_account_id = ?, provider_account_login = ?,
  granted_at = ?, updated_at = ?
WHERE grant_id = ? AND state = 'connecting'
RETURNING `+grantCols,
		scopesJSON(scopes), null(account.ID), null(account.Login), now, now, grantID)
	if !errors.Is(err, sql.ErrNoRows) {
		return g, err
	}
	var one int
	switch err := s.db.QueryRowContext(ctx, `SELECT 1 FROM oauth_grants WHERE grant_id = ?`, grantID).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return oauthbroker.Grant{}, oauthbroker.ErrNotFound
	case err != nil:
		return oauthbroker.Grant{}, fmt.Errorf("oauthbroker store: activate grant: %w", err)
	}
	return oauthbroker.Grant{}, oauthbroker.ErrGrantState
}

// MarkReconsentRequired implements oauthbroker.GrantStore.
func (s *Store) MarkReconsentRequired(ctx context.Context, userKey, provider, grantID string) (oauthbroker.Grant, error) {
	g, err := s.grantRow(ctx, "mark reconsent", `UPDATE oauth_grants SET state = 'reconsent_required', updated_at = ?
WHERE user_key = ? AND provider = ? AND grant_id = ? AND state IN ('active', 'reconsent_required')
RETURNING `+grantCols,
		ms(s.clk.Now()), userKey, provider, grantID)
	if !errors.Is(err, sql.ErrNoRows) {
		return g, err
	}
	if _, err := s.GetGrant(ctx, userKey, provider); err != nil {
		return oauthbroker.Grant{}, err
	}
	return oauthbroker.Grant{}, oauthbroker.ErrGrantState
}

// RevokeGrant implements oauthbroker.GrantStore. An already revoked grant is
// returned unchanged; a non-empty grantID must match the row's.
func (s *Store) RevokeGrant(ctx context.Context, userKey, provider, grantID string) (oauthbroker.Grant, error) {
	now := ms(s.clk.Now())
	g, err := s.grantRow(ctx, "revoke grant", `UPDATE oauth_grants
SET state = 'revoked', prev_grant_id = NULL, revoked_at = ?, updated_at = ?
WHERE user_key = ? AND provider = ? AND state <> 'revoked' AND (? = '' OR grant_id = ?)
RETURNING `+grantCols,
		now, now, userKey, provider, grantID, grantID)
	if !errors.Is(err, sql.ErrNoRows) {
		return g, err
	}
	cur, err := s.GetGrant(ctx, userKey, provider)
	if err != nil {
		return oauthbroker.Grant{}, err
	}
	if grantID != "" && cur.GrantID != grantID {
		return oauthbroker.Grant{}, oauthbroker.ErrGrantState
	}
	return cur, nil
}

// RestoreGrant implements oauthbroker.GrantStore as a compare-and-set on
// (connecting, grant_id, prev_grant_id).
func (s *Store) RestoreGrant(ctx context.Context, userKey, provider, connectingID, prevID string) (oauthbroker.Grant, error) {
	if connectingID == "" || prevID == "" {
		return oauthbroker.Grant{}, fmt.Errorf("%w: connecting and previous grant ids are required", oauthbroker.ErrInvalid)
	}
	g, err := s.grantRow(ctx, "restore grant", `UPDATE oauth_grants
SET state = 'active', grant_id = prev_grant_id, prev_grant_id = NULL, updated_at = ?
WHERE user_key = ? AND provider = ? AND state = 'connecting' AND grant_id = ? AND prev_grant_id = ?
RETURNING `+grantCols,
		ms(s.clk.Now()), userKey, provider, connectingID, prevID)
	if !errors.Is(err, sql.ErrNoRows) {
		return g, err
	}
	if _, err := s.GetGrant(ctx, userKey, provider); err != nil {
		return oauthbroker.Grant{}, err
	}
	return oauthbroker.Grant{}, oauthbroker.ErrGrantState
}

// GetGrant implements oauthbroker.GrantStore.
func (s *Store) GetGrant(ctx context.Context, userKey, provider string) (oauthbroker.Grant, error) {
	g, err := s.grantRow(ctx, "get grant", `SELECT `+grantCols+` FROM oauth_grants WHERE user_key = ? AND provider = ?`, userKey, provider)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthbroker.Grant{}, oauthbroker.ErrNotFound
	}
	return g, err
}

// ListGrants implements oauthbroker.GrantStore.
func (s *Store) ListGrants(ctx context.Context, userKey string, includeRevoked bool) ([]oauthbroker.Grant, error) {
	q := `SELECT ` + grantCols + ` FROM oauth_grants WHERE user_key = ?`
	if !includeRevoked {
		q += ` AND state <> 'revoked'`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY provider`, userKey)
	if err != nil {
		return nil, fmt.Errorf("oauthbroker store: list grants: %w", err)
	}
	return collectGrants(rows)
}

func collectGrants(rows *sql.Rows) ([]oauthbroker.Grant, error) {
	defer func() { _ = rows.Close() }()
	out := []oauthbroker.Grant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("oauthbroker store: list grants: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oauthbroker store: list grants: %w", err)
	}
	return out, nil
}

// TouchLastUsed implements oauthbroker.GrantStore. An in-memory throttle skips
// the statement for a pair written within TouchInterval; the SQL guard keeps
// the rule across processes and only moves last_used_at forward.
func (s *Store) TouchLastUsed(ctx context.Context, userKey, provider string, at time.Time) error {
	key := userKey + "\x00" + provider
	s.touchMu.Lock()
	last, ok := s.touched[key]
	s.touchMu.Unlock()
	if ok && at.Sub(last) < oauthbroker.TouchInterval {
		return nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE oauth_grants SET last_used_at = ?
WHERE user_key = ? AND provider = ? AND state = 'active'
  AND (last_used_at IS NULL OR last_used_at <= ?)`,
		ms(at), userKey, provider, ms(at.Add(-oauthbroker.TouchInterval)))
	if err != nil {
		return fmt.Errorf("oauthbroker store: touch last used: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		s.rememberTouch(key, at)
	}
	return nil
}

func (s *Store) rememberTouch(key string, at time.Time) {
	s.touchMu.Lock()
	defer s.touchMu.Unlock()
	if len(s.touched) >= maxTouchEntries {
		for k, t := range s.touched {
			if at.Sub(t) >= oauthbroker.TouchInterval {
				delete(s.touched, k)
			}
		}
		if len(s.touched) >= maxTouchEntries {
			clear(s.touched)
		}
	}
	s.touched[key] = at
}

// --- Sweep ---

// Sweep implements oauthbroker.GrantStore.
func (s *Store) Sweep(ctx context.Context, now time.Time) (oauthbroker.SweepResult, error) {
	var out oauthbroker.SweepResult
	res, err := s.db.ExecContext(ctx, `DELETE FROM connect_attempts WHERE expires_at <= ?`, ms(now))
	if err != nil {
		return out, fmt.Errorf("oauthbroker store: sweep attempts: %w", err)
	}
	n, _ := res.RowsAffected()
	out.AttemptsDeleted = int(n)

	expired, err := s.expirePendings(ctx, now)
	if err != nil {
		return out, err
	}
	out.PendingsExpired = len(expired)
	for _, id := range expired {
		s.notify.Complete(id, oauthbroker.StatusExpired)
	}

	res, err = s.db.ExecContext(ctx, `DELETE FROM pending_authorizations WHERE status <> 'pending' AND completed_at <= ?`,
		ms(now.Add(-oauthbroker.TerminalPendingRetention)))
	if err != nil {
		return out, fmt.Errorf("oauthbroker store: sweep pendings: %w", err)
	}
	n, _ = res.RowsAffected()
	out.PendingsDeleted = int(n)

	rows, err := s.db.QueryContext(ctx, `SELECT `+grantCols+` FROM oauth_grants
WHERE state = 'connecting' AND updated_at <= ? ORDER BY updated_at LIMIT ?`,
		ms(now.Add(-oauthbroker.ConnectingGrantTTL)), oauthbroker.MaxStaleConnecting)
	if err != nil {
		return out, fmt.Errorf("oauthbroker store: sweep grants: %w", err)
	}
	stale, err := collectGrants(rows)
	if err != nil {
		return out, err
	}
	out.StaleConnecting = stale
	return out, nil
}

func (s *Store) expirePendings(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE pending_authorizations
SET status = 'expired', reason = ?, completed_at = ?
WHERE status = 'pending' AND expires_at <= ?
RETURNING id`, oauthbroker.ReasonExpired, ms(now), ms(now))
	if err != nil {
		return nil, fmt.Errorf("oauthbroker store: sweep expire pendings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("oauthbroker store: sweep expire pendings: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oauthbroker store: sweep expire pendings: %w", err)
	}
	return ids, nil
}
