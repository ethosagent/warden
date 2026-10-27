package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Worker token format. A token is "wwt_" + 52 lowercase unpadded base32
// characters (32 random bytes); sha256 of it is enough at rest because the
// secret is 256 bits of entropy.
const (
	workerTokenPrefix  = "wwt_"
	workerTokenEncLen  = 52
	workerTokenLen     = len(workerTokenPrefix) + workerTokenEncLen
	workerTokenIDLen   = 8 // random bytes behind the "wt_" id
	maxWorkerTokenName = 64

	// maxActiveWorkerTokens per proxy_id lets a rotation overlap old and new.
	maxActiveWorkerTokens = 2

	defaultTokenFlushInterval = 60 * time.Second
	defaultTokenPollInterval  = 2 * time.Second
)

var (
	// ErrMalformed: the presented value is not shaped like a worker token. No
	// hashing or lookup happened.
	ErrMalformed = errors.New("worker token: malformed")
	// ErrUnknown: well-formed, but no such token.
	ErrUnknown = errors.New("worker token: unknown")
	// ErrRevoked: the token was revoked.
	ErrRevoked = errors.New("worker token: revoked")
	// ErrExpired: the token is past its expires_at (control-plane clock).
	ErrExpired = errors.New("worker token: expired")
)

var (
	// ErrNotFound: Revoke named an id that does not exist.
	ErrNotFound = errors.New("worker token: not found")
	// ErrTooManyActive: the proxy_id already has the maximum active tokens.
	ErrTooManyActive = errors.New("worker token: proxy id already has the maximum number of active tokens")
	// ErrNameTaken: a token (active or revoked) already has this name.
	ErrNameTaken = errors.New("worker token: name already in use")
	// ErrTokenInUse: an imported value is already registered under another name.
	ErrTokenInUse = errors.New("worker token: value already registered")
	// ErrInvalidInput: a name, proxy id, actor, expiry or imported value is not acceptable.
	ErrInvalidInput = errors.New("worker token: invalid input")
)

var proxyIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// WorkerTokenMigrations are the cpstate migrations of the worker_tokens table.
// StateMigrations includes them; callers that open the DB themselves (the
// offline CLI) must use StateMigrations too, so the downgrade guard sees every
// registered migration.
func WorkerTokenMigrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID: "workertokens/0001",
		SQL: `CREATE TABLE worker_tokens (
  id           TEXT PRIMARY KEY,
  name         TEXT UNIQUE NOT NULL,
  proxy_id     TEXT NOT NULL,
  token_hash   BLOB UNIQUE NOT NULL,
  created_by   TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NULL,
  last_used_at INTEGER NULL,
  revoked_at   INTEGER NULL,
  revoked_by   TEXT NULL
);
CREATE INDEX worker_tokens_proxy_id ON worker_tokens (proxy_id);`,
	}}
}

// Token is a worker token's metadata. It never holds the plaintext or the
// hash. Zero times mean "unset".
type Token struct {
	ID, Name, ProxyID string
	CreatedBy         string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	LastUsedAt        time.Time
	RevokedAt         time.Time
	RevokedBy         string
}

// String prints id, name and binding only, so %v and %+v are log-safe.
func (t Token) String() string {
	return fmt.Sprintf("worker token id=%s name=%q proxy_id=%s", t.ID, t.Name, t.ProxyID)
}

// LogValue keeps slog output to id, name and binding.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", t.ID), slog.String("name", t.Name), slog.String("proxy_id", t.ProxyID))
}

// CreateOpts describes a token to mint. A non-empty Plaintext is imported (it
// is format-checked and registered as given) instead of generated.
type CreateOpts struct {
	Name, ProxyID string
	ExpiresAt     time.Time // zero: never expires
	Actor         string
	Plaintext     string
}

// StoreOptions configures a WorkerTokenStore. Zero values use the real clock,
// a 60 s flush interval, a 2 s poll interval and slog.Default.
type StoreOptions struct {
	Clock         clock.Clock
	FlushInterval time.Duration
	PollInterval  time.Duration
	Logger        *slog.Logger
}

// tokenIndex is one immutable snapshot of every row.
type tokenIndex struct {
	byHash map[[sha256.Size]byte]Token
	byID   map[string]Token
}

// WorkerTokenStore creates, authenticates, revokes and lists worker tokens on
// the cpstate database. Authenticate reads only an in-memory index, so the
// request path does no DB I/O; the index is rebuilt after local writes and
// reloaded when another process commits to the same file (PRAGMA data_version).
// It has no HTTP concerns, so a later Postgres backend can replace the polling
// behind the same methods.
type WorkerTokenStore struct {
	db            *sql.DB
	clk           clock.Clock
	log           *slog.Logger
	flushInterval time.Duration
	pollInterval  time.Duration

	idx atomic.Pointer[tokenIndex]

	// loadMu serialises reloads and guards dataVersion and hooks.
	loadMu      sync.Mutex
	dataVersion int64
	hooks       []func(id string)

	// usedMu guards the in-memory last-used values awaiting a flush.
	usedMu sync.Mutex
	used   map[string]time.Time // every MarkUsed value not yet visible in DB
	dirty  map[string]time.Time // subset to write at the next flush

	flushTx atomic.Int64 // write transactions committed by Flush (tests)
}

// NewWorkerTokenStore builds a store over db (opened with StateMigrations) and
// loads the index; an error here means no store, never an empty index.
func NewWorkerTokenStore(db *cpstate.DB, opts StoreOptions) (*WorkerTokenStore, error) {
	if opts.Clock == nil {
		opts.Clock = clock.Real()
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultTokenFlushInterval
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultTokenPollInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &WorkerTokenStore{
		db: db.SQL(), clk: opts.Clock, log: opts.Logger,
		flushInterval: opts.FlushInterval, pollInterval: opts.PollInterval,
		used: map[string]time.Time{}, dirty: map[string]time.Time{},
	}
	if err := s.reload(context.Background()); err != nil {
		return nil, fmt.Errorf("worker tokens: load: %w", err)
	}
	return s, nil
}

// OnRevoked registers fn, called with the token id after an in-process Revoke
// and when a reload finds a token newly revoked by another process. Hooks run
// outside the store's locks.
func (s *WorkerTokenStore) OnRevoked(fn func(id string)) {
	s.loadMu.Lock()
	s.hooks = append(s.hooks, fn)
	s.loadMu.Unlock()
}

func hashToken(plaintext string) [sha256.Size]byte { return sha256.Sum256([]byte(plaintext)) }

// wellFormed reports whether v has the wwt_ prefix, the exact length and only
// lowercase base32 characters.
func wellFormed(v string) bool {
	if len(v) != workerTokenLen || v[:len(workerTokenPrefix)] != workerTokenPrefix {
		return false
	}
	for i := len(workerTokenPrefix); i < len(v); i++ {
		c := v[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

func generateWorkerToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("worker tokens: random: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	return workerTokenPrefix + strings.ToLower(enc), nil
}

func validateTokenName(name string) error {
	n := utf8.RuneCountInString(name)
	if !utf8.ValidString(name) || n < 1 || n > maxWorkerTokenName {
		return fmt.Errorf("%w: name must be 1-%d characters", ErrInvalidInput, maxWorkerTokenName)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: name has control characters", ErrInvalidInput)
		}
	}
	return nil
}

// Authenticate resolves a presented token. It does one sha256 and one map
// read; the revoked and expired checks follow, in that order.
func (s *WorkerTokenStore) Authenticate(plaintext string) (Token, error) {
	if !wellFormed(plaintext) {
		return Token{}, ErrMalformed
	}
	t, ok := s.idx.Load().byHash[hashToken(plaintext)]
	if !ok {
		return Token{}, ErrUnknown
	}
	if !t.RevokedAt.IsZero() {
		return Token{}, ErrRevoked
	}
	if !t.ExpiresAt.IsZero() && !s.clk.Now().Before(t.ExpiresAt) {
		return Token{}, ErrExpired
	}
	return t, nil
}

// Valid re-checks an already authenticated token by id against the in-memory
// index (no DB I/O, no hashing): ErrUnknown, ErrRevoked or ErrExpired when it
// no longer authenticates.
func (s *WorkerTokenStore) Valid(id string) error {
	t, ok := s.idx.Load().byID[id]
	switch {
	case !ok:
		return ErrUnknown
	case !t.RevokedAt.IsZero():
		return ErrRevoked
	case s.expired(t, s.clk.Now()):
		return ErrExpired
	}
	return nil
}

// Create mints (or imports) a token and returns its plaintext, which no later
// call returns. Importing the same name and value as an active row is a no-op
// that returns the existing token.
func (s *WorkerTokenStore) Create(ctx context.Context, o CreateOpts) (string, Token, error) {
	if err := validateTokenName(o.Name); err != nil {
		return "", Token{}, err
	}
	if !proxyIDRe.MatchString(o.ProxyID) {
		return "", Token{}, fmt.Errorf("%w: proxy id must match %s", ErrInvalidInput, proxyIDRe)
	}
	if o.Actor == "" {
		return "", Token{}, fmt.Errorf("%w: actor is required", ErrInvalidInput)
	}
	imported := o.Plaintext != ""
	plaintext := o.Plaintext
	if imported {
		if !wellFormed(plaintext) {
			return "", Token{}, fmt.Errorf("%w: imported value is not a worker token", ErrInvalidInput)
		}
	} else {
		var err error
		if plaintext, err = generateWorkerToken(); err != nil {
			return "", Token{}, err
		}
	}
	now := s.clk.Now()
	if !o.ExpiresAt.IsZero() && !o.ExpiresAt.After(now) {
		return "", Token{}, fmt.Errorf("%w: expiry is not in the future", ErrInvalidInput)
	}
	hash := hashToken(plaintext)

	if existing, ok, err := s.rowByName(ctx, o.Name); err != nil {
		return "", Token{}, err
	} else if ok {
		if imported && existing.hash == hash && existing.t.RevokedAt.IsZero() && !s.expired(existing.t, now) && existing.t.ProxyID == o.ProxyID {
			return plaintext, existing.t, nil
		}
		return "", Token{}, ErrNameTaken
	}

	var idb [workerTokenIDLen]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return "", Token{}, fmt.Errorf("worker tokens: random id: %w", err)
	}
	id := "wt_" + hex.EncodeToString(idb[:])
	var exp any
	if !o.ExpiresAt.IsZero() {
		exp = o.ExpiresAt.Unix()
	}
	// The limit check and the insert are one statement, so two processes cannot
	// both slip past the count.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO worker_tokens (id, name, proxy_id, token_hash, created_by, created_at, expires_at)
		 SELECT ?, ?, ?, ?, ?, ?, ?
		 WHERE (SELECT COUNT(*) FROM worker_tokens
		        WHERE proxy_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)) < ?`,
		id, o.Name, o.ProxyID, hash[:], o.Actor, now.Unix(), exp,
		o.ProxyID, now.Unix(), maxActiveWorkerTokens)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "worker_tokens.name"):
			return "", Token{}, ErrNameTaken
		case strings.Contains(err.Error(), "worker_tokens.token_hash"):
			return "", Token{}, ErrTokenInUse
		}
		return "", Token{}, fmt.Errorf("worker tokens: insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", Token{}, fmt.Errorf("worker tokens: insert: %w", err)
	}
	if n == 0 {
		return "", Token{}, ErrTooManyActive
	}
	if err := s.reload(ctx); err != nil {
		s.log.Warn("worker tokens: index reload failed after create", "err", err)
	}
	t, ok := s.idx.Load().byID[id]
	if !ok {
		// The reload failed; the row is committed, so describe it from the input.
		t = Token{ID: id, Name: o.Name, ProxyID: o.ProxyID, CreatedBy: o.Actor, CreatedAt: time.Unix(now.Unix(), 0)}
		if !o.ExpiresAt.IsZero() {
			t.ExpiresAt = time.Unix(o.ExpiresAt.Unix(), 0)
		}
	}
	return plaintext, t, nil
}

func (s *WorkerTokenStore) expired(t Token, now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

type tokenRow struct {
	t    Token
	hash [sha256.Size]byte
}

const tokenColumns = `id, name, proxy_id, token_hash, created_by, created_at, expires_at, last_used_at, revoked_at, revoked_by`

func scanToken(sc interface{ Scan(...any) error }) (tokenRow, error) {
	var (
		r                          tokenRow
		hash                       []byte
		created                    int64
		expires, lastUsed, revoked sql.NullInt64
		revokedBy                  sql.NullString
	)
	if err := sc.Scan(&r.t.ID, &r.t.Name, &r.t.ProxyID, &hash, &r.t.CreatedBy, &created, &expires, &lastUsed, &revoked, &revokedBy); err != nil {
		return tokenRow{}, err
	}
	if len(hash) != sha256.Size {
		return tokenRow{}, fmt.Errorf("worker tokens: row %s has a malformed hash", r.t.ID)
	}
	copy(r.hash[:], hash)
	r.t.CreatedAt = time.Unix(created, 0)
	if expires.Valid {
		r.t.ExpiresAt = time.Unix(expires.Int64, 0)
	}
	if lastUsed.Valid {
		r.t.LastUsedAt = time.Unix(lastUsed.Int64, 0)
	}
	if revoked.Valid {
		r.t.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	r.t.RevokedBy = revokedBy.String
	return r, nil
}

func (s *WorkerTokenStore) rowByName(ctx context.Context, name string) (tokenRow, bool, error) {
	r, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM worker_tokens WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return tokenRow{}, false, nil
	}
	if err != nil {
		return tokenRow{}, false, fmt.Errorf("worker tokens: lookup: %w", err)
	}
	return r, true, nil
}

// Revoke soft-deletes a token. It is idempotent: revoking a revoked token
// keeps the first revoked_at and revoked_by. An unknown id is ErrNotFound.
func (s *WorkerTokenStore) Revoke(ctx context.Context, id, actor string) error {
	if actor == "" {
		return fmt.Errorf("%w: actor is required", ErrInvalidInput)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE worker_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
		s.clk.Now().Unix(), actor, id)
	if err != nil {
		return fmt.Errorf("worker tokens: revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("worker tokens: revoke: %w", err)
	}
	if n == 0 {
		var one int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM worker_tokens WHERE id = ?`, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("worker tokens: revoke: %w", err)
		}
		return nil
	}
	if err := s.reload(ctx); err != nil {
		// The revocation is committed; the poll loop retries the reload. Never
		// report a failed revoke for a committed one.
		s.log.Warn("worker tokens: index reload failed after revoke", "err", err)
	}
	return nil
}

// List returns every token's metadata (revoked ones included), oldest first,
// with pending last-used values applied. It never returns a plaintext or hash.
func (s *WorkerTokenStore) List(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM worker_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("worker tokens: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Token
	s.usedMu.Lock()
	defer s.usedMu.Unlock()
	for rows.Next() {
		r, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("worker tokens: list: %w", err)
		}
		if u, ok := s.used[r.t.ID]; ok && u.After(r.t.LastUsedAt) {
			r.t.LastUsedAt = u
		}
		out = append(out, r.t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("worker tokens: list: %w", err)
	}
	return out, nil
}

// MarkUsed records a use in memory only; Flush (or Run's timer) persists it.
func (s *WorkerTokenStore) MarkUsed(id string, t time.Time) {
	s.usedMu.Lock()
	if cur, ok := s.used[id]; !ok || t.After(cur) {
		s.used[id] = t
		s.dirty[id] = t
	}
	s.usedMu.Unlock()
}

// Flush writes every dirty last_used_at in one transaction. A failure keeps
// the values for the next flush.
func (s *WorkerTokenStore) Flush(ctx context.Context) error {
	s.usedMu.Lock()
	batch := s.dirty
	s.dirty = map[string]time.Time{}
	s.usedMu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	err := s.writeUsed(ctx, batch)
	if err != nil {
		s.usedMu.Lock()
		for id, t := range batch {
			if cur, ok := s.dirty[id]; !ok || t.After(cur) {
				s.dirty[id] = t
			}
		}
		s.usedMu.Unlock()
		return fmt.Errorf("worker tokens: flush last used: %w", err)
	}
	s.flushTx.Add(1)
	s.usedMu.Lock()
	for id, t := range batch {
		if s.used[id].Equal(t) && !s.dirtyHas(id) {
			delete(s.used, id)
		}
	}
	s.usedMu.Unlock()
	return nil
}

func (s *WorkerTokenStore) dirtyHas(id string) bool { _, ok := s.dirty[id]; return ok }

func (s *WorkerTokenStore) writeUsed(ctx context.Context, batch map[string]time.Time) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for id, t := range batch {
		if _, err = tx.ExecContext(ctx,
			`UPDATE worker_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
			t.Unix(), id, t.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Run polls for changes made by other processes and flushes last-used values
// until ctx ends, then flushes once more. A reload error keeps the last good
// index (revocations already loaded stay in force) and logs a warning.
func (s *WorkerTokenStore) Run(ctx context.Context) {
	poll := s.clk.NewTimer(s.pollInterval)
	flush := s.clk.NewTimer(s.flushInterval)
	defer poll.Stop()
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := s.Flush(fctx); err != nil {
				s.log.Warn("worker tokens: final flush failed", "err", err)
			}
			cancel()
			return
		case <-poll.C():
			s.poll(ctx)
			poll.Reset(s.pollInterval)
		case <-flush.C():
			if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("worker tokens: flush failed", "err", err)
			}
			flush.Reset(s.flushInterval)
		}
	}
}

// poll reloads the index when PRAGMA data_version moved.
func (s *WorkerTokenStore) poll(ctx context.Context) {
	s.loadMu.Lock()
	v, err := s.readDataVersion(ctx)
	changed := err == nil && v != s.dataVersion
	s.loadMu.Unlock()
	if err == nil && !changed {
		return
	}
	if err == nil {
		err = s.reload(ctx)
	}
	if err != nil && ctx.Err() == nil {
		s.log.Warn("worker tokens: index reload failed; keeping the last good index", "err", err)
	}
}

func (s *WorkerTokenStore) readDataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// reload rebuilds the index from the table and fires OnRevoked for ids that
// are revoked now but were not before. data_version is read before the rows,
// so a commit that lands in between is picked up by the next poll.
func (s *WorkerTokenStore) reload(ctx context.Context) error {
	s.loadMu.Lock()
	v, err := s.readDataVersion(ctx)
	if err != nil {
		s.loadMu.Unlock()
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM worker_tokens`)
	if err != nil {
		s.loadMu.Unlock()
		return err
	}
	next := &tokenIndex{byHash: map[[sha256.Size]byte]Token{}, byID: map[string]Token{}}
	for rows.Next() {
		r, serr := scanToken(rows)
		if serr != nil {
			_ = rows.Close()
			s.loadMu.Unlock()
			return serr
		}
		next.byHash[r.hash] = r.t
		next.byID[r.t.ID] = r.t
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		s.loadMu.Unlock()
		return err
	}
	_ = rows.Close()

	prev := s.idx.Load()
	var revoked []string
	if prev != nil {
		for id, t := range next.byID {
			if t.RevokedAt.IsZero() {
				continue
			}
			if old, ok := prev.byID[id]; !ok || old.RevokedAt.IsZero() {
				revoked = append(revoked, id)
			}
		}
	}
	s.idx.Store(next)
	s.dataVersion = v
	hooks := append([]func(string){}, s.hooks...)
	s.loadMu.Unlock()

	for _, id := range revoked {
		for _, fn := range hooks {
			fn(id)
		}
	}
	return nil
}
