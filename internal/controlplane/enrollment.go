package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
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

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/workerca"
)

// Enrollment token format (W-P2-WCA-02). A token is "wet_" plus 52 lowercase
// unpadded base32 characters (32 random bytes), visibly distinct from "wwt_";
// only its sha256 is stored, which is enough because the secret has 256 bits
// of entropy.
const (
	enrollTokenPrefix = "wet_"
	enrollTokenEncLen = 52
	enrollTokenLen    = len(enrollTokenPrefix) + enrollTokenEncLen
	enrollTokenIDLen  = 8 // random bytes behind the "et_" id

	// MaxEnrollUses is the most uses a prefix-bound token may carry.
	MaxEnrollUses = 100

	// Defaults when the store is built without the workerCA TTLs.
	defaultEnrollTokenTTL    = time.Hour
	defaultEnrollTokenMaxTTL = 24 * time.Hour

	// Issued-via values of worker_certs.
	CertIssuedViaEnroll = "enroll"
	CertIssuedViaRenew  = "renew"
)

// Typed errors of the enrollment store. The unknown, revoked, expired and
// exhausted ones are all the same 401 on the wire; they differ only in the
// rate-limited log line.
var (
	ErrEnrollUnknown   = errors.New("enrollment token: unknown")
	ErrEnrollRevoked   = errors.New("enrollment token: revoked")
	ErrEnrollExpired   = errors.New("enrollment token: expired")
	ErrEnrollExhausted = errors.New("enrollment token: used up")
	// ErrEnrollBadWorkerID is a suffix that makes the final worker id invalid,
	// or a missing one for a prefix token (a 400, not a 401).
	ErrEnrollBadWorkerID = errors.New("enrollment token: worker id is invalid")
	// ErrEnrollNotFound is Revoke naming an id that does not exist.
	ErrEnrollNotFound = errors.New("enrollment token: not found")
	// ErrEnrollNameTaken: a token (active or revoked) already has this name.
	ErrEnrollNameTaken = errors.New("enrollment token: name already in use")
	// ErrEnrollInUse: an imported value is already registered under another name.
	ErrEnrollInUse = errors.New("enrollment token: value already registered")
	// ErrCertNotFound is RevokeCert naming a serial that does not exist.
	ErrCertNotFound = errors.New("worker cert: not found")
)

var enrollPrefixRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,127}$`)

// EnrollmentMigrations are the cpstate migrations of worker_enroll_tokens and
// worker_certs. StateMigrations includes them; callers that open the DB
// themselves must use StateMigrations too, for the downgrade guard.
func EnrollmentMigrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID: "workerenroll/0001",
		SQL: `CREATE TABLE worker_enroll_tokens (
  id               TEXT PRIMARY KEY,
  name             TEXT UNIQUE NOT NULL,
  token_hash       BLOB UNIQUE NOT NULL,
  worker_id        TEXT NULL,
  worker_id_prefix TEXT NULL,
  max_uses         INTEGER NOT NULL DEFAULT 1,
  uses             INTEGER NOT NULL DEFAULT 0,
  created_by       TEXT NOT NULL,
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  revoked_at       INTEGER NULL,
  revoked_by       TEXT NULL,
  CHECK ((worker_id IS NULL) <> (worker_id_prefix IS NULL))
);
CREATE TABLE worker_certs (
  serial          TEXT PRIMARY KEY,
  worker_id       TEXT NOT NULL,
  spki_sha256     TEXT NOT NULL,
  issuer_kid      TEXT NOT NULL,
  prev_serial     TEXT NULL,
  enroll_token_id TEXT NULL,
  issued_via      TEXT NOT NULL CHECK (issued_via IN ('enroll', 'renew')),
  issued_at       INTEGER NOT NULL,
  not_after       INTEGER NOT NULL,
  revoked_at      INTEGER NULL,
  revoked_by      TEXT NULL,
  revoke_reason   TEXT NULL
);
CREATE INDEX worker_certs_worker_id ON worker_certs (worker_id);`,
	}}
}

// EnrollToken is an enrollment token's metadata. It never holds the plaintext
// or the hash. Exactly one of WorkerID and WorkerIDPrefix is set.
type EnrollToken struct {
	ID, Name       string
	WorkerID       string
	WorkerIDPrefix string
	MaxUses, Uses  int
	CreatedBy      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RevokedAt      time.Time
	RevokedBy      string
}

// String prints id, name and binding only, so %v and %+v are log-safe.
func (t EnrollToken) String() string {
	return fmt.Sprintf("enrollment token id=%s name=%q binding=%s", t.ID, t.Name, t.Binding())
}

// LogValue keeps slog output to id, name and binding.
func (t EnrollToken) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", t.ID), slog.String("name", t.Name), slog.String("binding", t.Binding()))
}

// Binding is the worker id, or the worker id prefix followed by "*".
func (t EnrollToken) Binding() string {
	if t.WorkerID != "" {
		return t.WorkerID
	}
	return t.WorkerIDPrefix + "*"
}

// Usable reports why the token cannot enroll at now, or nil.
func (t EnrollToken) Usable(now time.Time) error {
	switch {
	case !t.RevokedAt.IsZero():
		return ErrEnrollRevoked
	case !now.Before(t.ExpiresAt):
		return ErrEnrollExpired
	case t.Uses >= t.MaxUses:
		return ErrEnrollExhausted
	}
	return nil
}

// ResolveWorkerID is the worker id a redemption with suffix enrolls: the
// token's id as is, or prefix+suffix for a prefix token. The result must be a
// valid worker id (so "../x" is refused).
func (t EnrollToken) ResolveWorkerID(suffix string) (string, error) {
	if t.WorkerID != "" {
		return t.WorkerID, nil
	}
	if suffix == "" || !workerca.ValidWorkerID(t.WorkerIDPrefix+suffix) {
		return "", ErrEnrollBadWorkerID
	}
	return t.WorkerIDPrefix + suffix, nil
}

// EnrollCreateOpts describes a token to mint. A non-empty Plaintext is
// imported (format-checked and registered as given) instead of generated.
type EnrollCreateOpts struct {
	Name           string
	WorkerID       string
	WorkerIDPrefix string
	MaxUses        int           // 0: 1
	TTL            time.Duration // 0: the store default
	Actor          string
	Plaintext      string
}

// CertRecord is one worker_certs row.
type CertRecord struct {
	Serial        string // lowercase hex
	WorkerID      string
	SPKISHA256    string // hex sha256 of the SubjectPublicKeyInfo
	IssuerKID     string
	PrevSerial    string
	EnrollTokenID string
	IssuedVia     string
	IssuedAt      time.Time
	NotAfter      time.Time
	RevokedAt     time.Time
}

// RecordFor describes cert as a worker_certs row.
func RecordFor(cert *x509.Certificate, workerID, via string, at time.Time) CertRecord {
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return CertRecord{
		Serial: cert.SerialNumber.Text(16), WorkerID: workerID, SPKISHA256: hex.EncodeToString(spki[:]),
		IssuerKID: hex.EncodeToString(cert.AuthorityKeyId), IssuedVia: via, IssuedAt: at, NotAfter: cert.NotAfter,
	}
}

// Redeemed is the outcome of a successful Redeem.
type Redeemed struct {
	Token    EnrollToken // with the use counted
	WorkerID string
	Cert     *x509.Certificate
}

// EnrollmentTokenStore creates, checks, redeems, revokes and lists enrollment
// tokens. It has no HTTP concerns, so a Postgres backend can replace the SQLite
// one behind the same methods.
type EnrollmentTokenStore interface {
	// Create mints (or imports) a token and returns its plaintext, which no
	// later call returns. created is false for an import of a name and value
	// that already exist (nothing changed).
	Create(ctx context.Context, o EnrollCreateOpts) (plaintext string, t EnrollToken, created bool, err error)
	// Peek resolves a presented token from memory (no DB I/O, nothing
	// consumed) and says why it cannot enroll, if so.
	Peek(plaintext string) (EnrollToken, error)
	// Redeem atomically consumes one use of the token, calls issue with the
	// final worker id and records the certificate it returns. issue runs inside
	// the transaction and must not touch the database; if it fails nothing is
	// consumed.
	Redeem(ctx context.Context, plaintext, suffix string, issue func(workerID string) (*x509.Certificate, error)) (Redeemed, error)
	// Revoke soft-deletes a token; it is idempotent.
	Revoke(ctx context.Context, id, actor string) error
	// List returns every token's metadata, oldest first.
	List(ctx context.Context) ([]EnrollToken, error)
}

// WorkerCertStore records the certificates the control plane issued.
type WorkerCertStore interface {
	// RecordCert inserts a row (renewals, W-P2-WCA-04; enrollment records its
	// own inside Redeem).
	RecordCert(ctx context.Context, r CertRecord) error
	// RevokeCert marks one serial revoked; ErrCertNotFound for an unknown one.
	RevokeCert(ctx context.Context, serial, actor, reason string) error
	// Cert returns the row of a serial, or ErrCertNotFound.
	Cert(ctx context.Context, serial string) (CertRecord, error)
}

// EnrollmentOptions configures an EnrollmentStore. Zero values use the real
// clock, a 2 s poll, slog.Default, a 1 h default and a 24 h maximum lifetime.
type EnrollmentOptions struct {
	Clock        clock.Clock
	PollInterval time.Duration
	Logger       *slog.Logger
	DefaultTTL   time.Duration
	MaxTTL       time.Duration
}

type enrollIndex struct {
	byHash map[[sha256.Size]byte]EnrollToken
}

// EnrollmentStore is the SQLite EnrollmentTokenStore and WorkerCertStore on
// the cpstate database. Peek reads only an in-memory index; the index is
// rebuilt after local writes and reloaded when another process commits to the
// same file (PRAGMA data_version), like WorkerTokenStore.
type EnrollmentStore struct {
	db           *sql.DB
	clk          clock.Clock
	log          *slog.Logger
	pollInterval time.Duration
	defaultTTL   time.Duration
	maxTTL       time.Duration

	idx atomic.Pointer[enrollIndex]

	loadMu      sync.Mutex // serialises reloads; guards dataVersion
	dataVersion int64
}

var (
	_ EnrollmentTokenStore = (*EnrollmentStore)(nil)
	_ WorkerCertStore      = (*EnrollmentStore)(nil)
)

// NewEnrollmentStore builds a store over db (opened with StateMigrations) and
// loads the index; an error here means no store, never an empty index.
func NewEnrollmentStore(db *cpstate.DB, o EnrollmentOptions) (*EnrollmentStore, error) {
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.PollInterval <= 0 {
		o.PollInterval = defaultTokenPollInterval
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.DefaultTTL <= 0 {
		o.DefaultTTL = defaultEnrollTokenTTL
	}
	if o.MaxTTL <= 0 {
		o.MaxTTL = defaultEnrollTokenMaxTTL
	}
	s := &EnrollmentStore{db: db.SQL(), clk: o.Clock, log: o.Logger, pollInterval: o.PollInterval,
		defaultTTL: o.DefaultTTL, maxTTL: o.MaxTTL}
	if err := s.reload(context.Background()); err != nil {
		return nil, fmt.Errorf("enrollment tokens: load: %w", err)
	}
	return s, nil
}

func enrollWellFormed(v string) bool {
	if len(v) != enrollTokenLen || v[:len(enrollTokenPrefix)] != enrollTokenPrefix {
		return false
	}
	for i := len(enrollTokenPrefix); i < len(v); i++ {
		c := v[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

func generateEnrollToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("enrollment tokens: random: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	return enrollTokenPrefix + strings.ToLower(enc), nil
}

// Peek implements EnrollmentTokenStore.
func (s *EnrollmentStore) Peek(plaintext string) (EnrollToken, error) {
	if !enrollWellFormed(plaintext) {
		return EnrollToken{}, ErrEnrollUnknown
	}
	t, ok := s.idx.Load().byHash[sha256.Sum256([]byte(plaintext))]
	if !ok {
		return EnrollToken{}, ErrEnrollUnknown
	}
	if err := t.Usable(s.clk.Now()); err != nil {
		return t, err
	}
	return t, nil
}

// Create implements EnrollmentTokenStore.
func (s *EnrollmentStore) Create(ctx context.Context, o EnrollCreateOpts) (string, EnrollToken, bool, error) {
	if err := validateTokenName(o.Name); err != nil {
		return "", EnrollToken{}, false, err
	}
	if o.Actor == "" {
		return "", EnrollToken{}, false, fmt.Errorf("%w: actor is required", ErrInvalidInput)
	}
	if (o.WorkerID == "") == (o.WorkerIDPrefix == "") {
		return "", EnrollToken{}, false, fmt.Errorf("%w: give exactly one of a worker id and a worker id prefix", ErrInvalidInput)
	}
	if o.WorkerID != "" && !workerca.ValidWorkerID(o.WorkerID) {
		return "", EnrollToken{}, false, fmt.Errorf("%w: worker id must match %s", ErrInvalidInput, proxyIDRe)
	}
	if o.WorkerIDPrefix != "" && !enrollPrefixRe.MatchString(o.WorkerIDPrefix) {
		return "", EnrollToken{}, false, fmt.Errorf("%w: worker id prefix must match %s", ErrInvalidInput, enrollPrefixRe)
	}
	maxUses := o.MaxUses
	if maxUses == 0 {
		maxUses = 1
	}
	if maxUses < 1 || maxUses > MaxEnrollUses || (maxUses > 1 && o.WorkerIDPrefix == "") {
		return "", EnrollToken{}, false, fmt.Errorf("%w: max uses must be 1 to %d, and above 1 only with a worker id prefix", ErrInvalidInput, MaxEnrollUses)
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = s.defaultTTL
	}
	if ttl < 0 || ttl > s.maxTTL {
		return "", EnrollToken{}, false, fmt.Errorf("%w: lifetime must be positive and at most %s", ErrInvalidInput, s.maxTTL)
	}
	imported := o.Plaintext != ""
	plaintext := o.Plaintext
	if imported {
		if !enrollWellFormed(plaintext) {
			return "", EnrollToken{}, false, fmt.Errorf("%w: imported value is not an enrollment token", ErrInvalidInput)
		}
	} else {
		var err error
		if plaintext, err = generateEnrollToken(); err != nil {
			return "", EnrollToken{}, false, err
		}
	}
	hash := sha256.Sum256([]byte(plaintext))
	now := s.clk.Now()

	if imported {
		// Same name, value and binding as a live row: nothing to do. Any other
		// row of that name is a conflict, never a silent overwrite.
		t, h, err := scanEnroll(s.db.QueryRowContext(ctx, `SELECT `+enrollColumns+` FROM worker_enroll_tokens WHERE name = ?`, o.Name))
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return "", EnrollToken{}, false, fmt.Errorf("enrollment tokens: lookup: %w", err)
		case subtle.ConstantTimeCompare(h[:], hash[:]) == 1 && t.Usable(now) == nil &&
			t.WorkerID == o.WorkerID && t.WorkerIDPrefix == o.WorkerIDPrefix:
			return plaintext, t, false, nil
		default:
			return "", EnrollToken{}, false, ErrEnrollNameTaken
		}
	}

	var idb [enrollTokenIDLen]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return "", EnrollToken{}, false, fmt.Errorf("enrollment tokens: random id: %w", err)
	}
	id := "et_" + hex.EncodeToString(idb[:])
	exp := now.Add(ttl).Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO worker_enroll_tokens (id, name, token_hash, worker_id, worker_id_prefix, max_uses, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, o.Name, hash[:], nullIfEmpty(o.WorkerID), nullIfEmpty(o.WorkerIDPrefix), maxUses, o.Actor, now.Unix(), exp)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "worker_enroll_tokens.name"):
			return "", EnrollToken{}, false, ErrEnrollNameTaken
		case strings.Contains(err.Error(), "worker_enroll_tokens.token_hash"):
			return "", EnrollToken{}, false, ErrEnrollInUse
		}
		return "", EnrollToken{}, false, fmt.Errorf("enrollment tokens: insert: %w", err)
	}
	if err := s.reload(ctx); err != nil {
		s.log.Warn("enrollment tokens: index reload failed after create", "err", err)
	}
	t := EnrollToken{ID: id, Name: o.Name, WorkerID: o.WorkerID, WorkerIDPrefix: o.WorkerIDPrefix, MaxUses: maxUses,
		CreatedBy: o.Actor, CreatedAt: time.Unix(now.Unix(), 0), ExpiresAt: time.Unix(exp, 0)}
	return plaintext, t, true, nil
}

const enrollColumns = `id, name, token_hash, worker_id, worker_id_prefix, max_uses, uses, created_by, created_at, expires_at, revoked_at, revoked_by`

func scanEnroll(sc interface{ Scan(...any) error }) (EnrollToken, [sha256.Size]byte, error) {
	var (
		t                  EnrollToken
		hash               []byte
		wid, prefix, revBy sql.NullString
		created, expires   int64
		revoked            sql.NullInt64
		out                [sha256.Size]byte
	)
	if err := sc.Scan(&t.ID, &t.Name, &hash, &wid, &prefix, &t.MaxUses, &t.Uses, &t.CreatedBy, &created, &expires, &revoked, &revBy); err != nil {
		return EnrollToken{}, out, err
	}
	if len(hash) != sha256.Size {
		return EnrollToken{}, out, fmt.Errorf("enrollment tokens: row %s has a malformed hash", t.ID)
	}
	copy(out[:], hash)
	t.WorkerID, t.WorkerIDPrefix = wid.String, prefix.String
	t.CreatedAt, t.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	if revoked.Valid {
		t.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	t.RevokedBy = revBy.String
	return t, out, nil
}

// Redeem implements EnrollmentTokenStore: one BEGIN IMMEDIATE transaction
// looks the token up by hash, checks revocation, expiry and uses, counts the
// use, runs issue and inserts the worker_certs row. Two redemptions of a
// single-use token can never both commit.
func (s *EnrollmentStore) Redeem(ctx context.Context, plaintext, suffix string, issue func(workerID string) (*x509.Certificate, error)) (Redeemed, error) {
	if !enrollWellFormed(plaintext) {
		return Redeemed{}, ErrEnrollUnknown
	}
	res, err := s.redeemTx(ctx, plaintext, suffix, issue)
	if err != nil {
		return Redeemed{}, err
	}
	if err := s.reload(ctx); err != nil {
		s.log.Warn("enrollment tokens: index reload failed after redeem", "err", err)
	}
	return res, nil
}

func (s *EnrollmentStore) redeemTx(ctx context.Context, plaintext, suffix string, issue func(string) (*x509.Certificate, error)) (res Redeemed, err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Redeemed{}, fmt.Errorf("enrollment tokens: redeem: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return Redeemed{}, fmt.Errorf("enrollment tokens: redeem: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()

	hash := sha256.Sum256([]byte(plaintext))
	t, stored, err := scanEnroll(conn.QueryRowContext(ctx, `SELECT `+enrollColumns+` FROM worker_enroll_tokens WHERE token_hash = ?`, hash[:]))
	if errors.Is(err, sql.ErrNoRows) {
		return Redeemed{}, ErrEnrollUnknown
	}
	if err != nil {
		return Redeemed{}, fmt.Errorf("enrollment tokens: redeem: %w", err)
	}
	if subtle.ConstantTimeCompare(stored[:], hash[:]) != 1 {
		return Redeemed{}, ErrEnrollUnknown
	}
	now := s.clk.Now()
	if err := t.Usable(now); err != nil {
		return Redeemed{}, err
	}
	workerID, err := t.ResolveWorkerID(suffix)
	if err != nil {
		return Redeemed{}, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE worker_enroll_tokens SET uses = uses + 1 WHERE id = ?`, t.ID); err != nil {
		return Redeemed{}, fmt.Errorf("enrollment tokens: redeem: %w", err)
	}
	t.Uses++
	cert, err := issue(workerID)
	if err != nil {
		return Redeemed{}, err
	}
	rec := RecordFor(cert, workerID, CertIssuedViaEnroll, now)
	rec.EnrollTokenID = t.ID
	if err = insertCert(ctx, conn, rec); err != nil {
		return Redeemed{}, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return Redeemed{}, fmt.Errorf("enrollment tokens: redeem: commit: %w", err)
	}
	committed = true
	return Redeemed{Token: t, WorkerID: workerID, Cert: cert}, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertCert(ctx context.Context, ex execer, r CertRecord) error {
	_, err := ex.ExecContext(ctx,
		`INSERT INTO worker_certs (serial, worker_id, spki_sha256, issuer_kid, prev_serial, enroll_token_id, issued_via, issued_at, not_after)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Serial, r.WorkerID, r.SPKISHA256, r.IssuerKID, nullIfEmpty(r.PrevSerial), nullIfEmpty(r.EnrollTokenID),
		r.IssuedVia, r.IssuedAt.Unix(), r.NotAfter.Unix())
	if err != nil {
		return fmt.Errorf("worker certs: insert: %w", err)
	}
	return nil
}

// RecordCert implements WorkerCertStore.
func (s *EnrollmentStore) RecordCert(ctx context.Context, r CertRecord) error {
	return insertCert(ctx, s.db, r)
}

// RevokeCert implements WorkerCertStore.
func (s *EnrollmentStore) RevokeCert(ctx context.Context, serial, actor, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE worker_certs SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE serial = ? AND revoked_at IS NULL`,
		s.clk.Now().Unix(), actor, reason, serial)
	if err != nil {
		return fmt.Errorf("worker certs: revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.Cert(ctx, serial); err != nil {
			return err
		}
	}
	return nil
}

// Cert implements WorkerCertStore.
func (s *EnrollmentStore) Cert(ctx context.Context, serial string) (CertRecord, error) {
	var (
		r                CertRecord
		prev, tok        sql.NullString
		issued, notAfter int64
		revoked          sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT serial, worker_id, spki_sha256, issuer_kid, prev_serial, enroll_token_id, issued_via, issued_at, not_after, revoked_at
		 FROM worker_certs WHERE serial = ?`, serial).
		Scan(&r.Serial, &r.WorkerID, &r.SPKISHA256, &r.IssuerKID, &prev, &tok, &r.IssuedVia, &issued, &notAfter, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return CertRecord{}, ErrCertNotFound
	}
	if err != nil {
		return CertRecord{}, fmt.Errorf("worker certs: lookup: %w", err)
	}
	r.PrevSerial, r.EnrollTokenID = prev.String, tok.String
	r.IssuedAt, r.NotAfter = time.Unix(issued, 0), time.Unix(notAfter, 0)
	if revoked.Valid {
		r.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	return r, nil
}

// Revoke implements EnrollmentTokenStore. It is idempotent: revoking a revoked
// token keeps the first revoked_at and revoked_by.
func (s *EnrollmentStore) Revoke(ctx context.Context, id, actor string) error {
	if actor == "" {
		return fmt.Errorf("%w: actor is required", ErrInvalidInput)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE worker_enroll_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
		s.clk.Now().Unix(), actor, id)
	if err != nil {
		return fmt.Errorf("enrollment tokens: revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var one int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM worker_enroll_tokens WHERE id = ?`, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollNotFound
		}
		if err != nil {
			return fmt.Errorf("enrollment tokens: revoke: %w", err)
		}
		return nil
	}
	if err := s.reload(ctx); err != nil {
		// The revocation is committed; the poll loop retries the reload.
		s.log.Warn("enrollment tokens: index reload failed after revoke", "err", err)
	}
	return nil
}

// List implements EnrollmentTokenStore.
func (s *EnrollmentStore) List(ctx context.Context) ([]EnrollToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+enrollColumns+` FROM worker_enroll_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("enrollment tokens: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []EnrollToken
	for rows.Next() {
		t, _, err := scanEnroll(rows)
		if err != nil {
			return nil, fmt.Errorf("enrollment tokens: list: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("enrollment tokens: list: %w", err)
	}
	return out, nil
}

// Run polls for changes other processes made until ctx ends. A reload error
// keeps the last good index (revocations already loaded stay in force).
func (s *EnrollmentStore) Run(ctx context.Context) {
	poll := s.clk.NewTimer(s.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C():
			s.poll(ctx)
			poll.Reset(s.pollInterval)
		}
	}
}

func (s *EnrollmentStore) poll(ctx context.Context) {
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
		s.log.Warn("enrollment tokens: index reload failed; keeping the last good index", "err", err)
	}
}

func (s *EnrollmentStore) readDataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// reload rebuilds the index. data_version is read before the rows, so a commit
// that lands in between is picked up by the next poll.
func (s *EnrollmentStore) reload(ctx context.Context) error {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	v, err := s.readDataVersion(ctx)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+enrollColumns+` FROM worker_enroll_tokens`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	next := &enrollIndex{byHash: map[[sha256.Size]byte]EnrollToken{}}
	for rows.Next() {
		t, h, err := scanEnroll(rows)
		if err != nil {
			return err
		}
		next.byHash[h] = t
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.idx.Store(next)
	s.dataVersion = v
	return nil
}
