package controlplane

// policystore.go is the versioned policy store (W-P1-PVER-01): an append-only
// history of the served policy doc (the canonical policyWire {allowlist,
// denylist, settings}) in the CP state DB, with a one-row head that moves by
// compare-and-swap. --policy-store=versioned serves the head version; file mode
// (the default) and an empty store keep serving the YAML exactly as before.
//
// Credential values are never versioned: RedactCredentials replaces the AWS
// secretAccessKey with its fingerprint before a doc is hashed or stored, and
// the credential overlay puts the live value from the served YAML back at serve
// time. Serve-time overlay data (the credential, the block list) is never part
// of a version, so a rollback can never restore it.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Policy store modes (--policy-store).
const (
	PolicyStoreFile      = "file"
	PolicyStoreVersioned = "versioned"
)

// Version sources: what produced a version.
const (
	SourcePolicy       = "policy"
	SourceSettings     = "settings"
	SourceLLMProviders = "llmproviders"
	SourceRollback     = "rollback"
	SourceImport       = "import"
)

// Author kinds: the admin-audit auth_method set.
const (
	AuthorKindOIDC       = "oidc"
	AuthorKindBreakglass = "breakglass"
	AuthorKindCLI        = "cli"
	AuthorKindBearer     = "bearer"
	AuthorKindNone       = "none"
	AuthorKindSystem     = "system"
)

// maxPolicyMessage caps a version message, in characters.
const maxPolicyMessage = 512

// List page bounds.
const (
	defaultPolicyListLimit = 50
	maxPolicyListLimit     = 500
)

// credentialRedactPrefix and credentialRedactHexLen give the redacted form of a
// credential: sha256:<16 lowercase hex>.
const (
	credentialRedactPrefix = "sha256:"
	credentialRedactHexLen = 16
)

var (
	// ErrConflict is returned by Create when the head is not expectedHead.
	// Nothing was written.
	ErrConflict = errors.New("policy store: head moved")
	// ErrVersionNotFound is returned by Get for a version the store lacks.
	ErrVersionNotFound = errors.New("policy store: version not found")
	// ErrDocIntegrity is returned by Get when a stored doc fails its doc_sha256
	// check.
	ErrDocIntegrity = errors.New("policy store: doc fails its doc_sha256 check")
)

var authorKinds = map[string]bool{
	AuthorKindOIDC: true, AuthorKindBreakglass: true, AuthorKindCLI: true,
	AuthorKindBearer: true, AuthorKindNone: true, AuthorKindSystem: true,
}

var versionSources = map[string]bool{
	SourcePolicy: true, SourceSettings: true, SourceLLMProviders: true,
	SourceRollback: true, SourceImport: true,
}

// PolicyStoreMigrations are the cpstate migrations of the versioned policy
// store. Run registers them whenever a state dir is set, in either mode, so
// switching back to --policy-store=file never trips the downgrade guard; the
// tables stay empty in file mode. Triggers make the history append-only.
func PolicyStoreMigrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID: "policystore/0001",
		SQL: `CREATE TABLE policy_versions (
  version        INTEGER PRIMARY KEY,
  parent_version INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  author_sub     TEXT NOT NULL,
  author_email   TEXT NOT NULL,
  author_kind    TEXT NOT NULL,
  message        TEXT NOT NULL,
  source         TEXT NOT NULL,
  doc_json       TEXT NOT NULL,
  doc_sha256     TEXT NOT NULL
);
CREATE TABLE policy_head (
  version INTEGER NOT NULL
);
INSERT INTO policy_head (version) VALUES (0);
CREATE TABLE policy_publish_log (
  seq       INTEGER PRIMARY KEY,
  version   INTEGER NOT NULL,
  etag      TEXT NOT NULL,
  reason    TEXT NOT NULL,
  actor_sub TEXT NOT NULL,
  at        INTEGER NOT NULL
);
CREATE TRIGGER policy_versions_no_update BEFORE UPDATE ON policy_versions
BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only'); END;
CREATE TRIGGER policy_versions_no_delete BEFORE DELETE ON policy_versions
BEGIN SELECT RAISE(ABORT, 'policy_versions is append-only'); END;
CREATE TRIGGER policy_publish_log_no_update BEFORE UPDATE ON policy_publish_log
BEGIN SELECT RAISE(ABORT, 'policy_publish_log is append-only'); END;
CREATE TRIGGER policy_publish_log_no_delete BEFORE DELETE ON policy_publish_log
BEGIN SELECT RAISE(ABORT, 'policy_publish_log is append-only'); END;`,
	}}
}

// StateMigrations are every migration the control plane registers with
// cpstate.Open, in order. Run uses it; out-of-process tools opening the same
// file must too, or the downgrade guard refuses the file.
func StateMigrations() []cpstate.Migration {
	var migs []cpstate.Migration
	migs = append(migs, SessionMigrations()...)
	migs = append(migs, OIDCPendingMigrations()...)
	migs = append(migs, PolicyStoreMigrations()...)
	return migs
}

// PolicyAuthor is who created a version. Kind is one of the AuthorKind values.
type PolicyAuthor struct {
	Sub, Email, Kind string
}

// PolicyVersion is one stored version. Doc is set by Get only; List leaves it
// zero.
type PolicyVersion struct {
	Version   int64
	Parent    int64
	CreatedAt time.Time
	Author    PolicyAuthor
	Message   string
	Source    string
	Doc       policyWire
	DocSHA256 string
}

// PublishEntry is one policy_publish_log row: a head move (or, later, an ETag
// change without a new version) and the served ETag it produced.
type PublishEntry struct {
	Seq      int64
	Version  int64
	ETag     string
	Reason   string
	ActorSub string
	At       time.Time
}

// PolicyVersionStore is the versioned policy history. It has no update or
// delete of versions. A Postgres store can implement it later.
type PolicyVersionStore interface {
	// Create appends doc (credentials redacted) as a new head version if the
	// head is still expectedHead, in one transaction with its publish-log row.
	// A doc equal to head's writes nothing and returns (head, false, nil). A
	// moved head returns ErrConflict and writes nothing. Callers validate the
	// doc (Server.validateDoc) first.
	Create(ctx context.Context, doc policyWire, author PolicyAuthor, msg, source string, expectedHead int64) (version int64, changed bool, err error)
	// Head returns the head version; 0 means the store is empty.
	Head(ctx context.Context) (int64, error)
	// Get returns one version with its doc, checked against doc_sha256.
	Get(ctx context.Context, version int64) (PolicyVersion, error)
	// List returns up to limit versions older than cursor (0 = from the
	// newest), newest first, without docs, and the cursor of the next page
	// (0 = no more).
	List(ctx context.Context, cursor int64, limit int) ([]PolicyVersion, int64, error)
	// PublishLog returns up to limit publish-log rows after afterSeq, oldest
	// first.
	PublishLog(ctx context.Context, afterSeq int64, limit int) ([]PublishEntry, error)
}

// sqlitePolicyStore is the PolicyVersionStore on the cpstate SQLite DB.
type sqlitePolicyStore struct {
	db     *sql.DB
	now    func() time.Time
	logger *slog.Logger
	// etagOf returns the served ETag a doc produces (overlays applied), for the
	// publish-log row; nil uses etagFor(doc). onCreated runs after a committed
	// Create (the policy server's Refresh, so long-poll waiters wake at once).
	// Both are set once at wiring time, before the store is used.
	etagOf    func(ctx context.Context, doc policyWire) (string, error)
	onCreated func()
}

var _ PolicyVersionStore = (*sqlitePolicyStore)(nil)

// newSQLitePolicyStore builds a store over db (a cpstate DB opened with
// PolicyStoreMigrations).
func newSQLitePolicyStore(db *sql.DB, now func() time.Time, logger *slog.Logger) *sqlitePolicyStore {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &sqlitePolicyStore{db: db, now: now, logger: logger}
}

// Create implements PolicyVersionStore. It runs under BEGIN IMMEDIATE on one
// connection, so the head read, the CAS update and the inserts see no other
// writer, in this process or another.
func (st *sqlitePolicyStore) Create(ctx context.Context, doc policyWire, author PolicyAuthor, msg, source string, expectedHead int64) (int64, bool, error) {
	if !authorKinds[author.Kind] {
		return 0, false, fmt.Errorf("policy store: unknown author kind %q", author.Kind)
	}
	if strings.TrimSpace(author.Sub) == "" {
		return 0, false, errors.New("policy store: author sub is empty")
	}
	if !versionSources[source] {
		return 0, false, fmt.Errorf("policy store: unknown version source %q", source)
	}
	msg = sanitizeMessage(msg)
	red := RedactCredentials(doc)
	docJSON, err := json.Marshal(red)
	if err != nil {
		return 0, false, fmt.Errorf("policy store: encode doc: %w", err)
	}
	sum := sha256.Sum256(docJSON)
	docSHA := hex.EncodeToString(sum[:])
	etag := etagFor(red)
	if st.etagOf != nil {
		if etag, err = st.etagOf(ctx, red); err != nil {
			return 0, false, fmt.Errorf("policy store: served etag: %w", err)
		}
	}

	version, parent, changed, err := st.createTx(ctx, docJSON, docSHA, etag, author, msg, source, expectedHead)
	if err != nil || !changed {
		return version, changed, err
	}
	st.logger.Info("policy version created",
		"version", version, "parent", parent, "source", source,
		"author_sub", author.Sub, "doc_sha256", docSHA)
	if st.onCreated != nil {
		st.onCreated()
	}
	return version, true, nil
}

// createTx is Create's transaction. It returns the new version and its parent,
// or the head and changed=false for a doc equal to head's.
func (st *sqlitePolicyStore) createTx(ctx context.Context, docJSON []byte, docSHA, etag string, author PolicyAuthor, msg, source string, expectedHead int64) (version, parent int64, changed bool, err error) {
	conn, err := st.db.Conn(ctx)
	if err != nil {
		return 0, 0, false, fmt.Errorf("policy store: connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return 0, 0, false, fmt.Errorf("policy store: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()

	var head int64
	if err := conn.QueryRowContext(ctx, "SELECT version FROM policy_head").Scan(&head); err != nil {
		return 0, 0, false, fmt.Errorf("policy store: read head: %w", err)
	}
	if head != expectedHead {
		return 0, 0, false, fmt.Errorf("%w: head is v%d, expected v%d", ErrConflict, head, expectedHead)
	}
	if head > 0 {
		var headSHA string
		err := conn.QueryRowContext(ctx, "SELECT doc_sha256 FROM policy_versions WHERE version = ?", head).Scan(&headSHA)
		if err != nil {
			return 0, 0, false, fmt.Errorf("policy store: read head v%d: %w", head, err)
		}
		if headSHA == docSHA {
			return head, head, false, nil
		}
	}
	var next int64
	if err := conn.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions").Scan(&next); err != nil {
		return 0, 0, false, fmt.Errorf("policy store: next version: %w", err)
	}
	at := st.now().UnixMilli()
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO policy_versions (version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		next, head, at, author.Sub, author.Email, author.Kind, msg, source, string(docJSON), docSHA); err != nil {
		return 0, 0, false, fmt.Errorf("policy store: insert version: %w", err)
	}
	// The cross-process compare-and-swap.
	res, err := conn.ExecContext(ctx, "UPDATE policy_head SET version = ? WHERE version = ?", next, expectedHead)
	if err != nil {
		return 0, 0, false, fmt.Errorf("policy store: move head: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return 0, 0, false, fmt.Errorf("%w: head is no longer v%d", ErrConflict, expectedHead)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO policy_publish_log (version, etag, reason, actor_sub, at) VALUES (?, ?, ?, ?, ?)`,
		next, etag, source, author.Sub, at); err != nil {
		return 0, 0, false, fmt.Errorf("policy store: append publish log: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, 0, false, fmt.Errorf("policy store: commit: %w", err)
	}
	committed = true
	return next, head, true, nil
}

// Head implements PolicyVersionStore.
func (st *sqlitePolicyStore) Head(ctx context.Context) (int64, error) {
	var head int64
	if err := st.db.QueryRowContext(ctx, "SELECT version FROM policy_head").Scan(&head); err != nil {
		return 0, fmt.Errorf("policy store: read head: %w", err)
	}
	return head, nil
}

// Get implements PolicyVersionStore.
func (st *sqlitePolicyStore) Get(ctx context.Context, version int64) (PolicyVersion, error) {
	var (
		v       PolicyVersion
		at      int64
		docJSON string
	)
	err := st.db.QueryRowContext(ctx,
		`SELECT version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256
		 FROM policy_versions WHERE version = ?`, version).
		Scan(&v.Version, &v.Parent, &at, &v.Author.Sub, &v.Author.Email, &v.Author.Kind, &v.Message, &v.Source, &docJSON, &v.DocSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyVersion{}, fmt.Errorf("%w: version %d", ErrVersionNotFound, version)
	}
	if err != nil {
		return PolicyVersion{}, fmt.Errorf("policy store: read version %d: %w", version, err)
	}
	sum := sha256.Sum256([]byte(docJSON))
	if hex.EncodeToString(sum[:]) != v.DocSHA256 {
		return PolicyVersion{}, fmt.Errorf("%w: version %d", ErrDocIntegrity, version)
	}
	if err := json.Unmarshal([]byte(docJSON), &v.Doc); err != nil {
		return PolicyVersion{}, fmt.Errorf("policy store: decode version %d: %w", version, err)
	}
	v.CreatedAt = time.UnixMilli(at)
	return v, nil
}

// List implements PolicyVersionStore.
func (st *sqlitePolicyStore) List(ctx context.Context, cursor int64, limit int) ([]PolicyVersion, int64, error) {
	limit = clampLimit(limit)
	rows, err := st.db.QueryContext(ctx,
		`SELECT version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_sha256
		 FROM policy_versions WHERE (? = 0 OR version < ?) ORDER BY version DESC LIMIT ?`, cursor, cursor, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("policy store: list versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PolicyVersion
	for rows.Next() {
		var (
			v  PolicyVersion
			at int64
		)
		if err := rows.Scan(&v.Version, &v.Parent, &at, &v.Author.Sub, &v.Author.Email, &v.Author.Kind, &v.Message, &v.Source, &v.DocSHA256); err != nil {
			return nil, 0, fmt.Errorf("policy store: list versions: %w", err)
		}
		v.CreatedAt = time.UnixMilli(at)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("policy store: list versions: %w", err)
	}
	var next int64
	if len(out) == limit && out[len(out)-1].Version > 1 {
		next = out[len(out)-1].Version
	}
	return out, next, nil
}

// PublishLog implements PolicyVersionStore.
func (st *sqlitePolicyStore) PublishLog(ctx context.Context, afterSeq int64, limit int) ([]PublishEntry, error) {
	rows, err := st.db.QueryContext(ctx,
		`SELECT seq, version, etag, reason, actor_sub, at FROM policy_publish_log WHERE seq > ? ORDER BY seq LIMIT ?`,
		afterSeq, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("policy store: read publish log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PublishEntry
	for rows.Next() {
		var (
			e  PublishEntry
			at int64
		)
		if err := rows.Scan(&e.Seq, &e.Version, &e.ETag, &e.Reason, &e.ActorSub, &at); err != nil {
			return nil, fmt.Errorf("policy store: read publish log: %w", err)
		}
		e.At = time.UnixMilli(at)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy store: read publish log: %w", err)
	}
	return out, nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultPolicyListLimit
	}
	return min(limit, maxPolicyListLimit)
}

// sanitizeMessage strips control characters and caps the message at
// maxPolicyMessage characters.
func sanitizeMessage(msg string) string {
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(msg, ""))
	if r := []rune(msg); len(r) > maxPolicyMessage {
		msg = string(r[:maxPolicyMessage])
	}
	return msg
}

// RedactCredentials returns doc with every credential value replaced by its
// fingerprint, sha256:<16 lowercase hex>. Today that is a non-empty
// settings.secrets.secretAccessKey. doc is not modified, and an already
// redacted value is kept, so redacting twice is a no-op.
func RedactCredentials(doc policyWire) policyWire {
	if doc.Settings == nil || doc.Settings.Secrets == nil {
		return doc
	}
	key := doc.Settings.Secrets.SecretAccessKey
	if key == "" || isRedactedCredential(key) {
		return doc
	}
	settings := *doc.Settings
	secrets := *settings.Secrets
	secrets.SecretAccessKey = redactCredential(key)
	settings.Secrets = &secrets
	doc.Settings = &settings
	return doc
}

// redactCredential is the fingerprint of a credential value.
func redactCredential(v string) string {
	sum := sha256.Sum256([]byte(v))
	return credentialRedactPrefix + hex.EncodeToString(sum[:])[:credentialRedactHexLen]
}

// isRedactedCredential reports whether s is a credential fingerprint.
func isRedactedCredential(s string) bool {
	h, ok := strings.CutPrefix(s, credentialRedactPrefix)
	if !ok || len(h) != credentialRedactHexLen {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// credentialOverlay puts the live AWS secretAccessKey from the served YAML
// secretStore block back into a wire whose doc carries only its fingerprint
// (a versioned head). A wire holding a raw value (file mode, an empty store)
// is left alone. The fingerprint it reports is the live value's, never the
// value.
func credentialOverlay(policyPath string) wireOverlay {
	return wireOverlay{name: "credential", apply: func(_ context.Context, w *policyWire) (string, error) {
		if w.Settings == nil || w.Settings.Secrets == nil || !isRedactedCredential(w.Settings.Secrets.SecretAccessKey) {
			return "", nil
		}
		prov, err := config.NewLocalYAMLProvider(policyPath)
		if err != nil {
			return "", err
		}
		p, err := prov.GetPolicy()
		if err != nil {
			return "", err
		}
		live := ""
		if p.SecretStore.AWS != nil {
			live = p.SecretStore.AWS.SecretAccessKey
		}
		// Copy before writing: the wire's Settings may be shared.
		settings := *w.Settings
		secrets := *settings.Secrets
		secrets.SecretAccessKey = live
		settings.Secrets = &secrets
		w.Settings = &settings
		if live == "" {
			return "", nil
		}
		return redactCredential(live), nil
	}}
}

// checkPolicyStoreStartup is the fail-closed startup check of versioned mode:
// the head must be readable and, when non-zero, its version present and intact.
func checkPolicyStoreStartup(ctx context.Context, st PolicyVersionStore, dbPath string) (int64, error) {
	head, err := st.Head(ctx)
	if err != nil {
		return 0, fmt.Errorf("control-plane: --policy-store=versioned: cannot read the policy store in %s: %w "+
			"(restore warden-cp.db from backup; the control plane does not fall back to the YAML)", dbPath, err)
	}
	if head == 0 {
		return 0, nil
	}
	if _, err := st.Get(ctx, head); err != nil {
		switch {
		case errors.Is(err, ErrVersionNotFound):
			return 0, fmt.Errorf("control-plane: --policy-store=versioned: policy_head in %s points at version %d, which is missing "+
				"(restore warden-cp.db from backup; the control plane does not fall back to the YAML)", dbPath, head)
		case errors.Is(err, ErrDocIntegrity):
			return 0, fmt.Errorf("control-plane: --policy-store=versioned: head version %d in %s fails its doc_sha256 check "+
				"(restore warden-cp.db from backup; the control plane does not fall back to the YAML)", head, dbPath)
		default:
			return 0, fmt.Errorf("control-plane: --policy-store=versioned: cannot read head version %d in %s: %w", head, dbPath, err)
		}
	}
	return head, nil
}

// resolvePolicyStore checks the --policy-store value against --state-dir and
// returns the mode ("" means file).
func resolvePolicyStore(mode, stateDir string) (string, error) {
	switch mode {
	case "", PolicyStoreFile:
		return PolicyStoreFile, nil
	case PolicyStoreVersioned:
		if stateDir == "" {
			return "", errors.New("control-plane: --policy-store=versioned requires --state-dir " +
				"(versions live in <state-dir>/warden-cp.db next to the writable config copy); " +
				"pass --state-dir or use --policy-store=file")
		}
		return PolicyStoreVersioned, nil
	default:
		return "", fmt.Errorf("control-plane: unknown --policy-store %q: want %s or %s", mode, PolicyStoreFile, PolicyStoreVersioned)
	}
}

// initPolicyStore wires the versioned store in versioned mode: the policy
// server reads its head, Create refreshes the policy server and records the
// served ETag, and the credential overlay restores the live credential. It
// runs in New before the initial load. File mode, or no state DB, is a no-op
// (Run refuses versioned mode without a state dir).
func (s *Server) initPolicyStore() {
	if s.cfg.PolicyStore != PolicyStoreVersioned || s.cfg.State == nil {
		return
	}
	st := newSQLitePolicyStore(s.cfg.State.SQL(), s.cfg.Clock.Now, s.cfg.Logger)
	st.etagOf = s.policy.servedETag
	st.onCreated = s.policy.Refresh
	s.policy.versions = st
	s.versions = st
	if err := s.policy.addOverlay(credentialOverlay(s.cfg.PolicyPath)); err != nil {
		// Unreachable: registration precedes the first Refresh and the name is
		// unique. Logged rather than ignored so a wiring change shows up.
		s.cfg.Logger.Error("control plane: credential overlay not registered", "error", err)
	}
}
