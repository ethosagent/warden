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
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
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
	}, {
		// VersionForETag reads the newest row per etag on every fleet-view load.
		ID:  "policystore/0002",
		SQL: `CREATE INDEX policy_publish_log_etag ON policy_publish_log (etag, seq);`,
	}}
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

// PublishEntry is one policy_publish_log row: a head move, or a served-ETag
// change without a new version (AppendPublish), and the served ETag.
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
	// AppendPublish records that the served ETag changed while the head stayed
	// at version (an overlay change). It appends nothing and returns false when
	// version is no longer the head (that head's own Create row covers it) or
	// when the newest row already has this version and etag.
	AppendPublish(ctx context.Context, version int64, etag, reason, actor string) (appended bool, err error)
	// VersionForETag returns the version of the newest publish-log row with
	// etag; ok is false when no row has it (or the read fails).
	VersionForETag(ctx context.Context, etag string) (version int64, ok bool)
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
	// The block list is served by the blocked_users overlay, never versioned: a
	// rollback must not restore (or drop) it.
	red.BlockedUsers = nil
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
	err = st.immediateTx(ctx, func(conn *sql.Conn) error {
		var head int64
		if err := conn.QueryRowContext(ctx, "SELECT version FROM policy_head").Scan(&head); err != nil {
			return fmt.Errorf("policy store: read head: %w", err)
		}
		if head != expectedHead {
			return fmt.Errorf("%w: head is v%d, expected v%d", ErrConflict, head, expectedHead)
		}
		if head > 0 {
			var headSHA string
			err := conn.QueryRowContext(ctx, "SELECT doc_sha256 FROM policy_versions WHERE version = ?", head).Scan(&headSHA)
			if err != nil {
				return fmt.Errorf("policy store: read head v%d: %w", head, err)
			}
			if headSHA == docSHA {
				version, parent = head, head
				return errNoChange
			}
		}
		var next int64
		if err := conn.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions").Scan(&next); err != nil {
			return fmt.Errorf("policy store: next version: %w", err)
		}
		at := st.now().UnixMilli()
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO policy_versions (version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			next, head, at, author.Sub, author.Email, author.Kind, msg, source, string(docJSON), docSHA); err != nil {
			return fmt.Errorf("policy store: insert version: %w", err)
		}
		// The cross-process compare-and-swap.
		res, err := conn.ExecContext(ctx, "UPDATE policy_head SET version = ? WHERE version = ?", next, expectedHead)
		if err != nil {
			return fmt.Errorf("policy store: move head: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("%w: head is no longer v%d", ErrConflict, expectedHead)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO policy_publish_log (version, etag, reason, actor_sub, at) VALUES (?, ?, ?, ?, ?)`,
			next, etag, source, author.Sub, at); err != nil {
			return fmt.Errorf("policy store: append publish log: %w", err)
		}
		version, parent, changed = next, head, true
		return nil
	})
	if errors.Is(err, errNoChange) {
		return version, parent, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return version, parent, changed, nil
}

// errNoChange makes immediateTx roll back a transaction that has nothing to
// write; callers map it to their own no-change result.
var errNoChange = errors.New("policy store: nothing to write")

// immediateTx runs fn in a BEGIN IMMEDIATE transaction on one connection, so
// its reads and writes see no other writer, in this process or another. It
// commits when fn returns nil and rolls back otherwise.
func (st *sqlitePolicyStore) immediateTx(ctx context.Context, fn func(conn *sql.Conn) error) error {
	conn, err := st.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("policy store: connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("policy store: begin: %w", err)
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
		return fmt.Errorf("policy store: commit: %w", err)
	}
	committed = true
	return nil
}

// AppendPublish implements PolicyVersionStore. The head check and the
// newest-row check run in one BEGIN IMMEDIATE transaction with the insert, so
// two control planes refreshing at once append one row.
func (st *sqlitePolicyStore) AppendPublish(ctx context.Context, version int64, etag, reason, actor string) (bool, error) {
	if etag == "" || reason == "" || strings.TrimSpace(actor) == "" {
		return false, errors.New("policy store: publish entry needs an etag, a reason and an actor")
	}
	err := st.immediateTx(ctx, func(conn *sql.Conn) error {
		var head int64
		if err := conn.QueryRowContext(ctx, "SELECT version FROM policy_head").Scan(&head); err != nil {
			return fmt.Errorf("policy store: read head: %w", err)
		}
		if head != version {
			return errNoChange
		}
		var lastVer int64
		var lastETag string
		err := conn.QueryRowContext(ctx, "SELECT version, etag FROM policy_publish_log ORDER BY seq DESC LIMIT 1").Scan(&lastVer, &lastETag)
		switch {
		case err == nil && lastVer == version && lastETag == etag:
			return errNoChange
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("policy store: read publish log: %w", err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO policy_publish_log (version, etag, reason, actor_sub, at) VALUES (?, ?, ?, ?, ?)`,
			version, etag, reason, actor, st.now().UnixMilli()); err != nil {
			return fmt.Errorf("policy store: append publish log: %w", err)
		}
		return nil
	})
	if errors.Is(err, errNoChange) {
		return false, nil
	}
	return err == nil, err
}

// VersionForETag implements PolicyVersionStore. A read error is logged and
// reported as unknown: the fleet view degrades to the bare ETag.
func (st *sqlitePolicyStore) VersionForETag(ctx context.Context, etag string) (int64, bool) {
	if etag == "" {
		return 0, false
	}
	var v int64
	err := st.db.QueryRowContext(ctx,
		"SELECT version FROM policy_publish_log WHERE etag = ? ORDER BY seq DESC LIMIT 1", etag).Scan(&v)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			st.logger.Warn("policy store: etag lookup failed", "error", err)
		}
		return 0, false
	}
	return v, true
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

// fleetVersionLookupTimeout bounds the ETag lookups of one worker-list call.
const fleetVersionLookupTimeout = 2 * time.Second

// fillPolicyVersions sets PolicyVersion on each view whose heartbeat ETag maps
// to a version in st's publish log. It runs only when the dashboard builds the
// worker list, with one lookup per distinct ETag per call; st nil (file mode)
// leaves the views alone.
func fillPolicyVersions(st PolicyVersionStore, views []dashboard.WorkerView) {
	if st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fleetVersionLookupTimeout)
	defer cancel()
	seen := make(map[string]int64)
	for i := range views {
		etag := views[i].PolicyETag
		if etag == "" {
			continue
		}
		v, cached := seen[etag]
		if !cached {
			v, _ = st.VersionForETag(ctx, etag) // 0 when unknown
			seen[etag] = v
		}
		views[i].PolicyVersion = v
	}
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

// The initial import's identity and audit action (W-P1-PVER-07).
const (
	importAuthorSub           = "system:import"
	actionPolicyInitialImport = "policy.initial_import"
	auditTargetPolicy         = "policy"
	auditActorSystem          = "system"
)

// policyImport is the initial import of the served YAML as version 1. Its
// collaborators are funcs so a test can fake the served-ETag prediction.
type policyImport struct {
	store PolicyVersionStore
	// path is the served YAML.
	path string
	// load builds the doc from the served YAML (allowlist, denylist,
	// SettingsWireFromPolicy), never from serve-time overlay data.
	load func() (policyWire, error)
	// served is the ETag /policy serves now; predict is the ETag doc would be
	// served with as head.
	served  func(ctx context.Context) (string, error)
	predict func(ctx context.Context, doc policyWire) (string, error)
	// validate is Server.validateDoc; refresh reloads the policy server.
	validate func(doc policyWire) error
	refresh  func()
	// audit is the admin audit recorder; nil when admin audit is disabled.
	audit  adminaudit.Recorder
	logger *slog.Logger
}

// policyImport wires the import to the Server's policy server and store.
func (s *Server) policyImport() policyImport {
	im := policyImport{
		store: s.versions,
		path:  s.cfg.PolicyPath,
		load:  s.policy.loadFile,
		served: func(ctx context.Context) (string, error) {
			wire, _, _, err := s.policy.loadPolicy(ctx)
			if err != nil {
				return "", err
			}
			return etagFor(wire), nil
		},
		predict:  s.policy.servedETag,
		validate: s.validateDoc,
		refresh:  s.policy.Refresh,
		logger:   s.cfg.Logger,
	}
	if s.cfg.AdminAudit != nil {
		im.audit = s.cfg.AdminAudit
	}
	return im
}

// importInitialVersion stores the served YAML's policy doc as version 1 on
// the first versioned start (W-P1-PVER-07), so workers keep the exact policy
// and ETag they have. Run calls it in versioned mode before serving. It is a
// no-op in file mode and on a non-empty store; an error means the control
// plane must not start.
func (s *Server) importInitialVersion(ctx context.Context) error {
	if s.versions == nil {
		return nil
	}
	return s.policyImport().run(ctx)
}

// run is importInitialVersion. The served ETag is predicted before anything is
// written, so a doc that would change it leaves the store empty; Create is a
// compare-and-swap from head 0, so control planes racing the first start
// import once.
func (im policyImport) run(ctx context.Context) error {
	const flag = "control-plane: --policy-store=versioned"
	head, err := im.store.Head(ctx)
	if err != nil {
		return fmt.Errorf("%s: cannot read the policy store: %w", flag, err)
	}
	if head != 0 {
		return nil
	}
	raw, err := os.ReadFile(im.path)
	if err != nil {
		return fmt.Errorf("%s: read the served config for the initial import: %w", flag, err)
	}
	doc, err := im.load()
	if err != nil {
		return fmt.Errorf("%s: load the served config %s for the initial import: %w", flag, im.path, err)
	}
	doc = RedactCredentials(doc)
	if err := im.validate(doc); err != nil {
		return fmt.Errorf("%s: the served config %s does not validate as version 1: %w "+
			"(fix the config, or start with --policy-store=file)", flag, im.path, err)
	}
	before, err := im.served(ctx)
	if err != nil {
		return fmt.Errorf("%s: compute the served /policy ETag: %w", flag, err)
	}
	predicted, err := im.predict(ctx, doc)
	if err != nil {
		return fmt.Errorf("%s: compute the /policy ETag of version 1: %w", flag, err)
	}
	if predicted != before {
		return fmt.Errorf("%s: importing %s as version 1 would change the served /policy ETag from %s to %s, "+
			"so every worker would see a policy change; nothing was imported and the policy store is still empty. "+
			"Start with --policy-store=file and report this as a bug (the served config holds something a policy version cannot carry)",
			flag, im.path, before, predicted)
	}
	version, _, err := im.store.Create(ctx, doc, PolicyAuthor{Sub: importAuthorSub, Kind: AuthorKindSystem},
		"initial import from "+im.path, SourceImport, 0)
	if errors.Is(err, ErrConflict) {
		// Another control plane on the same state DB imported first.
		im.refresh()
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: store the served config as version 1: %w", flag, err)
	}
	after, err := im.served(ctx)
	if err != nil {
		return fmt.Errorf("%s: compute the served /policy ETag after the initial import: %w", flag, err)
	}
	if after != before {
		return fmt.Errorf("%s: the initial import of %s changed the served /policy ETag from %s to %s; "+
			"start with --policy-store=file (it serves the YAML, unchanged) and report this as a bug",
			flag, im.path, before, after)
	}
	im.record(ctx, raw, version)
	return nil
}

// record appends the import's admin audit row directly through the Recorder:
// startup is outside the HTTP audit middleware. A failure is logged and does
// not stop startup.
func (im policyImport) record(ctx context.Context, servedYAML []byte, version int64) {
	if im.audit == nil {
		return
	}
	v, err := im.store.Get(ctx, version)
	if err != nil {
		im.logger.Error("control plane: cannot read the imported version for its admin audit row; no row appended",
			"action", actionPolicyInitialImport, "version", version, "error", err)
		return
	}
	sum := sha256.Sum256(servedYAML)
	if _, err := im.audit.Record(ctx, adminaudit.Input{
		Actor:      adminaudit.Actor{Sub: auditActorSystem},
		ActorRole:  auditActorSystem,
		AuthMethod: adminaudit.AuthMethodSystem,
		Action:     actionPolicyInitialImport,
		Target:     auditTargetPolicy,
		Outcome:    adminaudit.OutcomeOK,
		BeforeHash: "file:" + hex.EncodeToString(sum[:]),
		AfterHash:  fmt.Sprintf("v%d:%s", v.Version, v.DocSHA256),
	}); err != nil {
		im.logger.Error("control plane: admin audit append failed", "action", actionPolicyInitialImport, "error", err)
	}
}

// The write-through mirror (W-P1-PVER-05). In versioned mode the served YAML
// is not the policy source, but --policy-store=file or an older binary serves
// it, so after every head move the control plane renders head into it. A hand
// edit of its policy/settings blocks is drift: warned about once per distinct
// blocks hash, shown on the dashboard and audited as config.external_change,
// never served. It comes back in only through `warden policy import`.

// mirrorDriftMsg is the drift warning, worded as the design states it.
const mirrorDriftMsg = "served config policy block differs from head; ignored"

// policyMirror is the mirror and drift state. Every field but drift is guarded
// by Server.writeMu; drift is read by the dashboard without it.
type policyMirror struct {
	// head is the version the served YAML was last mirrored from or checked
	// against (0 = not yet, before the first tick), headSHA its doc_sha256.
	head    int64
	headSHA string
	// hash is the blocks hash (servedBlocksHash) the served YAML has when it
	// equals head; "" when unknown (a failed mirror), which skips the check.
	hash string
	// warned are the blocks hashes already reported as drift against this
	// head, oldest first and at most externalSeenMax, so each distinct edit is
	// warned about once (a head move starts over).
	warned []string
	// primeErr is the last first-tick error logged, so it is logged once.
	primeErr string
	drift    atomic.Bool
}

// record sets the mirrored head and hash and clears drift.
func (m *policyMirror) record(v PolicyVersion, hash string) {
	m.head, m.headSHA, m.hash, m.warned = v.Version, v.DocSHA256, hash, nil
	m.drift.Store(false)
}

// policyDrift reports whether the served YAML's policy/settings blocks differ
// from head (always false in file mode).
func (s *Server) policyDrift() bool { return s.mirror.drift.Load() }

// mirrorHead renders head version into the served YAML through
// atomicWriteConfig (validated by the full loader, never a partial file) and
// records the mirrored blocks hash. The credential, held in versions only as
// its fingerprint, keeps the served file's live value (renderDocToRoot's
// preserve-on-empty rule); blocks no policy version carries are kept as the
// file has them. A failure is logged at error with the version and never
// fails or rolls back the version. The caller holds writeMu.
func (s *Server) mirrorHead(ctx context.Context, version int64) {
	v, err := s.versions.Get(ctx, version)
	if err == nil {
		err = s.writeMirror(v.Doc)
	}
	if err != nil {
		s.cfg.Logger.Error("control plane: cannot mirror the policy head into the served config; the version stands",
			"version", version, "error", err)
		// The file is not head and its expected hash is unknown: skip the drift
		// check until the next head move mirrors again. The drift state is kept
		// as it was: a failed mirror neither shows nor clears the banner.
		s.mirror.head, s.mirror.headSHA, s.mirror.hash = version, v.DocSHA256, ""
		return
	}
	hash, err := servedBlocksHash(s.cfg.PolicyPath)
	if err != nil {
		hash = ""
	}
	s.mirror.record(v, hash)
}

// writeMirror replaces the served YAML with doc rendered into it. A served
// file that is unreadable, does not parse or is read-only is left alone: it is
// the only home of the CP-local blocks, and a read-only file is the operator's
// choice.
func (s *Server) writeMirror(doc policyWire) error {
	raw, err := os.ReadFile(s.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("read the served config: %w", err)
	}
	root := map[string]yaml.Node{}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse the served config: %w", err)
	}
	f, err := os.OpenFile(s.cfg.PolicyPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("the served config is not writable: %w", err)
	}
	_ = f.Close()
	if err := renderDocToRoot(root, doc); err != nil {
		return err
	}
	return s.atomicWriteConfig(root)
}

// expectedBlocksHash is the blocks hash the served YAML would have with doc
// mirrored into it, computed on a validated temp copy; the served file is not
// written.
func (s *Server) expectedBlocksHash(doc policyWire) (string, error) {
	root := s.readServedRoot()
	if err := renderDocToRoot(root, doc); err != nil {
		return "", err
	}
	tmpName, err := s.writeValidatedTemp(root)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmpName) }()
	return servedBlocksHash(tmpName)
}

// checkMirror is the versioned ticker's mirror and drift step. A head moved
// outside the publish path (the CLI, another control plane) is mirrored. On
// the first tick the served file is not written: its expected hash is
// computed from head, so an edit made while the control plane was down is
// drift rather than overwritten. Then the served YAML's blocks hash is
// compared with the mirrored one; a difference is an external edit, warned
// about and audited once per distinct hash and never served. Head 0 (an empty
// store, before the initial import) serves the YAML and has no mirror.
func (s *Server) checkMirror(ctx context.Context) {
	// The head is read under writeMu: a publish holds it from Create to its
	// mirror, so a head read before it could mirror an older version over a
	// newer one.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	head, err := s.versions.Head(ctx)
	if err != nil || head == 0 {
		return // Refresh already logged a store error
	}
	if head != s.mirror.head {
		if s.mirror.head != 0 {
			s.mirrorHead(ctx, head)
		} else if !s.primeMirror(ctx, head) {
			return
		}
	}
	if s.mirror.hash == "" {
		return
	}
	sum, err := servedBlocksHash(s.cfg.PolicyPath)
	if err != nil {
		return // unreadable: keep the last drift state
	}
	if sum == s.mirror.hash {
		s.mirror.drift.Store(false)
		return
	}
	s.mirror.drift.Store(true)
	if slices.Contains(s.mirror.warned, sum) {
		return
	}
	if len(s.mirror.warned) == externalSeenMax {
		s.mirror.warned = slices.Delete(s.mirror.warned, 0, 1)
	}
	s.mirror.warned = append(s.mirror.warned, sum)
	s.cfg.Logger.Warn(mirrorDriftMsg, "file_sha256", sum, "head", s.mirror.head)
	s.auditExternalChange(ctx, externalChangeTarget,
		fmt.Sprintf("v%d:%s", s.mirror.head, s.mirror.headSHA), "file:"+sum)
}

// primeMirror records head and the served YAML's expected blocks hash on the
// first tick. It reports false, leaving the state unset so the next tick
// retries, when head cannot be read or rendered.
func (s *Server) primeMirror(ctx context.Context, head int64) bool {
	v, err := s.versions.Get(ctx, head)
	if err != nil {
		return false
	}
	hash, err := s.expectedBlocksHash(v.Doc)
	if err != nil {
		if msg := err.Error(); msg != s.mirror.primeErr {
			s.mirror.primeErr = msg
			s.cfg.Logger.Warn("control plane: cannot compute the served config's expected policy blocks; drift check skipped until it can",
				"head", head, "error", err)
		}
		return false
	}
	s.mirror.primeErr = ""
	s.mirror.record(v, hash)
	return true
}

// servedBlocksHash is the sha256 of the policy and settings blocks of the
// config at path, as the full loader reads them (the wire file mode would
// serve), so formatting, comments and the CP-local blocks do not count. The
// credential value is left out: it lives only in the served YAML and the
// credential overlay serves it, so editing it there is not drift. A file the
// loader rejects hashes to its raw bytes: it is never equal to head.
func servedBlocksHash(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		return sha256Hex(string(raw)), nil
	}
	p, err := prov.GetPolicy()
	if err != nil {
		return sha256Hex(string(raw)), nil
	}
	w := policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist, Settings: config.SettingsWireFromPolicy(p)}
	if w.Settings != nil && w.Settings.Secrets != nil {
		settings := *w.Settings
		secrets := *settings.Secrets
		secrets.SecretAccessKey = ""
		settings.Secrets = &secrets
		w.Settings = &settings
	}
	b, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	return sha256Hex(string(b)), nil
}
