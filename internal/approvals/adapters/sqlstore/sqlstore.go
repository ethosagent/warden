// Package sqlstore is the SQLite approvals.Store: the change_drafts and
// change_approvals tables on the control plane's state database (cpstate).
// Every transition runs in one BEGIN IMMEDIATE transaction that reads the row,
// asks the state machine (approvals.Transition) and writes with
// `UPDATE ... WHERE id=? AND state=? AND revision=?`, so writers in this
// process or another (a CLI) are serialised by the database and a lost
// compare-and-swap writes nothing.
package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/cpstate"
)

// MigrationID is the id of the approvals migration; ReplayMigrationID adds the
// draft_replays table (W-P2-APPR-03).
const (
	MigrationID       = "approvals/0001"
	ReplayMigrationID = "approvals/0002"
	// MetaMigrationID adds approvals_meta (W-P2-APPR-06): the single row the
	// control plane writes at startup so the offline CLI knows whether approvals
	// are enabled.
	MetaMigrationID = "approvals/0003"
)

// EnabledMigrationIDs lists every approvals migration, for cpstate.Enable.
func EnabledMigrationIDs() []string { return []string{MigrationID, ReplayMigrationID, MetaMigrationID} }

// Migrations returns the approvals migration. It is Optional: the control plane
// registers it always (so the downgrade guard knows it) and applies it only
// with console.approvals.enabled, via cpstate.Enable(…, MigrationID). A control
// plane without approvals creates no table.
//
// change_approvals is append-only (triggers), and an approval belongs to one
// revision: an edit creates revision n+1, which the earlier rows no longer
// count toward. change_drafts holds the redacted canonical doc, never YAML and
// never a raw credential.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID:       MigrationID,
		Optional: true,
		SQL: `CREATE TABLE change_drafts (
  id                  TEXT PRIMARY KEY,
  target              TEXT NOT NULL CHECK (target IN ('policy','blocked_users','agents')),
  target_ref          TEXT NOT NULL,
  revision            INTEGER NOT NULL CHECK (revision >= 1),
  base_version        INTEGER NOT NULL,
  state               TEXT NOT NULL CHECK (state IN ('draft','pending','applying','applied','rejected','needs_rebase','withdrawn','expired','applied_unreviewed')),
  author_iss          TEXT NOT NULL,
  author_sub          TEXT NOT NULL,
  author_email        TEXT NOT NULL,
  author_kind         TEXT NOT NULL,
  source              TEXT NOT NULL CHECK (source IN ('console','rollback','cli','api','git','admin-mcp')),
  provenance_json     TEXT NOT NULL,
  message             TEXT NOT NULL,
  doc_json            TEXT NOT NULL,
  doc_sha256          TEXT NOT NULL,
  classification_json TEXT NOT NULL,
  required_role       TEXT NOT NULL,
  last_error          TEXT NOT NULL,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL,
  expires_at          INTEGER NOT NULL,
  applied_version     INTEGER NOT NULL
);
CREATE INDEX change_drafts_state_target ON change_drafts (state, target);
CREATE INDEX change_drafts_author_sub ON change_drafts (author_sub);
CREATE TABLE change_approvals (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  draft_id              TEXT NOT NULL REFERENCES change_drafts (id),
  revision              INTEGER NOT NULL,
  doc_sha256            TEXT NOT NULL,
  approver_iss          TEXT NOT NULL,
  approver_sub          TEXT NOT NULL,
  approver_email        TEXT NOT NULL,
  approver_role         TEXT NOT NULL,
  auth_method           TEXT NOT NULL,
  decision              TEXT NOT NULL CHECK (decision IN ('approve','reject','self','emergency','post_review')),
  replay_id             TEXT NOT NULL,
  acknowledge_no_replay INTEGER NOT NULL,
  comment               TEXT NOT NULL,
  at                    INTEGER NOT NULL,
  UNIQUE (draft_id, revision, approver_iss, approver_sub)
);
CREATE TRIGGER change_approvals_no_update BEFORE UPDATE ON change_approvals
BEGIN SELECT RAISE(ABORT, 'change_approvals is append-only'); END;
CREATE TRIGGER change_approvals_no_delete BEFORE DELETE ON change_approvals
BEGIN SELECT RAISE(ABORT, 'change_approvals is append-only'); END;`,
	}, {
		ID:       ReplayMigrationID,
		Optional: true,
		SQL: `CREATE TABLE draft_replays (
  id             TEXT PRIMARY KEY,
  draft_id       TEXT NOT NULL REFERENCES change_drafts (id),
  revision       INTEGER NOT NULL,
  base_version   INTEGER NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('pending','running','done','failed','unavailable')),
  window_from    INTEGER NOT NULL,
  window_to      INTEGER NOT NULL,
  events_scanned INTEGER NOT NULL,
  truncated      INTEGER NOT NULL,
  result_json    TEXT NOT NULL,
  error_code     TEXT NOT NULL,
  started_at     INTEGER NOT NULL,
  finished_at    INTEGER NOT NULL
);
CREATE INDEX draft_replays_draft ON draft_replays (draft_id, revision);`,
	}, {
		ID:       MetaMigrationID,
		Optional: true,
		SQL: `CREATE TABLE approvals_meta (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  enabled         INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  draft_ttl_ms    INTEGER NOT NULL,
  max_open_drafts INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);`,
	}}
}

// List page bounds.
const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// systemActor names the sweeper in the transition log.
const systemActor = "system"

// Store implements approvals.Store over a cpstate database opened with the
// approvals migration enabled.
type Store struct {
	db     *sql.DB
	now    func() time.Time
	logger *slog.Logger
}

var _ approvals.Store = (*Store)(nil)

// New builds a Store over db (cpstate.DB.SQL()). now is the clock (nil =
// time.Now); logger receives one change_draft_transition line per transition
// (nil = slog.Default()).
func New(db *sql.DB, now func() time.Time, logger *slog.Logger) *Store {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{db: db, now: now, logger: logger}
}

// transitionLog is one change_draft_transition line, emitted after commit. It
// carries identifiers and states only, never doc content or settings values.
type transitionLog struct {
	id, target, from, to, actor string
	revision                    int
}

func (st *Store) emit(ls ...transitionLog) {
	for _, l := range ls {
		st.logger.Info("change_draft_transition",
			"draft_id", l.id, "revision", l.revision, "target", l.target,
			"state_from", l.from, "state_to", l.to, "actor_sub", l.actor)
	}
}

// immediateTx runs fn in a BEGIN IMMEDIATE transaction on one connection, so
// its reads and writes see no other writer. It commits when fn returns nil and
// rolls back otherwise.
func (st *Store) immediateTx(ctx context.Context, fn func(conn *sql.Conn) error) error {
	conn, err := st.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("approvals store: connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("approvals store: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			// The caller's ctx may be cancelled; the rollback must not be.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("approvals store: commit: %w", err)
	}
	committed = true
	return nil
}

func newID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("approvals store: draft id: %w", err)
	}
	return "cd_" + hex.EncodeToString(b[:]), nil
}

func ms(t time.Time) int64 { return t.UnixMilli() }

// draftCols are the change_drafts columns in scan order. docExpr is what stands
// for doc_json (an empty string literal in List, which never returns docs).
func draftCols(docExpr string) string {
	return "id, target, target_ref, revision, base_version, state, author_iss, author_sub, author_email, author_kind, " +
		"source, provenance_json, message, " + docExpr + ", doc_sha256, classification_json, required_role, last_error, " +
		"created_at, updated_at, expires_at, applied_version"
}

type rowScanner interface{ Scan(dest ...any) error }

func scanDraft(r rowScanner) (approvals.Draft, error) {
	var (
		d                          approvals.Draft
		target, state, source      string
		prov, doc, class           string
		created, updated, expireAt int64
	)
	err := r.Scan(&d.ID, &target, &d.TargetRef, &d.Revision, &d.BaseVersion, &state,
		&d.Author.Iss, &d.Author.Sub, &d.Author.Email, &d.Author.Kind,
		&source, &prov, &d.Message, &doc, &d.DocSHA256, &class, &d.RequiredRole, &d.LastError,
		&created, &updated, &expireAt, &d.AppliedVersion)
	if err != nil {
		return approvals.Draft{}, err
	}
	d.Target, d.State, d.Source = approvals.Target(target), approvals.State(state), approvals.Source(source)
	if prov != "" {
		if err := json.Unmarshal([]byte(prov), &d.Provenance); err != nil {
			return approvals.Draft{}, fmt.Errorf("approvals store: draft %s provenance: %w", d.ID, err)
		}
	}
	d.Provenance.Source, d.Provenance.Message = d.Source, d.Message
	if doc != "" {
		d.DocJSON = json.RawMessage(doc)
	}
	if class != "" {
		d.Classification = json.RawMessage(class)
	}
	d.CreatedAt, d.UpdatedAt, d.ExpiresAt = time.UnixMilli(created), time.UnixMilli(updated), time.UnixMilli(expireAt)
	return d, nil
}

func (st *Store) load(ctx context.Context, conn *sql.Conn, id string) (approvals.Draft, error) {
	d, err := scanDraft(conn.QueryRowContext(ctx, "SELECT "+draftCols("doc_json")+" FROM change_drafts WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return approvals.Draft{}, approvals.ErrNotFound
	}
	if err != nil {
		return approvals.Draft{}, fmt.Errorf("approvals store: read draft %s: %w", id, err)
	}
	return d, nil
}

// Create implements approvals.Store.
func (st *Store) Create(ctx context.Context, nd approvals.NewDraft, maxOpen int) (approvals.Draft, error) {
	if !nd.Target.Valid() {
		return approvals.Draft{}, fmt.Errorf("approvals store: unknown target %q", nd.Target)
	}
	if !nd.Source.Valid() {
		return approvals.Draft{}, fmt.Errorf("approvals store: unknown source %q", nd.Source)
	}
	if nd.Author.Sub == "" || len(nd.DocJSON) == 0 || nd.DocSHA256 == "" {
		return approvals.Draft{}, errors.New("approvals store: draft needs an author, a doc and its digest")
	}
	prov, err := json.Marshal(nd.Provenance)
	if err != nil {
		return approvals.Draft{}, fmt.Errorf("approvals store: encode provenance: %w", err)
	}
	id, err := newID()
	if err != nil {
		return approvals.Draft{}, err
	}
	at := ms(st.now())
	var d approvals.Draft
	err = st.immediateTx(ctx, func(conn *sql.Conn) error {
		if maxOpen > 0 {
			var n int
			if err := conn.QueryRowContext(ctx,
				"SELECT count(*) FROM change_drafts WHERE state IN ('draft','pending','applying','needs_rebase')").Scan(&n); err != nil {
				return fmt.Errorf("approvals store: count open drafts: %w", err)
			}
			if n >= maxOpen {
				return fmt.Errorf("%w: %d open (limit %d)", approvals.ErrTooManyDrafts, n, maxOpen)
			}
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO change_drafts (id, target, target_ref, revision, base_version, state, author_iss, author_sub, author_email, author_kind,
			   source, provenance_json, message, doc_json, doc_sha256, classification_json, required_role, last_error,
			   created_at, updated_at, expires_at, applied_version)
			 VALUES (?, ?, ?, 1, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, 0)`,
			id, string(nd.Target), nd.TargetRef, nd.BaseVersion, nd.Author.Iss, nd.Author.Sub, nd.Author.Email, nd.Author.Kind,
			string(nd.Source), string(prov), nd.Message, string(nd.DocJSON), nd.DocSHA256, string(nd.Classification), nd.RequiredRole,
			at, at, ms(nd.ExpiresAt)); err != nil {
			return fmt.Errorf("approvals store: insert draft: %w", err)
		}
		var lerr error
		d, lerr = st.load(ctx, conn, id)
		return lerr
	})
	if err != nil {
		return approvals.Draft{}, err
	}
	st.emit(transitionLog{id: d.ID, target: string(d.Target), from: "", to: string(d.State), actor: d.Author.Sub, revision: d.Revision})
	return d, nil
}

// Get implements approvals.Store.
func (st *Store) Get(ctx context.Context, id string) (approvals.Draft, error) {
	d, err := scanDraft(st.db.QueryRowContext(ctx, "SELECT "+draftCols("doc_json")+" FROM change_drafts WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return approvals.Draft{}, approvals.ErrNotFound
	}
	if err != nil {
		return approvals.Draft{}, fmt.Errorf("approvals store: read draft %s: %w", id, err)
	}
	return d, nil
}

// List implements approvals.Store. The cursor is "<created_at ms>:<id>" of the
// last row of the previous page.
func (st *Store) List(ctx context.Context, f approvals.Filter, cursor string, limit int) ([]approvals.Draft, string, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	limit = min(limit, maxListLimit)
	var (
		where []string
		args  []any
	)
	if f.Target != "" {
		where, args = append(where, "target = ?"), append(args, string(f.Target))
	}
	if f.State != "" {
		where, args = append(where, "state = ?"), append(args, string(f.State))
	}
	if f.AuthorSub != "" {
		where, args = append(where, "author_sub = ?"), append(args, f.AuthorSub)
	}
	if cursor != "" {
		at, id, ok := strings.Cut(cursor, ":")
		n, err := strconv.ParseInt(at, 10, 64)
		if !ok || err != nil || id == "" {
			return nil, "", fmt.Errorf("approvals store: malformed cursor %q", cursor)
		}
		where = append(where, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, n, n, id)
	}
	q := "SELECT " + draftCols("''") + " FROM change_drafts"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT ?"
	rows, err := st.db.QueryContext(ctx, q, append(args, limit+1)...)
	if err != nil {
		return nil, "", fmt.Errorf("approvals store: list drafts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []approvals.Draft
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, "", fmt.Errorf("approvals store: list drafts: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("approvals store: list drafts: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = strconv.FormatInt(ms(last.CreatedAt), 10) + ":" + last.ID
	}
	return out, next, nil
}

// set is one extra column a transition writes.
type set struct {
	col string
	val any
}

// step runs one state-machine transition inside a transaction: it reads the
// draft, checks the revision the caller saw, asks approvals.Transition, and
// writes the new state (and revision, for an event that bumps it) with the
// compare-and-swap.
func (st *Store) step(ctx context.Context, conn *sql.Conn, id string, revision int, ev approvals.Event, actor string, extra ...set) (approvals.Draft, transitionLog, error) {
	cur, err := st.load(ctx, conn, id)
	if err != nil {
		return approvals.Draft{}, transitionLog{}, err
	}
	if cur.Revision != revision {
		return approvals.Draft{}, transitionLog{}, fmt.Errorf("%w: draft is at revision %d, not %d", approvals.ErrStateChanged, cur.Revision, revision)
	}
	to, err := approvals.Transition(cur.State, ev)
	if err != nil {
		return approvals.Draft{}, transitionLog{}, err
	}
	newRev := cur.Revision
	if approvals.BumpsRevision(ev) {
		newRev++
	}
	cols := []string{"state = ?", "revision = ?", "updated_at = ?"}
	args := []any{string(to), newRev, ms(st.now())}
	for _, e := range extra {
		cols = append(cols, e.col+" = ?")
		args = append(args, e.val)
	}
	args = append(args, id, string(cur.State), cur.Revision)
	where := " WHERE id = ? AND state = ? AND revision = ?"
	// Expiry is part of the compare-and-swap: an expired draft can neither be
	// approved nor claimed for publishing, whatever the caller read earlier.
	if ev == approvals.EventApprove || ev == approvals.EventBeginApply {
		now := ms(st.now())
		if ms(cur.ExpiresAt) <= now {
			return approvals.Draft{}, transitionLog{}, approvals.ErrDraftExpired
		}
		where += " AND expires_at > ?"
		args = append(args, now)
	}
	res, err := conn.ExecContext(ctx, "UPDATE change_drafts SET "+strings.Join(cols, ", ")+where, args...)
	if err != nil {
		return approvals.Draft{}, transitionLog{}, fmt.Errorf("approvals store: %s draft %s: %w", ev, id, err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return approvals.Draft{}, transitionLog{}, fmt.Errorf("%w: %s", approvals.ErrStateChanged, id)
	}
	d, err := st.load(ctx, conn, id)
	if err != nil {
		return approvals.Draft{}, transitionLog{}, err
	}
	return d, transitionLog{id: id, target: string(d.Target), from: string(cur.State), to: string(to), actor: actor, revision: d.Revision}, nil
}

// transition runs one step in its own transaction and logs it after commit.
func (st *Store) transition(ctx context.Context, id string, revision int, ev approvals.Event, actor string, extra ...set) (approvals.Draft, error) {
	var (
		d approvals.Draft
		l transitionLog
	)
	err := st.immediateTx(ctx, func(conn *sql.Conn) error {
		var serr error
		d, l, serr = st.step(ctx, conn, id, revision, ev, actor, extra...)
		return serr
	})
	if err != nil {
		return approvals.Draft{}, err
	}
	st.emit(l)
	return d, nil
}

func revisionSets(in approvals.UpdateInput) ([]set, error) {
	if len(in.DocJSON) == 0 || in.DocSHA256 == "" {
		return nil, errors.New("approvals store: a new revision needs a doc and its digest")
	}
	sets := []set{
		{"doc_json", string(in.DocJSON)}, {"doc_sha256", in.DocSHA256},
		{"classification_json", string(in.Classification)}, {"required_role", in.RequiredRole},
		{"last_error", ""},
	}
	if in.Message != "" {
		sets = append(sets, set{"message", in.Message})
	}
	return sets, nil
}

// Update implements approvals.Store.
func (st *Store) Update(ctx context.Context, id string, in approvals.UpdateInput, actorSub string) (approvals.Draft, error) {
	sets, err := revisionSets(in)
	if err != nil {
		return approvals.Draft{}, err
	}
	return st.transition(ctx, id, in.ExpectedRevision, approvals.EventUpdate, actorSub, sets...)
}

// Rebase implements approvals.Store.
func (st *Store) Rebase(ctx context.Context, id string, in approvals.UpdateInput, actorSub string) (approvals.Draft, error) {
	sets, err := revisionSets(in)
	if err != nil {
		return approvals.Draft{}, err
	}
	return st.transition(ctx, id, in.ExpectedRevision, approvals.EventRebase, actorSub, append(sets, set{"base_version", in.BaseVersion})...)
}

// Submit implements approvals.Store.
func (st *Store) Submit(ctx context.Context, id string, revision int, actorSub string) (approvals.Draft, error) {
	return st.transition(ctx, id, revision, approvals.EventSubmit, actorSub)
}

// Withdraw implements approvals.Store.
func (st *Store) Withdraw(ctx context.Context, id string, revision int, actorSub string) (approvals.Draft, error) {
	return st.transition(ctx, id, revision, approvals.EventWithdraw, actorSub)
}

// MarkApplied implements approvals.Store.
func (st *Store) MarkApplied(ctx context.Context, id string, revision int, version int64, actorSub string) (approvals.Draft, error) {
	return st.transition(ctx, id, revision, approvals.EventApply, actorSub, set{"applied_version", version}, set{"last_error", ""})
}

// MarkNeedsRebase implements approvals.Store.
func (st *Store) MarkNeedsRebase(ctx context.Context, id string, revision int, lastError, actorSub string) (approvals.Draft, error) {
	return st.transition(ctx, id, revision, approvals.EventConflict, actorSub, set{"last_error", lastError})
}

// BeginApply implements approvals.Store.
func (st *Store) BeginApply(ctx context.Context, id string, revision int, actorSub string) (approvals.Draft, error) {
	return st.transition(ctx, id, revision, approvals.EventBeginApply, actorSub)
}

// FailApply implements approvals.Store.
func (st *Store) FailApply(ctx context.Context, id string, revision int, lastError, actorSub string) (approvals.Draft, error) {
	return st.transition(ctx, id, revision, approvals.EventApplyFailed, actorSub, set{"last_error", lastError})
}

// Applying implements approvals.Store.
func (st *Store) Applying(ctx context.Context) ([]approvals.Draft, error) {
	rows, err := st.db.QueryContext(ctx, "SELECT "+draftCols("doc_json")+" FROM change_drafts WHERE state = 'applying' ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("approvals store: list applying drafts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []approvals.Draft
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, fmt.Errorf("approvals store: list applying drafts: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordDecision implements approvals.Store.
func (st *Store) RecordDecision(ctx context.Context, id string, in approvals.DecisionInput) (approvals.Draft, int, error) {
	var ev approvals.Event
	switch in.Decision {
	case approvals.DecisionApprove, approvals.DecisionSelf:
		ev = approvals.EventApprove
	case approvals.DecisionReject:
		ev = approvals.EventReject
	default:
		return approvals.Draft{}, 0, fmt.Errorf("approvals store: decision %q is not recorded here", in.Decision)
	}
	if in.Approver.Sub == "" {
		return approvals.Draft{}, 0, errors.New("approvals store: decision has no approver")
	}
	var (
		d approvals.Draft
		l transitionLog
		n int
	)
	err := st.immediateTx(ctx, func(conn *sql.Conn) error {
		var serr error
		if d, l, serr = st.step(ctx, conn, id, in.Revision, ev, in.Approver.Sub); serr != nil {
			return serr
		}
		if d.DocSHA256 != in.DocSHA256 {
			return fmt.Errorf("%w: the reviewed doc is not the draft's", approvals.ErrStateChanged)
		}
		ack := 0
		if in.AcknowledgeNoReplay {
			ack = 1
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO change_approvals (draft_id, revision, doc_sha256, approver_iss, approver_sub, approver_email, approver_role,
			   auth_method, decision, replay_id, acknowledge_no_replay, comment, at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, in.Revision, in.DocSHA256, in.Approver.Iss, in.Approver.Sub, in.Approver.Email, in.ApproverRole,
			in.Approver.Kind, string(in.Decision), in.ReplayID, ack, in.Comment, ms(st.now())); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				return fmt.Errorf("%w: %s at revision %d", approvals.ErrDuplicateDecision, in.Approver.Sub, in.Revision)
			}
			return fmt.Errorf("approvals store: record decision: %w", err)
		}
		if err := conn.QueryRowContext(ctx,
			"SELECT count(*) FROM change_approvals WHERE draft_id = ? AND revision = ? AND decision = 'approve'",
			id, in.Revision).Scan(&n); err != nil {
			return fmt.Errorf("approvals store: count approvals: %w", err)
		}
		return nil
	})
	if err != nil {
		return approvals.Draft{}, 0, err
	}
	st.emit(l)
	return d, n, nil
}

// ExpireDue implements approvals.Store.
func (st *Store) ExpireDue(ctx context.Context, now time.Time) ([]approvals.Draft, error) {
	var (
		out  []approvals.Draft
		logs []transitionLog
	)
	err := st.immediateTx(ctx, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx,
			"SELECT id, revision FROM change_drafts WHERE state IN ('draft','pending','needs_rebase') AND expires_at <= ? ORDER BY expires_at, id", ms(now))
		if err != nil {
			return fmt.Errorf("approvals store: find expired drafts: %w", err)
		}
		type idRev struct {
			id  string
			rev int
		}
		var due []idRev
		for rows.Next() {
			var x idRev
			if err := rows.Scan(&x.id, &x.rev); err != nil {
				_ = rows.Close()
				return fmt.Errorf("approvals store: find expired drafts: %w", err)
			}
			due = append(due, x)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("approvals store: find expired drafts: %w", err)
		}
		for _, x := range due {
			d, l, err := st.step(ctx, conn, x.id, x.rev, approvals.EventExpire, systemActor)
			if err != nil {
				return err
			}
			out, logs = append(out, d), append(logs, l)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	st.emit(logs...)
	return out, nil
}

// Approvals implements approvals.Store.
func (st *Store) Approvals(ctx context.Context, id string) ([]approvals.Approval, error) {
	rows, err := st.db.QueryContext(ctx,
		`SELECT id, draft_id, revision, doc_sha256, approver_iss, approver_sub, approver_email, approver_role, auth_method,
		        decision, replay_id, acknowledge_no_replay, comment, at
		 FROM change_approvals WHERE draft_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("approvals store: list approvals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []approvals.Approval
	for rows.Next() {
		var (
			a       approvals.Approval
			dec     string
			ack, at int64
		)
		if err := rows.Scan(&a.ID, &a.DraftID, &a.Revision, &a.DocSHA256, &a.ApproverIss, &a.ApproverSub, &a.ApproverEmail,
			&a.ApproverRole, &a.AuthMethod, &dec, &a.ReplayID, &ack, &a.Comment, &at); err != nil {
			return nil, fmt.Errorf("approvals store: list approvals: %w", err)
		}
		a.Decision, a.AcknowledgeNoReplay, a.At = approvals.Decision(dec), ack != 0, time.UnixMilli(at)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("approvals store: list approvals: %w", err)
	}
	return out, nil
}

// ApprovalCounts implements approvals.Store: one grouped query counts the
// distinct approvers of every given draft's current revision and doc.
func (st *Store) ApprovalCounts(ctx context.Context, ds []approvals.Draft) (map[string]int, error) {
	out := make(map[string]int, len(ds))
	if len(ds) == 0 {
		return out, nil
	}
	cur := make(map[string]approvals.Draft, len(ds))
	marks := make([]string, 0, len(ds))
	args := make([]any, 0, len(ds))
	for _, d := range ds {
		cur[d.ID] = d
		marks = append(marks, "?")
		args = append(args, d.ID)
	}
	rows, err := st.db.QueryContext(ctx,
		`SELECT draft_id, revision, doc_sha256, count(DISTINCT approver_iss || char(0) || approver_sub)
		 FROM change_approvals WHERE decision = 'approve' AND draft_id IN (`+strings.Join(marks, ",")+`)
		 GROUP BY draft_id, revision, doc_sha256`, args...)
	if err != nil {
		return nil, fmt.Errorf("approvals store: count approvals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id, sha string
			rev, n  int
		)
		if err := rows.Scan(&id, &rev, &sha, &n); err != nil {
			return nil, fmt.Errorf("approvals store: count approvals: %w", err)
		}
		if d, ok := cur[id]; ok && d.Revision == rev && d.DocSHA256 == sha {
			out[id] = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("approvals store: count approvals: %w", err)
	}
	return out, nil
}
