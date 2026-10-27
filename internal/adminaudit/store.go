package adminaudit

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Details keys the key-defining entries (genesis, segment_start) carry.
const (
	detailAlg           = "alg"
	detailPublicKey     = "public_key"
	detailActorKeyCheck = "actor_key_check"
	algEd25519          = "ed25519"
	actorKeyCheckLabel  = "warden.admin.v1/actor-key"
)

// List limits.
const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// ErrKeyIDMismatch is returned (wrapped, naming both key_ids) when the loaded
// signing key is not the key the chain head is signed with. Nothing is
// written. The only legal key change is an audit.segment_start entry.
var ErrKeyIDMismatch = errors.New("adminaudit: signing key does not match the chain head")

// Actor is the authenticated principal behind an entry. Sub and Email are
// stored only in the admin_audit_actor side table, never in the signed row.
type Actor struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

// Input is what a caller records; the store stamps everything else.
type Input struct {
	Actor      Actor
	ActorRole  string
	AuthMethod string
	Action     string
	Target     string
	TargetRef  string
	Details    map[string]string
	Outcome    string
	HTTPStatus int
	BeforeHash string
	AfterHash  string
	ClientIP   string
	RequestID  string
}

// Recorder is the single write API for admin audit entries: the HTTP
// middleware, auth handlers, break-glass and the offline CLIs all record
// through it.
type Recorder interface {
	Record(ctx context.Context, in Input) (Entry, error)
}

// Options configures a Store. Signer and HMACKey are needed only to Record;
// a read-only Store (Verify, List, Head, PubKeys) may leave them unset.
type Options struct {
	Signer  *audit.Signer
	HMACKey []byte
	Clock   clock.Clock
}

// Store is the admin audit chain on a cpstate database.
type Store struct {
	db      *cpstate.DB
	signer  *audit.Signer
	keyID   string
	hmacKey []byte
	clock   clock.Clock
}

var _ Recorder = (*Store)(nil)

// NewStore returns a Store over db. It does no I/O; the tables must exist
// (cpstate.Open with Migrations()).
func NewStore(db *cpstate.DB, opts Options) *Store {
	s := &Store{db: db, signer: opts.Signer, hmacKey: opts.HMACKey, clock: opts.Clock}
	if s.clock == nil {
		s.clock = clock.Real()
	}
	if s.signer != nil {
		s.keyID = audit.KeyID(s.signer.PubKey())
	}
	return s
}

// KeyID returns the key_id of the store's signer ("" without one).
func (s *Store) KeyID() string { return s.keyID }

// Record validates in, derives actor_id = hex(HMAC-SHA256(hmacKey, sub)) (an
// empty sub is recorded as "anonymous"), and appends the entry in one BEGIN
// IMMEDIATE transaction: on an empty table the genesis entry is written first.
// The plaintext sub and email go only to admin_audit_actor. A chain whose head
// is signed by another key is never extended (ErrKeyIDMismatch).
func (s *Store) Record(ctx context.Context, in Input) (Entry, error) {
	if err := s.canWrite(); err != nil {
		return Entry{}, err
	}
	e := Entry{
		ActorRole: in.ActorRole, AuthMethod: in.AuthMethod, Action: in.Action,
		Target: in.Target, TargetRef: in.TargetRef, Details: copyDetails(in.Details),
		Outcome: in.Outcome, HTTPStatus: in.HTTPStatus,
		BeforeHash: in.BeforeHash, AfterHash: in.AfterHash,
		ClientIP: in.ClientIP, RequestID: in.RequestID,
	}
	if err := e.validate(); err != nil {
		return Entry{}, err
	}
	e.ActorID = s.actorID(in.Actor.Sub)
	var side *Actor
	if in.Actor.Sub != "" || in.Actor.Email != "" {
		a := in.Actor
		side = &a
	}
	return s.appendTx(ctx, func(head headRow) (*Entry, *Actor, error) {
		if head.KeyID != s.keyID {
			return nil, nil, fmt.Errorf("%w: the chain head (seq %d) is signed by key_id %s but the loaded key is key_id %s; "+
				"load the signing key for key_id %s, or start a new segment for the new key",
				ErrKeyIDMismatch, head.Seq, head.KeyID, s.keyID, head.KeyID)
		}
		return &e, side, nil
	})
}

func (s *Store) canWrite() error {
	if s.signer == nil {
		return errors.New("adminaudit: store has no signer; it is read-only")
	}
	if len(s.hmacKey) == 0 {
		return errors.New("adminaudit: store has no HMAC key; it is read-only")
	}
	return nil
}

func copyDetails(d map[string]string) map[string]string {
	if d == nil {
		return nil
	}
	out := make(map[string]string, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

// actorID is hex(HMAC-SHA256(hmacKey, sub)), or "anonymous" for an empty sub.
func (s *Store) actorID(sub string) string {
	if sub == "" {
		return actorIDAnonymous
	}
	return hmacHex(s.hmacKey, sub)
}

func hmacHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// actorKeyCheck lets a later start prove it holds the same HMAC key as the
// genesis writer without revealing the key: the first 16 hex characters of
// HMAC(key, "warden.admin.v1/actor-key").
func actorKeyCheck(key []byte) string {
	return hmacHex(key, actorKeyCheckLabel)[:16]
}

// headRow is the newest row of the chain as an append sees it.
type headRow struct {
	Seq   int64
	Hash  []byte
	KeyID string
}

// buildFunc decides the next entry given the current head (after genesis on an
// empty table). It returns the entry to append (store-stamped fields are
// overwritten) and an optional side-table actor.
type buildFunc func(head headRow) (*Entry, *Actor, error)

// appendTx runs one append on a dedicated connection inside an explicit BEGIN
// IMMEDIATE, so two processes on one file serialise and extend one linear
// chain: read the head, write genesis if the table is empty, build, sign and
// insert seq+1 (plus the side row), COMMIT. Any error rolls back everything.
func (s *Store) appendTx(ctx context.Context, build buildFunc) (out Entry, err error) {
	conn, err := s.db.SQL().Conn(ctx)
	if err != nil {
		return Entry{}, fmt.Errorf("adminaudit: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return Entry{}, fmt.Errorf("adminaudit: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollback(conn)
		}
	}()

	head, found, err := readHead(ctx, conn)
	if err != nil {
		return Entry{}, err
	}
	now := s.clock.Now()
	if !found {
		g := s.genesis(now)
		if err := s.signAndInsert(ctx, conn, &g, nil); err != nil {
			return Entry{}, err
		}
		head = headRow{Seq: g.Seq, Hash: g.EntryHash, KeyID: g.KeyID}
	}
	e, side, err := build(head)
	if err != nil {
		return Entry{}, err
	}
	e.V = EntryVersion
	e.Seq = head.Seq + 1
	e.TSUnixNano = now.UnixNano()
	e.KeyID = s.keyID
	e.PrevHash = head.Hash
	if err := s.signAndInsert(ctx, conn, e, side); err != nil {
		return Entry{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Entry{}, fmt.Errorf("adminaudit: commit: %w", err)
	}
	committed = true
	return *e, nil
}

// rollback ends an open transaction. If even that fails the connection's
// state is unknown, so it is discarded rather than returned to the pool.
func rollback(conn *sql.Conn) {
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
}

// genesis builds seq 1: the self-describing first entry that carries the
// signing public key and the HMAC key check value.
func (s *Store) genesis(now time.Time) Entry {
	return Entry{
		V: EntryVersion, Seq: 1, TSUnixNano: now.UnixNano(),
		ActorID: actorIDSystem, ActorRole: actorIDSystem, AuthMethod: AuthMethodSystem,
		Action: ActionGenesis, Target: "admin_audit",
		Details: map[string]string{
			detailAlg:           algEd25519,
			detailPublicKey:     base64.StdEncoding.EncodeToString(s.signer.PubKey()),
			detailActorKeyCheck: actorKeyCheck(s.hmacKey),
		},
		Outcome:  OutcomeOK,
		KeyID:    s.keyID,
		PrevHash: make([]byte, prevHashLen),
	}
}

func readHead(ctx context.Context, conn *sql.Conn) (headRow, bool, error) {
	var h headRow
	err := conn.QueryRowContext(ctx,
		"SELECT seq, entry_hash, key_id FROM admin_audit ORDER BY seq DESC LIMIT 1").Scan(&h.Seq, &h.Hash, &h.KeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return headRow{}, false, nil
	}
	if err != nil {
		return headRow{}, false, fmt.Errorf("adminaudit: read chain head: %w", err)
	}
	return h, true, nil
}

const insertEntrySQL = `INSERT INTO admin_audit (seq, ts_unix_nano, actor_id, actor_role, auth_method, action,
    target, target_ref, details_json, outcome, http_status, before_hash, after_hash, client_ip, request_id,
    key_id, prev_hash, entry_hash, signature) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// signAndInsert stamps entry_hash and signature on e and inserts it, plus the
// side-table row when side is set.
func (s *Store) signAndInsert(ctx context.Context, conn *sql.Conn, e *Entry, side *Actor) error {
	h, err := e.entryHash()
	if err != nil {
		return err
	}
	e.EntryHash = h
	e.Signature = s.signer.SignBytes(h)
	dj, err := detailsJSON(e.Details)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, insertEntrySQL,
		e.Seq, e.TSUnixNano, e.ActorID, e.ActorRole, e.AuthMethod, e.Action,
		e.Target, e.TargetRef, dj, e.Outcome, e.HTTPStatus, e.BeforeHash, e.AfterHash,
		e.ClientIP, e.RequestID, e.KeyID, e.PrevHash, e.EntryHash, e.Signature); err != nil {
		return fmt.Errorf("adminaudit: insert entry %d: %w", e.Seq, err)
	}
	if side != nil {
		if _, err := conn.ExecContext(ctx,
			"INSERT INTO admin_audit_actor (seq, sub, email) VALUES (?,?,?)", e.Seq, side.Sub, side.Email); err != nil {
			return fmt.Errorf("adminaudit: insert actor row %d: %w", e.Seq, err)
		}
	}
	return nil
}

// Head returns the newest entry's seq, entry_hash and key_id; an empty chain
// returns seq 0 and no error.
func (s *Store) Head(ctx context.Context) (seq int64, entryHash []byte, keyID string, err error) {
	err = s.db.SQL().QueryRowContext(ctx,
		"SELECT seq, entry_hash, key_id FROM admin_audit ORDER BY seq DESC LIMIT 1").Scan(&seq, &entryHash, &keyID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, "", nil
	}
	if err != nil {
		return 0, nil, "", fmt.Errorf("adminaudit: read chain head: %w", err)
	}
	return seq, entryHash, keyID, nil
}

// Filter narrows List. Zero values match everything. Actor matches either an
// actor_id or a sub (hashed with the store's HMAC key when it has one).
type Filter struct {
	Actor   string
	Action  string
	Outcome string
	Since   time.Time
}

// ListItem is one listed entry with its side-table identity (empty when the
// entry has no side row).
type ListItem struct {
	Entry
	Actor Actor `json:"actor"`
}

// List returns entries newest first. limit defaults to 50 and is clamped to
// 200; a positive cursor returns only entries with seq below it (pass the last
// returned seq to page).
func (s *Store) List(ctx context.Context, f Filter, limit int, cursor int64) ([]ListItem, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	var where []string
	var args []any
	if cursor > 0 {
		where = append(where, "a.seq < ?")
		args = append(args, cursor)
	}
	if f.Actor != "" {
		ids := []any{f.Actor}
		if len(s.hmacKey) > 0 {
			ids = append(ids, hmacHex(s.hmacKey, f.Actor))
		}
		where = append(where, "a.actor_id IN (?"+strings.Repeat(",?", len(ids)-1)+")")
		args = append(args, ids...)
	}
	if f.Action != "" {
		where = append(where, "a.action = ?")
		args = append(args, f.Action)
	}
	if f.Outcome != "" {
		where = append(where, "a.outcome = ?")
		args = append(args, f.Outcome)
	}
	if !f.Since.IsZero() {
		where = append(where, "a.ts_unix_nano >= ?")
		args = append(args, f.Since.UnixNano())
	}
	q := selectRowsSQL
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY a.seq DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("adminaudit: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ListItem
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("adminaudit: list: %w", err)
		}
		item := ListItem{Entry: r.entry}
		if r.side != nil {
			item.Actor = *r.side
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("adminaudit: list: %w", err)
	}
	return out, nil
}

// KeyInfo is one signing key declared in the chain.
type KeyInfo struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"` // std base64 of the 32-byte Ed25519 key
	FirstSeq  int64  `json:"firstSeq"`
}

// PubKeys returns every key declared by a key-defining entry (audit.genesis,
// audit.segment_start, and the reserved audit.key_rotated), oldest first, so
// keys of earlier segments stay available after a key change. It lists what
// the chain declares; Verify is what checks those declarations.
func (s *Store) PubKeys(ctx context.Context) ([]KeyInfo, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		"SELECT seq, key_id, details_json FROM admin_audit WHERE action IN (?,?,?) ORDER BY seq",
		ActionGenesis, ActionSegmentStart, ActionKeyRotated)
	if err != nil {
		return nil, fmt.Errorf("adminaudit: read keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KeyInfo
	for rows.Next() {
		var k KeyInfo
		var dj string
		if err := rows.Scan(&k.FirstSeq, &k.KeyID, &dj); err != nil {
			return nil, fmt.Errorf("adminaudit: read keys: %w", err)
		}
		var d map[string]string
		if err := json.Unmarshal([]byte(dj), &d); err != nil {
			return nil, fmt.Errorf("adminaudit: entry %d has malformed details", k.FirstSeq)
		}
		k.PublicKey = d[detailPublicKey]
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("adminaudit: read keys: %w", err)
	}
	return out, nil
}

// declaredKey parses the public key a key-defining entry declares and checks
// that it hashes to the entry's own key_id.
func declaredKey(e *Entry) (ed25519.PublicKey, bool) {
	if e.Details[detailAlg] != "" && e.Details[detailAlg] != algEd25519 {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(e.Details[detailPublicKey])
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	pub := ed25519.PublicKey(raw)
	if audit.KeyID(pub) != e.KeyID {
		return nil, false
	}
	return pub, true
}

func isKeyDefining(action string) bool {
	return action == ActionGenesis || action == ActionSegmentStart || action == ActionKeyRotated
}

// selectRowsSQL reads chain rows with their optional side row.
const selectRowsSQL = `SELECT a.seq, a.ts_unix_nano, a.actor_id, a.actor_role, a.auth_method, a.action,
    a.target, a.target_ref, a.details_json, a.outcome, a.http_status, a.before_hash, a.after_hash,
    a.client_ip, a.request_id, a.key_id, a.prev_hash, a.entry_hash, a.signature, s.sub, s.email
    FROM admin_audit a LEFT JOIN admin_audit_actor s ON s.seq = a.seq`

// storedRow is a scanned row. malformed is set when a column is NULL or the
// details do not decode: such a row can never verify, but scanning it is not
// an error, so Verify reports it at its seq instead of failing outright.
type storedRow struct {
	entry     Entry
	side      *Actor
	malformed bool
}

func scanRow(rows *sql.Rows) (storedRow, error) {
	var (
		seq                                                  int64
		ts, status                                           sql.NullInt64
		actorID, role, method, action, target, ref, dj, outc sql.NullString
		before, after, ip, reqID, keyID, sub, email          sql.NullString
		prev, hash, sig                                      []byte
	)
	if err := rows.Scan(&seq, &ts, &actorID, &role, &method, &action, &target, &ref, &dj, &outc,
		&status, &before, &after, &ip, &reqID, &keyID, &prev, &hash, &sig, &sub, &email); err != nil {
		return storedRow{}, err
	}
	r := storedRow{entry: Entry{
		V: EntryVersion, Seq: seq, TSUnixNano: ts.Int64,
		ActorID: actorID.String, ActorRole: role.String, AuthMethod: method.String,
		Action: action.String, Target: target.String, TargetRef: ref.String,
		Outcome: outc.String, HTTPStatus: int(status.Int64),
		BeforeHash: before.String, AfterHash: after.String,
		ClientIP: ip.String, RequestID: reqID.String, KeyID: keyID.String,
		PrevHash: prev, EntryHash: hash, Signature: sig,
	}}
	for _, v := range []bool{ts.Valid, status.Valid, actorID.Valid, role.Valid, method.Valid, action.Valid,
		target.Valid, ref.Valid, dj.Valid, outc.Valid, before.Valid, after.Valid, ip.Valid, reqID.Valid,
		keyID.Valid, prev != nil, hash != nil, sig != nil} {
		if !v {
			r.malformed = true
		}
	}
	if dj.Valid {
		if err := json.Unmarshal([]byte(dj.String), &r.entry.Details); err != nil {
			r.malformed = true
		}
	}
	if sub.Valid || email.Valid {
		r.side = &Actor{Sub: sub.String, Email: email.String}
	}
	return r, nil
}

// equalHash reports whether two non-empty hashes are equal.
func equalHash(a, b []byte) bool {
	return len(a) > 0 && hmac.Equal(a, b)
}
