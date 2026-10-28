package adminaudit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ethosagent/warden/internal/audit"
)

// DefaultVerifyMaxRows caps the rows one Verify call checks.
const DefaultVerifyMaxRows = 100000

// verifyPageSize is how many rows one query reads. Verify releases the
// connection between pages, so an Append on the same handle waits at most one
// page, never the whole scan.
const verifyPageSize = 256

// Reasons Verify reports for the first bad seq.
const (
	ReasonSeqGap         = "seq_gap"         // a seq is missing (deleted row)
	ReasonMalformed      = "malformed_row"   // a NULL column or undecodable details
	ReasonGenesis        = "genesis"         // seq 1 is not a proper genesis, or genesis appears later
	ReasonPrevHash       = "prev_hash"       // prev_hash does not link to the previous entry
	ReasonEntryHash      = "entry_hash"      // the stored entry_hash is not sha256(canonical)
	ReasonDeclaredKey    = "declared_key"    // a key-defining entry's public key is bad or not its key_id
	ReasonKeyChange      = "key_change"      // key_id changed outside a segment_start/key_rotated entry
	ReasonUnknownKey     = "unknown_key"     // no key in the chain declares this key_id
	ReasonSignature      = "signature"       // the signature does not verify
	ReasonActorID        = "actor_id"        // actor_id is not HMAC(sub) of the side row
	ReasonAnchorMissing  = "anchor_missing"  // the chain ends before the anchor seq (tail deleted)
	ReasonAnchorMismatch = "anchor_mismatch" // the entry at the anchor seq has a different hash
)

// Anchor is a previously observed head (for example from an emitted log
// line). Verify fails when the chain no longer reaches it or its hash changed,
// which catches deletion of the newest rows.
type Anchor struct {
	Seq  int64
	Hash []byte
}

// VerifyOptions bounds a Verify call. FromSeq defaults to 1 and ToSeq to the
// head; MaxRows defaults to DefaultVerifyMaxRows. With HMACKey set, rows that
// have a side row must carry actor_id = HMAC(sub).
type VerifyOptions struct {
	FromSeq int64
	ToSeq   int64
	Anchor  *Anchor
	MaxRows int
	HMACKey []byte
}

// Result is the outcome of Verify. On failure FirstBadSeq is the first seq
// that does not verify and Reason names the failed check. LastVerifiedSeq is
// the last seq that verified; when Partial is set the MaxRows cap stopped the
// scan and the caller resumes with FromSeq = LastVerifiedSeq + 1.
type Result struct {
	OK              bool   `json:"ok"`
	Checked         int    `json:"checked"`
	FirstBadSeq     int64  `json:"firstBadSeq,omitempty"`
	Reason          string `json:"reason,omitempty"`
	HeadSeq         int64  `json:"headSeq"`
	HeadHash        []byte `json:"headHash"`
	LastVerifiedSeq int64  `json:"lastVerifiedSeq"`
	Partial         bool   `json:"partial,omitempty"`
}

// chainVerifier holds the state carried from one row to the next: the keys
// declared so far and the previous entry. VerifyExport (W-P1-AAUD-04) reuses
// it over an export stream.
type chainVerifier struct {
	keys     map[string]ed25519.PublicKey
	hmacKey  []byte
	havePrev bool
	prev     headRow
}

func newChainVerifier(hmacKey []byte) *chainVerifier {
	return &chainVerifier{keys: map[string]ed25519.PublicKey{}, hmacKey: hmacKey}
}

// nextSeq is the seq the chain expects next.
func (v *chainVerifier) nextSeq() int64 {
	if v.havePrev {
		return v.prev.Seq + 1
	}
	return 1
}

// check verifies r against the chain so far. It returns the bad seq and the
// reason, or 0 and "" when r verifies (and becomes the new previous entry).
func (v *chainVerifier) check(r storedRow) (int64, string) {
	e := &r.entry
	want := v.nextSeq()
	if e.Seq != want {
		return want, ReasonSeqGap
	}
	if r.malformed {
		return e.Seq, ReasonMalformed
	}
	if e.Seq == 1 {
		if e.Action != ActionGenesis || !isZero(e.PrevHash) || len(e.PrevHash) != prevHashLen {
			return e.Seq, ReasonGenesis
		}
	} else {
		if e.Action == ActionGenesis {
			return e.Seq, ReasonGenesis
		}
		if !equalHash(e.PrevHash, v.prev.Hash) {
			return e.Seq, ReasonPrevHash
		}
	}
	h, err := e.entryHash()
	if err != nil || !equalHash(h, e.EntryHash) {
		return e.Seq, ReasonEntryHash
	}
	if isKeyDefining(e.Action) {
		pub, ok := declaredKey(e)
		if !ok {
			return e.Seq, ReasonDeclaredKey
		}
		if known, dup := v.keys[e.KeyID]; dup && !known.Equal(pub) {
			return e.Seq, ReasonDeclaredKey
		}
		v.keys[e.KeyID] = pub
	} else if v.havePrev && e.KeyID != v.prev.KeyID {
		return e.Seq, ReasonKeyChange
	}
	pub, ok := v.keys[e.KeyID]
	if !ok {
		return e.Seq, ReasonUnknownKey
	}
	if !audit.VerifyBytes(pub, e.EntryHash, e.Signature) {
		return e.Seq, ReasonSignature
	}
	if len(v.hmacKey) > 0 && r.side != nil {
		wantID := actorIDAnonymous
		if r.side.Sub != "" {
			wantID = hmacHex(v.hmacKey, r.side.Sub)
		}
		if e.ActorID != wantID {
			return e.Seq, ReasonActorID
		}
	}
	v.prev = headRow{Seq: e.Seq, Hash: e.EntryHash, KeyID: e.KeyID}
	v.havePrev = true
	return 0, ""
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Verify streams the chain from FromSeq to ToSeq (bounded by the head read at
// the start) and checks seq continuity, prev_hash links, the recomputed
// entry_hash, each signature under the key its key_id names (keys come from
// the chain's key-defining entries, and a declared key must hash to its own
// key_id), that key_id changes only at a segment_start or key_rotated entry,
// and, with HMACKey, actor_id against the side row. It stops at the first bad
// row. Verify only reads: it takes no write lock and reads in pages, so it
// never holds off an Append for longer than one page.
func (s *Store) Verify(ctx context.Context, opts VerifyOptions) (Result, error) {
	headSeq, headHash, _, err := s.Head(ctx)
	if err != nil {
		return Result{}, err
	}
	res := Result{HeadSeq: headSeq, HeadHash: headHash}
	from := max(opts.FromSeq, 1)
	upper := headSeq
	if opts.ToSeq > 0 && opts.ToSeq < upper {
		upper = opts.ToSeq
	}
	maxRows := opts.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultVerifyMaxRows
	}

	v := newChainVerifier(opts.HMACKey)
	res.LastVerifiedSeq = from - 1
	if from > 1 && from <= upper {
		bad, err := s.primeVerifier(ctx, v, from)
		if err != nil {
			return Result{}, err
		}
		if bad != 0 {
			res.FirstBadSeq, res.Reason = bad, ReasonSeqGap
			res.LastVerifiedSeq = 0
			return res, nil
		}
	}

	last := from - 1
	for last < upper && res.Checked < maxRows {
		n := min(verifyPageSize, maxRows-res.Checked)
		page, err := s.readPage(ctx, last, upper, n)
		if err != nil {
			return Result{}, err
		}
		for _, r := range page {
			if bad, reason := v.check(r); bad != 0 {
				res.FirstBadSeq, res.Reason = bad, reason
				return res, nil
			}
			res.Checked++
			last = r.entry.Seq
			res.LastVerifiedSeq = last
		}
		if len(page) < n {
			break
		}
	}
	res.Partial = last < upper && res.Checked >= maxRows

	if opts.Anchor != nil && opts.Anchor.Seq > 0 {
		bad, reason, err := s.checkAnchor(ctx, *opts.Anchor, headSeq)
		if err != nil {
			return Result{}, err
		}
		if bad != 0 {
			res.FirstBadSeq, res.Reason = bad, reason
			return res, nil
		}
	}
	res.OK = true
	return res, nil
}

// VerifyWithStoreKey is Verify with the store's own HMAC key in place of
// opts.HMACKey, so rows that have a side row are also checked for actor_id =
// HMAC(sub) without the key leaving the store. The control plane's dashboard
// verify (W-P1-AAUD-03) uses it.
func (s *Store) VerifyWithStoreKey(ctx context.Context, opts VerifyOptions) (Result, error) {
	opts.HMACKey = s.hmacKey
	return s.Verify(ctx, opts)
}

// readPage returns up to n rows with after < seq <= upper, in seq order.
func (s *Store) readPage(ctx context.Context, after, upper int64, n int) ([]storedRow, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		selectRowsSQL+" WHERE a.seq > ? AND a.seq <= ? ORDER BY a.seq LIMIT ?", after, upper, n)
	if err != nil {
		return nil, fmt.Errorf("adminaudit: verify: read rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storedRow
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("adminaudit: verify: read rows: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("adminaudit: verify: read rows: %w", err)
	}
	return out, nil
}

// primeVerifier prepares a resumed Verify: it loads the keys declared before
// from and the entry at from-1 (both verified by the earlier call). It
// returns from-1 as the bad seq when that entry is gone.
func (s *Store) primeVerifier(ctx context.Context, v *chainVerifier, from int64) (int64, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		selectRowsSQL+" WHERE a.seq < ? AND a.action IN (?,?,?) ORDER BY a.seq",
		from, ActionGenesis, ActionSegmentStart, ActionKeyRotated)
	if err != nil {
		return 0, fmt.Errorf("adminaudit: verify: read keys: %w", err)
	}
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("adminaudit: verify: read keys: %w", err)
		}
		if pub, ok := declaredKey(&r.entry); ok {
			v.keys[r.entry.KeyID] = pub
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("adminaudit: verify: read keys: %w", err)
	}
	_ = rows.Close()

	var p headRow
	err = s.db.SQL().QueryRowContext(ctx,
		"SELECT seq, entry_hash, key_id FROM admin_audit WHERE seq = ?", from-1).Scan(&p.Seq, &p.Hash, &p.KeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return from - 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("adminaudit: verify: read entry %d: %w", from-1, err)
	}
	v.prev, v.havePrev = p, true
	return 0, nil
}

// checkAnchor fails when the chain ends before the anchor (the first missing
// seq is reported) or the entry at the anchor seq has a different hash.
func (s *Store) checkAnchor(ctx context.Context, a Anchor, headSeq int64) (int64, string, error) {
	if a.Seq > headSeq {
		return headSeq + 1, ReasonAnchorMissing, nil
	}
	var h []byte
	err := s.db.SQL().QueryRowContext(ctx, "SELECT entry_hash FROM admin_audit WHERE seq = ?", a.Seq).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return a.Seq, ReasonAnchorMissing, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("adminaudit: verify: read anchor entry: %w", err)
	}
	if !equalHash(h, a.Hash) {
		return a.Seq, ReasonAnchorMismatch, nil
	}
	return 0, "", nil
}
