package adminaudit

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/cpstate"
)

// ExportFormat names the JSONL export layout: one keys record, then one entry
// record per chained row in seq order.
const ExportFormat = "warden.admin.export.v1"

// Export record types (the "type" field of each line).
const (
	exportTypeKeys  = "keys"
	exportTypeEntry = "entry"
)

// ReasonKeysRecord is the Result reason when an export's keys record does not
// list exactly the keys the chain declares.
const ReasonKeysRecord = "keys_record"

// exportFileMode is the mode of a new export file: it holds the chain (and,
// with identity, subs and emails), so only the owner may read it.
const exportFileMode os.FileMode = 0o600

// maxExportLine bounds one export line. An entry is far smaller (details are
// capped at 16 x 288 bytes); a longer line is reported as malformed.
const maxExportLine = 1 << 20

// exportKeys is the first line of an export: every key the chain declares.
// It is informational (VerifyExport takes keys from the chain's own
// key-defining entries) but VerifyExport checks it matches them.
type exportKeys struct {
	Type   string    `json:"type"`
	Format string    `json:"format"`
	Keys   []KeyInfo `json:"keys"`
}

// exportEntry is one chained row. Hashes and the signature are lowercase hex.
// Actor (the side-table sub and email) is written only with IncludeIdentity.
type exportEntry struct {
	Type       string            `json:"type"`
	V          int               `json:"v"`
	Seq        int64             `json:"seq"`
	TSUnixNano int64             `json:"ts_unix_nano"`
	ActorID    string            `json:"actor_id"`
	ActorRole  string            `json:"actor_role"`
	AuthMethod string            `json:"auth_method"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	TargetRef  string            `json:"target_ref"`
	Details    map[string]string `json:"details"`
	Outcome    string            `json:"outcome"`
	HTTPStatus int               `json:"http_status"`
	BeforeHash string            `json:"before_hash"`
	AfterHash  string            `json:"after_hash"`
	ClientIP   string            `json:"client_ip"`
	RequestID  string            `json:"request_id"`
	KeyID      string            `json:"key_id"`
	PrevHash   string            `json:"prev_hash"`
	EntryHash  string            `json:"entry_hash"`
	Signature  string            `json:"signature"`
	Actor      *Actor            `json:"actor,omitempty"`
}

func toExportEntry(r storedRow, withIdentity bool) exportEntry {
	e := r.entry
	out := exportEntry{
		Type: exportTypeEntry, V: e.V, Seq: e.Seq, TSUnixNano: e.TSUnixNano,
		ActorID: e.ActorID, ActorRole: e.ActorRole, AuthMethod: e.AuthMethod,
		Action: e.Action, Target: e.Target, TargetRef: e.TargetRef, Details: e.Details,
		Outcome: e.Outcome, HTTPStatus: e.HTTPStatus,
		BeforeHash: e.BeforeHash, AfterHash: e.AfterHash,
		ClientIP: e.ClientIP, RequestID: e.RequestID, KeyID: e.KeyID,
		PrevHash:  hex.EncodeToString(e.PrevHash),
		EntryHash: hex.EncodeToString(e.EntryHash),
		Signature: hex.EncodeToString(e.Signature),
	}
	if out.Details == nil {
		out.Details = map[string]string{}
	}
	if withIdentity && r.side != nil {
		a := *r.side
		out.Actor = &a
	}
	return out
}

// fromExportEntry decodes a line back into a row; a bad hex field marks the
// row malformed so the verifier reports it at its seq.
func fromExportEntry(x exportEntry) storedRow {
	r := storedRow{entry: Entry{
		V: x.V, Seq: x.Seq, TSUnixNano: x.TSUnixNano,
		ActorID: x.ActorID, ActorRole: x.ActorRole, AuthMethod: x.AuthMethod,
		Action: x.Action, Target: x.Target, TargetRef: x.TargetRef, Details: x.Details,
		Outcome: x.Outcome, HTTPStatus: x.HTTPStatus,
		BeforeHash: x.BeforeHash, AfterHash: x.AfterHash,
		ClientIP: x.ClientIP, RequestID: x.RequestID, KeyID: x.KeyID,
	}, side: x.Actor}
	var err error
	if r.entry.PrevHash, err = hex.DecodeString(x.PrevHash); err != nil {
		r.malformed = true
	}
	if r.entry.EntryHash, err = hex.DecodeString(x.EntryHash); err != nil || len(r.entry.EntryHash) == 0 {
		r.malformed = true
	}
	if r.entry.Signature, err = hex.DecodeString(x.Signature); err != nil || len(r.entry.Signature) == 0 {
		r.malformed = true
	}
	if x.Type != exportTypeEntry || x.Details == nil {
		r.malformed = true
	}
	return r
}

// ExportOptions configures Export.
type ExportOptions struct {
	// IncludeIdentity adds each entry's side-table sub and email. Off by
	// default: the chain itself carries only the HMAC actor_id.
	IncludeIdentity bool
}

// ExportResult summarises an export.
type ExportResult struct {
	Keys     int   `json:"keys"`
	Entries  int   `json:"entries"`
	HeadSeq  int64 `json:"headSeq"`
	Identity bool  `json:"identity"`
}

// Export writes the chain as JSONL to w: one keys record (every declared key
// with its public key and first seq, from PubKeys) and then every entry from
// seq 1 to the head read at the start, in seq order. Rows appended while the
// export runs are left out, so the keys record always matches the entries.
// Export only reads.
func (s *Store) Export(ctx context.Context, w io.Writer, o ExportOptions) (ExportResult, error) {
	headSeq, _, _, err := s.Head(ctx)
	if err != nil {
		return ExportResult{}, err
	}
	all, err := s.PubKeys(ctx)
	if err != nil {
		return ExportResult{}, err
	}
	keys := []KeyInfo{}
	for _, k := range all {
		if k.FirstSeq <= headSeq {
			keys = append(keys, k)
		}
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(exportKeys{Type: exportTypeKeys, Format: ExportFormat, Keys: keys}); err != nil {
		return ExportResult{}, fmt.Errorf("adminaudit: export: %w", err)
	}
	res := ExportResult{Keys: len(keys), HeadSeq: headSeq, Identity: o.IncludeIdentity}
	var last int64
	for last < headSeq {
		page, err := s.readPage(ctx, last, headSeq, verifyPageSize)
		if err != nil {
			return ExportResult{}, err
		}
		for _, r := range page {
			if err := enc.Encode(toExportEntry(r, o.IncludeIdentity)); err != nil {
				return ExportResult{}, fmt.Errorf("adminaudit: export entry %d: %w", r.entry.Seq, err)
			}
			res.Entries++
			last = r.entry.Seq
		}
		if len(page) < verifyPageSize {
			break
		}
	}
	if err := bw.Flush(); err != nil {
		return ExportResult{}, fmt.Errorf("adminaudit: export: %w", err)
	}
	return res, nil
}

// ExportFile writes Export to a new file at path, created 0600. An existing
// file is never overwritten (an earlier export may be audit evidence), and a
// failed export removes the partial file.
func (s *Store) ExportFile(ctx context.Context, path string, o ExportOptions) (res ExportResult, err error) {
	if path == "" {
		return ExportResult{}, errors.New("adminaudit: export needs an output file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, exportFileMode)
	if err != nil {
		return ExportResult{}, fmt.Errorf("adminaudit: create export file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	// The umask can only remove bits from the requested mode; make it exact.
	if err := f.Chmod(exportFileMode); err != nil {
		return ExportResult{}, fmt.Errorf("adminaudit: chmod export file: %w", err)
	}
	if res, err = s.Export(ctx, f, o); err != nil {
		return ExportResult{}, err
	}
	if err := f.Sync(); err != nil {
		return ExportResult{}, fmt.Errorf("adminaudit: sync export file: %w", err)
	}
	if err := f.Close(); err != nil {
		return ExportResult{}, fmt.Errorf("adminaudit: close export file: %w", err)
	}
	return res, nil
}

// VerifyExportOptions configures VerifyExport.
type VerifyExportOptions struct {
	// Anchor is a previously observed head; the export must reach it with the
	// same entry hash (catches removal of the newest lines).
	Anchor *Anchor
	// HMACKey, when set, checks actor_id against the identity of entries
	// exported with IncludeIdentity.
	HMACKey []byte
}

// VerifyExport verifies an export file with no database, using the checks
// Verify uses: seq continuity from 1, prev_hash links, the recomputed
// entry_hash, each signature under the key its key_id names (keys come from
// the chain's own key-defining entries), and key_id changes only at a
// segment_start or key_rotated entry. A line that is altered, removed or not
// a valid entry fails at its seq. With every entry valid, the keys record
// must list exactly the keys the entries declare, and Anchor is checked. An
// error means the file could not be read or does not start with a keys
// record.
func VerifyExport(path string, o VerifyExportOptions) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("adminaudit: open export: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxExportLine)

	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return Result{}, fmt.Errorf("adminaudit: read export: %w", err)
		}
		return Result{}, fmt.Errorf("adminaudit: export %s is empty; it must start with a keys record", path)
	}
	var hdr exportKeys
	if err := strictUnmarshal(sc.Bytes(), &hdr); err != nil || hdr.Type != exportTypeKeys || hdr.Format != ExportFormat {
		return Result{}, fmt.Errorf("adminaudit: export %s does not start with a %s keys record", path, ExportFormat)
	}

	v := newChainVerifier(o.HMACKey)
	var res Result
	var declared []KeyInfo
	var anchorHash []byte // the verified entry hash at the anchor seq
	failed := false
	for sc.Scan() {
		line := sc.Bytes()
		if failed {
			// Keep reading only to report the export's head.
			noteHead(&res, line)
			continue
		}
		r := decodeExportLine(line, v.nextSeq())
		if bad, reason := v.check(r); bad != 0 {
			res.FirstBadSeq, res.Reason = bad, reason
			failed = true
			noteHead(&res, line)
			continue
		}
		res.Checked++
		res.LastVerifiedSeq = r.entry.Seq
		res.HeadSeq, res.HeadHash = r.entry.Seq, r.entry.EntryHash
		if o.Anchor != nil && r.entry.Seq == o.Anchor.Seq {
			anchorHash = r.entry.EntryHash
		}
		if isKeyDefining(r.entry.Action) {
			declared = append(declared, keyInfoOf(&r.entry))
		}
	}
	if err := sc.Err(); err != nil {
		if !errors.Is(err, bufio.ErrTooLong) {
			return Result{}, fmt.Errorf("adminaudit: read export: %w", err)
		}
		if !failed {
			res.FirstBadSeq, res.Reason = v.nextSeq(), ReasonMalformed
		}
		return res, nil
	}
	if failed {
		return res, nil
	}
	if bad := keysRecordMismatch(hdr.Keys, declared); bad != 0 {
		res.FirstBadSeq, res.Reason = bad, ReasonKeysRecord
		return res, nil
	}
	if a := o.Anchor; a != nil && a.Seq > 0 {
		if a.Seq > res.HeadSeq {
			res.FirstBadSeq, res.Reason = res.HeadSeq+1, ReasonAnchorMissing
			return res, nil
		}
		if !equalHash(anchorHash, a.Hash) {
			res.FirstBadSeq, res.Reason = a.Seq, ReasonAnchorMismatch
			return res, nil
		}
	}
	res.OK = true
	return res, nil
}

// decodeExportLine parses one entry line. A line that does not decode is a
// malformed row at the seq the chain expects next.
func decodeExportLine(line []byte, want int64) storedRow {
	var x exportEntry
	if err := strictUnmarshal(line, &x); err != nil {
		return storedRow{entry: Entry{Seq: want}, malformed: true}
	}
	return fromExportEntry(x)
}

// noteHead records the seq and hash of a line read after a failure, so the
// Result still names the export's head.
func noteHead(res *Result, line []byte) {
	var x struct {
		Seq       int64  `json:"seq"`
		EntryHash string `json:"entry_hash"`
	}
	if json.Unmarshal(line, &x) != nil || x.Seq <= res.HeadSeq {
		return
	}
	h, err := hex.DecodeString(x.EntryHash)
	if err != nil {
		return
	}
	res.HeadSeq, res.HeadHash = x.Seq, h
}

// keysRecordMismatch returns the first seq at which the keys record and the
// keys the chain declares differ (0 when they match).
func keysRecordMismatch(record, declared []KeyInfo) int64 {
	for i := 0; i < max(len(record), len(declared)); i++ {
		if i < len(record) && i < len(declared) && record[i] == declared[i] {
			continue
		}
		if i < len(declared) {
			return declared[i].FirstSeq
		}
		return max(record[i].FirstSeq, 1)
	}
	return 0
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ParseAnchor parses the --anchor value "seq:hash", where hash is the
// lowercase hex entry_hash a verify run or an emitted log line reported.
func ParseAnchor(s string) (*Anchor, error) {
	seqStr, hashStr, ok := strings.Cut(s, ":")
	if !ok {
		return nil, fmt.Errorf("adminaudit: anchor %q is not seq:hash", s)
	}
	seq, err := strconv.ParseInt(seqStr, 10, 64)
	if err != nil || seq < 1 {
		return nil, fmt.Errorf("adminaudit: anchor seq %q is not a positive integer", seqStr)
	}
	h, err := hex.DecodeString(hashStr)
	if err != nil || len(h) != prevHashLen {
		return nil, fmt.Errorf("adminaudit: anchor hash must be %d hex characters", 2*prevHashLen)
	}
	return &Anchor{Seq: seq, Hash: h}, nil
}

// Report is the printable form of a Result: hashes as lowercase hex, and the
// fields the CLI and the dashboard share.
type Report struct {
	OK              bool   `json:"ok"`
	Checked         int    `json:"checked"`
	FirstBadSeq     int64  `json:"firstBadSeq"`
	Reason          string `json:"reason,omitempty"`
	HeadSeq         int64  `json:"headSeq"`
	HeadHash        string `json:"headHash"`
	LastVerifiedSeq int64  `json:"lastVerifiedSeq"`
}

// Report returns r with its hash hex-encoded.
func (r Result) Report() Report {
	return Report{
		OK: r.OK, Checked: r.Checked, FirstBadSeq: r.FirstBadSeq, Reason: r.Reason,
		HeadSeq: r.HeadSeq, HeadHash: hex.EncodeToString(r.HeadHash), LastVerifiedSeq: r.LastVerifiedSeq,
	}
}

// VerifyAll runs Verify from opts.FromSeq to the head, resuming past the
// per-call MaxRows cap, so an offline run checks the whole range in bounded
// pages. Checked counts every row across the calls.
func (s *Store) VerifyAll(ctx context.Context, opts VerifyOptions) (Result, error) {
	checked := 0
	for {
		res, err := s.Verify(ctx, opts)
		if err != nil {
			return Result{}, err
		}
		checked += res.Checked
		res.Checked = checked
		if !res.OK || !res.Partial {
			return res, nil
		}
		opts.FromSeq = res.LastVerifiedSeq + 1
	}
}

// VerifyTail verifies the newest n rows (the whole chain when it is shorter),
// which includes the head entry's signature. Keys declared before the window
// come from the chain's key-defining entries. The CP runs it at startup.
func (s *Store) VerifyTail(ctx context.Context, n int) (Result, error) {
	if n <= 0 {
		return Result{}, errors.New("adminaudit: VerifyTail needs a positive row count")
	}
	headSeq, _, _, err := s.Head(ctx)
	if err != nil {
		return Result{}, err
	}
	from := max(headSeq-int64(n)+1, 1)
	return s.Verify(ctx, VerifyOptions{FromSeq: from, ToSeq: headSeq, MaxRows: n})
}

// ownMigrationPrefix is the namespace of this package's cpstate migrations.
const ownMigrationPrefix = "adminaudit/"

// OpenReadOnly opens <stateDir>/warden-cp.db read-only (cpstate mode=ro) for
// the offline verifier and exporter and returns a Store with no signer and no
// HMAC key: it can Verify, Export, List and read PubKeys, never write, and no
// key file is opened. migs is the caller's full CP migration list
// (Migrations() is added when absent). A file a newer binary migrated still
// opens, since nothing is written: IDs outside this package's namespace that
// migs does not register are tolerated, while an unknown adminaudit/ ID (a
// table layout this binary does not know) is refused. A missing file, or a
// file with no admin_audit table, is an error. closeFn closes the database.
func OpenReadOnly(ctx context.Context, stateDir string, migs []cpstate.Migration) (s *Store, closeFn func() error, err error) {
	if stateDir == "" {
		return nil, nil, errors.New("adminaudit: OpenReadOnly needs a state dir")
	}
	path := filepath.Join(stateDir, StateDBFileName)
	db, err := cpstate.OpenReadOnlyWith(ctx, path, withOwnMigrations(migs), cpstate.ReadOnlyOptions{
		AllowNewer: func(id string) bool { return !strings.HasPrefix(id, ownMigrationPrefix) },
	})
	if err != nil {
		return nil, nil, err
	}
	var tables int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='admin_audit'").Scan(&tables); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("adminaudit: inspect %s: %w", path, err)
	}
	if tables == 0 {
		_ = db.Close()
		return nil, nil, fmt.Errorf("adminaudit: %s has no admin audit chain (admin audit was never enabled with this state dir)", path)
	}
	return NewStore(db, Options{}), db.Close, nil
}
