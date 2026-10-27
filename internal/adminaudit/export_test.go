package adminaudit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// exportTo writes s's export to a new file in a temp dir and returns its path.
func exportTo(t *testing.T, s *Store, o ExportOptions) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if _, err := s.ExportFile(context.Background(), path, o); err != nil {
		t.Fatalf("ExportFile: %v", err)
	}
	return path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edited.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func verifyExport(t *testing.T, path string, o VerifyExportOptions) Result {
	t.Helper()
	res, err := VerifyExport(path, o)
	if err != nil {
		t.Fatalf("VerifyExport: %v", err)
	}
	return res
}

// lineFor returns the index of the export line holding seq (line 0 is the
// keys record, so seq N is line N).
func lineFor(seq int64) int { return int(seq) }

func editLine(t *testing.T, line string, edit func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func withoutLine(lines []string, i int) []string {
	out := append([]string(nil), lines[:i]...)
	return append(out, lines[i+1:]...)
}

// TestExportRoundTrip: an export of 500 rows verifies with VerifyExport, and
// altering, removing or garbling one line fails at exactly that seq.
func TestExportRoundTrip(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 499) // + genesis = 500 rows
	path := exportTo(t, s, ExportOptions{})

	res := verifyExport(t, path, VerifyExportOptions{})
	head, headHash, _, err := s.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Checked != 500 || res.HeadSeq != 500 || head != 500 || !bytes.Equal(res.HeadHash, headHash) {
		t.Fatalf("VerifyExport = %+v, want ok over 500 rows ending at the DB head", res)
	}

	lines := readLines(t, path)
	if len(lines) != 501 {
		t.Fatalf("export has %d lines, want 1 keys record + 500 entries", len(lines))
	}
	cases := map[string]struct {
		lines  []string
		seq    int64
		reason string
	}{
		"altered field": {
			lines: replaced(lines, lineFor(250), editLine(t, lines[lineFor(250)], func(m map[string]any) { m["target_ref"] = "policy@forged" })),
			seq:   250, reason: ReasonEntryHash,
		},
		"altered signature": {
			lines: replaced(lines, lineFor(321), editLine(t, lines[lineFor(321)], func(m map[string]any) {
				sig := []byte(m["signature"].(string))
				sig[0] ^= 1
				m["signature"] = string(sig)
			})),
			seq: 321, reason: "",
		},
		"removed line":   {lines: withoutLine(lines, lineFor(137)), seq: 137, reason: ReasonSeqGap},
		"garbled line":   {lines: replaced(lines, lineFor(42), "{not json"), seq: 42, reason: ReasonMalformed},
		"unknown field":  {lines: replaced(lines, lineFor(43), editLine(t, lines[lineFor(43)], func(m map[string]any) { m["extra"] = 1 })), seq: 43, reason: ReasonMalformed},
		"keys line kept": {lines: replaced(lines, lineFor(1), editLine(t, lines[lineFor(1)], func(m map[string]any) { m["ts_unix_nano"] = 1 })), seq: 1, reason: ReasonEntryHash},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res := verifyExport(t, writeLines(t, c.lines), VerifyExportOptions{})
			if res.OK || res.FirstBadSeq != c.seq {
				t.Fatalf("VerifyExport = %+v, want a failure at seq %d", res, c.seq)
			}
			if c.reason != "" && res.Reason != c.reason {
				t.Errorf("reason = %q, want %q", res.Reason, c.reason)
			}
			if res.LastVerifiedSeq != c.seq-1 || res.Checked != int(c.seq-1) {
				t.Errorf("lastVerifiedSeq/checked = %d/%d, want %d", res.LastVerifiedSeq, res.Checked, c.seq-1)
			}
			if res.HeadSeq != 500 {
				t.Errorf("headSeq = %d, want the export's head 500 even after a failure", res.HeadSeq)
			}
		})
	}
}

func replaced(lines []string, i int, line string) []string {
	out := append([]string(nil), lines...)
	out[i] = line
	return out
}

// TestVerifyExportAnchor: removing the newest lines still verifies on its own
// but fails against an anchor at the old head; a wrong anchor hash fails at
// the anchor seq.
func TestVerifyExportAnchor(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 30)
	path := exportTo(t, s, ExportOptions{})
	head, headHash, _, err := s.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	anchor := &Anchor{Seq: head, Hash: headHash}
	if res := verifyExport(t, path, VerifyExportOptions{Anchor: anchor}); !res.OK {
		t.Fatalf("intact export against its head anchor = %+v", res)
	}

	lines := readLines(t, path)
	truncated := writeLines(t, lines[:len(lines)-3])
	if res := verifyExport(t, truncated, VerifyExportOptions{}); !res.OK || res.HeadSeq != head-3 {
		t.Fatalf("truncated export without anchor = %+v, want ok with head %d", res, head-3)
	}
	res := verifyExport(t, truncated, VerifyExportOptions{Anchor: anchor})
	if res.OK || res.FirstBadSeq != head-2 || res.Reason != ReasonAnchorMissing {
		t.Fatalf("truncated export against the anchor = %+v, want anchor_missing at %d", res, head-2)
	}

	// An anchor inside the export with the wrong hash.
	wrong := &Anchor{Seq: 10, Hash: bytes.Repeat([]byte{0}, 32)}
	if res := verifyExport(t, path, VerifyExportOptions{Anchor: wrong}); res.OK || res.FirstBadSeq != 10 || res.Reason != ReasonAnchorMismatch {
		t.Fatalf("wrong anchor = %+v, want anchor_mismatch at 10", res)
	}
	// And one with the right hash for a middle seq.
	var mid struct {
		EntryHash string `json:"entry_hash"`
	}
	if err := json.Unmarshal([]byte(lines[lineFor(10)]), &mid); err != nil {
		t.Fatal(err)
	}
	h, _ := hex.DecodeString(mid.EntryHash)
	if res := verifyExport(t, path, VerifyExportOptions{Anchor: &Anchor{Seq: 10, Hash: h}}); !res.OK {
		t.Fatalf("matching middle anchor = %+v", res)
	}
}

// TestExportAcrossSegment: an export spanning an audit.segment_start entry
// lists both public keys in its keys record and verifies; removing the
// segment_start line fails at its seq.
func TestExportAcrossSegment(t *testing.T) {
	s1, db := freshStore(t)
	record(t, s1, 5)
	s2 := newStore(t, db, newSigner(t))
	added, err := s2.StartSegment(context.Background(), s2.KeyID())
	if err != nil || !added {
		t.Fatalf("StartSegment = %v, %v", added, err)
	}
	segSeq, _, _, _ := s2.Head(context.Background())
	record(t, s2, 5)
	path := exportTo(t, s2, ExportOptions{})

	var hdr exportKeys
	lines := readLines(t, path)
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	want := []KeyInfo{
		{KeyID: s1.KeyID(), PublicKey: pubB64(s1.PublicKey()), FirstSeq: 1},
		{KeyID: s2.KeyID(), PublicKey: pubB64(s2.PublicKey()), FirstSeq: segSeq},
	}
	if hdr.Type != "keys" || hdr.Format != ExportFormat || len(hdr.Keys) != 2 || hdr.Keys[0] != want[0] || hdr.Keys[1] != want[1] {
		t.Fatalf("keys record = %+v, want %+v", hdr, want)
	}
	if res := verifyExport(t, path, VerifyExportOptions{}); !res.OK || res.Checked != int(segSeq)+5 {
		t.Fatalf("VerifyExport across the segment = %+v", res)
	}
	res := verifyExport(t, writeLines(t, withoutLine(lines, lineFor(segSeq))), VerifyExportOptions{})
	if res.OK || res.FirstBadSeq != segSeq {
		t.Fatalf("export without the segment_start line = %+v, want a failure at %d", res, segSeq)
	}
}

// TestVerifyExportKeysRecord: a keys record that does not match the keys the
// chain declares fails, even though every entry verifies.
func TestVerifyExportKeysRecord(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 3)
	lines := readLines(t, exportTo(t, s, ExportOptions{}))
	other := newSigner(t)
	forged := editLine(t, lines[0], func(m map[string]any) {
		m["keys"] = []map[string]any{{"keyId": s.KeyID(), "publicKey": pubB64(other.PubKey()), "firstSeq": 1}}
	})
	res := verifyExport(t, writeLines(t, replaced(lines, 0, forged)), VerifyExportOptions{})
	if res.OK || res.Reason != ReasonKeysRecord || res.FirstBadSeq != 1 {
		t.Fatalf("forged keys record = %+v, want keys_record at 1", res)
	}
	extra := editLine(t, lines[0], func(m map[string]any) {
		ks := m["keys"].([]any)
		m["keys"] = append(ks, map[string]any{"keyId": "ffff", "publicKey": pubB64(other.PubKey()), "firstSeq": 3})
	})
	if res := verifyExport(t, writeLines(t, replaced(lines, 0, extra)), VerifyExportOptions{}); res.OK || res.Reason != ReasonKeysRecord || res.FirstBadSeq != 3 {
		t.Fatalf("keys record with an undeclared key = %+v, want keys_record at 3", res)
	}
}

// TestVerifyExportBadHeader: a file that is missing, empty or does not start
// with a keys record is an error, not a Result.
func TestVerifyExportBadHeader(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 2)
	lines := readLines(t, exportTo(t, s, ExportOptions{}))
	for name, path := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "nope.jsonl"),
		"empty":     writeEmpty(t),
		"no keys":   writeLines(t, lines[1:]),
		"bad keys":  writeLines(t, replaced(lines, 0, `{"type":"keys","format":"other","keys":[]}`)),
		"not json":  writeLines(t, replaced(lines, 0, "xx")),
		"long line": writeLines(t, []string{strings.Repeat("x", maxExportLine+10)}),
	} {
		if _, err := VerifyExport(path, VerifyExportOptions{}); err == nil {
			t.Errorf("%s: VerifyExport err = nil, want an error", name)
		}
	}
	// An over-long entry line is a malformed row at its seq.
	long := writeLines(t, append(append([]string(nil), lines[:2]...), strings.Repeat("x", maxExportLine+10)))
	if res := verifyExport(t, long, VerifyExportOptions{}); res.OK || res.FirstBadSeq != 2 || res.Reason != ReasonMalformed {
		t.Errorf("over-long entry line = %+v, want malformed at 2", res)
	}
}

func writeEmpty(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExportNoIdentityByDefault: the export carries no side-table sub or
// email unless IncludeIdentity is set; with it, VerifyExport can also check
// actor_id against the HMAC key. The file is created 0600 and an existing
// file is never overwritten.
func TestExportNoIdentityByDefault(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 6)
	plain := exportTo(t, s, ExportOptions{})
	b, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"user-0", "user-1", "user0@example.com", "@example.com", `"actor"`, `"sub"`, `"email"`} {
		if bytes.Contains(b, []byte(v)) {
			t.Errorf("default export contains %q", v)
		}
	}
	fi, err := os.Stat(plain)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("export mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := s.ExportFile(context.Background(), plain, ExportOptions{}); err == nil {
		t.Error("ExportFile overwrote an existing file")
	}
	if after, _ := os.ReadFile(plain); !bytes.Equal(after, b) {
		t.Error("a refused export changed the existing file")
	}

	withID := exportTo(t, s, ExportOptions{IncludeIdentity: true})
	b, err = os.ReadFile(withID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"user-0", "user0@example.com"} {
		if !bytes.Contains(b, []byte(v)) {
			t.Errorf("identity export lacks %q", v)
		}
	}
	if res := verifyExport(t, withID, VerifyExportOptions{HMACKey: testHMACKey}); !res.OK {
		t.Fatalf("identity export with the HMAC key = %+v", res)
	}
	lines := readLines(t, withID)
	forged := editLine(t, lines[3], func(m map[string]any) { m["actor"] = map[string]any{"sub": "mallory", "email": ""} })
	if res := verifyExport(t, writeLines(t, replaced(lines, 3, forged)), VerifyExportOptions{HMACKey: testHMACKey}); res.OK || res.FirstBadSeq != 3 || res.Reason != ReasonActorID {
		t.Errorf("swapped identity = %+v, want actor_id at 3", res)
	}
}

// TestVerifyExportReadOnly: OpenReadOnly, Verify and Export leave the
// database file's bytes and mtime unchanged and need no key file.
func TestVerifyExportReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateDBFileName)
	db := openDB(t, path)
	record(t, newStore(t, db, newSigner(t)), 20)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}

	s, closeFn, err := OpenReadOnly(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	if s.KeyID() != "" || s.PublicKey() != nil {
		t.Error("the read-only store loaded a signing key")
	}
	if res, err := s.VerifyAll(context.Background(), VerifyOptions{}); err != nil || !res.OK || res.Checked != 21 {
		t.Fatalf("VerifyAll = %+v, %v", res, err)
	}
	out := filepath.Join(t.TempDir(), "x.jsonl")
	if _, err := s.ExportFile(context.Background(), out, ExportOptions{IncludeIdentity: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Record(context.Background(), input(1)); err == nil {
		t.Error("the read-only store recorded an entry")
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("database bytes changed")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(past) {
		t.Errorf("database mtime changed: %v -> %v", past, fi.ModTime())
	}
	for _, f := range []string{DefaultKeyFileName, HMACKeyFileName} {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists after a read-only run (stat err %v)", f, err)
		}
	}
}

// TestOpenReadOnlyNewerMigrations: a state dir a newer binary migrated (extra
// migration IDs of other features) still opens read-only and verifies; an
// unknown adminaudit/ migration (a chain layout this binary does not know) is
// refused. Neither changes the file.
func TestOpenReadOnlyNewerMigrations(t *testing.T) {
	for name, tc := range map[string]struct {
		id   string
		want bool
	}{
		"other feature": {id: "policystore/0001", want: true},
		"own namespace": {id: "adminaudit/0099", want: false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, StateDBFileName)
			newer := append(Migrations(), cpstate.Migration{ID: tc.id, SQL: "CREATE TABLE newer_feature (id INTEGER)"})
			db, err := cpstate.Open(context.Background(), path, newer)
			if err != nil {
				t.Fatal(err)
			}
			record(t, newStore(t, db, newSigner(t)), 3)
			_ = db.Close()
			before, _ := os.ReadFile(path)

			s, closeFn, err := OpenReadOnly(context.Background(), dir, Migrations())
			if !tc.want {
				if err == nil || !strings.Contains(err.Error(), tc.id) {
					t.Fatalf("OpenReadOnly = %v, want an error naming %s", err, tc.id)
				}
				return
			}
			if err != nil {
				t.Fatalf("OpenReadOnly on a newer file: %v", err)
			}
			defer func() { _ = closeFn() }()
			if res, err := s.VerifyAll(context.Background(), VerifyOptions{}); err != nil || !res.OK {
				t.Fatalf("VerifyAll = %+v, %v", res, err)
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Error("database bytes changed")
			}
		})
	}
}

// TestOpenReadOnlyErrors: no state dir, no file and no admin_audit table are
// errors, and none creates a file.
func TestOpenReadOnlyErrors(t *testing.T) {
	if _, _, err := OpenReadOnly(context.Background(), "", nil); err == nil {
		t.Error("empty state dir accepted")
	}
	dir := t.TempDir()
	if _, _, err := OpenReadOnly(context.Background(), dir, nil); err == nil {
		t.Error("missing database accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, StateDBFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Error("OpenReadOnly created the database")
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(dir, StateDBFileName), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, _, err := OpenReadOnly(context.Background(), dir, nil); err == nil || !strings.Contains(err.Error(), "no admin audit chain") {
		t.Errorf("database without admin_audit = %v, want the no-chain error", err)
	}
}

// TestVerifyAllResumesPastCap: VerifyAll checks the whole chain in capped
// calls and still stops at a tampered row.
func TestVerifyAllResumesPastCap(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 40)
	res, err := s.VerifyAll(context.Background(), VerifyOptions{MaxRows: 7})
	if err != nil || !res.OK || res.Checked != 41 || res.Partial {
		t.Fatalf("VerifyAll = %+v, %v", res, err)
	}
	exec(t, db, "UPDATE admin_audit SET target_ref = 'x' WHERE seq = 30")
	res, err = s.VerifyAll(context.Background(), VerifyOptions{MaxRows: 7})
	if err != nil || res.OK || res.FirstBadSeq != 30 || res.Checked != 29 {
		t.Fatalf("VerifyAll after tamper = %+v, %v", res, err)
	}
}

// TestVerifyTail: the bounded startup check covers the newest n rows (and so
// the head signature), not older ones, and works across a segment boundary.
func TestVerifyTail(t *testing.T) {
	s1, db := freshStore(t)
	record(t, s1, 10)
	s2 := newStore(t, db, newSigner(t))
	if _, err := s2.StartSegment(context.Background(), s2.KeyID()); err != nil {
		t.Fatal(err)
	}
	record(t, s2, 20) // head = 32
	if res, err := s2.VerifyTail(context.Background(), 1000); err != nil || !res.OK || res.Checked != 32 {
		t.Fatalf("VerifyTail(1000) = %+v, %v", res, err)
	}
	if res, err := s2.VerifyTail(context.Background(), 5); err != nil || !res.OK || res.Checked != 5 || res.LastVerifiedSeq != 32 {
		t.Fatalf("VerifyTail(5) = %+v, %v", res, err)
	}
	exec(t, db, "UPDATE admin_audit SET target_ref = 'x' WHERE seq = 3")
	if res, _ := s2.VerifyTail(context.Background(), 5); !res.OK {
		t.Errorf("a tamper outside the window failed the tail check: %+v", res)
	}
	exec(t, db, "UPDATE admin_audit SET signature = zeroblob(64) WHERE seq = 32")
	if res, _ := s2.VerifyTail(context.Background(), 5); res.OK || res.FirstBadSeq != 32 || res.Reason != ReasonSignature {
		t.Errorf("bad head signature = %+v, want signature at 32", res)
	}
	if _, err := s2.VerifyTail(context.Background(), 0); err == nil {
		t.Error("VerifyTail(0) accepted")
	}
}

// TestParseAnchor covers the --anchor value.
func TestParseAnchor(t *testing.T) {
	h := strings.Repeat("ab", 32)
	a, err := ParseAnchor("12:" + h)
	if err != nil || a.Seq != 12 || hex.EncodeToString(a.Hash) != h {
		t.Fatalf("ParseAnchor = %+v, %v", a, err)
	}
	for _, bad := range []string{"", "12", "x:" + h, "0:" + h, "-1:" + h, "12:zz", "12:abcd"} {
		if _, err := ParseAnchor(bad); err == nil {
			t.Errorf("ParseAnchor(%q) accepted", bad)
		}
	}
}

// TestResultReport hex-encodes the head hash.
func TestResultReport(t *testing.T) {
	r := Result{OK: false, Checked: 3, FirstBadSeq: 4, Reason: ReasonPrevHash, HeadSeq: 9, HeadHash: []byte{0xab, 0x01}, LastVerifiedSeq: 3}.Report()
	if r.HeadHash != "ab01" || r.FirstBadSeq != 4 || r.Reason != ReasonPrevHash || r.HeadSeq != 9 || r.LastVerifiedSeq != 3 || r.Checked != 3 {
		t.Fatalf("Report = %+v", r)
	}
}

// goldenExportStore is a chain with a fixed key, HMAC key and clock, so its
// export is byte-for-byte reproducible.
func goldenExportStore(t *testing.T) *Store {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	s := newStore(t, openDB(t, dbPath(t)), audit.NewSignerFromKey(ed25519.NewKeyFromSeed(seed)))
	record(t, s, 2)
	return s
}

// TestExportGolden pins the export wire format (warden.admin.export.v1): the
// keys record, field names and order, hex hashes and the identity field.
// Changing it breaks exports already held by auditors; bump ExportFormat.
func TestExportGolden(t *testing.T) {
	s := goldenExportStore(t)
	for name, o := range map[string]ExportOptions{
		"export_v1.golden.jsonl":          {},
		"export_v1_identity.golden.jsonl": {IncludeIdentity: true},
	} {
		var buf bytes.Buffer
		if _, err := s.Export(context.Background(), &buf, o); err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s: export =\n%s\nwant\n%s", name, buf.Bytes(), want)
		}
		if res := verifyExport(t, filepath.Join("testdata", name), VerifyExportOptions{HMACKey: testHMACKey}); !res.OK || res.Checked != 3 {
			t.Errorf("%s: VerifyExport = %+v", name, res)
		}
	}
}
