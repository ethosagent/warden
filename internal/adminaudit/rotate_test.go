package adminaudit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// seededDir opens a state dir whose database holds a chain of genesis + n
// entries signed by the state dir's own key, the way a control plane with
// admin audit enabled leaves it. The handle is left open (RotateKeyFile opens
// its own); Close is once-guarded, so the cleanup at test end is a no-op.
func seededDir(t *testing.T, n int) (dir, keyFile string, db *cpstate.DB) {
	t.Helper()
	dir = t.TempDir()
	keyFile = DefaultKeyPath(dir)
	db = openDB(t, filepath.Join(dir, StateDBFileName))
	s := mustOpenKeyed(t, db, keyFile, "")
	record(t, s, n)
	return dir, keyFile, db
}

// keyIDOf loads the key file at path and returns its key_id.
func keyIDOf(t *testing.T, path string) string {
	t.Helper()
	s, err := audit.LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("load key %s: %v", path, err)
	}
	return audit.KeyID(s.PubKey())
}

// appendRawKeyRotated appends an audit.key_rotated entry with caller-supplied
// details, skipping the checks RotateKey does (to build an invalid one).
func appendRawKeyRotated(t *testing.T, s *Store, details map[string]string) Entry {
	t.Helper()
	e, err := s.appendTx(context.Background(), func(headRow) (*Entry, *Actor, error) {
		return &Entry{
			ActorID: actorIDSystem, ActorRole: actorIDSystem, AuthMethod: AuthMethodSystem,
			Action: ActionKeyRotated, Target: "admin_audit", Outcome: OutcomeOK,
			Details: details,
		}, nil, nil
	})
	if err != nil {
		t.Fatalf("append key_rotated: %v", err)
	}
	return e
}

// TestKeyRotationChain: a 100-entry chain rotated with a signed
// audit.key_rotated entry and extended by 10 entries on the new key verifies
// end to end, the key lists name both keys, and a chain whose key_id changes
// without (or not straight after) a key_rotated entry fails at that seq.
func TestKeyRotationChain(t *testing.T) {
	ctx := context.Background()
	t.Run("rotated_chain_verifies", func(t *testing.T) {
		db, _, keyA, sA := seededChain(t, 99) // genesis + 99 = 100 rows
		idA := sA.KeyID()
		keyB, signerB := otherKey(t, keyA)
		idB := audit.KeyID(signerB.PubKey())
		hk, err := os.ReadFile(DefaultHMACKeyPath(keyA))
		if err != nil {
			t.Fatal(err)
		}

		kr, err := sA.RotateKey(ctx, signerB)
		if err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		seqA, _, _, err := sA.Head(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if kr.Seq != seqA || kr.Seq != 101 || kr.KeyID != idA || kr.Action != ActionKeyRotated {
			t.Fatalf("key_rotated = seq %d key %s action %s, want seq 101 signed by %s", kr.Seq, kr.KeyID, kr.Action, idA)
		}
		if kr.Details[detailOldKeyID] != idA || kr.Details[detailNewKeyID] != idB {
			t.Errorf("key_rotated details = %v, want old %s new %s", kr.Details, idA, idB)
		}
		if kr.Details[detailNewPublicKey] != pubB64(signerB.PubKey()) {
			t.Errorf("key_rotated declares %q, want B's public key", kr.Details[detailNewPublicKey])
		}

		// The control plane starts on the new key (the AAUD-01 check accepts
		// the take-up of the signed handover) and records on it.
		sB := mustOpenKeyed(t, db, keyB, "")
		record(t, sB, 10) // seqs 102..111
		if got := headKeyID(t, sB); got != idB {
			t.Fatalf("head key_id = %s, want %s", got, idB)
		}
		res, err := sB.VerifyAll(ctx, VerifyOptions{HMACKey: hk})
		if err != nil || !res.OK || res.Checked != 111 || res.LastVerifiedSeq != 111 {
			t.Fatalf("VerifyAll across the rotation = %+v, %v; want 111 checked", res, err)
		}
		// Resuming past the handover also verifies (the head before the window
		// is the key_rotated entry).
		if res := verify(t, sB, VerifyOptions{FromSeq: 105, HMACKey: hk}); !res.OK || res.Checked != 7 {
			t.Fatalf("resume past key_rotated = %+v, want ok with 7 checked", res)
		}

		keys, err := sB.PubKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := []KeyInfo{
			{KeyID: idA, PublicKey: pubB64(sA.signer.PubKey()), FirstSeq: 1},
			{KeyID: idB, PublicKey: pubB64(signerB.PubKey()), FirstSeq: 101},
		}
		if len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
			t.Fatalf("PubKeys = %+v, want %+v", keys, want)
		}

		// The export's keys record names both keys and verifies with no
		// database.
		out := filepath.Join(t.TempDir(), "export.jsonl")
		if _, err := sB.ExportFile(ctx, out, ExportOptions{}); err != nil {
			t.Fatalf("ExportFile: %v", err)
		}
		vr, err := VerifyExport(out, VerifyExportOptions{})
		if err != nil || !vr.OK || vr.Checked != 111 {
			t.Fatalf("VerifyExport = %+v, %v", vr, err)
		}

		// The handover is taken up: the old key can no longer open the chain.
		if _, err := openKeyed(t, db, keyA, ""); !errors.Is(err, ErrKeyIDMismatch) {
			t.Errorf("Open A after rotation = %v, want ErrKeyIDMismatch", err)
		}
	})

	t.Run("change_without_key_rotated", func(t *testing.T) {
		a, db := freshStore(t)
		record(t, a, 3)
		b := newStore(t, db, newSigner(t))
		e := appendUnchecked(t, b, input(1)) // seq 5, key B, no key_rotated
		res := verify(t, a, VerifyOptions{HMACKey: testHMACKey})
		if res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("Verify = %+v, want key_change at %d", res, e.Seq)
		}
	})

	t.Run("change_only_immediately_after_key_rotated", func(t *testing.T) {
		a, db := freshStore(t)
		record(t, a, 3) // seqs 1..4
		b := newStore(t, db, newSigner(t))
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		// The old key may not sign the take-up entry: the handover names B.
		e := appendUnchecked(t, a, input(9)) // seq 5, key A again
		res := verify(t, a, VerifyOptions{HMACKey: testHMACKey})
		if res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("Verify = %+v, want key_change at %d", res, e.Seq)
		}

		// From a clean chain: the new key takes over right after the handover,
		// and from then on the old key is done for good.
		a, db = freshStore(t)
		record(t, a, 2)
		b = newStore(t, db, newSigner(t))
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		record(t, b, 2)                     // seqs 4..5 on key B
		e = appendUnchecked(t, a, input(9)) // seq 6, key A
		res = verify(t, a, VerifyOptions{HMACKey: testHMACKey})
		if res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("Verify = %+v, want key_change at %d", res, e.Seq)
		}
	})

	t.Run("key_defining_entries_obey_the_pending_key", func(t *testing.T) {
		// The old key signs its handover and nothing after it: a segment_start
		// or a second key_rotated signed by the old key right after the
		// handover fails at that seq. The shapes a writer produces still
		// verify: a segment_start started with the key the handover named, and
		// a back-to-back rotation signed by the pending key.

		// A segment_start signed by the old key right after its handover.
		a, db := freshStore(t)
		record(t, a, 3)
		b := newStore(t, db, newSigner(t))
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		e := appendSegmentStart(t, a)
		res := verify(t, a, VerifyOptions{HMACKey: testHMACKey})
		if res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("segment_start by the old key after the handover = %+v, want key_change at %d", res, e.Seq)
		}

		// A second key_rotated signed by the old key right after its handover.
		a, db = freshStore(t)
		record(t, a, 3)
		b = newStore(t, db, newSigner(t))
		c := newSigner(t)
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		kr := appendRawKeyRotated(t, a, map[string]string{
			detailAlg:          algEd25519,
			detailOldKeyID:     a.KeyID(),
			detailNewKeyID:     audit.KeyID(c.PubKey()),
			detailNewPublicKey: pubB64(c.PubKey()),
		})
		res = verify(t, a, VerifyOptions{HMACKey: testHMACKey})
		if res.OK || res.FirstBadSeq != kr.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("second key_rotated by the old key = %+v, want key_change at %d", res, kr.Seq)
		}

		// A segment_start started with the key the handover named — the
		// take-up as --admin-audit-new-segment writes it — verifies, and the
		// chain stays on that key.
		a, db = freshStore(t)
		record(t, a, 3)
		b = newStore(t, db, newSigner(t))
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		appendSegmentStart(t, b)
		record(t, b, 2)
		if res := verify(t, a, VerifyOptions{HMACKey: testHMACKey}); !res.OK || res.Checked != 8 {
			t.Fatalf("segment_start by the pending key after the handover = %+v, want ok with 8 checked", res)
		}

		// A back-to-back rotation is signed by the pending key, and resuming
		// onto it (the window starts at the second handover) verifies too.
		a, db = freshStore(t)
		record(t, a, 2)
		b = newStore(t, db, newSigner(t))
		c = newSigner(t)
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		appendRawKeyRotated(t, b, map[string]string{
			detailAlg:          algEd25519,
			detailOldKeyID:     b.KeyID(),
			detailNewKeyID:     audit.KeyID(c.PubKey()),
			detailNewPublicKey: pubB64(c.PubKey()),
		})
		record(t, newStore(t, db, c), 1)
		if res := verify(t, a, VerifyOptions{HMACKey: testHMACKey}); !res.OK || res.Checked != 6 {
			t.Fatalf("back-to-back rotation signed by the pending key = %+v, want ok with 6 checked", res)
		}
		if res := verify(t, a, VerifyOptions{FromSeq: 5, HMACKey: testHMACKey}); !res.OK || res.Checked != 2 {
			t.Fatalf("resume onto a back-to-back rotation = %+v, want ok with 2 checked", res)
		}
	})

	t.Run("segment_start_recovers_a_lost_pending_key", func(t *testing.T) {
		// B's parked key is lost before the take-up: the recovery start with a
		// fresh key C (--admin-audit-new-segment=C) appends the segment_start
		// and takes the chain over, and the chain verifies on from there.
		db, _, keyA, sA := seededChain(t, 2)
		hk, err := os.ReadFile(DefaultHMACKeyPath(keyA))
		if err != nil {
			t.Fatal(err)
		}
		_, signerB := otherKey(t, keyA)
		keyC, signerC := otherKey(t, keyA)
		if _, err := sA.RotateKey(ctx, signerB); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		// Without the flag the third key is still refused, with the new
		// segment named as the way out.
		_, err = openKeyed(t, db, keyC, "")
		if !errors.Is(err, ErrKeyIDMismatch) || !strings.Contains(err.Error(), NewSegmentFlag) {
			t.Fatalf("Open C on a key_rotated head without the flag = %v, want ErrKeyIDMismatch naming %s", err, NewSegmentFlag)
		}
		// The recovery start with the flag: the segment_start is appended, the
		// head moves to C, and the chain verifies across the whole story.
		sC := mustOpenKeyed(t, db, keyC, audit.KeyID(signerC.PubKey()))
		if got := headKeyID(t, sC); got != audit.KeyID(signerC.PubKey()) {
			t.Fatalf("head key_id after the recovery start = %s, want %s", got, audit.KeyID(signerC.PubKey()))
		}
		record(t, sC, 1)
		if res := verify(t, sA, VerifyOptions{HMACKey: hk}); !res.OK {
			t.Fatalf("Verify across the recovery = %+v, want ok", res)
		}

		// The one shape the verifier still refuses: the old key signing a
		// segment_start right after its own handover.
		_, _, keyA2, sA2 := seededChain(t, 1)
		hk2, err := os.ReadFile(DefaultHMACKeyPath(keyA2))
		if err != nil {
			t.Fatal(err)
		}
		_, signerB2 := otherKey(t, keyA2)
		if _, err := sA2.RotateKey(ctx, signerB2); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		e := appendSegmentStart(t, sA2)
		if res := verify(t, sA2, VerifyOptions{HMACKey: hk2}); res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("segment_start by the old key after the handover = %+v, want key_change at %d", res, e.Seq)
		}
	})

	t.Run("resume_at_the_recovery_segment_start", func(t *testing.T) {
		// A key_rotated, its take-up, then the lost-key recovery: resuming
		// exactly at the segment_start primes pending from the row before the
		// window (the take-up), not from the handover.
		a, db := freshStore(t)
		record(t, a, 3) // seqs 1..4
		b := newStore(t, db, newSigner(t))
		if _, err := a.RotateKey(ctx, b.signer); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}
		record(t, b, 1) // seq 5, the take-up
		c := newStore(t, db, newSigner(t))
		seg := appendSegmentStart(t, c) // seq 6, the recovery
		record(t, c, 1)                 // seq 7
		if res := verify(t, a, VerifyOptions{FromSeq: seg.Seq, HMACKey: testHMACKey}); !res.OK || res.Checked != 2 {
			t.Fatalf("resume at the recovery segment_start = %+v, want ok with 2 checked", res)
		}
		if res := verify(t, a, VerifyOptions{HMACKey: testHMACKey}); !res.OK || res.Checked != 8 {
			t.Fatalf("full verify across the recovery = %+v, want ok with 8 checked", res)
		}
	})
}

// TestRotateKey covers the store method: the entry is signed by the old key
// and declares the new one; a read-only store, the loaded key itself, a head
// on another key and a pending handover are refused, and nothing is written
// on any refusal.
func TestRotateKey(t *testing.T) {
	ctx := context.Background()
	t.Run("refusals", func(t *testing.T) {
		s, db := freshStore(t)
		record(t, s, 1)
		ro := NewStore(db, Options{})
		if _, err := ro.RotateKey(ctx, newSigner(t)); err == nil {
			t.Error("RotateKey on a read-only store must fail")
		}
		if _, err := s.RotateKey(ctx, nil); err == nil {
			t.Error("RotateKey without a new signer must fail")
		}
		if _, err := s.RotateKey(ctx, s.signer); err == nil || !strings.Contains(err.Error(), s.KeyID()) {
			t.Errorf("RotateKey to the loaded key = %v, want an error naming %s", err, s.KeyID())
		}
		if n := rowCount(t, db, "admin_audit"); n != 2 {
			t.Errorf("rows = %d, want 2 (nothing written)", n)
		}
		other := newStore(t, db, newSigner(t))
		if _, err := other.RotateKey(ctx, newSigner(t)); !errors.Is(err, ErrKeyIDMismatch) {
			t.Errorf("RotateKey with the head on another key = %v, want ErrKeyIDMismatch", err)
		}
	})

	t.Run("pending_handover_refused", func(t *testing.T) {
		a, db := freshStore(t)
		record(t, a, 1)
		b := newSigner(t)
		if _, err := a.RotateKey(ctx, b); err != nil {
			t.Fatal(err)
		}
		c := newSigner(t)
		_, err := a.RotateKey(ctx, c)
		if !errors.Is(err, ErrKeyIDMismatch) || !strings.Contains(err.Error(), audit.KeyID(b.PubKey())) {
			t.Fatalf("second RotateKey before take-up = %v, want ErrKeyIDMismatch naming the pending key", err)
		}
		if n := rowCount(t, db, "admin_audit"); n != 3 {
			t.Errorf("rows = %d, want 3 (the pending handover only)", n)
		}
	})

	t.Run("behind_genesis", func(t *testing.T) {
		s, db := freshStore(t)
		next := newSigner(t)
		kr, err := s.RotateKey(ctx, next)
		if err != nil {
			t.Fatalf("RotateKey on a genesis-only chain: %v", err)
		}
		if kr.Seq != 2 || rowCount(t, db, "admin_audit") != 2 {
			t.Fatalf("key_rotated = seq %d with %d rows, want seq 2 behind the genesis", kr.Seq, rowCount(t, db, "admin_audit"))
		}
		if res := verify(t, s, VerifyOptions{HMACKey: testHMACKey}); !res.OK {
			t.Fatalf("Verify = %+v, want ok", res)
		}
	})

	t.Run("signature_by_old_key", func(t *testing.T) {
		a, _ := freshStore(t)
		record(t, a, 1)
		b := newSigner(t)
		kr, err := a.RotateKey(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		if !audit.VerifyBytes(a.signer.PubKey(), kr.EntryHash, kr.Signature) {
			t.Error("key_rotated is not signed by the old key")
		}
		if audit.VerifyBytes(b.PubKey(), kr.EntryHash, kr.Signature) {
			t.Error("key_rotated is signed by the new key")
		}
	})
}

// TestRotateKeyFile covers the offline command's operation on a state dir: it
// appends the signed handover, swaps the key files and keeps the retired one
// 0600; an interrupted rotation (the entry committed, the swap not done) is
// completed by the next run; without the new key's material it fails closed.
func TestRotateKeyFile(t *testing.T) {
	ctx := context.Background()
	t.Run("happy_path", func(t *testing.T) {
		dir, keyFile, db := seededDir(t, 3)
		oldID := keyIDOf(t, keyFile)
		res, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatalf("RotateKeyFile: %v", err)
		}
		if res.OldKeyID != oldID || res.NewKeyID == "" || res.NewKeyID == oldID || res.Seq != 5 || res.Recovered {
			t.Fatalf("result = %+v, want old %s, a new key_id, seq 5, not recovered", res, oldID)
		}
		if got := keyIDOf(t, keyFile); got != res.NewKeyID {
			t.Errorf("key file now holds %s, want %s", got, res.NewKeyID)
		}
		fi, err := os.Stat(res.RetiredPath)
		if err != nil {
			t.Fatalf("retired key: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("retired key mode = %o, want 600", fi.Mode().Perm())
		}
		if got := keyIDOf(t, res.RetiredPath); got != oldID {
			t.Errorf("retired key holds %s, want %s", got, oldID)
		}
		// The HMAC key is untouched by the rotation.
		if _, err := os.Stat(DefaultHMACKeyPath(keyFile)); err != nil {
			t.Errorf("HMAC key beside the key file: %v", err)
		}
		// No temp key file is left behind.
		if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
			t.Errorf("rotation left %v behind", left)
		}
		// The chain verifies, the startup check takes the handover up, and the
		// retired key is refused with the expected key_id named.
		if res := verify(t, mustOpenKeyed(t, db, keyFile, ""), VerifyOptions{}); !res.OK {
			t.Fatalf("Verify after rotation = %+v, want ok", res)
		}
		if _, err := openKeyed(t, db, keyFile, ""); err != nil {
			t.Errorf("Open on the new key after rotation = %v, want nil", err)
		}
		retired, err := os.ReadFile(res.RetiredPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, retired, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = openKeyed(t, db, keyFile, "")
		if !errors.Is(err, ErrKeyIDMismatch) || !strings.Contains(err.Error(), res.NewKeyID) {
			t.Errorf("Open on the retired key = %v, want ErrKeyIDMismatch naming %s", err, res.NewKeyID)
		}
	})

	t.Run("second_rotation", func(t *testing.T) {
		// The head stays a key_rotated entry until the next entry lands, so
		// the second run must read the key file, not the head, to see that the
		// first handover was taken up: it rotates again, B over A.
		dir, keyFile, db := seededDir(t, 2)
		idA := keyIDOf(t, keyFile)
		first, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatal(err)
		}
		second, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatalf("second RotateKeyFile = %v, want a second rotation", err)
		}
		if second.OldKeyID != first.NewKeyID || second.NewKeyID == idA || second.Recovered {
			t.Fatalf("second result = %+v, want %s rotated over", second, first.NewKeyID)
		}
		if got := keyIDOf(t, keyFile); got != second.NewKeyID {
			t.Errorf("key file now holds %s, want %s", got, second.NewKeyID)
		}
		if got := keyIDOf(t, second.RetiredPath); got != first.NewKeyID {
			t.Errorf("second retired key holds %s, want %s", got, first.NewKeyID)
		}
		if _, err := os.Stat(first.RetiredPath); err != nil {
			t.Errorf("the first retired key is gone: %v", err)
		}
		if res := verify(t, mustOpenKeyed(t, db, keyFile, ""), VerifyOptions{}); !res.OK {
			t.Fatalf("Verify after two rotations = %+v, want ok", res)
		}
	})

	t.Run("interrupted_handover_completed", func(t *testing.T) {
		// Simulate a crash after the handover entry committed but before the
		// key files were swapped: the new key sits at the rotation temp path.
		dir, keyFile, db := seededDir(t, 2)
		s := mustOpenKeyed(t, db, keyFile, "")
		seedPath := filepath.Join(t.TempDir(), "seed.key")
		seed, err := audit.LoadOrCreateSigner(seedPath)
		if err != nil {
			t.Fatal(err)
		}
		newID := audit.KeyID(seed.PubKey())
		if err := os.Rename(seedPath, rotatingKeyPath(keyFile, newID)); err != nil {
			t.Fatal(err)
		}
		kr, err := s.RotateKey(ctx, seed)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		res, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatalf("RotateKeyFile after an interrupted rotation: %v", err)
		}
		if !res.Recovered || res.NewKeyID != newID || res.OldKeyID != kr.KeyID || res.Seq != kr.Seq {
			t.Fatalf("result = %+v, want recovered with key %s at seq %d", res, newID, kr.Seq)
		}
		if got := keyIDOf(t, keyFile); got != newID {
			t.Errorf("key file now holds %s, want %s", got, newID)
		}
		if got := keyIDOf(t, res.RetiredPath); got != kr.KeyID {
			t.Errorf("retired key holds %s, want %s", got, kr.KeyID)
		}
		if _, err := openDir(t, dir, keyFile); err != nil {
			t.Errorf("Open on the recovered key = %v", err)
		}
	})

	t.Run("interrupted_without_new_key_material", func(t *testing.T) {
		dir, keyFile, db := seededDir(t, 2)
		s := mustOpenKeyed(t, db, keyFile, "")
		next := newSigner(t)
		if _, err := s.RotateKey(ctx, next); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		_, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err == nil || !strings.Contains(err.Error(), audit.KeyID(next.PubKey())) {
			t.Fatalf("RotateKeyFile with the new key lost = %v, want an error naming the pending key_id", err)
		}
	})

	t.Run("crash_between_the_renames_completed", func(t *testing.T) {
		// Simulate a crash between the two renames of the swap: the handover
		// entry is committed, the old key sits at the retired path, the key
		// file is gone and the new key is parked at the temp path. The next
		// run finishes the swap from the parked key and writes nothing.
		dir, keyFile, db := seededDir(t, 2)
		oldID := keyIDOf(t, keyFile)
		first, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatal(err)
		}
		parked, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		tmp := rotatingKeyPath(keyFile, first.NewKeyID)
		if err := os.WriteFile(tmp, parked, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(keyFile); err != nil {
			t.Fatal(err)
		}

		res, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatalf("RotateKeyFile after a crash between the renames: %v", err)
		}
		if !res.Recovered || res.NewKeyID != first.NewKeyID || res.OldKeyID != oldID || res.Seq != first.Seq || res.RetiredPath != first.RetiredPath {
			t.Fatalf("result = %+v, want the swap completed for %+v", res, first)
		}
		if got := keyIDOf(t, keyFile); got != first.NewKeyID {
			t.Errorf("key file now holds %s, want %s", got, first.NewKeyID)
		}
		if n := rowCount(t, db, "admin_audit"); n != 4 {
			t.Errorf("rows = %d, want 4 (the recovery writes nothing)", n)
		}
		if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
			t.Errorf("the recovery left %v behind", left)
		}
		if res := verify(t, mustOpenKeyed(t, db, keyFile, ""), VerifyOptions{}); !res.OK {
			t.Errorf("Verify after the recovery = %+v, want ok", res)
		}
	})

	t.Run("crash_between_the_renames_without_parked_key", func(t *testing.T) {
		// The same crash layout without the parked key: fail closed naming the
		// pending key_id, and never fabricate a key file.
		dir, keyFile, db := seededDir(t, 2)
		first, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(keyFile); err != nil {
			t.Fatal(err)
		}
		_, err = RotateKeyFile(ctx, dir, "", Migrations())
		if !errors.Is(err, ErrKeyIDMismatch) || !strings.Contains(err.Error(), first.NewKeyID) {
			t.Fatalf("RotateKeyFile with the parked key lost = %v, want ErrKeyIDMismatch naming %s", err, first.NewKeyID)
		}
		if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the refused run left a key file behind: %v", err)
		}
		if _, err := os.Stat(first.RetiredPath); err != nil {
			t.Errorf("the retired key is gone: %v", err)
		}
		if n := rowCount(t, db, "admin_audit"); n != 4 {
			t.Errorf("rows = %d, want 4 (nothing written)", n)
		}
	})

	t.Run("nothing_to_rotate", func(t *testing.T) {
		empty := t.TempDir()
		if _, err := RotateKeyFile(ctx, empty, "", Migrations()); err == nil || !strings.Contains(err.Error(), StateDBFileName) {
			t.Errorf("RotateKeyFile without a database = %v, want an error naming %s", err, StateDBFileName)
		}
		// A genesis-only chain rotates: the KR lands at seq 2.
		dir, keyFile, db := seededDir(t, 0)
		res, err := RotateKeyFile(ctx, dir, "", Migrations())
		if err != nil {
			t.Fatalf("RotateKeyFile on a genesis-only chain: %v", err)
		}
		if res.Seq != 2 {
			t.Errorf("key_rotated seq = %d, want 2", res.Seq)
		}
		if res := verify(t, mustOpenKeyed(t, db, keyFile, ""), VerifyOptions{}); !res.OK {
			t.Errorf("Verify = %+v, want ok", res)
		}
	})
}

// openDir opens a state dir's store the way the control plane does at startup
// (key check included), for assertions after RotateKeyFile has closed its own
// connection.
func openDir(t *testing.T, dir, keyFile string) (*Store, error) {
	t.Helper()
	db := openDB(t, filepath.Join(dir, StateDBFileName))
	return openKeyed(t, db, keyFile, "")
}

// TestKeyRotatedVerifyChecks: a key_rotated entry whose declaration does not
// parse fails Verify at its seq with declared_key, and PubKeys lists the row
// as the chain declares it rather than failing.
func TestKeyRotatedVerifyChecks(t *testing.T) {
	a, _ := freshStore(t)
	record(t, a, 1)
	b := newSigner(t)
	// A hand-built key_rotated whose new_key_id does not match the public key
	// it declares: hash-consistent, so Verify reaches the declaration check.
	kr := appendRawKeyRotated(t, a, map[string]string{
		detailAlg:          algEd25519,
		detailOldKeyID:     a.KeyID(),
		detailNewKeyID:     "zzzzzzzzzzzzzzzz",
		detailNewPublicKey: pubB64(b.PubKey()),
	})
	res := verify(t, a, VerifyOptions{})
	if res.OK || res.FirstBadSeq != kr.Seq || res.Reason != ReasonDeclaredKey {
		t.Fatalf("Verify = %+v, want declared_key at %d", res, kr.Seq)
	}
	keys, err := a.PubKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[1].KeyID != "zzzzzzzzzzzzzzzz" {
		t.Fatalf("PubKeys = %+v, want the (bad) declared key_id listed", keys)
	}
}

// TestRetiredKeyPath keeps the retired key beside the key file it came from,
// named for the key it holds, so retired files never collide.
func TestRetiredKeyPath(t *testing.T) {
	if got, want := RetiredKeyPath("/data/cp-audit.key", "abcd1234"), "/data/cp-audit.abcd1234.key.retired"; got != want {
		t.Errorf("RetiredKeyPath = %s, want %s", got, want)
	}
	if got, want := RetiredKeyPath("/secrets/audit", "abcd1234"), "/secrets/audit.abcd1234.key.retired"; got != want {
		t.Errorf("RetiredKeyPath = %s, want %s", got, want)
	}
}
