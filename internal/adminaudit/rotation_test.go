package adminaudit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

var fixedNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// keyDir returns a fresh directory and the default key path inside it.
func keyDir(t *testing.T) (dir, keyFile string) {
	t.Helper()
	dir = t.TempDir()
	return dir, filepath.Join(dir, DefaultKeyFileName)
}

// openKeyed opens the audit store on db with the key files at keyFile (and the
// HMAC key beside it) the way the control plane does at startup.
func openKeyed(t *testing.T, db *cpstate.DB, keyFile, newSegment string) (*Store, error) {
	t.Helper()
	return Open(context.Background(), db, OpenOptions{
		KeyFile:    keyFile,
		NewSegment: newSegment,
		Clock:      clocktest.NewFake(fixedNow),
	})
}

func mustOpenKeyed(t *testing.T, db *cpstate.DB, keyFile, newSegment string) *Store {
	t.Helper()
	s, err := openKeyed(t, db, keyFile, newSegment)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// seededChain opens a new DB, runs Open once with a fresh key in its own
// directory (writing genesis) and records n entries.
func seededChain(t *testing.T, n int) (db *cpstate.DB, path, keyFile string, s *Store) {
	t.Helper()
	path = dbPath(t)
	db = openDB(t, path)
	_, keyFile = keyDir(t)
	s = mustOpenKeyed(t, db, keyFile, "")
	record(t, s, n)
	return db, path, keyFile, s
}

// otherKey creates a new signing key in a new directory with a copy of the
// HMAC key that sits beside keyFile, and returns its path and signer.
func otherKey(t *testing.T, keyFile string) (string, *audit.Signer) {
	t.Helper()
	dir, path := keyDir(t)
	hk, err := os.ReadFile(DefaultHMACKeyPath(keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, HMACKeyFileName), hk, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := audit.LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, signer
}

func headKeyID(t *testing.T, s *Store) string {
	t.Helper()
	_, _, k, err := s.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestEnsureGenesisOnFirstOpen: the first enabled open creates both key files
// (0600) and writes the genesis row, so a state dir that ever ran with audit
// enabled always has rows; a second open writes nothing.
func TestEnsureGenesisOnFirstOpen(t *testing.T) {
	db := openDB(t, dbPath(t))
	dir, keyFile := keyDir(t)
	s := mustOpenKeyed(t, db, keyFile, "")
	if n := rowCount(t, db, "admin_audit"); n != 1 {
		t.Fatalf("rows after first open = %d, want 1 (genesis)", n)
	}
	for _, f := range []string{keyFile, filepath.Join(dir, HMACKeyFileName)} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatalf("key file not created: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", f, fi.Mode().Perm())
		}
	}
	if got := headKeyID(t, s); got != s.KeyID() {
		t.Errorf("genesis key_id = %s, want %s", got, s.KeyID())
	}
	mustOpenKeyed(t, db, keyFile, "")
	if n := rowCount(t, db, "admin_audit"); n != 1 {
		t.Errorf("rows after second open = %d, want 1", n)
	}
}

// TestCheckKeyMismatch: a chain with rows opened with a different signing key
// or a different HMAC key fails closed with an error naming the expected
// key_id and --admin-audit-key-file, and writes nothing.
func TestCheckKeyMismatch(t *testing.T) {
	t.Run("different signing key", func(t *testing.T) {
		db, _, keyFile, s := seededChain(t, 2)
		want := s.KeyID()
		other, _ := otherKey(t, keyFile)
		_, err := openKeyed(t, db, other, "")
		if !errors.Is(err, ErrKeyIDMismatch) {
			t.Fatalf("Open err = %v, want ErrKeyIDMismatch", err)
		}
		for _, w := range []string{want, KeyFileFlag} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error %q does not name %q", err, w)
			}
		}
		if n := rowCount(t, db, "admin_audit"); n != 3 {
			t.Errorf("rows = %d, want 3 (nothing written)", n)
		}
	})
	t.Run("different HMAC key", func(t *testing.T) {
		db, _, keyFile, s := seededChain(t, 1)
		if err := os.WriteFile(DefaultHMACKeyPath(keyFile), []byte("ffffffffffffffffffffffffffffffff"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := openKeyed(t, db, keyFile, "")
		if !errors.Is(err, ErrHMACKeyMismatch) {
			t.Fatalf("Open err = %v, want ErrHMACKeyMismatch", err)
		}
		for _, w := range []string{s.KeyID(), KeyFileFlag} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error %q does not name %q", err, w)
			}
		}
		if n := rowCount(t, db, "admin_audit"); n != 2 {
			t.Errorf("rows = %d, want 2 (nothing written)", n)
		}
	})
	t.Run("CheckKey on a store built with another key", func(t *testing.T) {
		db, _, _, s := seededChain(t, 1)
		other := NewStore(db, Options{Signer: newSigner(t), HMACKey: s.hmacKey})
		err := other.CheckKey(context.Background())
		if !errors.Is(err, ErrKeyIDMismatch) || !strings.Contains(err.Error(), s.KeyID()) {
			t.Fatalf("CheckKey err = %v, want ErrKeyIDMismatch naming %s", err, s.KeyID())
		}
	})
	t.Run("CheckKey on an empty chain", func(t *testing.T) {
		s, _ := freshStore(t)
		if err := s.CheckKey(context.Background()); err != nil {
			t.Errorf("CheckKey on an empty chain = %v, want nil", err)
		}
	})
}

// TestCheckKeyMissingFile: with rows present a missing key file (or HMAC key
// file) is an error naming the expected key_id and the flag, and neither file
// is ever created.
func TestCheckKeyMissingFile(t *testing.T) {
	t.Run("signing key", func(t *testing.T) {
		db, _, keyFile, s := seededChain(t, 1)
		if err := os.Remove(keyFile); err != nil {
			t.Fatal(err)
		}
		_, err := openKeyed(t, db, keyFile, "")
		if !errors.Is(err, ErrKeyFileMissing) {
			t.Fatalf("Open err = %v, want ErrKeyFileMissing", err)
		}
		for _, w := range []string{s.KeyID(), KeyFileFlag, "never replaced silently"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error %q does not name %q", err, w)
			}
		}
		if _, serr := os.Stat(keyFile); !errors.Is(serr, os.ErrNotExist) {
			t.Errorf("key file was re-created (stat err %v)", serr)
		}
		if n := rowCount(t, db, "admin_audit"); n != 2 {
			t.Errorf("rows = %d, want 2", n)
		}
	})
	t.Run("HMAC key", func(t *testing.T) {
		db, _, keyFile, s := seededChain(t, 1)
		hk := DefaultHMACKeyPath(keyFile)
		if err := os.Remove(hk); err != nil {
			t.Fatal(err)
		}
		_, err := openKeyed(t, db, keyFile, "")
		if !errors.Is(err, ErrKeyFileMissing) || !strings.Contains(err.Error(), s.KeyID()) {
			t.Fatalf("Open err = %v, want ErrKeyFileMissing naming %s", err, s.KeyID())
		}
		if _, serr := os.Stat(hk); !errors.Is(serr, os.ErrNotExist) {
			t.Errorf("HMAC key file was re-created (stat err %v)", serr)
		}
	})
	t.Run("CheckKey on a read-only store", func(t *testing.T) {
		db, _, _, _ := seededChain(t, 1)
		ro := NewStore(db, Options{})
		if err := ro.CheckKey(context.Background()); !errors.Is(err, ErrKeyFileMissing) {
			t.Errorf("CheckKey without a signer = %v, want ErrKeyFileMissing", err)
		}
	})
}

// TestNewSegmentRotation: head on key A, opened with key B and NewSegment = B's
// key_id, appends exactly one audit.segment_start row signed by B that links
// to A's head and names A; Verify is ok across both segments; the same flag
// on the next open writes nothing; a value that is not B's key_id fails.
func TestNewSegmentRotation(t *testing.T) {
	db, _, keyA, sA := seededChain(t, 2)
	idA := sA.KeyID()
	seqA, hashA, _, err := sA.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Key B in a new directory, with A's HMAC key beside it (the HMAC key does
	// not rotate with the signing key).
	keyB, signerB := otherKey(t, keyA)
	idB := audit.KeyID(signerB.PubKey())
	hk, err := os.ReadFile(DefaultHMACKeyPath(keyA))
	if err != nil {
		t.Fatal(err)
	}

	// Without the flag B is refused.
	if _, err := openKeyed(t, db, keyB, ""); !errors.Is(err, ErrKeyIDMismatch) {
		t.Fatalf("Open B without flag = %v, want ErrKeyIDMismatch", err)
	}
	// A flag value that is not B's key_id fails, even A's own.
	for _, bad := range []string{idA, "0000000000000000", "not-a-key-id"} {
		_, err := openKeyed(t, db, keyB, bad)
		if !errors.Is(err, ErrNewSegmentKeyID) || !strings.Contains(err.Error(), idB) {
			t.Errorf("Open B with --admin-audit-new-segment=%s = %v, want ErrNewSegmentKeyID naming %s", bad, err, idB)
		}
	}
	if n := rowCount(t, db, "admin_audit"); n != int(seqA) {
		t.Fatalf("rows after refused opens = %d, want %d", n, seqA)
	}

	sB := mustOpenKeyed(t, db, keyB, idB)
	if n := rowCount(t, db, "admin_audit"); n != int(seqA)+1 {
		t.Fatalf("rows after rotation = %d, want %d", n, seqA+1)
	}
	items, err := sB.List(context.Background(), Filter{Action: ActionSegmentStart}, 10, 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("segment_start rows = %d (%v), want 1", len(items), err)
	}
	e := items[0].Entry
	if e.Seq != seqA+1 || e.KeyID != idB || !equalHash(e.PrevHash, hashA) || e.AuthMethod != AuthMethodSystem {
		t.Errorf("segment_start = seq %d key %s auth %s, want seq %d key %s auth system linked to A's head",
			e.Seq, e.KeyID, e.AuthMethod, seqA+1, idB)
	}
	if e.Details["previous_key_id"] != idA || e.Details[detailPublicKey] != pubB64(signerB.PubKey()) {
		t.Errorf("segment_start details = %v, want previous_key_id %s and B's public key", e.Details, idA)
	}

	// Every later row carries B's key_id.
	rec, err := sB.Record(context.Background(), input(9))
	if err != nil || rec.KeyID != idB {
		t.Fatalf("Record after rotation = key %s, %v; want %s", rec.KeyID, err, idB)
	}
	if res := verify(t, sB, VerifyOptions{HMACKey: hk}); !res.OK {
		t.Fatalf("Verify across segments = %+v, want ok", res)
	}

	// The same flag again is a no-op; so is starting without it.
	before := rowCount(t, db, "admin_audit")
	mustOpenKeyed(t, db, keyB, idB)
	mustOpenKeyed(t, db, keyB, "")
	if n := rowCount(t, db, "admin_audit"); n != before {
		t.Errorf("rows after restart with the flag = %d, want %d", n, before)
	}
	// And A can no longer write.
	if _, err := openKeyed(t, db, keyA, ""); !errors.Is(err, ErrKeyIDMismatch) {
		t.Errorf("Open A after rotation = %v, want ErrKeyIDMismatch", err)
	}
}

// TestStartSegment covers the method directly: a key_id that is not the
// store's own fails, the head on the store's key is a no-op, and an empty
// chain gets only its genesis.
func TestStartSegment(t *testing.T) {
	ctx := context.Background()
	s, db := freshStore(t)
	if _, err := s.StartSegment(ctx, "deadbeefdeadbeef"); !errors.Is(err, ErrNewSegmentKeyID) {
		t.Errorf("StartSegment(other id) = %v, want ErrNewSegmentKeyID", err)
	}
	added, err := s.StartSegment(ctx, s.KeyID())
	if err != nil || added {
		t.Fatalf("StartSegment on empty chain = %v, %v; want false, nil", added, err)
	}
	if n := rowCount(t, db, "admin_audit"); n != 1 {
		t.Errorf("rows = %d, want 1 (genesis only)", n)
	}
	added, err = s.StartSegment(ctx, s.KeyID())
	if err != nil || added {
		t.Errorf("StartSegment with head on own key = %v, %v; want false, nil", added, err)
	}
	ro := NewStore(db, Options{})
	if _, err := ro.StartSegment(ctx, ""); err == nil {
		t.Error("StartSegment on a read-only store must fail")
	}
}

// TestOpenOptionsErrors: an empty key path is refused before any I/O.
func TestOpenOptionsErrors(t *testing.T) {
	db := openDB(t, dbPath(t))
	if _, err := Open(context.Background(), db, OpenOptions{}); err == nil {
		t.Error("Open with no key file must fail")
	}
	if n := rowCount(t, db, "admin_audit"); n != 0 {
		t.Errorf("rows = %d, want 0", n)
	}
}
