package adminaudit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Details keys the audit.key_rotated entry carries (W-P2-KEYS-06). It is
// signed by the OLD key and declares the NEW one, so the chain itself proves
// the handover: the next entry must already be signed by the new key.
const (
	detailOldKeyID     = "old_key_id"
	detailNewKeyID     = "new_key_id"
	detailNewPublicKey = "new_public_key"
)

// ErrControlPlaneRunning wraps cpstate.ErrLocked for the offline rotation:
// the state dir lock is held, so the control plane is running.
var ErrControlPlaneRunning = errors.New("adminaudit: control plane is running")

// keyRotation is the handover a key_rotated entry declares.
type keyRotation struct {
	oldID string
	newID string
}

// rotationChangeOf parses the key change a key_rotated entry declares. The
// entry is signed by the old key (keyID), so old_key_id must name it, and the
// new public key must be an Ed25519 key whose key_id is the declared
// new_key_id.
func rotationChangeOf(keyID string, d map[string]string) (keyRotation, ed25519.PublicKey, bool) {
	if d[detailAlg] != "" && d[detailAlg] != algEd25519 {
		return keyRotation{}, nil, false
	}
	rot := keyRotation{oldID: d[detailOldKeyID], newID: d[detailNewKeyID]}
	if rot.oldID != keyID || rot.newID == "" {
		return keyRotation{}, nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(d[detailNewPublicKey])
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return keyRotation{}, nil, false
	}
	pub := ed25519.PublicKey(raw)
	if audit.KeyID(pub) != rot.newID {
		return keyRotation{}, nil, false
	}
	return rot, pub, true
}

// keyInfoOf projects a key-defining entry into the KeyInfo the key lists
// show: the key the entry declares, first used at the entry's seq (for a
// key_rotated entry, the new key in its details). It is validation-free:
// PubKeys and the export's keys record list what the chain declares; Verify
// is what checks those declarations.
func keyInfoOf(e *Entry) KeyInfo {
	if e.Action == ActionKeyRotated {
		return KeyInfo{KeyID: e.Details[detailNewKeyID], PublicKey: e.Details[detailNewPublicKey], FirstSeq: e.Seq}
	}
	return KeyInfo{KeyID: e.KeyID, PublicKey: e.Details[detailPublicKey], FirstSeq: e.Seq}
}

// appendKeyErr is the key discipline every writer enforces against the chain
// head: a chain whose head was signed by another key is never extended,
// unless that head is a key_rotated entry handing the chain to the loaded key
// (the take-up of a signed rotation).
func appendKeyErr(head headRow, loaded string) error {
	if head.rotate != nil {
		if head.rotate.newID == loaded {
			return nil
		}
		if loaded == head.rotate.oldID {
			return fmt.Errorf("%w: the chain head (seq %d) is a key rotation naming key_id %s but the loaded key is key_id %s; "+
				"point %s at the key for key_id %s (restore the retired key for key_id %s to finish an interrupted rotation)",
				ErrKeyIDMismatch, head.Seq, head.rotate.newID, loaded, KeyFileFlag, head.rotate.newID, head.rotate.oldID)
		}
		// A third key: the handover's take-up key may be lost. The recovery is
		// a new segment started with it (Open appends the audit.segment_start
		// before this check would matter).
		return fmt.Errorf("%w: the chain head (seq %d) is a key rotation naming key_id %s but the loaded key is key_id %s; "+
			"point %s at the key for key_id %s, or start a new segment for the key you hold with %s=%s",
			ErrKeyIDMismatch, head.Seq, head.rotate.newID, loaded, KeyFileFlag, head.rotate.newID, NewSegmentFlag, loaded)
	}
	if head.KeyID == loaded {
		return nil
	}
	return fmt.Errorf("%w: the chain head (seq %d) is signed by key_id %s but the loaded key is key_id %s; "+
		"point %s at the key for key_id %s, or start a new segment for the new key with %s=%s",
		ErrKeyIDMismatch, head.Seq, head.KeyID, loaded, KeyFileFlag, head.KeyID, NewSegmentFlag, loaded)
}

// RotateKey appends one audit.key_rotated entry handing the chain over to
// next: signed by the store's own (old) key, linked to the current head, and
// carrying old_key_id, new_key_id and the new public key in its details, all
// in one BEGIN IMMEDIATE transaction. It never touches key files, and it
// refuses to hand the chain to the loaded key itself. The key discipline
// applies to the head: it must be on the store's key and must not be a
// handover to another key still waiting to be taken up.
func (s *Store) RotateKey(ctx context.Context, next *audit.Signer) (Entry, error) {
	if s.signer == nil {
		return Entry{}, errors.New("adminaudit: store has no signer; it is read-only")
	}
	if next == nil {
		return Entry{}, errors.New("adminaudit: no new signing key to rotate to")
	}
	newID := audit.KeyID(next.PubKey())
	if newID == s.keyID {
		return Entry{}, fmt.Errorf("adminaudit: refusing to rotate key_id %s to itself; generate a new key", s.keyID)
	}
	return s.appendTx(ctx, func(head headRow) (*Entry, *Actor, error) {
		if err := appendKeyErr(head, s.keyID); err != nil {
			return nil, nil, err
		}
		return &Entry{
			ActorID: actorIDSystem, ActorRole: actorIDSystem, AuthMethod: AuthMethodSystem,
			Action: ActionKeyRotated, Target: "admin_audit", Outcome: OutcomeOK,
			Details: map[string]string{
				detailAlg:          algEd25519,
				detailOldKeyID:     s.keyID,
				detailNewKeyID:     newID,
				detailNewPublicKey: base64.StdEncoding.EncodeToString(next.PubKey()),
			},
		}, nil, nil
	})
}

// RetiredKeyPath is where RotateKeyFile keeps the retired signing key: beside
// the key file, named for the key it holds, so retired files never collide
// and a restored older backup set can still be pointed at its key.
func RetiredKeyPath(keyFile, keyID string) string {
	dir, base := filepath.Split(keyFile)
	return filepath.Join(dir, strings.TrimSuffix(base, ".key")+"."+keyID+".key.retired")
}

// rotatingKeyPath is where an offline rotation parks the new key while it
// writes the handover entry: beside the key file, named for the key it holds,
// so a run interrupted between the entry and the file swap can be completed
// by re-running the command.
func rotatingKeyPath(keyFile, newKeyID string) string {
	dir, base := filepath.Split(keyFile)
	return filepath.Join(dir, base+".rotate-"+newKeyID+".tmp")
}

// RotateKeyResult is what an offline rotation reports (and the rotate-key
// command prints).
type RotateKeyResult struct {
	OldKeyID    string `json:"oldKeyID"`
	NewKeyID    string `json:"newKeyID"`
	Seq         int64  `json:"seq"`         // seq of the audit.key_rotated entry
	RetiredPath string `json:"retiredPath"` // where the old signing key was kept
	Recovered   bool   `json:"recovered"`   // an interrupted rotation was completed
}

// RotateKeyFile is the offline key rotation on a state dir (W-P2-KEYS-06): it
// takes the state-dir lock (a running control plane is refused with
// ErrControlPlaneRunning), appends the signed audit.key_rotated entry, then
// renames the new key over the key file and keeps the old one as
// <key file>.<old_key_id>.key.retired (0600) so an older backup set still has
// its key. The HMAC key beside the key file is untouched: it does not rotate
// with the signing key.
//
// The entry and the key files cannot be swapped atomically, so the new key is
// first written to a deterministic path beside the key file; if a run dies
// between the committed entry and the swap, the head is a key_rotated entry
// naming the new key while the key file still holds the old one, and the next
// run detects that, loads the parked key and completes the swap (Recovered).
// A run that dies between the two renames of the swap itself leaves no key
// file at all (the old key is already retired); the parked key completes that
// state the same way. Once the handover has been taken up (the key file holds
// the new key) the same command simply rotates again.
func RotateKeyFile(ctx context.Context, stateDir, keyFile string, migs []cpstate.Migration) (res RotateKeyResult, err error) {
	release, err := cpstate.AcquireDirLock(stateDir)
	if errors.Is(err, cpstate.ErrLocked) {
		return RotateKeyResult{}, fmt.Errorf("%w: %s is %w; stop it before rotating the admin audit key",
			ErrControlPlaneRunning, stateDir, cpstate.ErrLocked)
	}
	if err != nil {
		return RotateKeyResult{}, err
	}
	defer func() { _ = release() }()

	dbPath := filepath.Join(stateDir, StateDBFileName)
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return RotateKeyResult{}, fmt.Errorf("adminaudit: no %s in %s; nothing to rotate", StateDBFileName, stateDir)
	}
	db, err := cpstate.Open(ctx, dbPath, migs)
	if err != nil {
		return RotateKeyResult{}, fmt.Errorf("adminaudit: open %s: %w", dbPath, err)
	}
	defer func() { _ = db.Close() }()

	head, found, err := readHeadFrom(ctx, db.SQL())
	if err != nil {
		return RotateKeyResult{}, err
	}
	if !found {
		return RotateKeyResult{}, errors.New("adminaudit: the admin audit chain is empty; nothing to rotate")
	}
	if head.Action == ActionKeyRotated && head.rotate == nil {
		return RotateKeyResult{}, fmt.Errorf("adminaudit: the chain head (seq %d) is an audit.key_rotated entry that does not parse; run admin-audit verify", head.Seq)
	}
	if keyFile == "" {
		keyFile = DefaultKeyPath(stateDir)
	}

	if head.rotate != nil {
		if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
			// A crash between the two renames of the swap: the handover entry
			// is committed, the old key is already at the retired path and the
			// key file is gone. The parked key finishes the swap.
			return completeRotation(ctx, keyFile, head)
		}
	}

	loaded, err := loadKeyFile(keyFile)
	if err != nil {
		return RotateKeyResult{}, err
	}
	loadedID := audit.KeyID(loaded.PubKey())

	if head.rotate != nil && loadedID != head.rotate.newID {
		// The head hands the chain to another key and the key file does not
		// hold it: either the swap is still pending (the file holds the old
		// key) or the file was changed outside a rotation.
		if loadedID != head.rotate.oldID {
			return RotateKeyResult{}, fmt.Errorf("%w: the chain head (seq %d) is a key rotation naming key_id %s but the key at %s has key_id %s",
				ErrKeyIDMismatch, head.Seq, head.rotate.newID, keyFile, loadedID)
		}
		return completeRotation(ctx, keyFile, head)
	}
	if head.rotate == nil && loadedID != head.KeyID {
		return RotateKeyResult{}, appendKeyErr(head, loadedID)
	}

	next, nextPath, err := createNextKey(keyFile)
	if err != nil {
		return RotateKeyResult{}, err
	}
	kr, err := NewStore(db, Options{Signer: loaded}).RotateKey(ctx, next)
	if err != nil {
		_ = os.Remove(nextPath)
		return RotateKeyResult{}, err
	}
	res = RotateKeyResult{
		OldKeyID: kr.KeyID,
		NewKeyID: audit.KeyID(next.PubKey()),
		Seq:      kr.Seq,
	}
	retired := RetiredKeyPath(keyFile, res.OldKeyID)
	if err := swapKeys(keyFile, nextPath, retired); err != nil {
		return RotateKeyResult{}, err
	}
	res.RetiredPath = retired
	return res, nil
}

// completeRotation finishes an interrupted rotation: the handover entry is
// committed and the new key is parked at its temp path, but the file swap
// never finished — either not started (the key file still holds the old key)
// or left half done by a crash between the two renames (the key file is gone,
// the old key already retired). The parked key must parse to the key the head
// names.
func completeRotation(ctx context.Context, keyFile string, head headRow) (RotateKeyResult, error) {
	tmp := rotatingKeyPath(keyFile, head.rotate.newID)
	next, err := loadKeyFile(tmp)
	if err != nil {
		return RotateKeyResult{}, fmt.Errorf("%w: the chain head (seq %d) is a key rotation naming key_id %s whose key file was not swapped in; restore it at %s to finish the rotation",
			ErrKeyIDMismatch, head.Seq, head.rotate.newID, tmp)
	}
	if got := audit.KeyID(next.PubKey()); got != head.rotate.newID {
		return RotateKeyResult{}, fmt.Errorf("%w: the key at %s has key_id %s but the chain head (seq %d) names key_id %s",
			ErrKeyIDMismatch, tmp, got, head.Seq, head.rotate.newID)
	}
	retired := RetiredKeyPath(keyFile, head.rotate.oldID)
	if err := swapKeys(keyFile, tmp, retired); err != nil {
		return RotateKeyResult{}, err
	}
	return RotateKeyResult{
		OldKeyID:    head.rotate.oldID,
		NewKeyID:    head.rotate.newID,
		Seq:         head.Seq,
		RetiredPath: retired,
		Recovered:   true,
	}, nil
}

// loadKeyFile loads an existing signing key; a missing file is an error, so
// rotation never creates key material as a side effect of a typo'd path.
func loadKeyFile(path string) (*audit.Signer, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: no key file at %s; point %s at the chain's current signing key",
			ErrKeyFileMissing, path, KeyFileFlag)
	} else if err != nil {
		return nil, fmt.Errorf("adminaudit: stat key file %q: %w", path, err)
	}
	return audit.LoadOrCreateSigner(path)
}

// createNextKey generates the new signing key at the rotation temp path
// beside the key file, replacing a stale temp from an abandoned attempt (its
// key was never committed to the chain, so it is worthless).
func createNextKey(keyFile string) (next *audit.Signer, path string, err error) {
	seedDir, err := os.MkdirTemp(filepath.Dir(keyFile), ".cp-audit-rotate-")
	if err != nil {
		return nil, "", fmt.Errorf("adminaudit: create rotation temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(seedDir) }()
	seed, err := audit.LoadOrCreateSigner(filepath.Join(seedDir, "seed.key"))
	if err != nil {
		return nil, "", err
	}
	path = rotatingKeyPath(keyFile, audit.KeyID(seed.PubKey()))
	if err := os.Rename(filepath.Join(seedDir, "seed.key"), path); err != nil {
		return nil, "", fmt.Errorf("adminaudit: park the new key at %s: %w", path, err)
	}
	return seed, path, nil
}

// swapKeys retires the old key file and moves the new key into place, both
// renames on one directory so each is atomic. A missing key file is the crash
// between the two renames (the old key is already at the retired path) and
// only completes the recovery; on a fresh run the key file was just loaded,
// so it always exists.
func swapKeys(keyFile, nextPath, retired string) error {
	if err := os.Rename(keyFile, retired); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("adminaudit: retire the old key at %s: %w", retired, err)
	}
	if err := os.Rename(nextPath, keyFile); err != nil {
		return fmt.Errorf("adminaudit: move the new key to %s: %w", keyFile, err)
	}
	return nil
}
