package adminaudit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// DefaultKeyFileName is the audit signing key's file name inside the state dir.
const DefaultKeyFileName = "cp-audit.key"

// KeyFileFlag is the flag that points the control plane (and the offline CLIs)
// at the signing key. Key errors name it so the operator knows what to fix.
const KeyFileFlag = "--admin-audit-key-file"

// NewSegmentFlag is the flag that starts a new chain segment for a new key.
const NewSegmentFlag = "--admin-audit-new-segment"

// detailPreviousKeyID is the segment_start detail naming the key it replaces.
const detailPreviousKeyID = "previous_key_id"

var (
	// ErrKeyFileMissing is returned when the chain has rows but the signing key
	// file (or the HMAC key file beside it) is absent. A missing key is never
	// replaced silently: a new key would fork the chain.
	ErrKeyFileMissing = errors.New("adminaudit: key file missing")
	// ErrHMACKeyMismatch is returned when the HMAC key does not reproduce the
	// genesis entry's actor_key_check.
	ErrHMACKeyMismatch = errors.New("adminaudit: HMAC key does not match the chain")
	// ErrNewSegmentKeyID is returned when a requested new segment's key_id is
	// not the loaded key's key_id.
	ErrNewSegmentKeyID = errors.New("adminaudit: new segment key_id does not match the loaded key")
)

// PublicKey returns the store signer's public key (nil without a signer).
func (s *Store) PublicKey() ed25519.PublicKey {
	if s.signer == nil {
		return nil
	}
	return s.signer.PubKey()
}

// DefaultKeyPath returns <stateDir>/cp-audit.key.
func DefaultKeyPath(stateDir string) string { return filepath.Join(stateDir, DefaultKeyFileName) }

// CheckKey is the startup key check. With no rows it passes. Otherwise the
// store must hold a signer whose key_id is the chain head's and an HMAC key
// that reproduces the genesis actor_key_check; any other state fails closed
// with an error naming the expected key_id and KeyFileFlag.
func (s *Store) CheckKey(ctx context.Context) error {
	seq, _, headKey, err := s.Head(ctx)
	if err != nil || seq == 0 {
		return err
	}
	if s.signer == nil || len(s.hmacKey) == 0 {
		return missingKeyErr(headKey, "the signing or HMAC key")
	}
	if err := s.checkHMAC(ctx, headKey); err != nil {
		return err
	}
	if headKey != s.keyID {
		return keyMismatchErr(seq, headKey, s.keyID)
	}
	return nil
}

func missingKeyErr(headKey, what string) error {
	return fmt.Errorf("%w: the admin audit chain has rows signed by key_id %s but %s is missing; "+
		"restore the key file for key_id %s and point %s at it (a missing key file is never replaced silently)",
		ErrKeyFileMissing, headKey, what, headKey, KeyFileFlag)
}

func keyMismatchErr(seq int64, headKey, loaded string) error {
	return fmt.Errorf("%w: the chain head (seq %d) is signed by key_id %s but the loaded key is key_id %s; "+
		"point %s at the key for key_id %s, or start a new segment for this key with %s=%s",
		ErrKeyIDMismatch, seq, headKey, loaded, KeyFileFlag, headKey, NewSegmentFlag, loaded)
}

// checkHMAC compares the HMAC key's check value with the genesis entry's.
func (s *Store) checkHMAC(ctx context.Context, headKey string) error {
	var dj string
	err := s.db.SQL().QueryRowContext(ctx,
		"SELECT details_json FROM admin_audit WHERE seq = 1 AND action = ?", ActionGenesis).Scan(&dj)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("adminaudit: the chain has no genesis entry at seq 1; run admin-audit verify")
	}
	if err != nil {
		return fmt.Errorf("adminaudit: read genesis: %w", err)
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(dj), &d); err != nil {
		return fmt.Errorf("adminaudit: genesis entry has malformed details")
	}
	if d[detailActorKeyCheck] != actorKeyCheck(s.hmacKey) {
		return fmt.Errorf("%w: the HMAC key file %s beside %s is not the key the chain (head key_id %s) was started with; "+
			"restore the original %s next to the key file for key_id %s",
			ErrHMACKeyMismatch, HMACKeyFileName, KeyFileFlag, headKey, HMACKeyFileName, headKey)
	}
	return nil
}

// EnsureGenesis writes the genesis entry when the chain is empty, so a state
// dir that ever ran with audit enabled always has rows. It is a no-op
// otherwise.
func (s *Store) EnsureGenesis(ctx context.Context) error {
	if err := s.canWrite(); err != nil {
		return err
	}
	_, err := s.appendTx(ctx, func(headRow) (*Entry, *Actor, error) { return nil, nil, nil })
	return err
}

// StartSegment is the documented manual key rotation. newKeyID must be the
// store's own key_id. When the head is on another key it appends one
// audit.segment_start entry signed by the store's key, linked to the old head
// and declaring the new public key and the previous key_id, in one BEGIN
// IMMEDIATE transaction, and reports true. When the head is already on this
// key (or the chain was empty and got its genesis) it writes nothing more, so
// a restart with the same flag can never rotate twice.
func (s *Store) StartSegment(ctx context.Context, newKeyID string) (bool, error) {
	if err := s.canWrite(); err != nil {
		return false, err
	}
	if newKeyID != s.keyID {
		return false, fmt.Errorf("%w: %s=%s but the key at %s has key_id %s",
			ErrNewSegmentKeyID, NewSegmentFlag, newKeyID, KeyFileFlag, s.keyID)
	}
	added := false
	_, err := s.appendTx(ctx, func(head headRow) (*Entry, *Actor, error) {
		if head.KeyID == s.keyID {
			return nil, nil, nil
		}
		added = true
		return &Entry{
			ActorID: actorIDSystem, ActorRole: actorIDSystem, AuthMethod: AuthMethodSystem,
			Action: ActionSegmentStart, Target: "admin_audit", Outcome: OutcomeOK,
			Details: map[string]string{
				detailAlg:           algEd25519,
				detailPublicKey:     base64.StdEncoding.EncodeToString(s.signer.PubKey()),
				detailPreviousKeyID: head.KeyID,
			},
		}, nil, nil
	})
	if err != nil {
		return false, err
	}
	return added, nil
}

// OpenOptions configures Open.
type OpenOptions struct {
	// KeyFile is the Ed25519 signing key (PKCS#8 PEM). Required.
	KeyFile string
	// HMACKeyFile defaults to cp-audit-hmac.key beside KeyFile.
	HMACKeyFile string
	// NewSegment, when set, must equal the loaded key's key_id; a head on
	// another key then gets an audit.segment_start entry.
	NewSegment string
	Clock      clock.Clock
	// Logger receives the store's own failures (Options.Logger).
	Logger *slog.Logger
}

// Open builds a writing Store on db and runs the startup checks, in order:
// with rows present neither key file may be missing (they are never created
// then); the keys are loaded (created only on an empty chain); a NewSegment
// value must be the loaded key's key_id; the HMAC key must match genesis; a
// head on another key is refused unless NewSegment starts a segment; finally
// an empty chain gets its genesis entry. Nothing is written on any failure.
func Open(ctx context.Context, db *cpstate.DB, o OpenOptions) (*Store, error) {
	if o.KeyFile == "" {
		return nil, errors.New("adminaudit: no signing key file path")
	}
	hmacPath := o.HMACKeyFile
	if hmacPath == "" {
		hmacPath = DefaultHMACKeyPath(o.KeyFile)
	}
	seq, _, headKey, err := NewStore(db, Options{}).Head(ctx)
	if err != nil {
		return nil, err
	}
	if seq > 0 {
		for _, f := range []string{o.KeyFile, hmacPath} {
			if _, err := os.Stat(f); errors.Is(err, os.ErrNotExist) {
				return nil, missingKeyErr(headKey, fmt.Sprintf("key file %q", f))
			} else if err != nil {
				return nil, fmt.Errorf("adminaudit: stat key file %q: %w", f, err)
			}
		}
	}
	signer, err := audit.LoadOrCreateSigner(o.KeyFile)
	if err != nil {
		return nil, err
	}
	hk, err := LoadOrCreateHMACKey(hmacPath)
	if err != nil {
		return nil, err
	}
	s := NewStore(db, Options{Signer: signer, HMACKey: hk, Clock: o.Clock, Logger: o.Logger})
	if o.NewSegment != "" {
		if o.NewSegment != s.keyID {
			return nil, fmt.Errorf("%w: %s=%s but the key at %s has key_id %s",
				ErrNewSegmentKeyID, NewSegmentFlag, o.NewSegment, KeyFileFlag, s.keyID)
		}
		if seq > 0 {
			if err := s.checkHMAC(ctx, headKey); err != nil {
				return nil, err
			}
		}
		if _, err := s.StartSegment(ctx, o.NewSegment); err != nil {
			return nil, err
		}
	}
	if err := s.CheckKey(ctx); err != nil {
		return nil, err
	}
	if err := s.EnsureGenesis(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
