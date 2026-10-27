package adminaudit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// StateHashPrefix starts every state hash StateHash returns.
const StateHashPrefix = "hmac-sha256:"

// stateHashLabel domain-separates state hashes from actor ids, which use the
// same HMAC key.
const stateHashLabel = "warden.admin.v1/state"

// StateHash returns "hmac-sha256:<hex>" of HMAC-SHA256 over the label, target
// and data, keyed with the CP-local HMAC key. Keying it means a hash of
// low-entropy config (a short allowlist, a boolean setting) cannot be matched
// offline by guessing the config. The result fits before_hash/after_hash.
func (s *Store) StateHash(target string, data []byte) (string, error) {
	if len(s.hmacKey) == 0 {
		return "", fmt.Errorf("adminaudit: store has no HMAC key; it cannot hash state")
	}
	m := hmac.New(sha256.New, s.hmacKey)
	m.Write([]byte(stateHashLabel))
	m.Write([]byte{0})
	m.Write([]byte(target))
	m.Write([]byte{0})
	m.Write(data)
	return StateHashPrefix + hex.EncodeToString(m.Sum(nil)), nil
}

// Probe reports whether an append could run now: the store can sign and the
// database grants the write lock (BEGIN IMMEDIATE, then ROLLBACK). It writes
// nothing. The middleware uses it to clear a degraded flag.
func (s *Store) Probe(ctx context.Context) error {
	if err := s.canWrite(); err != nil {
		return err
	}
	conn, err := s.db.SQL().Conn(ctx)
	if err != nil {
		return fmt.Errorf("adminaudit: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("adminaudit: begin: %w", err)
	}
	rollback(conn)
	return nil
}
