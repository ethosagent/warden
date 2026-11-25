package tokensvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ReplayStore remembers the assertions an agent has already presented, so one
// signed assertion authenticates at most once. The SQLite implementation is
// internal/tokensvc/adapters/sqlite; implementations are safe for concurrent
// use. Only the hash of a jti ever reaches a store (JTIHash).
type ReplayStore interface {
	// Consume records (agentID, jtiHash) until expiresAt and reports whether
	// this call was the first to do so. A false result with a nil error means
	// the pair was already recorded: a replay. The check and the insert are
	// one atomic step, so of any number of concurrent calls for the same pair
	// exactly one returns true.
	Consume(ctx context.Context, agentID, jtiHash string, expiresAt time.Time) (bool, error)
	// Purge deletes every record whose expiresAt is before now and returns
	// how many it removed.
	Purge(ctx context.Context, now time.Time) (int64, error)
}

// JTIHash is the one definition of what a ReplayStore stores for a jti:
// the lowercase hex of its SHA-256.
func JTIHash(jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(sum[:])
}
