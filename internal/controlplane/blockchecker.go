package controlplane

import (
	"context"
	"errors"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/tokensvc"
)

// ErrBlockListNotReady is returned by BlockChecker before the block list
// has loaded: the answer is unknown, so the token service refuses.
var ErrBlockListNotReady = errors.New("controlplane: block list not loaded")

// BlockChecker is the one adapter over BlockStore's in-memory snapshot that
// the token service (tokensvc.BlockChecker) and the connect broker
// (oauthbroker.BlockChecker) share; each owns its interface so neither imports
// this package. The portal reads the same snapshot through BlockStore itself
// (portal.Blocklist). It reads the store's snapshot, never a policy version,
// so a rollback or import cannot unblock a user, and never queries SQLite per
// request.
type BlockChecker struct {
	store *BlockStore
}

// NewBlockChecker returns the adapter over store.
func NewBlockChecker(store *BlockStore) *BlockChecker {
	return &BlockChecker{store: store}
}

// IsBlocked reports whether sub (exact) or email (lowercased by the store) is
// blocked. A store that has not loaded yet is an error, never "not blocked".
func (c *BlockChecker) IsBlocked(ctx context.Context, sub, email string) (bool, error) {
	if c == nil || c.store == nil || !c.store.Ready() {
		return false, ErrBlockListNotReady
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return c.store.IsBlocked(sub, email), nil
}

var (
	_ tokensvc.BlockChecker    = (*BlockChecker)(nil)
	_ oauthbroker.BlockChecker = (*BlockChecker)(nil)
)
