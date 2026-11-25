package controlplane

import (
	"context"
	"errors"
)

// ErrBlockListNotReady is returned by TokenBlockChecker before the block list
// has loaded: the answer is unknown, so the token service refuses.
var ErrBlockListNotReady = errors.New("controlplane: block list not loaded")

// TokenBlockChecker adapts BlockStore to the token service's block check
// (tokensvc.BlockChecker, which tokensvc owns so it never imports this
// package). It reads the store's in-memory snapshot, never a policy version,
// so a rollback or import cannot unblock a user.
type TokenBlockChecker struct {
	store *BlockStore
}

// NewTokenBlockChecker returns the adapter over store.
func NewTokenBlockChecker(store *BlockStore) *TokenBlockChecker {
	return &TokenBlockChecker{store: store}
}

// IsBlocked reports whether sub (exact) or email (lowercased by the store) is
// blocked. A store that has not loaded yet is an error, never "not blocked".
func (c *TokenBlockChecker) IsBlocked(ctx context.Context, sub, email string) (bool, error) {
	if c == nil || c.store == nil || !c.store.Ready() {
		return false, ErrBlockListNotReady
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return c.store.IsBlocked(sub, email), nil
}
