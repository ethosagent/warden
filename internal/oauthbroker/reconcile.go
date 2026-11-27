package oauthbroker

import (
	"context"
	"errors"
	"strings"
	"time"
)

// OrphanInterval is how often the broker counts consent.store keys that no
// live grant row owns.
const OrphanInterval = time.Hour

// userKeyPrefix is the logical consent.store namespace of provider grants.
const userKeyPrefix = "users/"

// Reconcile settles grants the sweeper found stuck in connecting (a callback
// that died between its steps). It is the SweeperConfig.Reconcile hook. For
// each grant, under the same GrantLocks entry the callback holds:
//
//   - the row is re-read and skipped unless it is still connecting with the
//     same grant id (a later reconnect or a portal revoke moved it on);
//   - a reconnect over a working grant whose stored token still carries the
//     previous grant id is restored (RestoreGrant): the working token is never
//     deleted for a failed reconnect;
//   - otherwise the key is deleted (when it holds this grant's token or
//     nothing parseable) and the grant is revoked, only ever with its own id.
//
// A store that cannot be read or deleted from leaves the row connecting for
// the next pass: a row is never revoked while its key might survive.
func (b *Broker) Reconcile(ctx context.Context, stale []Grant) {
	for _, g := range stale {
		if ctx.Err() != nil {
			return
		}
		b.reconcileOne(ctx, g)
	}
}

func (b *Broker) reconcileOne(ctx context.Context, stale Grant) {
	if b.vault == nil || b.grantKey == nil {
		return
	}
	key, err := b.grantKey(stale.UserKey, stale.Provider)
	if err != nil {
		return
	}
	unlock := b.locks.Lock(stale.UserKey, stale.Provider)
	defer unlock()

	cur, err := b.store.GetGrant(ctx, stale.UserKey, stale.Provider)
	if err != nil || cur.State != GrantConnecting || cur.GrantID != stale.GrantID {
		return
	}
	var stored TokenRecord
	haveRecord := false
	raw, err := b.vault.Get(ctx, key)
	switch {
	case err == nil:
		if rec, perr := ParseTokenRecord([]byte(raw)); perr == nil {
			stored, haveRecord = rec, true
		}
	case b.notFound(err):
		raw = ""
	default:
		b.logger.Warn("oauth_reconcile_deferred", "provider", stale.Provider, "user_key", stale.UserKey, "reason", "secret_store_read")
		return
	}

	if haveRecord && cur.PrevGrantID != "" && stored.GrantID == cur.PrevGrantID {
		if _, err := b.store.RestoreGrant(ctx, stale.UserKey, stale.Provider, cur.GrantID, cur.PrevGrantID); err != nil {
			b.logger.Warn("oauth_reconcile_deferred", "provider", stale.Provider, "user_key", stale.UserKey, "reason", "restore")
			return
		}
		b.logger.Info("oauth_reconcile", "provider", stale.Provider, "user_key", stale.UserKey, "action", "restored")
		return
	}
	// The key is this grant's token, unreadable junk, or absent. A record of
	// some other grant is left alone: it is not ours to delete. A callback that
	// died after its Put landed but before Activate also ends here: the stored
	// token carries this grant's id, so it is deleted and the grant revoked
	// rather than activated (conservative, per spec: the user reconnects).
	if raw != "" && (!haveRecord || stored.GrantID == cur.GrantID) {
		if err := b.vault.Delete(ctx, key); err != nil && !b.notFound(err) {
			b.logger.Warn("oauth_reconcile_deferred", "provider", stale.Provider, "user_key", stale.UserKey, "reason", "secret_store_delete")
			return
		}
	}
	if _, err := b.store.RevokeGrant(ctx, stale.UserKey, stale.Provider, cur.GrantID); err != nil {
		b.logger.Warn("oauth_reconcile_deferred", "provider", stale.Provider, "user_key", stale.UserKey, "reason", "revoke")
		return
	}
	b.logger.Info("oauth_reconcile", "provider", stale.Provider, "user_key", stale.UserKey, "action", "revoked")
}

// CountOrphans counts the consent.store keys under users/ whose grant row is
// missing or revoked (a token with nobody able to see or revoke it), stores the
// count for OrphanedGrants and returns it. A key that is not users/<userKey>/
// <provider> is counted too. It changes nothing.
func (b *Broker) CountOrphans(ctx context.Context) (int, error) {
	if b.vault == nil {
		return 0, nil
	}
	keys, err := b.vault.Keys(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		rest, ok := strings.CutPrefix(k, userKeyPrefix)
		if !ok {
			continue
		}
		userKey, provider, ok := strings.Cut(rest, "/")
		if !ok || userKey == "" || provider == "" {
			n++
			continue
		}
		g, err := b.store.GetGrant(ctx, userKey, provider)
		switch {
		case errors.Is(err, ErrNotFound):
			n++
		case err != nil:
			return 0, err
		case g.State == GrantRevoked:
			n++
		}
	}
	b.metrics.mu.Lock()
	b.metrics.orphans = n
	b.metrics.mu.Unlock()
	if n > 0 {
		b.logger.Warn("oauth_orphaned_grant_keys", "count", n)
	}
	return n, nil
}

// OrphanedGrants returns the gauge CountOrphans last stored.
func (b *Broker) OrphanedGrants() int {
	b.metrics.mu.Lock()
	defer b.metrics.mu.Unlock()
	return b.metrics.orphans
}

// SweepOrphans deletes consent.store keys under users/<userKey>/<provider>
// whose grant row is missing or revoked: the leftover of a revoke or a blocked
// connect whose Delete failed. Each key is re-checked under the grant's
// GrantLocks entry, and a key is never touched while its row is connecting,
// active or reconsent_required. Keys not shaped users/<userKey>/<provider> are
// left alone (CountOrphans still reports them). It returns how many keys it
// deleted; a store error stops the pass and is returned.
func (b *Broker) SweepOrphans(ctx context.Context) (int, error) {
	if b.vault == nil || b.grantKey == nil {
		return 0, nil
	}
	keys, err := b.vault.Keys(ctx)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, k := range keys {
		rest, ok := strings.CutPrefix(k, userKeyPrefix)
		if !ok {
			continue
		}
		userKey, provider, ok := strings.Cut(rest, "/")
		if !ok || userKey == "" || provider == "" || strings.Contains(provider, "/") {
			continue
		}
		if want, kerr := b.grantKey(userKey, provider); kerr != nil || want != k {
			continue
		}
		done, err := b.sweepOrphan(ctx, userKey, provider, k)
		if err != nil {
			return deleted, err
		}
		if done {
			deleted++
		}
	}
	if deleted > 0 {
		b.logger.Info("oauth_orphan_keys_deleted", "count", deleted)
	}
	return deleted, nil
}

func (b *Broker) sweepOrphan(ctx context.Context, userKey, provider, key string) (bool, error) {
	unlock := b.locks.Lock(userKey, provider)
	defer unlock()
	g, err := b.store.GetGrant(ctx, userKey, provider)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return false, err
	case g.State != GrantRevoked:
		return false, nil
	}
	if err := b.vault.Delete(ctx, key); err != nil && !b.notFound(err) {
		return false, err
	}
	return true, nil
}
