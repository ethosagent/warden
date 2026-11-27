// This file is the consent.store implementation of the oauthbroker.GrantRecords
// port: guarded read and write helpers for a user's grant record. Keys come
// only from secrets.UserGrantKey and the record type is
// oauthbroker.TokenRecord, so there is no second key scheme or record format.
// It lives in the assembly layer because only assembly may import both the
// oauthbroker domain and internal/secrets (archtest L1/L7).

package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/secrets"
)

// isNotFound reports whether err means the key is absent: every SecretStore
// wraps secrets.ErrNotFound.
func isNotFound(err error) bool {
	return errors.Is(err, secrets.ErrNotFound)
}

// grantKey derives the store key through the one sanctioned key scheme.
func grantKey(userKey, provider string) (string, error) {
	key, err := secrets.UserGrantKey(userKey, provider)
	if err != nil {
		return "", fmt.Errorf("oauthbroker: grant key: %w", err)
	}
	return key, nil
}

// loadGrant reads and parses the user's grant for provider. On a
// secrets.VersionedStore the returned GrantVersion carries the backend version so
// StoreRotated can compare-and-swap; on other stores it carries only the
// grant_id. A missing key returns oauthbroker.ErrGrantMissing; any other store or parse
// failure is returned wrapped and is not oauthbroker.ErrGrantMissing. Errors name the key
// (and version), never a value.
func loadGrant(ctx context.Context, store secrets.SecretStore, userKey, provider string) (oauthbroker.TokenRecord, oauthbroker.GrantVersion, error) {
	key, err := grantKey(userKey, provider)
	if err != nil {
		return oauthbroker.TokenRecord{}, oauthbroker.GrantVersion{}, err
	}
	var (
		raw string
		ver oauthbroker.GrantVersion
	)
	if vs, ok := store.(secrets.VersionedStore); ok {
		v, n, gerr := vs.GetVersion(ctx, key)
		if gerr != nil {
			return oauthbroker.TokenRecord{}, oauthbroker.GrantVersion{}, readError(key, gerr)
		}
		raw, ver = v, oauthbroker.GrantVersion{N: n, Versioned: true}
	} else {
		v, gerr := store.Get(ctx, key)
		if gerr != nil {
			return oauthbroker.TokenRecord{}, oauthbroker.GrantVersion{}, readError(key, gerr)
		}
		raw = v
	}
	rec, err := oauthbroker.ParseTokenRecord([]byte(raw))
	if err != nil {
		return oauthbroker.TokenRecord{}, oauthbroker.GrantVersion{}, fmt.Errorf("oauthbroker: grant %q (version %d): %w", key, ver.N, err)
	}
	ver.GrantID = rec.GrantID
	return rec, ver, nil
}

func readError(key string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%w: %q", oauthbroker.ErrGrantMissing, key)
	}
	return fmt.Errorf("oauthbroker: read grant %q: %w", key, err)
}

// storeRotated writes rec (a rotated copy of the record LoadGrant returned
// with version read) back only while the stored grant is still the one that
// was read.
//
//   - rec.GrantID must equal read.GrantID, else oauthbroker.ErrGrantChanged, no write.
//   - On a versioned read it re-checks the stored grant_id and version, then
//     calls PutIfVersion with read.N. A version conflict, a deleted key or a
//     different grant_id returns oauthbroker.ErrGrantChanged. The only exception: when the
//     stored bytes already equal rec the write is reported as success, so a
//     retry after a transport error (where the first attempt may have landed)
//     does not read as a conflict.
//   - On other stores it re-reads, compares grant_id and then Puts
//     (check-then-act).
//
// On EVERY backend the caller MUST hold GrantLocks for (userKey, provider)
// across LoadGrant..StoreRotated: Vault's Delete resets versions, so CAS is
// defence in depth, not the guard.
//
// Store failures other than a conflict are returned wrapped (not
// oauthbroker.ErrGrantChanged) and the caller treats them as "token unavailable". Errors
// carry only the key and version, never a value. The helper does not log.
func storeRotated(ctx context.Context, store secrets.SecretStore, userKey, provider string, rec oauthbroker.TokenRecord, read oauthbroker.GrantVersion) error {
	key, err := grantKey(userKey, provider)
	if err != nil {
		return err
	}
	if rec.GrantID != read.GrantID {
		return fmt.Errorf("%w: %q: rotated record is for a different grant_id", oauthbroker.ErrGrantChanged, key)
	}
	data, err := rec.Marshal()
	if err != nil {
		return fmt.Errorf("oauthbroker: grant %q: %w", key, err)
	}
	if vs, ok := store.(secrets.VersionedStore); ok {
		if !read.Versioned {
			// The read was unguarded but the store can compare-and-swap:
			// never downgrade to the unguarded path.
			return fmt.Errorf("%w: %q: read was not versioned", oauthbroker.ErrGrantChanged, key)
		}
		return storeVersioned(ctx, vs, key, string(data), read)
	}
	return storeReadCompare(ctx, store, key, string(data), read)
}

func storeVersioned(ctx context.Context, vs secrets.VersionedStore, key, data string, read oauthbroker.GrantVersion) error {
	// Narrow the delete-and-reconnect window (a recreated key restarts at a
	// low version that could equal the one read) with a cheap pre-check; the
	// CAS below stays the authority.
	cur, curVer, err := vs.GetVersion(ctx, key)
	switch {
	case err != nil && isNotFound(err):
		return fmt.Errorf("%w: %q was deleted", oauthbroker.ErrGrantChanged, key)
	case err != nil:
		return fmt.Errorf("oauthbroker: recheck grant %q: %w", key, err)
	case cur == data:
		return nil // our own write already landed
	case curVer != read.N:
		return fmt.Errorf("%w: %q is at version %d, read version %d", oauthbroker.ErrGrantChanged, key, curVer, read.N)
	}
	if id, ok := grantIDOf(cur); !ok || id != read.GrantID {
		return fmt.Errorf("%w: %q holds a different grant", oauthbroker.ErrGrantChanged, key)
	}
	perr := vs.PutIfVersion(ctx, key, data, read.N)
	if perr == nil {
		return nil
	}
	if !errors.Is(perr, secrets.ErrVersionConflict) {
		return fmt.Errorf("oauthbroker: write grant %q (version %d): %w", key, read.N, perr)
	}
	// A conflict can mean our own write landed on an earlier, apparently
	// failed attempt. Re-read and compare before reporting it.
	now, nowVer, gerr := vs.GetVersion(ctx, key)
	switch {
	case gerr == nil && now == data:
		return nil
	case gerr != nil && !isNotFound(gerr):
		return fmt.Errorf("oauthbroker: recheck grant %q after conflict: %w", key, gerr)
	}
	return fmt.Errorf("%w: %q moved past version %d (now %d)", oauthbroker.ErrGrantChanged, key, read.N, nowVer)
}

func storeReadCompare(ctx context.Context, store secrets.SecretStore, key, data string, read oauthbroker.GrantVersion) error {
	cur, err := store.Get(ctx, key)
	if err != nil {
		if isNotFound(err) {
			return fmt.Errorf("%w: %q was deleted", oauthbroker.ErrGrantChanged, key)
		}
		return fmt.Errorf("oauthbroker: recheck grant %q: %w", key, err)
	}
	if id, ok := grantIDOf(cur); !ok || id != read.GrantID {
		return fmt.Errorf("%w: %q holds a different grant", oauthbroker.ErrGrantChanged, key)
	}
	if err := store.Put(ctx, key, data); err != nil {
		return fmt.Errorf("oauthbroker: write grant %q: %w", key, err)
	}
	return nil
}

// grantIDOf extracts the grant_id of a stored record; ok is false when the
// value is not a valid record (treated as a changed grant, never rewritten).
func grantIDOf(raw string) (string, bool) {
	rec, err := oauthbroker.ParseTokenRecord([]byte(raw))
	if err != nil {
		return "", false
	}
	return rec.GrantID, true
}

// grantRecords binds the helpers to one consent.store; it implements
// oauthbroker.GrantRecords.
type grantRecords struct{ s secrets.SecretStore }

var _ oauthbroker.GrantRecords = grantRecords{}

// NewGrantRecords returns the GrantRecords over store.
func NewGrantRecords(store secrets.SecretStore) oauthbroker.GrantRecords {
	return grantRecords{s: store}
}

// LoadGrant implements oauthbroker.GrantRecords.
func (g grantRecords) LoadGrant(ctx context.Context, userKey, provider string) (oauthbroker.TokenRecord, oauthbroker.GrantVersion, error) {
	return loadGrant(ctx, g.s, userKey, provider)
}

// StoreRotated implements oauthbroker.GrantRecords.
func (g grantRecords) StoreRotated(ctx context.Context, userKey, provider string, rec oauthbroker.TokenRecord, read oauthbroker.GrantVersion) error {
	return storeRotated(ctx, g.s, userKey, provider, rec, read)
}
