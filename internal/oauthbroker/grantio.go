package oauthbroker

import (
	"context"
	"errors"
)

// ErrGrantMissing is returned by LoadGrant when the user has no stored grant
// for the provider (the store reports the key as absent). Callers map it to
// the grant_missing outcome. Any other store failure is NOT this error: it is
// returned wrapped, and callers must treat it as "token unavailable", never as
// a missing grant.
var ErrGrantMissing = errors.New("oauthbroker: grant missing")

// ErrGrantChanged is returned by StoreRotated when the stored grant is no
// longer the one that was read: it was deleted (revoke), replaced by a
// reconnect (new grant_id) or rewritten by another writer. Nothing was
// written. Callers drop the rotated record and re-load if they still need it.
var ErrGrantChanged = errors.New("oauthbroker: grant changed")

// Version is the opaque read token LoadGrant returns and StoreRotated takes
// back. It carries the store version (when the backend is a
// secrets.VersionedStore) and the grant_id that was read. It holds no secret
// value and is safe to log.
type Version struct {
	// N is the backend version of the record that was read; meaningful only
	// when Versioned is true.
	N int64
	// Versioned records that the store offered compare-and-swap at read time.
	Versioned bool
	// GrantID is the grant_id of the record that was read.
	GrantID string
}

// GrantStore is the port the refresh engine uses for the user's grant record.
// LoadGrant reads and parses it with its store version; StoreRotated writes a
// rotated record back only while the stored grant is still the one that was
// read (see adapters/grantstore for the semantics and the GrantLocks
// requirement on stores without compare-and-swap).
type GrantStore interface {
	LoadGrant(ctx context.Context, userKey, provider string) (TokenRecord, Version, error)
	StoreRotated(ctx context.Context, userKey, provider string, rec TokenRecord, read Version) error
}
