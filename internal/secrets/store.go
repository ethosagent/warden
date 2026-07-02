package secrets

import (
	"context"
	"time"
)

// SecretStore is the write-capable, backend-agnostic secret store shared by
// both Warden planes. It is the WRITE half that complements the read-only
// Fetcher/SecretProvider path: an operator SETs a key→value at the control
// plane (Put), the value lands in a dedicated external backend (AWS Secrets
// Manager, or an echo backend for dev/test), and a worker resolves it by key
// (Get) so the existing edge swap can replace a placeholder with the real
// value.
//
// The interface is full (all four verbs); scoping is by CAPABILITY, not by
// type. A worker is handed a store instance behind the read adapter
// (storeFetcher) and only ever calls Get through the existing Cache; the
// control plane uses Put/Delete/List. IAM — not the Go type — is what denies a
// worker Put/Delete. The interface documents intent; credentials enforce it.
//
// BY-REFERENCE LOGGING ONLY (invariant shared with the read path): every store
// operation may log the key and version, and — only where a raw value is in
// hand, i.e. Put on the control plane — a Reference (see Ref). Implementations
// MUST NEVER log, persist to Warden's own store, or otherwise surface the raw
// value. Values live only in the backend store.
type SecretStore interface {
	// Get resolves key to its raw secret value from the backend. This is the
	// only verb a worker uses (behind the Cache via storeFetcher). It has a
	// value in hand only in the returned string; callers reference it by Ref
	// for logging, never the raw value. It returns an error when the key has no
	// value in the backend.
	Get(ctx context.Context, key string) (string, error)

	// Put creates-or-updates (upsert) key→value in the backend. The operator
	// does not care whether the key already exists — one verb. This is the only
	// verb with a raw value in hand; implementations log key+version and a
	// Reference (Ref(value)) at most, never the raw value, and never persist
	// the value in Warden's own store.
	Put(ctx context.Context, key, value string) error

	// Delete removes key from the backend. It is idempotent from the operator's
	// point of view (deleting an absent key is not an error to the caller-facing
	// contract, though backends may surface a not-found). Logs key+version only,
	// never a value (there is none in hand).
	Delete(ctx context.Context, key string) error

	// List returns METADATA ONLY for the stored keys — never any value. It must
	// not call the backend's value-read path (e.g. GetSecretValue); it reads
	// only names/versions/timestamps. Logs key+version only.
	List(ctx context.Context) ([]SecretMeta, error)
}

// SecretMeta is a value-free descriptor of a stored secret, returned by
// SecretStore.List. It mirrors the SettingsWire secret-free discipline: the
// type carries NO field that can hold a raw secret value, so the guarantee is
// enforced structurally by the type itself rather than by careful handling.
// Adding a value-bearing field here is the only way to break it — which review
// (and the reflect test in store_test.go) must reject.
type SecretMeta struct {
	// Key is the logical secret key (backend name minus any namespace prefix).
	Key string
	// Version identifies the current version/stage of the stored value, for
	// by-reference logging and change detection. It is not the value.
	Version string
	// UpdatedAt is when the stored value last changed, per the backend.
	UpdatedAt time.Time
}

// storeFetcher adapts a SecretStore to the existing Fetcher interface so the
// worker's Cache (TTL, startup prefetch, silent-stale-on-failure) and the proxy
// swap plug in UNCHANGED over any store. This is the whole integration seam
// between the write-capable store and the read-only cache.
type storeFetcher struct {
	store SecretStore
	// ctx is the context handed to store.Get. It is captured at construction
	// because the Fetcher interface (Fetch(placeholder) (string, error)) has no
	// context parameter — the Cache calls it without one. We default to
	// context.Background() (never nil) so the store always receives a valid,
	// non-cancelable context; per-request cancellation is not part of the cache
	// refresh path, which runs on its own TTL schedule rather than under a
	// request's deadline.
	ctx context.Context
}

// Compile-time assertion: storeFetcher satisfies the read-path Fetcher, so a
// SecretStore can back the existing Cache with no changes to Cache.
var _ Fetcher = (*storeFetcher)(nil)

// NewStoreFetcher builds a Fetcher that resolves placeholders through
// store.Get, letting the existing Cache wrap any SecretStore. The store's Get is
// called with context.Background(); see storeFetcher.ctx for why the Fetcher
// seam carries no per-call context.
func NewStoreFetcher(store SecretStore) *storeFetcher {
	return &storeFetcher{store: store, ctx: context.Background()}
}

// Fetch resolves placeholder by delegating to the underlying store's Get. The
// placeholder is used directly as the store key; any error from the store is
// surfaced to the caller (the Cache) unchanged.
func (f *storeFetcher) Fetch(placeholder string) (string, error) {
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return f.store.Get(ctx, placeholder)
}
