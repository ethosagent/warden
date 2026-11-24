package apikeys

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Default polling and flush intervals.
const (
	DefaultPollInterval  = 2 * time.Second
	DefaultFlushInterval = 60 * time.Second

	rebuildTimeout = 10 * time.Second
	flushTimeout   = 5 * time.Second
)

// ErrUnauthorized is the only error Authenticate returns. Every failure looks
// the same to the caller; the Reason is for logs and a counter only.
var ErrUnauthorized = errors.New("apikeys: unauthorized")

// Reason says why Authenticate refused a key. It is never shown to the client.
type Reason string

// Authentication failure reasons ("" means success).
const (
	ReasonMalformed Reason = "malformed"
	ReasonUnknown   Reason = "unknown"
	ReasonBadSecret Reason = "bad_secret"
	ReasonExpired   Reason = "expired"
	ReasonRevoked   Reason = "revoked"
	// ReasonIndexStale: the Index has not been able to confirm it is current
	// for longer than the staleness ceiling, so it refuses every key rather
	// than risk accepting one revoked elsewhere.
	ReasonIndexStale Reason = "index_stale"
)

// staleAfterPolls is the staleness ceiling in poll intervals (30s at the
// default 2s): the longest Run may go without a successful data_version check
// or reload before Authenticate fails closed.
const staleAfterPolls = 15

// IndexOptions configures an Index. Now and After are required: this is a
// domain package, which reads no clock of its own, so assembly injects the
// clock port's methods (clk.Now, clk.After). Zero intervals mean a 2 s poll and
// a 60 s flush; a nil Logger means slog.Default.
type IndexOptions struct {
	// Now returns the current instant.
	Now func() time.Time
	// After returns a channel that receives once d has elapsed.
	After         func(d time.Duration) <-chan time.Time
	PollInterval  time.Duration
	FlushInterval time.Duration
	Logger        *slog.Logger
}

// Index authenticates keys from an immutable in-memory snapshot, so the request
// path does one map read, one sha256 and one constant-time compare and no DB
// I/O. The snapshot is rebuilt synchronously after this process commits a
// Create, Revoke or RevokeByOwner on the Store, and reloaded by Run when
// another process changes the database (the offline CLI revoking a leaked key).
// A failed reload keeps the last good snapshot, so a revocation already loaded
// is never undone; a failed rebuild after a local write is retried by the next
// poll even though the database version did not move.
type Index struct {
	store         Store
	now           func() time.Time
	after         func(time.Duration) <-chan time.Time
	log           *slog.Logger
	pollInterval  time.Duration
	flushInterval time.Duration

	snap atomic.Pointer[indexSnapshot]

	// loadMu serialises rebuilds and revocation overlays and guards version.
	loadMu  sync.Mutex
	version int64
	stale   atomic.Bool

	// lastOK is the clock time (unix nanos) of the last successful
	// data_version check or reload, starting at NewIndex's initial load, so an
	// Index whose Run never starts fails closed after the ceiling. polls counts
	// completed poll cycles (tests wait on it). staleLogged makes the stale log
	// line fire once per episode.
	polls       atomic.Int64
	lastOK      atomic.Int64
	staleLogged atomic.Bool

	// usedMu guards last-use values waiting for a flush.
	usedMu sync.Mutex
	used   map[string]Use
}

type indexSnapshot struct {
	byID map[string]entry
}

// NewIndex loads the Store's keys into a new Index and subscribes it to the
// Store's own writes. An error here means no Index, never an empty one.
func NewIndex(ctx context.Context, store Store, opts IndexOptions) (*Index, error) {
	if opts.Now == nil || opts.After == nil {
		return nil, errors.New("apikeys: IndexOptions.Now and After are required")
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = DefaultFlushInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	ix := &Index{
		store: store, now: opts.Now, after: opts.After, log: opts.Logger,
		pollInterval: opts.PollInterval, flushInterval: opts.FlushInterval,
		used: map[string]Use{},
	}
	if err := ix.Rebuild(ctx); err != nil {
		return nil, fmt.Errorf("apikeys: load index: %w", err)
	}
	ix.lastOK.Store(ix.now().UnixNano())
	store.OnChange(ix.onLocalChange)
	return ix, nil
}

// onLocalChange handles a write this process just committed. A revocation is
// first applied to the in-memory snapshot, a step that cannot fail, so the key
// stops authenticating at once even if the full reload below does not work.
func (ix *Index) onLocalChange(c Change) {
	if c.revokes() {
		ix.applyRevocation(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), rebuildTimeout)
	defer cancel()
	if err := ix.Rebuild(ctx); err != nil {
		// The write is committed but the snapshot may be behind (a new key is
		// missing). The database version will not move for our own write, so
		// force the next poll to reload.
		ix.stale.Store(true)
		ix.log.Warn("apikeys: index rebuild failed after a local write; will retry at the next poll", "err", err)
	}
}

// applyRevocation swaps in a copy of the snapshot with the revoked keys marked.
func (ix *Index) applyRevocation(c Change) {
	ix.loadMu.Lock()
	defer ix.loadMu.Unlock()
	cur := ix.snap.Load()
	next := &indexSnapshot{byID: make(map[string]entry, len(cur.byID))}
	byID := make(map[string]struct{}, len(c.RevokedIDs))
	for _, id := range c.RevokedIDs {
		byID[id] = struct{}{}
	}
	for id, e := range cur.byID {
		_, hit := byID[id]
		if hit || (c.OwnerSub != "" && e.key.OwnerIss == c.OwnerIss && e.key.OwnerSub == c.OwnerSub) {
			if e.key.RevokedAt.IsZero() {
				e.key.RevokedAt, e.key.RevokedBy = c.RevokedAt, c.RevokedBy
			}
		}
		next.byID[id] = e
	}
	ix.snap.Store(next)
}

// Rebuild replaces the snapshot with the Store's current rows. On error the
// previous snapshot stays in force.
func (ix *Index) Rebuild(ctx context.Context) error {
	ix.loadMu.Lock()
	defer ix.loadMu.Unlock()
	snap, err := ix.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	next := &indexSnapshot{byID: make(map[string]entry, len(snap.entries))}
	for _, e := range snap.entries {
		next.byID[e.key.ID] = e
	}
	ix.snap.Store(next)
	ix.version = snap.version
	ix.stale.Store(false)
	ix.touch()
	return nil
}

// touch records that the index was confirmed current just now.
func (ix *Index) touch() {
	ix.lastOK.Store(ix.now().UnixNano())
	ix.staleLogged.Store(false)
}

// tooStale reports whether the Index has gone past the staleness ceiling
// without a successful check, logging once per episode.
func (ix *Index) tooStale() bool {
	age := ix.now().Sub(time.Unix(0, ix.lastOK.Load()))
	if age <= staleAfterPolls*ix.pollInterval {
		return false
	}
	if ix.staleLogged.CompareAndSwap(false, true) {
		ix.log.Error("apikeys: index not refreshed within the staleness ceiling; refusing all keys until it is",
			"age", age.Round(time.Second), "ceiling", staleAfterPolls*ix.pollInterval)
	}
	return true
}

// Authenticate resolves a presented key: Parse, a map lookup by id, a
// constant-time compare of sha256(secret), then revocation and expiry against
// now. A snapshot that could not be confirmed current for 15 poll intervals refuses every key with ReasonIndexStale. Every failure returns ErrUnauthorized; the Reason is for logs and the
// counter. The returned Key shares slices with the snapshot: do not modify it.
func (ix *Index) Authenticate(token string, now time.Time) (Key, Reason, error) {
	id, hash, err := parse(token)
	if err != nil {
		return Key{}, ReasonMalformed, ErrUnauthorized
	}
	if ix.tooStale() {
		return Key{}, ReasonIndexStale, ErrUnauthorized
	}
	e, ok := ix.snap.Load().byID[id]
	if !ok {
		return Key{}, ReasonUnknown, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare(hash[:], e.hash[:]) != 1 {
		return Key{}, ReasonBadSecret, ErrUnauthorized
	}
	if !e.key.RevokedAt.IsZero() {
		return Key{}, ReasonRevoked, ErrUnauthorized
	}
	if !now.Before(e.key.ExpiresAt) {
		return Key{}, ReasonExpired, ErrUnauthorized
	}
	return e.key, "", nil
}

// Key returns a key's metadata by id from the snapshot (last-use values as
// last flushed), without any secret check; for callers that already
// authenticated it.
func (ix *Index) Key(id string) (Key, bool) {
	e, ok := ix.snap.Load().byID[id]
	return e.key, ok
}

// MarkUsed records a use in memory only; Flush (or Run's timer) persists it.
func (ix *Index) MarkUsed(id string, at time.Time, ip string) {
	ix.usedMu.Lock()
	if cur, ok := ix.used[id]; !ok || !at.Before(cur.At) {
		ix.used[id] = Use{At: at, IP: ip}
	}
	ix.usedMu.Unlock()
}

// Flush writes every pending last-use value in one transaction. A failure keeps
// the values for the next flush.
func (ix *Index) Flush(ctx context.Context) error {
	ix.usedMu.Lock()
	batch := ix.used
	ix.used = map[string]Use{}
	ix.usedMu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := ix.store.FlushLastUsed(ctx, batch); err != nil {
		ix.usedMu.Lock()
		for id, u := range batch {
			if cur, ok := ix.used[id]; !ok || u.At.After(cur.At) {
				ix.used[id] = u
			}
		}
		ix.usedMu.Unlock()
		return err
	}
	return nil
}

// Run polls for changes made by other processes and flushes last-use values
// until ctx ends, then flushes once more.
func (ix *Index) Run(ctx context.Context) {
	ix.touch()
	pollCh := ix.after(ix.pollInterval)
	flushCh := ix.after(ix.flushInterval)
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flushTimeout)
			if err := ix.Flush(fctx); err != nil {
				ix.log.Warn("apikeys: final last-use flush failed", "err", err)
			}
			cancel()
			return
		case <-pollCh:
			ix.poll(ctx)
			pollCh = ix.after(ix.pollInterval)
		case <-flushCh:
			if err := ix.Flush(ctx); err != nil && ctx.Err() == nil {
				ix.log.Warn("apikeys: last-use flush failed", "err", err)
			}
			flushCh = ix.after(ix.flushInterval)
		}
	}
}

// Polls returns how many poll cycles Run has completed. Tests wait on it
// instead of sleeping; it is also a liveness signal for metrics.
func (ix *Index) Polls() int64 { return ix.polls.Load() }

// poll reloads the snapshot when the database version moved or an earlier
// local rebuild failed.
func (ix *Index) poll(ctx context.Context) {
	defer ix.polls.Add(1)
	v, err := ix.store.DataVersion(ctx)
	if err != nil {
		if ctx.Err() == nil {
			ix.log.Warn("apikeys: data_version unreadable; keeping the last good index", "err", err)
		}
		return
	}
	ix.loadMu.Lock()
	changed := v != ix.version || ix.stale.Load()
	ix.loadMu.Unlock()
	if !changed {
		ix.touch()
		return
	}
	if err := ix.Rebuild(ctx); err != nil && ctx.Err() == nil {
		ix.log.Warn("apikeys: index reload failed; keeping the last good index", "err", err)
	}
}
