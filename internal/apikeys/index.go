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

	"github.com/ethosagent/warden/internal/clock"
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
)

// IndexOptions configures an Index. Zero values use the real clock, a 2 s poll
// interval, a 60 s flush interval and slog.Default.
type IndexOptions struct {
	Clock         clock.Clock
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
	clk           clock.Clock
	log           *slog.Logger
	pollInterval  time.Duration
	flushInterval time.Duration

	snap atomic.Pointer[indexSnapshot]

	// loadMu serialises rebuilds and guards version.
	loadMu  sync.Mutex
	version int64
	stale   atomic.Bool

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
	if opts.Clock == nil {
		opts.Clock = clock.Real()
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
		store: store, clk: opts.Clock, log: opts.Logger,
		pollInterval: opts.PollInterval, flushInterval: opts.FlushInterval,
		used: map[string]Use{},
	}
	if err := ix.Rebuild(ctx); err != nil {
		return nil, fmt.Errorf("apikeys: load index: %w", err)
	}
	store.OnChange(ix.onLocalChange)
	return ix, nil
}

func (ix *Index) onLocalChange() {
	ctx, cancel := context.WithTimeout(context.Background(), rebuildTimeout)
	defer cancel()
	if err := ix.Rebuild(ctx); err != nil {
		// The write is committed but the snapshot is behind. The database
		// version will not move for our own write, so force the next poll.
		ix.stale.Store(true)
		ix.log.Warn("apikeys: index rebuild failed after a local write; will retry at the next poll", "err", err)
	}
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
	return nil
}

// Authenticate resolves a presented key: Parse, a map lookup by id, a
// constant-time compare of sha256(secret), then expiry and revocation against
// now. Every failure returns ErrUnauthorized; the Reason is for logs and the
// counter. The returned Key shares slices with the snapshot: do not modify it.
func (ix *Index) Authenticate(token string, now time.Time) (Key, Reason, error) {
	id, hash, err := parse(token)
	if err != nil {
		return Key{}, ReasonMalformed, ErrUnauthorized
	}
	e, ok := ix.snap.Load().byID[id]
	if !ok {
		return Key{}, ReasonUnknown, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare(hash[:], e.hash[:]) != 1 {
		return Key{}, ReasonBadSecret, ErrUnauthorized
	}
	if !now.Before(e.key.ExpiresAt) {
		return Key{}, ReasonExpired, ErrUnauthorized
	}
	if !e.key.RevokedAt.IsZero() {
		return Key{}, ReasonRevoked, ErrUnauthorized
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
	poll := ix.clk.NewTimer(ix.pollInterval)
	flush := ix.clk.NewTimer(ix.flushInterval)
	defer poll.Stop()
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flushTimeout)
			if err := ix.Flush(fctx); err != nil {
				ix.log.Warn("apikeys: final last-use flush failed", "err", err)
			}
			cancel()
			return
		case <-poll.C():
			ix.poll(ctx)
			poll.Reset(ix.pollInterval)
		case <-flush.C():
			if err := ix.Flush(ctx); err != nil && ctx.Err() == nil {
				ix.log.Warn("apikeys: last-use flush failed", "err", err)
			}
			flush.Reset(ix.flushInterval)
		}
	}
}

// poll reloads the snapshot when the database version moved or an earlier
// local rebuild failed.
func (ix *Index) poll(ctx context.Context) {
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
		return
	}
	if err := ix.Rebuild(ctx); err != nil && ctx.Err() == nil {
		ix.log.Warn("apikeys: index reload failed; keeping the last good index", "err", err)
	}
}
