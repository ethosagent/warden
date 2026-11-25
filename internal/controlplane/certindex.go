package controlplane

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// certIndexMaxAge is how often the index is rebuilt even when nothing changed,
// so serials of certificates that have expired leave it.
const certIndexMaxAge = 10 * time.Minute

// certIndex is the in-memory set of revoked worker certificate serials that
// WorkerAuthenticator consults on every request, so authentication does no DB
// I/O. Rebuild loads it from the WorkerCertStore; Run reloads it when another
// process (the offline CLI) commits to the database, on the same 2 s
// PRAGMA data_version poll as the token indexes. A failed rebuild keeps the
// last good set (revocations already loaded stay in force). Until the first
// load succeeds the set is unavailable and certificate authentication fails
// closed.
type certIndex struct {
	store WorkerCertStore
	clk   clock.Clock
	log   *slog.Logger
	poll  time.Duration

	set atomic.Pointer[map[string]RevokedCert] // serial -> entry; nil until loaded

	mu      sync.Mutex // serialises rebuilds; guards version and builtAt
	version int64
	builtAt time.Time

	// onRevoked is called, outside mu, with each serial that became revoked
	// since the previous load (the authenticator cancels its held long-polls).
	onRevoked func(serial string)
}

func newCertIndex(store WorkerCertStore, clk clock.Clock, log *slog.Logger) *certIndex {
	return &certIndex{store: store, clk: clk, log: log, poll: defaultTokenPollInterval}
}

// Revoked reports whether serial is revoked, and whether the index is loaded at
// all (false: the answer is unknown, treat the certificate as unusable).
func (x *certIndex) Revoked(serial string) (revoked, loaded bool) {
	e, revoked, loaded := x.Entry(serial)
	_ = e
	return revoked, loaded
}

// Entry is Revoked plus the revoked row (worker id and reason).
func (x *certIndex) Entry(serial string) (e RevokedCert, revoked, loaded bool) {
	set := x.set.Load()
	if set == nil {
		return RevokedCert{}, false, false
	}
	e, revoked = (*set)[serial]
	return e, revoked, true
}

// Len is the number of revoked serials held (0 before the first load).
func (x *certIndex) Len() int {
	if set := x.set.Load(); set != nil {
		return len(*set)
	}
	return 0
}

// Rebuild reloads the set from the store. data_version is read before the rows,
// so a commit that lands in between is picked up by the next poll.
func (x *certIndex) Rebuild(ctx context.Context) error {
	x.mu.Lock()
	v, err := x.store.DataVersion(ctx)
	if err != nil {
		x.mu.Unlock()
		return err
	}
	now := x.clk.Now()
	rows, err := x.store.RevokedCerts(ctx, now)
	if err != nil {
		x.mu.Unlock()
		return err
	}
	next := make(map[string]RevokedCert, len(rows))
	for _, r := range rows {
		next[r.Serial] = r
	}
	var fresh []string
	if old := x.set.Load(); old != nil {
		for sn := range next {
			if _, was := (*old)[sn]; !was {
				fresh = append(fresh, sn)
			}
		}
	}
	x.set.Store(&next)
	x.version, x.builtAt = v, now
	cb := x.onRevoked
	x.mu.Unlock()
	if cb != nil {
		for _, sn := range fresh {
			cb(sn)
		}
	}
	return nil
}

// Run polls data_version and rebuilds on a change (and when the index is not
// loaded yet, or old) until ctx ends. It runs on the control plane clock.
func (x *certIndex) Run(ctx context.Context) {
	t := x.clk.NewTimer(x.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			x.tick(ctx)
			t.Reset(x.poll)
		}
	}
}

func (x *certIndex) tick(ctx context.Context) {
	v, err := x.store.DataVersion(ctx)
	if err == nil {
		x.mu.Lock()
		due := x.set.Load() == nil || v != x.version || x.clk.Now().Sub(x.builtAt) >= certIndexMaxAge
		x.mu.Unlock()
		if !due {
			return
		}
		err = x.Rebuild(ctx)
	}
	if err != nil && ctx.Err() == nil {
		x.log.Warn("worker certs: revoked index reload failed; keeping the last good index", "err", err)
	}
}
