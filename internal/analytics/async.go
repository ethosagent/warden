package analytics

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Async-writer defaults. A bounded queue plus batched, off-path pruning turns
// the per-request synchronous INSERT+prune (~one fsync + a SELECT COUNT/DELETE
// each) into ~one fsync per batch, moving the cost off the request goroutine.
const (
	// defaultAsyncQueueCap bounds the in-flight event queue. A full queue means
	// SQLite is the bottleneck: StoreEvent then BLOCKS (backpressure), never
	// drops — events are the audit trail.
	defaultAsyncQueueCap = 1024
	// defaultAsyncBatchSize flushes as soon as this many events accumulate.
	defaultAsyncBatchSize = 64
	// defaultAsyncFlushInterval flushes a partial batch on this tick so a trickle
	// of events is still persisted promptly.
	defaultAsyncFlushInterval = 250 * time.Millisecond
	// defaultAsyncPruneEvery runs retention pruning every N flushes.
	defaultAsyncPruneEvery = 16
	// defaultAsyncPruneInterval is a backstop prune tick so retention still runs
	// during long low-volume periods that never reach pruneEvery flushes.
	defaultAsyncPruneInterval = 30 * time.Second
)

// asyncConfig holds the tunable knobs; all have safe defaults.
type asyncConfig struct {
	queueCap      int
	batchSize     int
	flushInterval time.Duration
	pruneEvery    int
	pruneInterval time.Duration
	logger        *slog.Logger
}

// AsyncOption configures a NewAsyncWriter.
type AsyncOption func(*asyncConfig)

// WithQueueCap sets the bounded queue capacity (backpressure threshold).
func WithQueueCap(n int) AsyncOption { return func(c *asyncConfig) { c.queueCap = n } }

// WithBatchSize sets how many events accumulate before an immediate flush.
func WithBatchSize(n int) AsyncOption { return func(c *asyncConfig) { c.batchSize = n } }

// WithFlushInterval sets the partial-batch flush tick.
func WithFlushInterval(d time.Duration) AsyncOption {
	return func(c *asyncConfig) { c.flushInterval = d }
}

// WithLogger sets the logger for the (rare) batch-write error path. Defaults to
// slog.Default().
func WithLogger(l *slog.Logger) AsyncOption { return func(c *asyncConfig) { c.logger = l } }

// asyncWriter is an AnalyticsStore decorator that moves the local SQLite write
// off the request goroutine: StoreEvent enqueues onto a bounded channel and a
// single writer goroutine batch-inserts via the underlying *SQLiteStore, pruning
// off the write path. Reads (GetEvents) bypass the queue and hit the base store
// directly — they may miss not-yet-flushed events, which matches the existing
// dashboard-reads-base-store design.
//
// Overflow policy is BACKPRESSURE, never drop: a full queue blocks the caller
// until the writer drains one slot. Events are the audit trail (signed receipts
// and compliance depend on them), so shedding is never acceptable.
// batchStore is the package-private capability set the async writer needs from
// its underlying store. *SQLiteStore satisfies it; keeping the field an
// interface (rather than the concrete type) lets tests inject a gated store to
// exercise backpressure. It is deliberately unexported — not a cross-package
// seam, just an internal test hook.
type batchStore interface {
	StoreEvent(e Event) error
	StoreEventsBatch(evs []Event) error
	Prune() error
	GetEvents(filter EventFilter) ([]Event, error)
}

type asyncWriter struct {
	store batchStore
	ch    chan Event
	cfg   asyncConfig

	// depth is the number of events enqueued (or blocked waiting to enqueue) but
	// not yet pulled by the writer — the warden_analytics_queue_depth gauge.
	depth atomic.Int64

	// closeMu is a barrier between producers and Close. Producers hold RLock for
	// the whole enqueue (a possibly-blocking send); Close takes the write lock,
	// which therefore waits until every in-flight send has completed before it
	// closes ch. That makes close(ch) provably free of a send-on-closed-channel
	// race without ever dropping an event.
	closeMu sync.RWMutex
	closed  bool

	closeOnce sync.Once
	wg        sync.WaitGroup
	logger    *slog.Logger
}

var _ AnalyticsStore = (*asyncWriter)(nil)

// NewAsyncWriter wraps store in an async batching writer and starts its single
// writer goroutine. Call Close on shutdown to drain and flush the queue.
func NewAsyncWriter(store *SQLiteStore, opts ...AsyncOption) *asyncWriter {
	return newAsyncWriter(store, opts...)
}

// newAsyncWriter is the internal constructor over the batchStore interface so
// tests can inject a gated store (backpressure). NewAsyncWriter is the public
// entry point over the concrete *SQLiteStore.
func newAsyncWriter(store batchStore, opts ...AsyncOption) *asyncWriter {
	cfg := asyncConfig{
		queueCap:      defaultAsyncQueueCap,
		batchSize:     defaultAsyncBatchSize,
		flushInterval: defaultAsyncFlushInterval,
		pruneEvery:    defaultAsyncPruneEvery,
		pruneInterval: defaultAsyncPruneInterval,
	}
	for _, o := range opts {
		o(&cfg)
	}
	// Clamp to sane minimums so a misconfigured option can't deadlock or spin.
	if cfg.queueCap < 1 {
		cfg.queueCap = 1
	}
	if cfg.batchSize < 1 {
		cfg.batchSize = 1
	}
	if cfg.flushInterval <= 0 {
		cfg.flushInterval = defaultAsyncFlushInterval
	}
	if cfg.pruneEvery < 1 {
		cfg.pruneEvery = defaultAsyncPruneEvery
	}
	if cfg.pruneInterval <= 0 {
		cfg.pruneInterval = defaultAsyncPruneInterval
	}
	w := &asyncWriter{
		store:  store,
		ch:     make(chan Event, cfg.queueCap),
		cfg:    cfg,
		logger: cfg.logger,
	}
	if w.logger == nil {
		w.logger = slog.Default()
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// StoreEvent enqueues e for asynchronous batch persistence. On a full queue it
// BLOCKS (backpressure) until the writer frees a slot — it never drops the
// event and never returns a "queue full" error. After Close it falls back to a
// synchronous write to the underlying store, so a post-Close call still
// persists the event and never panics on a send-to-closed channel.
func (w *asyncWriter) StoreEvent(e Event) error {
	w.closeMu.RLock()
	if w.closed {
		w.closeMu.RUnlock()
		// Post-Close: best-effort synchronous write (documented behavior). The
		// queue is gone, but the audit record must still land.
		return w.store.StoreEvent(e)
	}
	// Count before the (possibly blocking) send so the gauge reflects callers
	// stuck under backpressure, not just events already resident in the channel.
	w.depth.Add(1)
	w.ch <- e
	w.closeMu.RUnlock()
	return nil
}

// GetEvents delegates to the underlying store. Reads bypass the write queue and
// may not see events still buffered in the channel or the pending batch — the
// same read-your-base-store semantics the dashboard already relies on.
func (w *asyncWriter) GetEvents(filter EventFilter) ([]Event, error) {
	return w.store.GetEvents(filter)
}

// QueueDepth returns the current number of enqueued-or-blocked events. It backs
// the warden_analytics_queue_depth gauge so operators can see write saturation
// (a persistently high depth means SQLite is the bottleneck and callers are
// being backpressured).
func (w *asyncWriter) QueueDepth() int { return int(w.depth.Load()) }

// Close stops accepting new events, drains the queue, flushes the final batch,
// runs a final prune, and waits for the writer goroutine to exit before
// returning — guaranteeing every enqueued event is persisted (the audit-trail
// invariant). It is idempotent; concurrent producers blocked in StoreEvent
// complete their send first (the writer keeps draining), then fall through to
// the synchronous post-Close path.
func (w *asyncWriter) Close() error {
	w.closeOnce.Do(func() {
		// Take the write lock: this blocks until every in-flight StoreEvent send
		// has returned, so no producer will touch ch after we close it.
		w.closeMu.Lock()
		w.closed = true
		w.closeMu.Unlock()
		close(w.ch)
	})
	w.wg.Wait()
	return nil
}

// loop is the single writer goroutine: it accumulates events and flushes a
// batch on batchSize, on the flush tick, or when ch is closed (drain path).
func (w *asyncWriter) loop() {
	defer w.wg.Done()

	flush := time.NewTicker(w.cfg.flushInterval)
	defer flush.Stop()
	prune := time.NewTicker(w.cfg.pruneInterval)
	defer prune.Stop()

	buf := make([]Event, 0, w.cfg.batchSize)
	flushes := 0

	// flushBuf writes the accumulated batch and prunes every pruneEvery flushes.
	// On a write error it retains buf (does not clear) so the events are retried
	// on the next flush rather than dropped — backpressure will build if the
	// error persists, which is the correct, non-lossy behavior.
	flushBuf := func() {
		if len(buf) == 0 {
			return
		}
		if err := w.store.StoreEventsBatch(buf); err != nil {
			w.logger.Warn("analytics: async batch write failed; retrying", "error", err, "batch", len(buf))
			return
		}
		buf = buf[:0]
		flushes++
		if flushes%w.cfg.pruneEvery == 0 {
			if err := w.store.Prune(); err != nil {
				w.logger.Warn("analytics: async prune failed", "error", err)
			}
		}
	}

	for {
		select {
		case e, ok := <-w.ch:
			if !ok {
				// Close: channel drained of live events. Flush the tail and run a
				// final prune, then exit.
				flushBuf()
				if err := w.store.Prune(); err != nil {
					w.logger.Warn("analytics: async final prune failed", "error", err)
				}
				return
			}
			w.depth.Add(-1)
			buf = append(buf, e)
			if len(buf) >= w.cfg.batchSize {
				flushBuf()
			}
		case <-flush.C:
			flushBuf()
		case <-prune.C:
			if err := w.store.Prune(); err != nil {
				w.logger.Warn("analytics: async prune failed", "error", err)
			}
		}
	}
}
