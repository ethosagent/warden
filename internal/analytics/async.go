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
	onBatch       func([]Event)
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

// WithOnBatch installs a TEE: fn is invoked with each batch of events as it is
// pulled off the queue by the single writer goroutine — OFF the request hot path
// (the request goroutine only enqueues). It runs regardless of whether the
// subsequent SQLite write succeeds or is retried, so every event is teed exactly
// ONCE. The local-only worker uses this to feed its own event stream into the
// embedded alert pipeline's Observe fan-in without adding latency to request
// handling. fn must not retain the slice past the call (the backing array is a
// fresh allocation per batch, but the contract is copy-if-kept). A nil fn (the
// default) disables the tee at zero cost.
func WithOnBatch(fn func([]Event)) AsyncOption { return func(c *asyncConfig) { c.onBatch = fn } }

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

	// flushReq carries one ack channel per Flush call to the writer goroutine —
	// the only goroutine that may touch buf, so a flush must run there. The ack
	// receives the batch write's outcome (nil = the queue as of the request has
	// been persisted; non-nil = the write failed and the batch is retained for
	// retry), so a caller never mistakes an unpersisted batch for a drained one.
	flushReq chan chan error
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
		store:    store,
		ch:       make(chan Event, cfg.queueCap),
		cfg:      cfg,
		logger:   cfg.logger,
		flushReq: make(chan chan error),
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

// Flush persists every event queued at the time of the call and returns — no
// waiting for the flush tick, no deadline. It hands a flush request to the
// single writer goroutine (the only goroutine allowed to touch the batch), which
// drains the channel into the batch, writes it, and acknowledges; Flush blocks
// on that acknowledgment, so on nil a reader over the base store sees a
// read-your-writes view the moment Flush returns. A FAILED batch write is NOT
// acked as persisted: the error is returned (the batch stays buffered for the
// next flush, never dropped), so a caller reading the base store through Flush
// — the L1 harness's event oracle — fails clearly instead of reading a short
// list. The onBatch tee fires for the flushed batch exactly as it would on a
// tick flush. After Close it is a no-op returning nil (Close already drained).
func (w *asyncWriter) Flush() error {
	// The same closeMu barrier Close uses: while Flush holds the read lock,
	// Close cannot set closed or close ch, so the writer goroutine is provably
	// alive to receive the request, and the ack is provably coming.
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()
	if w.closed {
		return nil
	}
	// Buffered so the writer's send can never block, even if this goroutine
	// went away between the request and the receive.
	ack := make(chan error, 1)
	w.flushReq <- ack
	return <-ack
}

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

	// tee accumulates the events observed since the last emit. It is kept SEPARATE
	// from buf because buf is retained across a failed write (retry), while the tee
	// must fire exactly once per event regardless of persistence retries. It stays
	// nil (never allocated) when no onBatch tee is installed.
	var tee []Event
	// emitTee hands the accumulated batch to the tee (off the request hot path) and
	// starts a FRESH backing array so the callee can never observe a slot reused by
	// a later batch. It is decoupled from write success so an event is teed once,
	// when its flush point is reached.
	emitTee := func() {
		if w.cfg.onBatch == nil || len(tee) == 0 {
			return
		}
		w.cfg.onBatch(tee)
		tee = nil
	}

	// flushBuf writes the accumulated batch and prunes every pruneEvery flushes.
	// On a write error it retains buf (does not clear) so the events are retried
	// on the next flush rather than dropped — backpressure will build if the
	// error persists, which is the correct, non-lossy behavior — and returns the
	// error so an on-demand Flush can surface it instead of acking a batch that
	// never landed.
	flushBuf := func() error {
		if len(buf) == 0 {
			return nil
		}
		if err := w.store.StoreEventsBatch(buf); err != nil {
			w.logger.Warn("analytics: async batch write failed; retrying", "error", err, "batch", len(buf))
			return err
		}
		buf = buf[:0]
		flushes++
		if flushes%w.cfg.pruneEvery == 0 {
			if err := w.store.Prune(); err != nil {
				w.logger.Warn("analytics: async prune failed", "error", err)
			}
		}
		return nil
	}

	for {
		select {
		case e, ok := <-w.ch:
			if !ok {
				// Close: channel drained of live events. Flush the tail, tee it, and
				// run a final prune, then exit.
				_ = flushBuf() // shutdown drain: the error is logged in flushBuf
				emitTee()
				if err := w.store.Prune(); err != nil {
					w.logger.Warn("analytics: async final prune failed", "error", err)
				}
				return
			}
			w.depth.Add(-1)
			buf = append(buf, e)
			if w.cfg.onBatch != nil {
				tee = append(tee, e)
			}
			if len(buf) >= w.cfg.batchSize {
				_ = flushBuf() // tick/batch flush: the error is logged in flushBuf
				emitTee()
			}
		case ack := <-w.flushReq:
			// On-demand flush (Flush): pull everything already queued into the
			// batch, write it, then acknowledge WITH the write's outcome — a
			// failed write is returned, never acked as persisted. A producer
			// that lands mid-drain waits for the next flush point — Flush's
			// contract covers the queue as of the request, never a moving
			// target. Exactly ONE ack value is sent: the first write failure
			// wins (a drain that spans several batches reports the failure, and
			// the buffered ack channel cannot absorb a second send).
			var flushErr error
		drain:
			for {
				select {
				case e, ok := <-w.ch:
					if !ok {
						break drain // Close raced in; the close path flushes below
					}
					w.depth.Add(-1)
					buf = append(buf, e)
					if w.cfg.onBatch != nil {
						tee = append(tee, e)
					}
					if len(buf) >= w.cfg.batchSize {
						if err := flushBuf(); err != nil && flushErr == nil {
							flushErr = err
						}
						emitTee()
					}
				default:
					break drain
				}
			}
			if err := flushBuf(); err != nil && flushErr == nil {
				flushErr = err
			}
			emitTee()
			ack <- flushErr
		case <-flush.C:
			_ = flushBuf() // tick flush: the error is logged in flushBuf
			emitTee()
		case <-prune.C:
			if err := w.store.Prune(); err != nil {
				w.logger.Warn("analytics: async prune failed", "error", err)
			}
		}
	}
}
