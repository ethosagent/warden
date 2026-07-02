package integration

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// integrationDownPrefix is the DedupKey prefix of the self-alert emitted when a
// sink fails delivery after retries. The router uses it to skip routing a
// down-alert back to the very instance it is about (self-loop guard).
const integrationDownPrefix = "integration_down:"

// RouterOptions tunes delivery. Zero values fall back to sane defaults.
type RouterOptions struct {
	// Timeout bounds a single delivery attempt (context.WithTimeout).
	Timeout time.Duration
	// MaxRetries is the number of retries after the first attempt. 0 uses the
	// default (2). (M1 does not support an explicit "zero retries" — a fail-fast
	// caller sets MaxRetries to 1 and relies on the short timeout.)
	MaxRetries int
	// QueueDepth is the max number of DISTINCT DedupKeys buffered per instance
	// before drop-oldest kicks in. It bounds the queue by distinct keys, not
	// event rate.
	QueueDepth int
}

// binding is one bound Alerter plus its coalescing delivery queue. The queue is
// keyed by DedupKey: enqueuing a key already present REPLACES it (freshest
// state) instead of growing the buffer.
type binding struct {
	name    string
	match   []MatchClause
	alerter Alerter

	mu      sync.Mutex
	order   []string         // FIFO of DedupKeys awaiting delivery
	pending map[string]Alert // DedupKey -> freshest Alert
	dropped int              // per-instance dropped-on-overflow counter
	signal  chan struct{}    // buffered(1) wake for the drain goroutine
}

// enqueue adds a to the queue, coalescing by DedupKey and dropping the oldest
// distinct key on overflow. It never blocks.
func (b *binding) enqueue(a Alert, depth int, logger *slog.Logger) {
	b.mu.Lock()
	if _, exists := b.pending[a.DedupKey]; exists {
		// Coalesce: replace the queued alert with the freshest state, no growth.
		b.pending[a.DedupKey] = a
	} else {
		if len(b.order) >= depth {
			// Drop-oldest: the newest state is the most actionable. Never silent.
			oldest := b.order[0]
			b.order = b.order[1:]
			delete(b.pending, oldest)
			b.dropped++
			// TODO(M2): ride the accumulated dropped-count on the next delivery
			// payload (Alerter.Alert's signature is fixed, so M1 only counts +
			// logs + exposes via DroppedCount).
			logger.Warn("integration: router queue overflow, dropped oldest alert",
				"integration", b.name, "droppedTotal", b.dropped, "droppedKey", oldest)
		}
		b.order = append(b.order, a.DedupKey)
		b.pending[a.DedupKey] = a
	}
	b.mu.Unlock()

	select {
	case b.signal <- struct{}{}:
	default:
	}
}

// dequeue pops the oldest queued alert, returning false when the queue is empty.
func (b *binding) dequeue() (Alert, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		return Alert{}, false
	}
	key := b.order[0]
	b.order = b.order[1:]
	a := b.pending[key]
	delete(b.pending, key)
	return a, true
}

// Router evaluates each instance's match predicate and PUSHES matching Alerts to
// its per-instance coalescing queue, draining it in a dedicated goroutine with
// per-attempt timeout, bounded retry, dead-letter, and an integration_down
// self-alert on persistent failure. It never blocks the AlertManager.
type Router struct {
	store  *Store
	bus    *Bus
	logger *slog.Logger
	opts   RouterOptions

	now         func() time.Time
	backoffBase time.Duration

	mu       sync.RWMutex
	bindings []*binding
	started  bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewRouter constructs a Router. A nil logger defaults to slog.Default(); zero
// RouterOptions fields fall back to sane defaults.
func NewRouter(store *Store, bus *Bus, logger *slog.Logger, opts RouterOptions) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 2
	}
	if opts.QueueDepth <= 0 {
		opts.QueueDepth = 256
	}
	return &Router{
		store:       store,
		bus:         bus,
		logger:      logger,
		opts:        opts,
		now:         time.Now,
		backoffBase: 100 * time.Millisecond,
	}
}

// Bind registers an integration instance under name with its routing match. It
// type-asserts capabilities: only an Alerter gets an alert-delivery queue. An
// EventStreamer is accepted but NOT wired in M1 (logged). An instance
// implementing neither is not bound.
func (r *Router) Bind(name string, match []MatchClause, inst Integration) {
	b := &binding{
		name:    name,
		match:   match,
		pending: map[string]Alert{},
		signal:  make(chan struct{}, 1),
	}
	if a, ok := inst.(Alerter); ok {
		b.alerter = a
	}
	if _, ok := inst.(EventStreamer); ok {
		r.logger.Info("integration: EventStreamer capability present but NOT wired in M1 (raw event firehose is M2)", "integration", name)
	}
	if b.alerter == nil {
		r.logger.Warn("integration: instance implements no wired capability (no Alerter); not binding alert delivery", "integration", name)
		return
	}
	r.mu.Lock()
	r.bindings = append(r.bindings, b)
	r.mu.Unlock()
}

// Deliver enqueues a to every bound instance whose match predicate accepts it.
// It first asserts egress-safety (the single choke point) and drops the alert
// entirely if a field exceeds its cap. It never blocks — enqueue returns
// immediately; drops are delivery-only (the Alert is already persisted).
func (r *Router) Deliver(a Alert) {
	if err := assertEgressSafe(a); err != nil {
		r.logger.Error("integration: alert failed egress-safety check; dropping (not delivering)", "id", a.ID, "err", err)
		return
	}

	// Self-loop guard: an integration_down:<name> alert must never route back to
	// <name>, or a persistently failing sink would loop forever (deliver fails →
	// emit down → route to same sink → fail → …).
	downTarget := ""
	if len(a.DedupKey) > len(integrationDownPrefix) && a.DedupKey[:len(integrationDownPrefix)] == integrationDownPrefix {
		downTarget = a.DedupKey[len(integrationDownPrefix):]
	}

	r.mu.RLock()
	bindings := r.bindings
	r.mu.RUnlock()
	for _, b := range bindings {
		if downTarget != "" && downTarget == b.name {
			continue
		}
		if !matchAny(b.match, a) {
			continue
		}
		b.enqueue(a, r.opts.QueueDepth, r.logger)
	}
}

// Start spawns one drain goroutine per bound instance. It is idempotent.
func (r *Router) Start(ctx context.Context) {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	dctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	bindings := append([]*binding(nil), r.bindings...)
	r.mu.Unlock()

	for _, b := range bindings {
		r.wg.Add(1)
		go r.drain(dctx, b)
	}
}

// Stop cancels drains and waits for them to finish (or until ctx is done). It is
// idempotent.
func (r *Router) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return nil
	}
	r.started = false
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DroppedCount returns the number of overflow drops for the named instance.
func (r *Router) DroppedCount(name string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.bindings {
		if b.name == name {
			b.mu.Lock()
			d := b.dropped
			b.mu.Unlock()
			return d
		}
	}
	return 0
}

// drain is the per-instance delivery loop.
func (r *Router) drain(ctx context.Context, b *binding) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.signal:
		}
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			a, ok := b.dequeue()
			if !ok {
				break
			}
			r.deliver(ctx, b, a)
		}
	}
}

// deliver attempts one alert to one sink with bounded retry + backoff. On
// persistent failure it dead-letters and emits an integration_down self-alert.
func (r *Router) deliver(ctx context.Context, b *binding, a Alert) {
	attempts := r.opts.MaxRetries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(r.backoff(attempt)):
			}
			if err := ctx.Err(); err != nil {
				lastErr = err
				break
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		err := b.alerter.Alert(attemptCtx, a)
		cancel()
		if err == nil {
			return
		}
		lastErr = err
		r.logger.Warn("integration: alert delivery attempt failed", "integration", b.name, "id", a.ID, "attempt", attempt+1, "err", err)
	}
	r.onDeliveryFailure(b, a, lastErr)
}

// backoff returns the pre-delay before retry #attempt (1-based), exponential and
// capped so a broken sink cannot spin.
func (r *Router) backoff(attempt int) time.Duration {
	d := r.backoffBase << (attempt - 1)
	const max = 5 * time.Second
	if d <= 0 || d > max {
		return max
	}
	return d
}

// onDeliveryFailure records a dead-letter and emits an integration_down
// self-alert onto the bus so a failing sink is itself observable. The self-loop
// guard in Deliver prevents that alert from routing back to this instance.
func (r *Router) onDeliveryFailure(b *binding, a Alert, cause error) {
	msg := "unknown error"
	if cause != nil {
		msg = cause.Error()
	}
	r.logger.Error("integration: alert delivery permanently failed; dead-lettering", "integration", b.name, "id", a.ID, "err", msg)

	if err := r.store.RecordDeadLetter(a.ID, b.name, msg, r.now()); err != nil {
		r.logger.Error("integration: record dead-letter failed", "integration", b.name, "id", a.ID, "err", err)
	}

	down := Finding{
		RuleID:   "integration_down",
		Category: "integration",
		Severity: SevHigh,
		Subject:  Subject{Tool: b.name},
		Summary:  boundedSummary(fmt.Sprintf("integration %q delivery failed after retries", b.name)),
		Evidence: boundEvidence(Evidence("error=" + firstLine(msg))),
		DedupKey: integrationDownPrefix + b.name,
		Ts:       r.now(),
	}
	r.bus.PublishFinding(down)
}
