package proxy

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
)

// Inflight tracks the proxy's request-scoped work so a reader can wait for
// every scope's TERMINAL bookkeeping (its analytics event, metric, decision
// log) to be recorded — the deterministic-quiescence seam the L1 test harness
// reads through (worker.Overrides.Inflight; production never sets it).
//
// Why it exists: the proxy records an allowed request's event only AFTER the
// response has been relayed to the agent (#363), so a reader that flushes the
// analytics queue right after a response arrives can race the proxy goroutine
// and read short. Waiting for the tracker to drain instead of sleeping makes
// the oracles exact: a drained tracker happens-after every bookkeeping the
// requests it names will do, because every scope calls done() only after its
// bookkeeping is enqueued.
//
// Units are described with the same one-line, log-safe text the analytics
// events use (protocol, method, host, path — placeholders swapped, no bodies,
// no secrets), so a stalled wait can name what it is waiting for.
//
// The critical section is a plain sync.Mutex; WaitIdle drops the lock around
// its channel wait and re-takes it after (its defer unlocks on every path,
// including a cancelled context). The tracker is assembly-only — production
// never constructs it — so its cost is irrelevant to the hot path.
type Inflight struct {
	mu sync.Mutex
	// open, next and zero are guarded by mu.
	open map[int64]string // id -> description; every entry has a pending done()
	next int64
	// zero is closed each time open becomes empty and replaced by the next
	// Start on an empty tracker; waiters park on the instance they saw.
	zero chan struct{}
}

// NewInflight builds an empty tracker.
func NewInflight() *Inflight {
	return &Inflight{
		open: make(map[int64]string),
		zero: make(chan struct{}),
	}
}

// Start marks one unit of request-scoped work in flight and returns its done
// function. done is idempotent (a scope both steps out early on a streaming
// handoff and defers its final done) and MUST eventually be called exactly
// once-net: the tracker has no other way to drain.
func (t *Inflight) Start(desc string) func() {
	t.mu.Lock()
	if len(t.open) == 0 {
		// Fresh batch: retire the channel the previous drain closed so the
		// next waiter parks on one that will actually fire.
		t.zero = make(chan struct{})
	}
	t.next++
	id := t.next
	t.open[id] = desc
	t.mu.Unlock()
	var fired atomic.Bool
	return func() {
		if !fired.CompareAndSwap(false, true) {
			return // idempotent: the scope defers done AND steps out early
		}
		t.finish(id)
	}
}

// finish removes one unit; closing zero on the drain is the broadcast.
func (t *Inflight) finish(id int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.open[id]; !ok {
		return // already finished (defensive; done guards itself anyway)
	}
	delete(t.open, id)
	if len(t.open) == 0 {
		close(t.zero)
	}
}

// WaitIdle blocks until every tracked unit is done, or ctx is done. It wakes
// on the drain itself — no polling — so an oracle reading right after a
// response arrives never sleeps.
func (t *Inflight) WaitIdle(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.open) > 0 {
		ch := t.zero
		// Drop the lock around the wait so a finish can broadcast. The lock
		// discipline must stay balanced: re-take it on EVERY path out of the
		// select — including the cancelled one — so the deferred Unlock above
		// always unlocks a held lock.
		t.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			t.mu.Lock()
			return ctx.Err()
		}
		t.mu.Lock()
	}
	return nil
}

// InFlight returns the sorted descriptions of the units still tracked —
// the "what is still in flight" a deadline failure names.
func (t *Inflight) InFlight() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.open))
	for _, desc := range t.open {
		out = append(out, desc)
	}
	sort.Strings(out)
	return out
}

// inflightStart is the hot-path entry: production (cfg.Inflight == nil) pays
// one nil check and no allocation; the assembly-only harness tracker pays the
// map insert. Returns nil when untracked — callers spread `if done != nil`.
// Callers guard the DESCRIPTION build the same way (it concatenates strings);
// see the four call sites (h1, h2/gRPC, SSE, WS).
func (p *Proxy) inflightStart(desc string) func() {
	if p.cfg.Inflight == nil {
		return nil
	}
	return p.cfg.Inflight.Start(desc)
}

// beforeTerminal runs the test-only terminal hook when installed (the
// assembly-only worker.Overrides.BeforeTerminal; production nil = one nil
// check): the harness parks terminal bookkeeping in it to make the #363
// window deterministic.
func (p *Proxy) beforeTerminal() {
	if p.cfg.BeforeTerminal != nil {
		p.cfg.BeforeTerminal()
	}
}

// runInflight runs done when non-nil; the scope bookkeeping around an early
// step-out reads better as a call than an if.
func runInflight(done func()) {
	if done != nil {
		done()
	}
}
