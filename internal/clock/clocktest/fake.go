// Package clocktest holds the fake Clock for tests that need deterministic
// time: expiry fires on Advance, never on a real sleep. It lives in its own
// package so test-only code never ships inside the production clock port.
package clocktest

import (
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// Fake is a manually-advanced clock.Clock. Time moves only when the test moves
// it — Advance(d) relative, Set(t) absolute — and timers fire synchronously
// during that move, so an expiry test is exact and instant. Safe for
// concurrent use: every method takes the Fake's mutex, so a goroutine running
// a real loop on the fake races with nothing (go test -race clean).
type Fake struct {
	mu  sync.Mutex
	now time.Time
	// seq orders timers created at the same instant (deadline ties fire in
	// creation order, like real timers armed in sequence).
	seq    uint64
	timers map[uint64]*fakeTimer
}

var _ clock.Clock = (*Fake)(nil)

// NewFake returns a Fake starting at start. Scenarios pass a fixed instant so
// every derived timestamp in a test run is reproducible.
func NewFake(start time.Time) *Fake {
	return &Fake{now: start, timers: make(map[uint64]*fakeTimer)}
}

// Now returns the fake's current instant.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake time forward by d and fires every timer whose
// deadline has been reached — earliest deadline first, ties by creation order.
// It never sleeps: firing is a send into a cap-1 buffered channel that never
// blocks, mirroring time.Timer (a second fire before the first is drained is
// dropped, not queued).
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advanceTo(f.now.Add(d))
}

// Set moves the fake time to t absolutely (forward or back) and, when moving
// forward, fires every timer whose deadline is at or before t — Advance in
// absolute form.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advanceTo(t)
}

// NewTimer returns a Timer firing once at now+d. Like time.NewTimer's timer,
// it is one-shot: Reset re-arms it, Stop disarms it.
func (f *Fake) NewTimer(d time.Duration) clock.Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.timers == nil {
		f.timers = make(map[uint64]*fakeTimer)
	}
	f.seq++
	t := &fakeTimer{
		f:        f,
		c:        make(chan time.Time, 1),
		deadline: f.now.Add(d),
		seq:      f.seq,
	}
	f.timers[t.seq] = t
	return t
}

// After is NewTimer's channel, matching clock.Clock's After.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	return f.NewTimer(d).C()
}

// PendingTimers reports how many timers are currently armed. A driving test
// uses it to synchronize with a loop running on the fake: "the goroutine has
// (re)armed its next timer" is exactly the moment an Advance is guaranteed to
// fire it, closing the race between observing a tick and arming the next one.
func (f *Fake) PendingTimers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.timers)
}

// advanceTo moves now to target and fires due timers in deadline order. The
// caller must hold f.mu.
func (f *Fake) advanceTo(target time.Time) {
	f.now = target
	var due []*fakeTimer
	for _, t := range f.timers {
		if !t.deadline.After(target) {
			due = append(due, t)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].deadline.Equal(due[j].deadline) {
			return due[i].deadline.Before(due[j].deadline)
		}
		return due[i].seq < due[j].seq
	})
	for _, t := range due {
		delete(f.timers, t.seq) // one-shot: a fired timer leaves the registry
		select {
		case t.c <- t.deadline:
		default:
		}
	}
}

// fakeTimer is Fake's clock.Timer. The channel is cap-1 and the fire is a
// non-blocking send, so Advance never blocks on a slow consumer and never
// sleeps; lifecycle (Stop/Reset) goes through the owning Fake's mutex.
type fakeTimer struct {
	f        *Fake
	c        chan time.Time
	deadline time.Time
	seq      uint64
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

// drain removes any pending, undelivered fire from the channel, matching Go
// 1.23+ time.Timer: after Stop or Reset, a receive can never observe a stale
// value. Non-blocking, so it is safe under the owning Fake's mutex (a buffered
// receive never waits, and fires happen only inside Advance/Set on that mutex).
func (t *fakeTimer) drain() {
	for {
		select {
		case <-t.c:
		default:
			return
		}
	}
}

// Stop disarms the timer, reporting whether it was still pending (the
// *time.Timer contract), and drains any undelivered fire.
func (t *fakeTimer) Stop() bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	t.drain()
	if _, pending := t.f.timers[t.seq]; !pending {
		return false
	}
	delete(t.f.timers, t.seq)
	return true
}

// Reset arms the timer at now+d (or re-arms an expired one), reporting whether
// it had been active before the call (the *time.Timer contract), and drains any
// undelivered fire from the previous arming.
func (t *fakeTimer) Reset(d time.Duration) bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	t.drain()
	_, wasActive := t.f.timers[t.seq]
	t.deadline = t.f.now.Add(d)
	t.f.timers[t.seq] = t
	return wasActive
}
