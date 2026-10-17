// Package clock is Warden's time port: a tiny interface every time-dependent
// component ticks on, real by default and fake-injectable in tests. It exists
// so expiry and interval behavior (P2 token/key expiry, the worker's control
// plane loops) is provable without real sleeps — rule L3 in #349 migrates each
// phase's own time sites; nothing outside the phases that opt in consumes it.
package clock

import "time"

// Clock is the time source time-dependent components depend on. The surface is
// exactly the three operations Warden consumes — read the instant, wait a
// duration, arm a one-shot timer — so a fake can implement it in a page.
type Clock interface {
	// Now returns the current instant.
	Now() time.Time
	// After waits for d to elapse and then sends the current instant on the
	// returned channel. Like time.After, the timer is not collected until it
	// fires; long-lived loops should prefer NewTimer so they can Stop it.
	After(d time.Duration) <-chan time.Time
	// NewTimer returns a Timer that fires once, after d.
	NewTimer(d time.Duration) Timer
}

// Timer is the one-shot timer half of Clock, mirroring the *time.Timer methods
// consumers already know. C delivers the deadline's instant once; Stop and
// Reset keep *time.Timer's contract (Stop reports whether the timer was still
// pending; Reset reports whether it had been active).
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// Real returns the Clock backed by the standard library — the production
// default every consumer falls back to when no Clock was injected.
func Real() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (realClock) NewTimer(d time.Duration) Timer         { return realTimer{t: time.NewTimer(d)} }

// realTimer adapts *time.Timer to the Timer port.
type realTimer struct{ t *time.Timer }

func (t realTimer) C() <-chan time.Time        { return t.t.C }
func (t realTimer) Stop() bool                 { return t.t.Stop() }
func (t realTimer) Reset(d time.Duration) bool { return t.t.Reset(d) }
