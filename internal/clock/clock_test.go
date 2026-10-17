package clock

import (
	"testing"
	"time"
)

// TestRealNowTracksWallClock pins Real's Now to the standard library: it must
// track the wall clock, not a frozen or scaled instant.
func TestRealNowTracksWallClock(t *testing.T) {
	before := time.Now()
	got := Real().Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("Real().Now() = %v, want a wall-clock instant in [%v, %v]", got, before, after)
	}
}

// TestRealTimerFires covers the Timer port on the real clock: a millisecond
// timer fires once, Stop on the fired timer reports false, and After shares
// the same behavior.
func TestRealTimerFires(t *testing.T) {
	clk := Real()
	tm := clk.NewTimer(time.Millisecond)
	select {
	case <-tm.C():
	case <-time.After(5 * time.Second):
		t.Fatal("real timer did not fire within 5s")
	}
	if tm.Stop() {
		t.Error("Stop on a fired timer = true, want false")
	}

	ch := clk.After(time.Millisecond)
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("After did not fire within 5s")
	}
}
