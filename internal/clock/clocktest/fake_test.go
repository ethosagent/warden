package clocktest

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// start is the deterministic instant every test boots the fake at.
var start = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// recvImmediately drains c without waiting, reporting whether a value was
// buffered. Firing is synchronous with Advance/Set, so a timer that is due is
// readable at once and a timer that is not due must never block the test.
func recvImmediately(t *testing.T, c <-chan time.Time) (time.Time, bool) {
	t.Helper()
	select {
	case v := <-c:
		return v, true
	default:
		return time.Time{}, false
	}
}

// TestFakeImplementsClock pins the port: the fake must satisfy clock.Clock, so
// it can be injected anywhere a Clock is consumed.
func TestFakeImplementsClock(t *testing.T) {
	var _ clock.Clock = NewFake(start)
}

// TestFakeTimerDoesNotFireUntilAdvanced is the deterministic-expiry proof: a
// 10s timer never fires on its own (the fake never sleeps), and Advance(10s)
// fires it exactly once with the deadline as the value.
func TestFakeTimerDoesNotFireUntilAdvanced(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(10 * time.Second)

	if v, fired := recvImmediately(t, tm.C()); fired {
		t.Fatalf("10s timer fired without Advance: %v", v)
	}
	if got := f.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, want the untouched start %v", got, start)
	}

	f.Advance(10 * time.Second)
	v, fired := recvImmediately(t, tm.C())
	if !fired {
		t.Fatal("10s timer did not fire after Advance(10s)")
	}
	if want := start.Add(10 * time.Second); !v.Equal(want) {
		t.Fatalf("timer fired with %v, want the deadline %v", v, want)
	}
	if v, fired := recvImmediately(t, tm.C()); fired {
		t.Fatalf("one-shot timer fired twice: %v", v)
	}
}

// TestFakeAdvanceShortOfDeadline proves the boundary: an Advance that stops
// short of the deadline must not fire, and the remainder must.
func TestFakeAdvanceShortOfDeadline(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(10 * time.Second)

	f.Advance(5 * time.Second)
	if _, fired := recvImmediately(t, tm.C()); fired {
		t.Fatal("timer fired after Advance(5s) for a 10s deadline")
	}
	f.Advance(5 * time.Second)
	if _, fired := recvImmediately(t, tm.C()); !fired {
		t.Fatal("timer did not fire after advancing to its deadline")
	}
}

// TestFakeAfterSharesTimerSemantics covers the After convenience: it fires on
// Advance exactly like a NewTimer channel.
func TestFakeAfterSharesTimerSemantics(t *testing.T) {
	f := NewFake(start)
	ch := f.After(time.Minute)

	f.Advance(59 * time.Second)
	if _, fired := recvImmediately(t, ch); fired {
		t.Fatal("After(1m) fired 1s early")
	}
	f.Advance(time.Second)
	if v, fired := recvImmediately(t, ch); !fired || !v.Equal(start.Add(time.Minute)) {
		t.Fatalf("After(1m) = (%v, %v), want the deadline", v, fired)
	}
}

// TestFakeNowTracksAdvanceAndSet covers the time-travel primitives: Advance is
// relative, Set is absolute, and both are visible through Now.
func TestFakeNowTracksAdvanceAndSet(t *testing.T) {
	f := NewFake(start)

	f.Advance(90 * time.Minute)
	if got, want := f.Now(), start.Add(90*time.Minute); !got.Equal(want) {
		t.Fatalf("after Advance(90m) Now() = %v, want %v", got, want)
	}
	later := start.Add(72 * time.Hour)
	f.Set(later)
	if got := f.Now(); !got.Equal(later) {
		t.Fatalf("after Set(later) Now() = %v, want %v", got, later)
	}
	// Moving backward is legal (a scenario may rewind); Now must follow.
	f.Set(start)
	if got := f.Now(); !got.Equal(start) {
		t.Fatalf("after rewinding Set Now() = %v, want %v", got, start)
	}
}

// TestFakeTimerStop covers Stop before and after firing: a stopped timer never
// fires even when its deadline passes, and Stop on an already-fired (or
// stopped) timer reports false like *time.Timer.
func TestFakeTimerStop(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(10 * time.Second)

	if !tm.Stop() {
		t.Fatal("Stop on an active timer = false, want true")
	}
	f.Advance(time.Hour)
	if _, fired := recvImmediately(t, tm.C()); fired {
		t.Fatal("stopped timer fired after Advance past its deadline")
	}
	if tm.Stop() {
		t.Fatal("Stop on an already-stopped timer = true, want false")
	}

	fired := f.NewTimer(time.Second)
	f.Advance(time.Second)
	recvImmediately(t, fired.C())
	if fired.Stop() {
		t.Fatal("Stop on an already-fired timer = true, want false")
	}
}

// TestFakeTimerResetReArms covers Reset in both states: shortening a pending
// deadline, and re-arming an expired timer for a second fire.
func TestFakeTimerResetReArms(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(10 * time.Second)

	// Shorten a pending deadline: the 2s boundary now governs.
	tm.Reset(2 * time.Second)
	f.Advance(2 * time.Second)
	if v, fired := recvImmediately(t, tm.C()); !fired || !v.Equal(start.Add(2*time.Second)) {
		t.Fatalf("Reset(2s) timer = (%v, %v), want a fire at start+2s", v, fired)
	}

	// Re-arm an expired timer: Reset then Advance fires it once more.
	tm.Reset(5 * time.Second)
	f.Advance(5 * time.Second)
	if _, fired := recvImmediately(t, tm.C()); !fired {
		t.Fatal("re-armed timer did not fire after Advance to its new deadline")
	}
}

// TestFakeTimerResetDrainsUndeliveredFire covers the Go 1.23+ *time.Timer
// contract Reset must honor: a fire that was delivered into the channel but
// never read must be drained, so a receive after the Reset can never observe
// the stale deadline. Concretely: fire, do not read, Reset, Advance short of
// the new deadline — the channel must be empty.
func TestFakeTimerResetDrainsUndeliveredFire(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(10 * time.Second)

	f.Advance(10 * time.Second) // fires; the value sits in the buffer, unread.
	if tm.Reset(10 * time.Minute) {
		t.Fatal("Reset on an already-fired timer = true, want false")
	}

	f.Advance(9 * time.Minute) // short of the new deadline: must deliver nothing.
	if v, fired := recvImmediately(t, tm.C()); fired {
		t.Fatalf("Reset left a stale value in the channel: %v", v)
	}

	f.Advance(time.Minute) // exactly the new deadline: the re-arm governs.
	if v, fired := recvImmediately(t, tm.C()); !fired || !v.Equal(start.Add(10*time.Second).Add(10*time.Minute)) {
		t.Fatalf("timer after Reset = (%v, %v), want a fire at the new deadline", v, fired)
	}
}

// TestFakeTimerStopDrainsUndeliveredFire is Stop's half of the same contract:
// a pending, undelivered fire must not survive a Stop, so a later receive on
// the channel finds it empty.
func TestFakeTimerStopDrainsUndeliveredFire(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(10 * time.Second)

	f.Advance(10 * time.Second) // fires; the value sits in the buffer, unread.
	if tm.Stop() {
		t.Fatal("Stop on an already-fired timer = true, want false")
	}

	f.Advance(time.Hour)
	if v, fired := recvImmediately(t, tm.C()); fired {
		t.Fatalf("Stop left a stale value in the channel: %v", v)
	}
}

// TestFakeFiresTimersInDeadlineOrder proves determinism when one Advance
// crosses several deadlines: the earliest deadline is delivered first, ties
// broken by creation order.
func TestFakeFiresTimersInDeadlineOrder(t *testing.T) {
	f := NewFake(start)
	first := f.NewTimer(5 * time.Second)
	second := f.NewTimer(2 * time.Second)
	third := f.NewTimer(5 * time.Second)

	f.Advance(5 * time.Second)
	for _, want := range []struct {
		name string
		tm   clock.Timer
		at   time.Time
	}{
		{"2s", second, start.Add(2 * time.Second)},
		{"first 5s", first, start.Add(5 * time.Second)},
		{"third 5s", third, start.Add(5 * time.Second)},
	} {
		v, fired := recvImmediately(t, want.tm.C())
		if !fired || !v.Equal(want.at) {
			t.Fatalf("%s timer = (%v, %v), want a fire at %v", want.name, v, fired, want.at)
		}
	}
}

// TestFakeSetFiresDueTimers covers Set as a firing primitive: jumping the time
// forward with Set (not Advance) fires everything at or before the new instant.
func TestFakeSetFiresDueTimers(t *testing.T) {
	f := NewFake(start)
	tm := f.NewTimer(time.Hour)

	f.Set(start.Add(2 * time.Hour))
	if v, fired := recvImmediately(t, tm.C()); !fired || !v.Equal(start.Add(time.Hour)) {
		t.Fatalf("Set past the deadline = (%v, %v), want a fire at the deadline", v, fired)
	}
}

// TestFakePendingTimersTracksArming covers the driver-synchronization signal:
// arming raises the count, firing and Stop lower it.
func TestFakePendingTimersTracksArming(t *testing.T) {
	f := NewFake(start)
	if n := f.PendingTimers(); n != 0 {
		t.Fatalf("fresh fake PendingTimers = %d, want 0", n)
	}
	a, b := f.NewTimer(time.Second), f.NewTimer(time.Second)
	if n := f.PendingTimers(); n != 2 {
		t.Fatalf("after arming two timers PendingTimers = %d, want 2", n)
	}
	a.Stop()
	if n := f.PendingTimers(); n != 1 {
		t.Fatalf("after Stop PendingTimers = %d, want 1", n)
	}
	f.Advance(time.Second)
	recvImmediately(t, b.C())
	if n := f.PendingTimers(); n != 0 {
		t.Fatalf("after the fire PendingTimers = %d, want 0", n)
	}
}
