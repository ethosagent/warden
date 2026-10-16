package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// await polls cond until it holds or the deadline expires. The fake clock's
// firing is synchronous, so these conditions go true in microseconds; the
// deadline only bounds a regression (a loop that never arms or never ticks).
func await(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(d)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(time.Millisecond):
		}
	}
}

// fakeControlPlaneClient is a package-local fake ControlPlaneClient that drives the
// long-poll loop without a live HTTP server. It proves the loop depends ONLY on the
// ControlPlaneClient interface (transport is fully swappable): PollLong reports a
// change once, then blocks on ctx so the loop applies exactly one reload.
type fakeControlPlaneClient struct {
	mu        sync.Mutex
	polls     int
	policy    config.Policy
	settings  *config.SettingsWire
	heartbeat int
}

func (f *fakeControlPlaneClient) PollLong(ctx context.Context, _ time.Duration) (bool, error) {
	f.mu.Lock()
	f.polls++
	first := f.polls == 1
	f.mu.Unlock()
	if first {
		return true, nil // signal one policy change
	}
	<-ctx.Done() // then block until cancelled so the loop settles
	return false, ctx.Err()
}

func (f *fakeControlPlaneClient) GetPolicy() (config.Policy, error) { return f.policy, nil }

func (f *fakeControlPlaneClient) Settings() *config.SettingsWire { return f.settings }

func (f *fakeControlPlaneClient) Heartbeat(context.Context) error {
	f.mu.Lock()
	f.heartbeat++
	f.mu.Unlock()
	return nil
}

// beats returns the heartbeat count so tests can await an exact tick.
func (f *fakeControlPlaneClient) beats() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeat
}

// recordingEvaluator is a minimal PolicyEvaluator that records the policy the
// long-poll hands it via Replace, so the test can assert the loop propagated the
// fetched policy through the interface alone.
type recordingEvaluator struct {
	mu       sync.Mutex
	replaced []config.Policy
}

func (e *recordingEvaluator) Evaluate(string, int, policy.Scheme) policy.Decision {
	return policy.Decision(0)
}

func (e *recordingEvaluator) Replace(p config.Policy) {
	e.mu.Lock()
	e.replaced = append(e.replaced, p)
	e.mu.Unlock()
}

// TestLongPollControlPlane_DrivesReloadViaInterface proves the long-poll loop is
// wired against the ControlPlaneClient + PolicyEvaluator seams only: a fake CP that
// reports a change makes the loop fetch the policy, Replace it on the evaluator, and
// run onApply — all without any HTTP server or the concrete *config.RemoteProvider.
func TestLongPollControlPlane_DrivesReloadViaInterface(t *testing.T) {
	want := config.Policy{LogLevel: "debug"}
	fake := &fakeControlPlaneClient{policy: want}
	ev := &recordingEvaluator{}

	var applied int
	var appliedMu sync.Mutex
	onApply := func() {
		appliedMu.Lock()
		applied++
		appliedMu.Unlock()
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		longPollControlPlane(ctx, clock.Real(), fake, ev, 10*time.Millisecond, logger, onApply)
		close(done)
	}()

	// Wait until the single change has been applied, then stop the loop.
	deadline := time.After(2 * time.Second)
	for {
		appliedMu.Lock()
		n := applied
		appliedMu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("onApply was never invoked; loop did not consume the interface change")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("long-poll loop did not return after ctx cancel")
	}

	ev.mu.Lock()
	defer ev.mu.Unlock()
	if len(ev.replaced) != 1 {
		t.Fatalf("evaluator.Replace called %d times, want exactly 1", len(ev.replaced))
	}
	if ev.replaced[0].LogLevel != want.LogLevel {
		t.Errorf("evaluator got policy %+v, want %+v (fetched via GetPolicy)", ev.replaced[0], want)
	}
}

// TestHeartbeatControlPlane_TicksViaInterface proves the heartbeat loop pings the
// control plane through the ControlPlaneClient interface alone (no live server).
func TestHeartbeatControlPlane_TicksViaInterface(t *testing.T) {
	fake := &fakeControlPlaneClient{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		heartbeatControlPlane(ctx, clock.Real(), fake, time.Millisecond, logger)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for fake.beats() < 1 {
		select {
		case <-deadline:
			t.Fatal("heartbeat never fired via the interface")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat loop did not return after ctx cancel")
	}
}

// TestHeartbeatControlPlane_FakeClockOneBeatPerAdvance proves the heartbeat
// ticks on the INJECTED clock: with the fake, exactly one heartbeat lands per
// Advance(interval) — and before the first Advance none can fire at all, since
// the loop's only wake-up is the fake's timer. Real time plays no role (the
// interval here is a minute; the test returns in microseconds).
func TestHeartbeatControlPlane_FakeClockOneBeatPerAdvance(t *testing.T) {
	fakeClk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cp := &fakeControlPlaneClient{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		heartbeatControlPlane(ctx, fakeClk, cp, time.Minute, logger)
		close(done)
	}()

	// Without an Advance the loop has no wake-up source: zero heartbeats, ever.
	if n := cp.beats(); n != 0 {
		t.Fatalf("heartbeats before any Advance = %d, want 0", n)
	}
	// The loop must have armed its first timer before the first Advance is
	// guaranteed to fire it.
	await(t, 2*time.Second, "the heartbeat loop to arm its timer", func() bool {
		return fakeClk.PendingTimers() == 1
	})
	const want = 3
	for i := 1; i <= want; i++ {
		fakeClk.Advance(time.Minute)
		// Beat i must land AND the loop must re-arm before the next Advance —
		// otherwise the advance could cross no deadline at all.
		await(t, 2*time.Second, fmt.Sprintf("heartbeat %d and the re-arm", i), func() bool {
			return cp.beats() >= i && fakeClk.PendingTimers() == 1
		})
		if n := cp.beats(); n != i {
			t.Fatalf("heartbeats after %d Advance(interval) = %d, want exactly %d", i, n, i)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat loop did not return after ctx cancel")
	}
}

// gatedControlPlaneClient makes every Heartbeat slow: it counts the beat and
// then blocks until the test closes the gate, simulating a control plane slow
// to answer. After the gate is closed the beat returns at once, so later beats
// (if any) do not stall the loop.
type gatedControlPlaneClient struct {
	gate chan struct{}

	mu        sync.Mutex
	inFlight  int
	heartbeat int
}

func (g *gatedControlPlaneClient) GetPolicy() (config.Policy, error) { return config.Policy{}, nil }
func (g *gatedControlPlaneClient) Settings() *config.SettingsWire    { return nil }
func (g *gatedControlPlaneClient) PollLong(ctx context.Context, _ time.Duration) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func (g *gatedControlPlaneClient) Heartbeat(context.Context) error {
	g.mu.Lock()
	g.inFlight++
	g.heartbeat++
	g.mu.Unlock()
	<-g.gate
	return nil
}

func (g *gatedControlPlaneClient) beats() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.heartbeat
}

func (g *gatedControlPlaneClient) slow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight > 0
}

// TestHeartbeatControlPlane_FixedPeriodDespiteSlowBeat pins the production
// cadence the ticket requires (unchanged from a ticker): the period is measured
// from the START of each beat, so a slow heartbeat does not drift the schedule.
// While beat 1 is still in flight the fake clock runs past the next boundary —
// with a fixed period that boundary fires into the buffered channel and beat 2
// lands the moment the loop is free; a cadence that re-arms only AFTER the beat
// (period = interval + beat duration) would schedule beat 2 a full beat later
// and this test goes red.
func TestHeartbeatControlPlane_FixedPeriodDespiteSlowBeat(t *testing.T) {
	fakeClk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cp := &gatedControlPlaneClient{gate: make(chan struct{})}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		heartbeatControlPlane(ctx, fakeClk, cp, time.Minute, logger)
		close(done)
	}()
	await(t, 2*time.Second, "the heartbeat loop to arm its timer", func() bool {
		return fakeClk.PendingTimers() == 1
	})

	// Beat 1 fires and runs slow; the loop is inside cp.Heartbeat.
	fakeClk.Advance(time.Minute)
	await(t, 2*time.Second, "the slow beat to be in flight", cp.slow)

	// The next period elapses — twice over — while beat 1 is still running.
	fakeClk.Advance(2 * time.Minute)

	// Release beat 1: a fixed-period loop has beat 2 already buffered at its
	// boundary and starts it immediately, with no further Advance.
	close(cp.gate)
	await(t, 2*time.Second, "heartbeat 2 and the re-arm", func() bool {
		return cp.beats() >= 2 && fakeClk.PendingTimers() == 1
	})
	if n := cp.beats(); n != 2 {
		t.Fatalf("heartbeats after a slow beat plus 2 intervals = %d, want exactly 2 (fixed period)", n)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat loop did not return after ctx cancel")
	}
}

// TestLongPollControlPlane_BackoffOnFakeClock proves the long-poll's capped
// backoff runs on the injected clock: a permanently failing CP is retried once
// per Advance of the current backoff, exactly, with no real time passing.
func TestLongPollControlPlane_BackoffOnFakeClock(t *testing.T) {
	fakeClk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cp := &failingControlPlaneClient{}
	ev := &recordingEvaluator{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		longPollControlPlane(ctx, fakeClk, cp, ev, time.Minute, logger, nil)
		close(done)
	}()

	// The loop's first poll fails immediately, then it arms its first backoff.
	await(t, 2*time.Second, "the first poll and its backoff timer", func() bool {
		return cp.polls() >= 1 && fakeClk.PendingTimers() == 1
	})
	// Backoff starts at 1s and doubles to the 15s cap: one Advance of exactly
	// the current backoff must produce exactly one retry — no real time passes.
	for i, backoff := 0, time.Second; i < 5; i++ {
		fakeClk.Advance(backoff)
		await(t, 2*time.Second, fmt.Sprintf("retry %d and its next backoff timer", i+2), func() bool {
			return cp.polls() >= i+2 && fakeClk.PendingTimers() == 1
		})
		if n := cp.polls(); n != i+2 {
			t.Fatalf("polls after %d backoff advances = %d, want exactly %d", i+1, n, i+2)
		}
		if backoff *= 2; backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("long-poll loop did not return after ctx cancel")
	}
}

// failingControlPlaneClient always errors, driving the long-poll loop down its
// backoff path without a live control plane.
type failingControlPlaneClient struct {
	mu   sync.Mutex
	poll int
}

func (f *failingControlPlaneClient) PollLong(context.Context, time.Duration) (bool, error) {
	f.mu.Lock()
	f.poll++
	f.mu.Unlock()
	return false, errors.New("control plane unreachable")
}

func (f *failingControlPlaneClient) GetPolicy() (config.Policy, error) {
	return config.Policy{}, errors.New("control plane unreachable")
}

func (f *failingControlPlaneClient) Settings() *config.SettingsWire { return nil }

func (f *failingControlPlaneClient) Heartbeat(context.Context) error { return nil }

// polls returns the poll count so tests can await an exact retry.
func (f *failingControlPlaneClient) polls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.poll
}
