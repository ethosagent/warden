package worker

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

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
		longPollControlPlane(ctx, fake, ev, 10*time.Millisecond, logger, onApply)
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
		heartbeatControlPlane(ctx, fake, time.Millisecond, logger)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		fake.mu.Lock()
		n := fake.heartbeat
		fake.mu.Unlock()
		if n >= 1 {
			break
		}
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
