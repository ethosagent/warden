package oauthbroker_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
)

type fakeSweeper struct {
	mu    sync.Mutex
	calls []time.Time
	errs  []error
	res   oauthbroker.SweepResult
}

func (f *fakeSweeper) Sweep(_ context.Context, now time.Time) (oauthbroker.SweepResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, now)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return oauthbroker.SweepResult{}, err
	}
	return f.res, nil
}

func (f *fakeSweeper) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// advanceUntil drives the fake clock one interval at a time until cond holds,
// so the test never depends on how far the loop got before a single Advance.
func advanceUntil(t *testing.T, clk *clocktest.Fake, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 5s")
		}
		if clk.PendingTimers() > 0 {
			clk.Advance(d)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRunSweeper(t *testing.T) {
	clk := clocktest.NewFake(oauthbrokertest.Start)
	stale := []oauthbroker.Grant{{UserKey: "u", Provider: "google", GrantID: "g1", State: oauthbroker.GrantConnecting}}
	fs := &fakeSweeper{
		errs: []error{errors.New("disk full")},
		res:  oauthbroker.SweepResult{AttemptsDeleted: 2, StaleConnecting: stale},
	}
	var logs syncBuffer
	var mu sync.Mutex
	var reconciled [][]oauthbroker.Grant
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		oauthbroker.RunSweeper(ctx, oauthbroker.SweeperConfig{
			Store: fs, Interval: time.Minute, Now: clk.Now, After: clk.After,
			Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			Reconcile: func(_ context.Context, g []oauthbroker.Grant) {
				mu.Lock()
				reconciled = append(reconciled, g)
				mu.Unlock()
			},
		})
	}()
	advanceUntil(t, clk, time.Minute, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(reconciled) >= 2
	})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSweeper did not return after cancel")
	}
	fs.mu.Lock()
	first, second := fs.calls[0], fs.calls[1]
	fs.mu.Unlock()
	if !first.Equal(oauthbrokertest.Start) || !second.After(first) {
		t.Fatalf("sweep times = %v, %v; want an immediate pass, then one per tick", first, second)
	}
	out := logs.String()
	if !strings.Contains(out, "sweep failed") || !strings.Contains(out, "attempts_deleted=2") {
		t.Fatalf("logs = %s", out)
	}
	if reconciled[0][0].GrantID != "g1" {
		t.Fatalf("reconciled %+v", reconciled[0])
	}
}

func TestRunSweeperDefaultsAndCancel(t *testing.T) {
	clk := clocktest.NewFake(oauthbrokertest.Start)
	fs := &fakeSweeper{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		oauthbroker.RunSweeper(ctx, oauthbroker.SweeperConfig{Store: fs, Now: clk.Now, After: clk.After})
	}()
	advanceUntil(t, clk, time.Second, func() bool { return clk.PendingTimers() > 0 })
	// The default interval is SweepInterval: 59s is not enough for a second pass.
	clk.Advance(oauthbroker.SweepInterval - time.Second)
	time.Sleep(20 * time.Millisecond)
	if n := fs.count(); n != 1 {
		t.Fatalf("passes before the default interval = %d, want 1", n)
	}
	advanceUntil(t, clk, time.Second, func() bool { return fs.count() >= 2 })
	cancel()
	<-done
}

func TestRunSweeperStopsOnCancelledSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fs := &fakeSweeper{errs: []error{context.Canceled}}
	clk := clocktest.NewFake(oauthbrokertest.Start)
	oauthbroker.RunSweeper(ctx, oauthbroker.SweeperConfig{Store: fs, Now: clk.Now, After: clk.After})
	if fs.count() != 1 {
		t.Fatalf("passes = %d, want 1", fs.count())
	}
}
