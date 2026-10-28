package controlplane

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// A write by another handle on the same database file (the offline CLI is
// another process; cpstate holds one connection per handle, so a second handle
// behaves the same) must refresh the policy and run the OnChange callbacks
// within a few poll intervals.
func TestBlockStoreWatchRefreshesSnapshot(t *testing.T) {
	s := blockServer(t, nil, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var changes atomic.Int32
	s.blocks.OnChange(func() { changes.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.blocks.Watch(ctx, 20*time.Millisecond)
	}()
	defer func() {
		cancel()
		<-done
	}()

	other, err := cpstate.Open(context.Background(), s.cfg.State.Path(), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	// Wait for the start-up refresh so the count below is the write's.
	waitFor(t, func() bool { return changes.Load() >= 1 })
	before := changes.Load()
	if _, err := NewBlockStore(other, BlockStoreOptions{}).Add(context.Background(),
		BlockEntry{Email: "alice@corp.com", Reason: "offline"}, "cli:tester"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return changes.Load() > before })

	_, body, _ := getPolicy(t, ts.URL+"/policy", nil)
	if got := wireBlocked(t, body); len(got) != 1 || got[0] != (config.BlockedUser{Email: "alice@corp.com"}) {
		t.Errorf("served blockedUsers = %+v, want alice", got)
	}
}

// With no writer the watcher stays quiet after the start-up refresh.
func TestBlockStoreWatchIdle(t *testing.T) {
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st := NewBlockStore(db, BlockStoreOptions{})
	var changes atomic.Int32
	st.OnChange(func() { changes.Add(1) })
	// An in-process write must not look like a foreign change.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		st.Watch(ctx, 10*time.Millisecond)
	}()
	waitFor(t, func() bool { return changes.Load() == 1 })
	if _, err := st.Add(context.Background(), BlockEntry{Sub: "u1"}, "cli:t"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	// start-up refresh + the Add's own callback, and no poll-triggered extra.
	if n := changes.Load(); n != 2 {
		t.Errorf("callbacks = %d, want 2 (start-up and the in-process Add)", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached within 5s")
}
