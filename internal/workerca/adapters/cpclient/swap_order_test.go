package cpclient_test

import (
	"context"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/workerca/adapters/cpclient"
)

// TestRenewerSwapAndPoolDropAreOneStep: once Source.Current reports the renewed
// certificate, the pooled connections of the old one are already dropped. Readers
// poll Current the whole time; the CloseIdle hook holds the drop open (yielding,
// no sleep) so a reader that could see the new certificate before the drop
// completes has every chance to.
func TestRenewerSwapAndPoolDropAreOneStep(t *testing.T) {
	clk := clocktest.NewFake(t0)
	cp := newFakeCP(t, clk.Now)
	dir := t.TempDir()
	cred, err := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cred.ReceivedAt = clk.Now()
	src := cpclient.NewSource(cred)
	oldSerial := cred.Serial()

	var dropped, stop atomic.Bool
	var early atomic.Value // the first serial observed before the drop finished
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if c := src.Current(); c != nil && c.Serial() != oldSerial && !dropped.Load() {
					early.CompareAndSwap(nil, c.Serial())
				}
				runtime.Gosched()
			}
		}()
	}
	closeIdle := func() {
		for range 20000 {
			runtime.Gosched()
		}
		dropped.Store(true)
	}
	r := &cpclient.Renewer{
		Endpoint: cp.url("/control/renew"), HTTP: http.DefaultClient, Source: src, StateDir: dir, Clock: clk,
		Jitter: func() float64 { return 0 }, CloseIdle: closeIdle,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done; stop.Store(true); wg.Wait() }()

	waitFor(t, "the renewer to arm", func() bool { return clk.PendingTimers() == 1 })
	clk.Advance(12 * time.Hour)
	waitFor(t, "the pool drop", dropped.Load)
	if src.Current().Serial() == oldSerial {
		t.Fatal("the certificate was not swapped")
	}
	if s := early.Load(); s != nil {
		t.Errorf("Current reported the renewed serial %v before the old connections were dropped", s)
	}
}
