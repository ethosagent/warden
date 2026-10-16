package harness

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestNew_Local_ProxyAddrAcceptsTCP is the Task A acceptance test: Local boots a
// real worker + control plane in-process, h.ProxyAddr() is the worker proxy's
// live listener (a TCP connection is accepted), and cleanup (via watchGoroutines)
// stops everything without leaking goroutines.
func TestNew_Local_ProxyAddrAcceptsTCP(t *testing.T) {
	h := New(t, Local())
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy at %s: %v", h.ProxyAddr(), err)
	}
	_ = conn.Close()

	if h.AdminAddr() == "" {
		t.Error("AdminAddr is empty; the worker admin listener was not reported")
	}
	if h.ControlPlaneAddr() == "" {
		t.Error("ControlPlaneAddr is empty; the control plane listener was not reported")
	}
}

// TestNew_Fleet2_BothWorkersPullPolicy is the second Task A test: Fleet(2) boots
// two workers sharing one control plane, and the control plane's fleet view
// lists both after each pulled policy.
func TestNew_Fleet2_BothWorkersPullPolicy(t *testing.T) {
	h := New(t, Fleet(2))
	if got := len(h.ProxyAddrs()); got != 2 {
		t.Fatalf("ProxyAddrs = %d entries, want 2", got)
	}
	// Both proxies are live listeners.
	for _, addr := range h.ProxyAddrs() {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial worker proxy at %s: %v", addr, err)
		}
		_ = conn.Close()
	}

	h.Eventually("both workers to appear in the control plane fleet list", func() bool {
		workers, err := h.CP().Workers()
		if err != nil {
			return false
		}
		return len(workers) == 2
	})
	workers, err := h.CP().Workers()
	if err != nil {
		t.Fatalf("control plane fleet list: %v", err)
	}
	ids := map[string]bool{}
	for _, w := range workers {
		ids[w.ProxyID] = true
	}
	for _, want := range []string{"worker-1", "worker-2"} {
		if !ids[want] {
			t.Errorf("fleet list is missing %q; got %v", want, workers)
		}
	}
}

// TestNew_DefaultsToLocal pins the zero-option default: New without a topology
// option is Local (one worker), so a scenario cannot accidentally boot nothing.
func TestNew_DefaultsToLocal(t *testing.T) {
	h := New(t)
	if got := len(h.ProxyAddrs()); got != 1 {
		t.Fatalf("New() without a topology booted %d workers, want 1 (Local)", got)
	}
}

// TestFleet_RejectsZero pins the misuse guard: Fleet(0) is a programming error.
func TestFleet_RejectsZero(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Fleet(0) did not panic; a zero-worker topology must fail loudly")
		}
	}()
	New(t, Fleet(0))
}

// TestNew_GoroutineLeakCheckFires proves the built-in leak check can fail: a
// goroutine the harness owns and never stops must be flagged at cleanup. Red
// the moment checkGoroutines becomes a no-op — the guard has to be able to
// bite, or every other green result here means nothing.
func TestNew_GoroutineLeakCheckFires(t *testing.T) {
	rec := &recordingTB{T: t}
	h := New(rec)
	if rec.Failed() {
		t.Fatalf("harness boot failed: %s", rec.failureMessage())
	}
	// Planted AFTER boot, so it sits above the leak baseline; its stack carries
	// no testing frames, so the leak dump cannot attribute it to the framework.
	planted := make(chan struct{})
	go func() { <-planted }()
	// Unplant when THIS test ends — which runs after the cleanup below has
	// already seen and failed for the still-living goroutine.
	t.Cleanup(func() { close(planted) })

	// This TB's cleanup registration never reaches the framework, so run the
	// (idempotent) cleanup by hand.
	h.cleanup()
	if !rec.Failed() {
		t.Fatal("checkGoroutines did not fail a harness that left a goroutine behind; the leak check is not guarding anything")
	}
	if msg := rec.failureMessage(); !strings.Contains(msg, "leaked") {
		t.Errorf("the leak failure does not say what leaked:\n%s", msg)
	}
}

// TestTarget_AddrsMatchH pins the Target seam (#351 runs scenarios against it):
// the in-process target reports the same addresses the H accessors do.
func TestTarget_AddrsMatchH(t *testing.T) {
	h := New(t, Local())
	tgt := h.Target()
	if tgt == nil {
		t.Fatal("Target() = nil, want the in-process target")
	}
	if tgt.ProxyAddr() != h.ProxyAddr() || tgt.AdminAddr() != h.AdminAddr() || tgt.ControlPlaneAddr() != h.ControlPlaneAddr() {
		t.Errorf("target addrs = (%s, %s, %s), want the H addrs (%s, %s, %s)",
			tgt.ProxyAddr(), tgt.AdminAddr(), tgt.ControlPlaneAddr(),
			h.ProxyAddr(), h.AdminAddr(), h.ControlPlaneAddr())
	}
}
