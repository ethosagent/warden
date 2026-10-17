package harness

import (
	"net"
	"os"
	"runtime"
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
	// Goroutines from earlier tests that are still exiting would inflate the
	// baseline New captures; when they finish, the count can drop back under it
	// and the count gate hides the planted leak. Boot only once the count settles.
	settleGoroutines(t)
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

// TestControlPlaneDownAtBoot_FailsClosedThenRecovers pins the boot-time outage
// fault: a worker started while the control plane is unreachable denies even a
// host its own local allowlist lists, and allows it within one retry once the
// control plane is up on the address the worker was configured with.
func TestControlPlaneDownAtBoot_FailsClosedThenRecovers(t *testing.T) {
	h := New(t, ControlPlaneDownAtBoot())
	h.Upstream("api.example.com")

	if got := connectStatus(t, h, "api.example.com:443"); got != 403 {
		t.Fatalf("CONNECT with the control plane down at boot = %d, want 403 (fail closed)", got)
	}

	h.CP().Start()
	h.Eventually("the worker to pull policy from the restarted control plane", func() bool {
		h.Clock().Advance(time.Second)
		return connectStatus(t, h, "api.example.com:443") == 200
	})
}

// TestControlPlaneDownAtBoot_RejectsSuppliedTarget: the fault is in-process
// only, so combining it with WithTarget must fail loudly, not silently boot a
// healthy stack.
func TestControlPlaneDownAtBoot_RejectsSuppliedTarget(t *testing.T) {
	rec := &recordingTB{T: t}
	New(rec, ControlPlaneDownAtBoot(), WithTarget(&fakeTarget{}))
	if !rec.Failed() || !strings.Contains(rec.failureMessage(), "ControlPlaneDownAtBoot") {
		t.Fatalf("expected a ControlPlaneDownAtBoot failure, got failed=%v msg=%q", rec.Failed(), rec.failureMessage())
	}
}

// TestRotateSecret_NewValueSweptToo: after a rotation the old AND the new value
// are both guarded, and an unknown name fails.
func TestRotateSecret_NewValueSweptToo(t *testing.T) {
	oldV, newV := Canary(), Canary()
	h := New(t, WithSecret("openai", oldV))
	h.RotateSecret("openai", newV)
	if len(h.secrets) != 2 || h.secrets[0].value != oldV || h.secrets[1].value != newV {
		t.Fatalf("secrets after rotation = %+v, want old then new", h.secrets)
	}
	if got := os.Getenv("WARDEN_HARNESS_SECRET_OPENAI"); got != newV {
		t.Errorf("env after rotation = %q, want the new value", got)
	}

	rec := &recordingTB{T: t}
	h.tb = rec
	h.RotateSecret("nope", "x")
	h.tb = t
	if !rec.Failed() {
		t.Error("RotateSecret of an unknown name must fail the test")
	}
}

// TestCanaryLeaks_ReportsWithoutFailing: the non-fatal sweep returns the hits a
// known-issue scenario asserts on, and an empty list when clean.
func TestCanaryLeaks_ReportsWithoutFailing(t *testing.T) {
	value := Canary()
	h := New(t, WithSecret("openai", value), Allow("echo.example.com"))
	if got := h.CanaryLeaks(); len(got) != 0 {
		t.Fatalf("clean harness reported leaks: %v", got)
	}
	// The agent sends the raw value itself (as TestCanary_Plant_AgentResponseBody
	// does): nothing is swapped, so the echo guard (#389) is not armed and the
	// reflected value lands in the agent's transcript for the sweep to report.
	plantEcho(h.Upstream("echo.example.com"))
	postThrough(t, h, "echo.example.com", "/reflect", "token="+value)
	leaks := h.CanaryLeaks()
	if len(leaks) == 0 || !strings.Contains(strings.Join(leaks, "\n"), "agent response #0 body") {
		t.Fatalf("CanaryLeaks = %v, want the echoed value in the agent's body", leaks)
	}
}

// TestAgentH2_NegotiatesHTTP2 pins the h2 agent: its request rides HTTP/2 to the
// upstream, and the response is in the shared transcript.
func TestAgentH2_NegotiatesHTTP2(t *testing.T) {
	h := New(t)
	u := h.Upstream("api.example.com")
	resp, err := h.AgentH2().Get("https://api.example.com/h2")
	if err != nil {
		t.Fatalf("h2 GET: %v", err)
	}
	_ = resp.Body.Close()
	if reqs := u.Requests(); len(reqs) != 1 || reqs[0].Proto != "HTTP/2.0" {
		t.Fatalf("upstream requests = %+v, want one HTTP/2.0 request", reqs)
	}
	if got := len(h.AgentResponses()); got != 1 {
		t.Errorf("transcript has %d responses, want 1 (AgentH2 shares it)", got)
	}
}

// settleGoroutines waits until the process goroutine count has stopped
// falling, so a baseline captured next is not inflated by exiting goroutines.
func settleGoroutines(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	prev, stable := runtime.NumGoroutine(), 0
	for stable < 5 && time.Now().Before(deadline) {
		<-time.After(20 * time.Millisecond)
		if n := runtime.NumGoroutine(); n < prev {
			prev, stable = n, 0
		} else {
			stable++
		}
	}
}
