package harness

import (
	"strings"
	"testing"
	"time"
)

// TestRestartWorker_FailClosedThenPullsPolicy: a restarted worker comes back on
// a new address, denies everything while the control plane is down (its
// in-memory policy is gone), and serves the control plane's policy again once
// it can pull.
func TestRestartWorker_FailClosedThenPullsPolicy(t *testing.T) {
	h := New(t, Local())
	h.Upstream("api.example.com")
	if got := connectStatus(t, h, "api.example.com:443"); got != 200 {
		t.Fatalf("CONNECT before the restart = %d, want 200", got)
	}
	before := h.ProxyAddrs()[0]

	h.CP().Stop()
	h.RestartWorker(0)
	if h.ProxyAddrs()[0] == before {
		t.Errorf("the restarted worker kept its proxy address %s, want a fresh one", before)
	}
	if status, _ := h.ConnectReplyAt(0, hostPortAPI, ""); status != 403 {
		t.Fatalf("CONNECT from a restarted worker with no policy = %d, want 403 (fail closed)", status)
	}

	h.CP().Start()
	h.Eventually("the restarted worker to pull policy", func() bool {
		h.Clock().Advance(time.Second)
		status, _ := h.ConnectReplyAt(0, hostPortAPI, "")
		return status == 200
	})
}

const hostPortAPI = "api.example.com:443"

func TestRestartWorker_RejectsOutOfRangeIndex(t *testing.T) {
	h := New(t, Local())
	err := h.target.(workerRestarter).restartWorker(t.Context(), 3)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("restartWorker(3) = %v, want an out-of-range error", err)
	}
}

func TestRestartWorker_RejectsSuppliedTarget(t *testing.T) {
	rec := &recordingTB{T: t}
	h := New(rec, WithTarget(&fakeTarget{}))
	h.RestartWorker(0)
	if !rec.Failed() || !strings.Contains(rec.failureMessage(), "RestartWorker") {
		t.Fatalf("expected a RestartWorker failure, got failed=%v msg=%q", rec.Failed(), rec.failureMessage())
	}
}
