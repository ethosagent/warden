package scenarios

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// The worker CA gate (W-P2-WCA-01). With workerCA.enabled and the intermediate
// key not yet in the key manager, the control plane starts degraded — /healthz
// says so, /policy keeps serving — and the 30s retry loop installs the CA once
// the key is imported. A restart then comes up healthy straight away, and no
// log line carries key material.

func workerCAOpts() []harness.Option { return []harness.Option{harness.WithWorkerCA()} }

func workerCAHealthz(h *harness.H) string {
	return h.CP().DoWorker(http.MethodGet, "/healthz", "", "", "").Body
}

func workerCADegradedThenReady(t *testing.T, h *harness.H) {
	if body := workerCAHealthz(h); !strings.HasPrefix(body, "degraded") {
		t.Fatalf("GET /healthz before the key exists = %q, want degraded", body)
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy while the worker CA is degraded = %d, want 200", status)
	}
	actor := keys.Actor{Subject: "scenario", AuthMethod: "cli"}
	if _, err := h.KeyManager().ImportKey(context.Background(), keys.PurposeCA, h.WorkerCAKey(), actor); err != nil {
		t.Fatalf("import the ca key: %v", err)
	}
	// The retry timer is armed on the harness clock next to the key loops, so
	// the scenario advances 30s per poll until the CA is installed.
	h.Eventually("the worker CA to load its key", func() bool {
		h.Clock().Advance(30 * time.Second)
		return workerCAHealthz(h) == "ok\n"
	})

	// A restart finds the key already imported: healthy with no retry needed.
	h.CP().Stop()
	h.CP().Start()
	if body := workerCAHealthz(h); body != "ok\n" {
		t.Fatalf("GET /healthz after a restart = %q, want ok", body)
	}
	logs := h.Logs()
	if !strings.Contains(logs, `"worker_ca":"enabled"`) || !strings.Contains(logs, harness.WorkerCATrustDomain) {
		t.Errorf("no worker CA startup line in the control plane log")
	}
	for _, marker := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if strings.Contains(logs, marker) {
			t.Errorf("control plane log carries %q", marker)
		}
	}
}
