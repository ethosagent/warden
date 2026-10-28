package harness

import (
	"context"
	"errors"
	"fmt"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// workerRestarter is the optional Target capability for restarting one worker:
// stop it and boot it again through the production Run on fresh listeners. The
// in-process target implements it; a deployment the harness does not own
// (compose, a supplied target) does not.
type workerRestarter interface {
	restartWorker(ctx context.Context, i int) error
}

// RestartWorker stops worker i (0-based: 0 is worker-1) and boots it again, as
// an operator restarting the process would: its in-memory policy is gone, so it
// is fail-closed until its first policy pull succeeds (denies everything, even a
// host its own allowlist lists). The worker comes back on a NEW proxy address:
// ProxyAddrs, ConnectReplyAt, DialConnectAt and AgentWithProxyTokenAt follow it,
// while a client or connection obtained before the restart still points at the
// old one. The control plane need not be up. In-process only.
func (h *H) RestartWorker(i int) {
	h.tb.Helper()
	r, ok := h.target.(workerRestarter)
	if !ok {
		h.tb.Fatal("harness: RestartWorker needs the in-process target")
		return
	}
	if err := r.restartWorker(context.Background(), i); err != nil {
		h.tb.Fatalf("harness: restart worker %d: %v", i+1, err)
	}
}

func (ip *inprocess) restartWorker(ctx context.Context, i int) error {
	if i < 0 || i >= len(ip.workers) {
		return fmt.Errorf("worker index %d out of range (the fleet has %d workers)", i, len(ip.workers))
	}
	w := ip.workers[i]
	w.stop()
	if w.exitErr != nil && !errors.Is(w.exitErr, context.Canceled) {
		return fmt.Errorf("%s did not stop cleanly: %w", w.name, w.exitErr)
	}
	w.exitErr = nil
	// A restarted process starts its counters at zero, and an OTel reader can be
	// registered with one meter provider only: give the worker a fresh one. The
	// slice is shared with H, whose workerParams reads it at start time.
	if i < len(ip.readers) {
		ip.readers[i] = sdkmetric.NewManualReader()
	}
	return w.start(ctx)
}
