package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Stopping and restarting the components of a stack (W-P2-WBND-10): the
// degraded-mode cases need a control plane that goes away while workers keep
// running, and a worker that boots while it is gone. Both come back on the same
// state, ports and keys, so the certificates, bundle pins and tokens of the
// stack stay valid across the restart.

// StopCP stops the control plane and waits until it has exited. The workers
// keep running with whatever they last applied. The admin console session is
// dropped: a restarted control plane does not know it.
func (s *Stack) StopCP(tb testing.TB) {
	tb.Helper()
	if s.CP == nil || s.CP.cancel == nil {
		tb.Fatal("security: the control plane is not running")
	}
	s.CP.cancel()
	s.CP.cancel = nil
	select {
	case err := <-s.CP.errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			tb.Fatalf("security: the control plane exited with %v", err)
		}
	case <-time.After(stopDeadline):
		tb.Fatalf("security: the control plane did not stop within %s", stopDeadline)
	}
	s.CP.HTTP.CloseIdleConnections()
	s.mu.Lock()
	s.admin = nil
	s.mu.Unlock()
}

// RestartCP boots the control plane again on the address, state directory,
// worker CA and keys it had.
func (s *Stack) RestartCP(tb testing.TB) {
	tb.Helper()
	if s.CP == nil || s.CP.cancel != nil {
		tb.Fatal("security: the control plane is running; StopCP first")
	}
	s.bootCP(s.CP.Addr)
}

// StopWorker stops w and waits until it has exited.
func (s *Stack) StopWorker(tb testing.TB, w *Worker) {
	tb.Helper()
	if w.cancel == nil {
		tb.Fatalf("security: %s is not running", w.Name)
	}
	w.cancel()
	w.cancel = nil
	select {
	case err := <-w.errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			tb.Fatalf("security: %s exited with %v", w.Name, err)
		}
	case <-time.After(stopDeadline):
		tb.Fatalf("security: %s did not stop within %s", w.Name, stopDeadline)
	}
}

// RestartWorker boots a stopped worker again on its addresses, state directory
// (certificate included) and analytics store. It returns when the worker
// reports ready, which does not wait for a first bundle: a worker that boots
// with the control plane down enforces nothing it has not verified.
func (s *Stack) RestartWorker(tb testing.TB, w *Worker) {
	tb.Helper()
	if w.cancel != nil {
		tb.Fatalf("security: %s is running; StopWorker first", w.Name)
	}
	s.runWorker(w, w.ProxyAddr, w.AdminAddr)
}

// DropBundleCache deletes w's last-known-good bundle (controlPlane.stateDir
// bundle/), so a worker that restarts while the control plane is down has no
// verified bundle at all. The certificate stays.
func (s *Stack) DropBundleCache(tb testing.TB, w *Worker) {
	tb.Helper()
	if err := os.RemoveAll(filepath.Join(w.StateDir, "bundle")); err != nil {
		tb.Fatalf("security: remove %s's bundle cache: %v", w.Name, err)
	}
}
