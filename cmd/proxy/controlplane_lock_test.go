package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
)

// startLockCP boots controlplane.Run on stateDir (empty = no state dir) with an
// injected listener and waits until it serves. stop cancels it and returns Run's
// error.
func startLockCP(t *testing.T, stateDir string) (addr string, stop func() error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	var out cpSyncBuffer
	go func() {
		errCh <- controlplane.Run(ctx, &out, controlplane.Params{
			ConfigPath: writeTempConfig(t, minimalConfig), StateDir: stateDir, Listener: ln,
			AnalyticsProvider: "memory",
			OnReady:           func(a string) { ready <- a },
		})
	}()
	select {
	case addr = <-ready:
	case err := <-errCh:
		cancel()
		t.Fatalf("control plane exited before ready: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for the control plane")
	}
	var once sync.Once
	var stopErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-errCh:
			case <-time.After(10 * time.Second):
				stopErr = errors.New("control plane did not stop")
			}
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stop() })
	return addr, stop
}

func TestControlPlaneStateDirLock(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	addr, stop := startLockCP(t, stateDir)

	fi, err := os.Stat(filepath.Join(stateDir, "warden-cp.lock"))
	if err != nil {
		t.Fatalf("lock file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("lock mode = %v, want 0600", fi.Mode().Perm())
	}

	// A second CP on the same state dir is refused and does not disturb the first.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2() // a regressed lock would serve; the timeout fails the test instead of hanging
	err = controlplane.Run(ctx2, &cpSyncBuffer{}, controlplane.Params{
		ConfigPath: writeTempConfig(t, minimalConfig), StateDir: stateDir,
		ListenAddr: "127.0.0.1:0", AnalyticsProvider: "memory",
	})
	if err == nil || !strings.Contains(err.Error(), "in use by another control plane") {
		t.Fatalf("second control plane error = %v, want 'in use by another control plane'", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(stateDir, "warden-cp.lock")) {
		t.Errorf("error %q does not name the lock file", err)
	}
	conn, derr := net.DialTimeout("tcp", addr, 2*time.Second)
	if derr != nil {
		t.Fatalf("first control plane stopped serving: %v", derr)
	}
	_ = conn.Close()

	// Shutdown releases the lock: a third start succeeds.
	if err := stop(); err != nil {
		t.Fatalf("first control plane shutdown: %v", err)
	}
	_, stop3 := startLockCP(t, stateDir)
	if err := stop3(); err != nil {
		t.Fatalf("third control plane shutdown: %v", err)
	}

	// Without --state-dir no lock is taken: two CPs run side by side.
	_, stopA := startLockCP(t, "")
	_, stopB := startLockCP(t, "")
	if err := stopA(); err != nil {
		t.Errorf("no-state-dir CP A: %v", err)
	}
	if err := stopB(); err != nil {
		t.Errorf("no-state-dir CP B: %v", err)
	}
}
