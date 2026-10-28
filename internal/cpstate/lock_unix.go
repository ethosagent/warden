//go:build unix

package cpstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// AcquireDirLock takes an exclusive, non-blocking flock on <dir>/warden-cp.lock
// (created 0600 if absent, never truncated) and returns a release func. It
// returns ErrLocked, wrapped with the dir and lock path, when the lock is held.
//
// SQLite keeps no lock while a control plane is idle, so this file is what
// lets restore and offline backup refuse to run under a live control plane and
// stops two control planes sharing one state dir. The kernel drops the flock
// when the holder dies, so a crash never leaves a stale lock. release closes
// the descriptor (dropping the flock) and never removes the file. The PID
// written into the file is informational only.
func AcquireDirLock(dir string) (release func() error, err error) {
	path := filepath.Join(dir, LockFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode)
	if err != nil {
		return nil, fmt.Errorf("cpstate: open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("cpstate: state dir %s is %w (lock %s)", dir, ErrLocked, path)
		}
		return nil, fmt.Errorf("cpstate: lock %s: %w", path, err)
	}
	// Informational only: a failure to record the PID must not fail the lock.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return f.Close, nil
}
