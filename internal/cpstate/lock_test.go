//go:build unix

package cpstate

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAcquireDirLock_Exclusive(t *testing.T) {
	dir := t.TempDir()
	release, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatalf("first AcquireDirLock: %v", err)
	}
	lockPath := filepath.Join(dir, LockFileName)
	fi, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("lock mode = %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(lockPath); strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("lock content = %q, want pid %d", b, os.Getpid())
	}

	_, err = AcquireDirLock(dir)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second AcquireDirLock = %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "state dir "+dir+" is locked by another process") {
		t.Errorf("error %q lacks the documented message", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("release must not delete the lock file: %v", err)
	}
	release2, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatalf("AcquireDirLock after release: %v", err)
	}
	_ = release2()
}

func TestAcquireDirLock_MissingDir(t *testing.T) {
	if _, err := AcquireDirLock(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("AcquireDirLock on a missing dir returned nil")
	} else if errors.Is(err, ErrLocked) {
		t.Fatalf("missing dir must not report ErrLocked: %v", err)
	}
}

// TestAcquireDirLock_HelperProcess is the re-executed child: it takes the lock,
// tells the parent, then blocks until killed.
func TestAcquireDirLock_HelperProcess(t *testing.T) {
	dir := os.Getenv("CPSTATE_LOCK_HELPER_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	if _, err := AcquireDirLock(dir); err != nil {
		os.Stdout.WriteString("ERR " + err.Error() + "\n")
		os.Exit(2)
	}
	os.Stdout.WriteString("LOCKED\n")
	time.Sleep(time.Minute)
}

func TestAcquireDirLock_ReleasedOnProcessDeath(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAcquireDirLock_HelperProcess$")
	cmd.Env = append(os.Environ(), "CPSTATE_LOCK_HELPER_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "LOCKED" {
		t.Fatalf("helper did not lock: %q, %v", line, err)
	}
	if _, err := AcquireDirLock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("while the child lives: %v, want ErrLocked", err)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	release, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatalf("after SIGKILL of the holder: %v", err)
	}
	_ = release()
}
