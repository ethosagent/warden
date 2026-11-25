//go:build unix

package identityclient_test

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

// A FIFO must be refused without blocking, wherever the caller reads a file.
func TestFIFOIsRefusedNotBlockedOn(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"agent key": func() error { _, err := identityclient.LoadAgentKey(fifo); return err },
		"subject file": func() error {
			_, err := identityclient.FileSubject{Path: fifo}.Subject(context.Background())
			return err
		},
		"cp ca": func() error { _, err := identityclient.NewCPHTTPClient(fifo); return err },
	}
	for name, call := range cases {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("%s: %v, want a not-a-regular-file error", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: reading a FIFO blocked", name)
		}
	}
}

func TestCPCAFileIsCapped(t *testing.T) {
	big := filepath.Join(t.TempDir(), "ca.pem")
	if err := writeFileOf(big, (1<<20)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := identityclient.NewCPHTTPClient(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized CA = %v, want a size refusal", err)
	}
}
