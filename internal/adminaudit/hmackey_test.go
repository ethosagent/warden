package adminaudit

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadOrCreateHMACKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, HMACKeyFileName)
	k, err := LoadOrCreateHMACKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Fatalf("key length = %d", len(k))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}
	again, err := LoadOrCreateHMACKey(path)
	if err != nil || !bytes.Equal(k, again) {
		t.Fatalf("reload: equal=%v err=%v", bytes.Equal(k, again), err)
	}

	short := filepath.Join(dir, "short.key")
	if err := os.WriteFile(short, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateHMACKey(short); err == nil {
		t.Fatal("short key file: want error")
	}
	if _, err := LoadOrCreateHMACKey(""); err == nil {
		t.Fatal("empty path: want error")
	}
	if _, err := LoadOrCreateHMACKey(filepath.Join(dir, "no-such-dir", "k")); err == nil {
		t.Fatal("missing directory: want error")
	}
}

func TestLoadOrCreateHMACKeyConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), HMACKeyFileName)
	const n = 16
	keys := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			keys[i], errs[i] = LoadOrCreateHMACKey(path)
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if !bytes.Equal(keys[i], keys[0]) {
			t.Fatalf("call %d returned a different key", i)
		}
	}
}

func TestDefaultHMACKeyPath(t *testing.T) {
	if got := DefaultHMACKeyPath("/var/lib/warden/cp-audit.key"); got != "/var/lib/warden/cp-audit-hmac.key" {
		t.Fatalf("DefaultHMACKeyPath = %q", got)
	}
}
