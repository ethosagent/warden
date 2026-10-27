package identityclient_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

func TestCacheFilePerms(t *testing.T) {
	r := newRig(t)
	r.login(t)
	st := r.cl.Store()
	fi, err := os.Stat(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(st.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir mode %v, want 0700", di.Mode().Perm())
	}
	if filepath.Base(st.Path()) != identityclient.CacheFileName(r.cl.Config.Issuer, r.cl.Config.ClientID) || len(strings.TrimSuffix(filepath.Base(st.Path()), ".json")) != 16 {
		t.Fatalf("cache file name %q", st.Path())
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		if err := os.Chmod(st.Path(), mode); err != nil {
			t.Fatal(err)
		}
		_, err := r.cl.Token(context.Background())
		if err == nil || !strings.Contains(err.Error(), st.Path()) {
			t.Fatalf("mode %v: want an error naming %s, got %v", mode, st.Path(), err)
		}
		if _, err := r.cl.Status(); err == nil || !strings.Contains(err.Error(), st.Path()) {
			t.Fatalf("status mode %v: got %v", mode, err)
		}
	}
	// The lock file is 0600 too.
	if err := os.Chmod(st.Path(), 0o600); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Hour)
	if _, err := r.cl.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	li, err := os.Stat(st.Path() + ".lock")
	if err != nil || li.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", li, err)
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	st := &identityclient.FileStore{Dir: filepath.Join(t.TempDir(), "a", "b"), Name: "x.json"}
	if _, err := st.Load(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty store: %v", err)
	}
	want := identityclient.Entry{Issuer: "i", ClientID: "c", RefreshToken: "r", IDToken: "t", ReceivedAt: time.Unix(100, 0).UTC()}
	if err := st.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load()
	if err != nil || got != want {
		t.Fatalf("got %+v err %v", got, err)
	}
	// No temp files are left behind.
	ents, _ := os.ReadDir(st.Dir)
	if len(ents) != 1 {
		t.Fatalf("dir has %d entries", len(ents))
	}
	// A corrupt file is reported by path, not content.
	if err := os.WriteFile(st.Path(), []byte("SECRET-JUNK"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil || strings.Contains(err.Error(), "SECRET-JUNK") || !strings.Contains(err.Error(), st.Path()) {
		t.Fatalf("corrupt: %v", err)
	}
	// A corrupt cache is not a crash for Status/Token.
}

func TestWithLockSerialises(t *testing.T) {
	st := &identityclient.FileStore{Dir: t.TempDir(), Name: "x.json"}
	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- st.WithLock(func() error { close(inside); <-release; return nil })
	}()
	<-inside
	second := make(chan struct{})
	go func() {
		_ = st.WithLock(func() error { close(second); return nil })
	}()
	select {
	case <-second:
		t.Fatal("second holder entered while the first held the lock")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("second holder never got the lock")
	}
	want := errors.New("fn failed")
	if err := st.WithLock(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("fn error not returned: %v", err)
	}
}

func TestSaveUnwritableDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st := &identityclient.FileStore{Dir: filepath.Join(f, "sub"), Name: "x.json"}
	if err := st.Save(identityclient.Entry{}); err == nil {
		t.Fatal("save under a file must fail")
	}
	if err := st.WithLock(func() error { return nil }); err == nil {
		t.Fatal("lock under a file must fail")
	}
}
