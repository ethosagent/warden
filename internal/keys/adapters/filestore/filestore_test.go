package filestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

const kid = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

var pemBody = []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n")

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutGetModes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, keys.PurposeToken, kid)
	if err != nil || !bytes.Equal(got, pemBody) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	path := filepath.Join(s.Dir(), "token", kid+".pem")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file %v mode %v, want 0600", err, fi.Mode().Perm())
	}
	for _, d := range []string{s.Dir(), filepath.Join(s.Dir(), "token")} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v, want 0700", d, fi.Mode().Perm())
		}
	}
}

// TestPutNeverOverwrites: O_EXCL — a second Put is ErrKeyExists and the first
// bytes survive.
func TestPutNeverOverwrites(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeBundle, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, keys.PurposeBundle, kid, []byte("other")); !errors.Is(err, keys.ErrKeyExists) {
		t.Fatalf("second Put = %v, want ErrKeyExists", err)
	}
	if got, _ := s.Get(ctx, keys.PurposeBundle, kid); !bytes.Equal(got, pemBody) {
		t.Errorf("first value was overwritten: %q", got)
	}
}

// TestExistingLooseDirIsTightened: directories that already exist with a loose
// mode end up 0700.
func TestExistingLooseDirIsTightened(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(filepath.Join(s.Dir(), "token"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(s.Dir(), "token"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), keys.PurposeToken, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{s.Dir(), filepath.Join(s.Dir(), "token")} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v, want 0700", d, fi.Mode().Perm())
		}
	}
}

func TestGetMissingAndDelete(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.Get(ctx, keys.PurposeCA, kid); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get missing = %v, want ErrKeyNotFound", err)
	}
	if err := s.Delete(ctx, keys.PurposeCA, kid); err != nil {
		t.Errorf("Delete missing = %v, want nil", err)
	}
	if err := s.Put(ctx, keys.PurposeCA, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, keys.PurposeCA, kid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, keys.PurposeCA, kid); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get after Delete = %v", err)
	}
}

func TestList(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if kids, err := s.List(ctx, keys.PurposeToken); err != nil || len(kids) != 0 {
		t.Fatalf("List on a missing dir = %v, %v", kids, err)
	}
	a, b := kid, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	for _, k := range []string{a, b} {
		if err := s.Put(ctx, keys.PurposeToken, k, pemBody); err != nil {
			t.Fatal(err)
		}
	}
	// Junk next to the keys is ignored, not listed (and so never swept).
	dir := filepath.Join(s.Dir(), "token")
	_ = os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad name.pem"), []byte("x"), 0o600)
	_ = os.Mkdir(filepath.Join(dir, "dir.pem"), 0o700)
	kids, err := s.List(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(kids)
	want := []string{a, b}
	sort.Strings(want)
	if strings.Join(kids, ",") != strings.Join(want, ",") {
		t.Errorf("List = %v, want %v", kids, want)
	}
	if other, _ := s.List(ctx, keys.PurposeBundle); len(other) != 0 {
		t.Errorf("List(bundle) = %v, want none", other)
	}
}

// TestRejectsEscapingNames: purpose and kid are validated, so no name can leave
// its directory.
func TestRejectsEscapingNames(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, bad := range []string{"", "../x", "a/b", "a\\b", "..", ".", "a.pem", "a b", strings.Repeat("A", 129), "k\x00id"} {
		if err := s.Put(ctx, keys.PurposeToken, bad, pemBody); err == nil {
			t.Errorf("Put accepted kid %q", bad)
		}
		if _, err := s.Get(ctx, keys.PurposeToken, bad); err == nil {
			t.Errorf("Get accepted kid %q", bad)
		}
		if err := s.Delete(ctx, keys.PurposeToken, bad); err == nil {
			t.Errorf("Delete accepted kid %q", bad)
		}
	}
	for _, bad := range []string{"", "../token", "audit", "Token", "token/x"} {
		if err := s.Put(ctx, bad, kid, pemBody); !errors.Is(err, keys.ErrInvalidPurpose) {
			t.Errorf("Put purpose %q = %v, want ErrInvalidPurpose", bad, err)
		}
		if _, err := s.List(ctx, bad); !errors.Is(err, keys.ErrInvalidPurpose) {
			t.Errorf("List purpose %q = %v, want ErrInvalidPurpose", bad, err)
		}
	}
	if _, err := os.Stat(s.Dir()); !os.IsNotExist(err) {
		t.Errorf("rejected names created the key directory: %v", err)
	}
}

func TestCancelledContext(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); !errors.Is(err, context.Canceled) {
		t.Errorf("Put = %v", err)
	}
	if _, err := s.Get(ctx, keys.PurposeToken, kid); !errors.Is(err, context.Canceled) {
		t.Errorf("Get = %v", err)
	}
	if err := s.Delete(ctx, keys.PurposeToken, kid); !errors.Is(err, context.Canceled) {
		t.Errorf("Delete = %v", err)
	}
	if _, err := s.List(ctx, keys.PurposeToken); !errors.Is(err, context.Canceled) {
		t.Errorf("List = %v", err)
	}
}

func TestNewRejectsEmptyDir(t *testing.T) {
	if _, err := New("  "); err == nil {
		t.Error("New accepted an empty directory")
	}
}

// TestErrorsCarryNoKeyBytes: an I/O failure names the operation, not the key
// bytes or the kid-bearing file name.
func TestErrorsCarryNoKeyBytes(t *testing.T) {
	root := t.TempDir()
	// A regular file where the key directory should be.
	blocker := filepath.Join(root, "keys")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := New(blocker)
	secret := []byte("SECRET-KEY-BYTES-0123456789")
	err := s.Put(context.Background(), keys.PurposeToken, kid, secret)
	if err == nil {
		t.Fatal("Put succeeded under a file")
	}
	if strings.Contains(err.Error(), string(secret)) || strings.Contains(err.Error(), kid) {
		t.Errorf("error leaks key data: %v", err)
	}
}

func TestGetReadErrorIsNotNotFound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	// A directory where the file should be: a read error, not "missing".
	if err := os.MkdirAll(filepath.Join(s.Dir(), "token", kid+".pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, keys.PurposeToken, kid); err == nil || errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get on a directory = %v, want a non-NotFound error", err)
	}
}
