package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadOrCreateSignerCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp-audit.key")
	s, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigner: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	again, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(s.PubKey(), again.PubKey()) {
		t.Fatal("reload returned a different key")
	}
}

func TestLoadOrCreateSignerRejectsNonEd25519(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ec.key")
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadOrCreateSigner(path)
	if err == nil || !strings.Contains(err.Error(), "not an Ed25519 key") {
		t.Fatalf("err = %v, want not an Ed25519 key", err)
	}
}

func TestLoadOrCreateSignerRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	noPEM := filepath.Join(dir, "nopem.key")
	if err := os.WriteFile(noPEM, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigner(noPEM); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("err = %v, want no PEM block", err)
	}
	badDER := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigner(badDER); err == nil || !strings.Contains(err.Error(), "parse key file") {
		t.Fatalf("err = %v, want parse key file", err)
	}
	if _, err := LoadOrCreateSigner(""); err == nil {
		t.Fatal("empty path: want error")
	}
	if _, err := LoadOrCreateSigner(filepath.Join(dir, "missing-dir", "k.key")); err == nil {
		t.Fatal("missing parent dir: want error")
	}
}

func TestLoadOrCreateSignerConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.key")
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
			s, err := LoadOrCreateSigner(path)
			errs[i] = err
			if err == nil {
				keys[i] = s.PubKey()
			}
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if !bytes.Equal(keys[i], keys[0]) {
			t.Fatalf("call %d returned a different public key", i)
		}
	}
}

func TestKeyID(t *testing.T) {
	s, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(s.PubKey())
	want := hex.EncodeToString(sum[:8])
	if got := KeyID(s.PubKey()); got != want || len(got) != 16 {
		t.Fatalf("KeyID = %q, want %q", got, want)
	}
}

// TestLoadOrCreateSignerWaitsForPartialFile: a key file that exists but is
// still empty (another process created it and has not written yet) is
// re-read until the writer finishes, not rejected at once.
func TestLoadOrCreateSignerWaitsForPartialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.key")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(want.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}()
	got, err := LoadOrCreateSigner(path)
	if werr := <-done; werr != nil {
		t.Fatal(werr)
	}
	if err != nil {
		t.Fatalf("LoadOrCreateSigner: %v", err)
	}
	if !bytes.Equal(got.PubKey(), want.PubKey()) {
		t.Fatal("loaded a different key than the writer wrote")
	}
}
