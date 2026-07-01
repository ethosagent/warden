package stdio

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.bin")
	content := []byte("#!/bin/sh\necho hello\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	t.Run("matching hash passes", func(t *testing.T) {
		if err := VerifyBinary(path, hexSum); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("uppercase hash passes (case-insensitive)", func(t *testing.T) {
		if err := VerifyBinary(path, strings.ToUpper(hexSum)); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("wrong hash fails", func(t *testing.T) {
		wrong := strings.Repeat("ab", 32)
		if err := VerifyBinary(path, wrong); err == nil {
			t.Fatal("want mismatch error, got nil")
		}
	})

	t.Run("empty want skips", func(t *testing.T) {
		if err := VerifyBinary(path, ""); err != nil {
			t.Fatalf("empty want should skip, got %v", err)
		}
		if err := VerifyBinary(path, "   "); err != nil {
			t.Fatalf("whitespace want should skip, got %v", err)
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if err := VerifyBinary(filepath.Join(dir, "nope"), hexSum); err == nil {
			t.Fatal("want error on missing file, got nil")
		}
	})

	t.Run("invalid hex errors", func(t *testing.T) {
		if err := VerifyBinary(path, "zzz"); err == nil {
			t.Fatal("want error on invalid hex, got nil")
		}
	})
}

func TestVerifyEd25519(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.bin")
	content := []byte("#!/bin/sh\necho hello\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	sigHex := hex.EncodeToString(ed25519.Sign(priv, content))

	t.Run("valid signature passes", func(t *testing.T) {
		if err := VerifyEd25519(path, pubHex, sigHex); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("uppercase hex passes (case-insensitive)", func(t *testing.T) {
		if err := VerifyEd25519(path, strings.ToUpper(pubHex), strings.ToUpper(sigHex)); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("tampered file fails", func(t *testing.T) {
		tampered := filepath.Join(dir, "tampered.bin")
		if err := os.WriteFile(tampered, []byte("#!/bin/sh\necho pwned\n"), 0o600); err != nil {
			t.Fatalf("write tampered: %v", err)
		}
		if err := VerifyEd25519(tampered, pubHex, sigHex); err == nil {
			t.Fatal("want signature-mismatch error on tampered file, got nil")
		}
	})

	t.Run("wrong public key fails", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if err := VerifyEd25519(path, hex.EncodeToString(otherPub), sigHex); err == nil {
			t.Fatal("want error with wrong public key, got nil")
		}
	})

	t.Run("empty pubkey and sig skips", func(t *testing.T) {
		if err := VerifyEd25519(path, "", ""); err != nil {
			t.Fatalf("empty pubkey+sig should skip, got %v", err)
		}
		if err := VerifyEd25519(path, "   ", "   "); err != nil {
			t.Fatalf("whitespace pubkey+sig should skip, got %v", err)
		}
	})

	t.Run("pubkey without sig errors (fail-closed)", func(t *testing.T) {
		if err := VerifyEd25519(path, pubHex, ""); err == nil {
			t.Fatal("want error when pubkey set but sig missing, got nil")
		}
	})

	t.Run("sig without pubkey errors (fail-closed)", func(t *testing.T) {
		if err := VerifyEd25519(path, "", sigHex); err == nil {
			t.Fatal("want error when sig set but pubkey missing, got nil")
		}
	})

	t.Run("malformed pubkey hex errors", func(t *testing.T) {
		if err := VerifyEd25519(path, "zzz", sigHex); err == nil {
			t.Fatal("want error on malformed pubkey hex, got nil")
		}
	})

	t.Run("malformed sig hex errors", func(t *testing.T) {
		if err := VerifyEd25519(path, pubHex, "zzz"); err == nil {
			t.Fatal("want error on malformed sig hex, got nil")
		}
	})

	t.Run("wrong public-key length errors", func(t *testing.T) {
		if err := VerifyEd25519(path, hex.EncodeToString([]byte("short")), sigHex); err == nil {
			t.Fatal("want error on wrong key length, got nil")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if err := VerifyEd25519(filepath.Join(dir, "nope"), pubHex, sigHex); err == nil {
			t.Fatal("want error on missing file, got nil")
		}
	})
}
