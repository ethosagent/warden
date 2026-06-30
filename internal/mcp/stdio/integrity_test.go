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
	content := []byte("#!/bin/sh\necho signed-server\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sig := ed25519.Sign(priv, content)
	sigHex := hex.EncodeToString(sig)
	pubHex := hex.EncodeToString(pub)

	t.Run("valid signature passes", func(t *testing.T) {
		if err := VerifyEd25519(path, sigHex, pubHex); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("uppercase hex passes (case-insensitive)", func(t *testing.T) {
		if err := VerifyEd25519(path, strings.ToUpper(sigHex), strings.ToUpper(pubHex)); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("empty sig+key skips", func(t *testing.T) {
		if err := VerifyEd25519(path, "", ""); err != nil {
			t.Fatalf("empty sig+key should skip, got %v", err)
		}
		if err := VerifyEd25519(path, "  ", "  "); err != nil {
			t.Fatalf("whitespace sig+key should skip, got %v", err)
		}
	})

	t.Run("sig without key errors", func(t *testing.T) {
		if err := VerifyEd25519(path, sigHex, ""); err == nil {
			t.Fatal("want error when key missing, got nil")
		}
	})

	t.Run("key without sig errors", func(t *testing.T) {
		if err := VerifyEd25519(path, "", pubHex); err == nil {
			t.Fatal("want error when sig missing, got nil")
		}
	})

	t.Run("wrong key fails", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if err := VerifyEd25519(path, sigHex, hex.EncodeToString(otherPub)); err == nil {
			t.Fatal("want mismatch error for wrong key, got nil")
		}
	})

	t.Run("tampered file fails", func(t *testing.T) {
		tampered := filepath.Join(dir, "tampered.bin")
		if err := os.WriteFile(tampered, append(append([]byte(nil), content...), '!'), 0o600); err != nil {
			t.Fatalf("write tampered: %v", err)
		}
		if err := VerifyEd25519(tampered, sigHex, pubHex); err == nil {
			t.Fatal("want mismatch error for tampered file, got nil")
		}
	})

	t.Run("bad sig hex errors", func(t *testing.T) {
		if err := VerifyEd25519(path, "zzz", pubHex); err == nil {
			t.Fatal("want error on bad signature hex, got nil")
		}
	})

	t.Run("bad key hex errors", func(t *testing.T) {
		if err := VerifyEd25519(path, sigHex, "zzz"); err == nil {
			t.Fatal("want error on bad key hex, got nil")
		}
	})

	t.Run("wrong key length errors", func(t *testing.T) {
		if err := VerifyEd25519(path, sigHex, "abcd"); err == nil {
			t.Fatal("want error on short key, got nil")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if err := VerifyEd25519(filepath.Join(dir, "nope"), sigHex, pubHex); err == nil {
			t.Fatal("want error on missing file, got nil")
		}
	})
}
