package stdio

import (
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
