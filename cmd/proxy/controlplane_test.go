package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeedServedConfig(t *testing.T) {
	t.Run("seeds when absent", func(t *testing.T) {
		dir := t.TempDir()
		seed := filepath.Join(dir, "seed.yaml")
		if err := os.WriteFile(seed, []byte("policy: {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		served := filepath.Join(dir, "state", "config.yaml")

		seeded, err := seedServedConfig(served, seed)
		if err != nil {
			t.Fatalf("seedServedConfig: %v", err)
		}
		if !seeded {
			t.Fatal("expected seeded=true on first call")
		}
		got, err := os.ReadFile(served)
		if err != nil {
			t.Fatalf("read served: %v", err)
		}
		if string(got) != "policy: {}\n" {
			t.Fatalf("served content = %q, want seed copy", string(got))
		}
	})

	t.Run("reuses when present and preserves edits", func(t *testing.T) {
		dir := t.TempDir()
		seed := filepath.Join(dir, "seed.yaml")
		if err := os.WriteFile(seed, []byte("seed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		served := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(served, []byte("edited\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		seeded, err := seedServedConfig(served, seed)
		if err != nil {
			t.Fatalf("seedServedConfig: %v", err)
		}
		if seeded {
			t.Fatal("expected seeded=false when served already exists")
		}
		got, _ := os.ReadFile(served)
		if string(got) != "edited\n" {
			t.Fatalf("served content = %q, want the existing edit preserved", string(got))
		}
	})

	t.Run("errors when seed missing", func(t *testing.T) {
		dir := t.TempDir()
		served := filepath.Join(dir, "config.yaml")
		if _, err := seedServedConfig(served, filepath.Join(dir, "nope.yaml")); err == nil {
			t.Fatal("expected error when seed file is missing")
		}
	})
}

func TestDirWritable(t *testing.T) {
	if !dirWritable(t.TempDir()) {
		t.Fatal("expected a fresh temp dir to be writable")
	}
	// A path under a non-existent directory cannot be written to.
	if dirWritable(filepath.Join(t.TempDir(), "does-not-exist")) {
		t.Fatal("expected a non-existent directory to be non-writable")
	}
}
