//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The behavioural end-to-end tests that used to live here (allowlisted HTTPS,
// default-deny, secret swap, decision logging) now run as harness scenarios in
// test/scenarios. This package keeps what the harness cannot test: the built
// binary itself.

// TestSingleBinary verifies that the warden binary builds with CGO_ENABLED=0,
// producing a statically linked executable.
func TestSingleBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping single-binary build test in short mode")
	}

	// Find the project root (test/integration -> ../..).
	// Use the go.mod location as anchor.
	projectRoot := findProjectRoot(t)

	outPath := filepath.Join(t.TempDir(), "warden-test")
	cmd := exec.Command("go", "build", "-o", outPath, "./cmd/proxy")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CGO_ENABLED=0 go build failed: %v\n%s", err, out)
	}

	// Verify the binary exists and is executable.
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat built binary: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("built binary is empty")
	}

	// Optionally check that `file` reports static linking.
	fileCmd := exec.Command("file", outPath)
	fileOut, err := fileCmd.Output()
	if err == nil {
		output := string(fileOut)
		// On Linux, a static Go binary shows "statically linked".
		// On macOS, it shows "Mach-O" without shared library references.
		t.Logf("file output: %s", output)
		if strings.Contains(output, "dynamically linked") {
			t.Fatalf("expected static binary, got: %s", output)
		}
	}
}

// findProjectRoot walks up from the current working directory to find the
// directory containing go.mod.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	// When tests run, the working directory is the test package directory.
	// We need to find the project root (where go.mod lives).
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}
