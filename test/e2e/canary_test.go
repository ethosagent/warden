//go:build e2e

package e2e

import (
	"testing"
)

// TestCanaryNeedles lives with the needles now: the compose package's
// TestNeedlesDetectsEveryEncoding proves every encoding, at every base64
// alignment, with and without padding.

// TestCanaryScannerSeesTheRecorder: the scanner demonstrably detects the
// canary where it legitimately is (the upstream recorder). Without this, a
// clean AssertCanaryNeverLeaked could just mean a blind scanner.
func TestCanaryScannerSeesTheRecorder(t *testing.T) {
	resetRecorded(t)
	res := agentRun(t, svcAgent1, "curl", "-sS", "--max-time", "10", "-H", "Authorization: Bearer "+placeholder, "-o", "/dev/null", "https://api.example.test/")
	if res.exit != 0 {
		t.Fatalf("allowed call failed: exit %d: %s", res.exit, res.stderr)
	}
	if hits := leaksIn(string(recordedRaw(t)), canaryNeedles(canary)); len(hits) == 0 {
		t.Fatal("scanner found no canary in the recorder, which holds it by design")
	}
}
