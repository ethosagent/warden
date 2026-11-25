package scenarios

import (
	"regexp"
	"testing"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/scan"
)

// internal/scan is in the data zone and cannot import internal/apikeys or
// internal/controlplane, so it carries copies of the two credential shapes. This
// test (test/** may import both sides) fails if a copy drifts from its owner.
func TestWardenTokenPatternsMatchOwners(t *testing.T) {
	if scan.WardenAPIKeyPattern != apikeys.Pattern {
		t.Errorf("scan.WardenAPIKeyPattern = %q, apikeys.Pattern = %q", scan.WardenAPIKeyPattern, apikeys.Pattern)
	}
	if scan.WardenWorkerTokenPattern != controlplane.WorkerTokenPattern {
		t.Errorf("scan.WardenWorkerTokenPattern = %q, controlplane.WorkerTokenPattern = %q", scan.WardenWorkerTokenPattern, controlplane.WorkerTokenPattern)
	}
}

// Real minted credentials are fully matched by the owners' patterns and detected
// by the scanner when the option is on.
func TestWardenTokenMintedCredentialsDetected(t *testing.T) {
	k, w := mintWardenCredentials(t)
	if !regexp.MustCompile("^" + apikeys.Pattern + "$").MatchString(k) {
		t.Error("a minted API key does not match apikeys.Pattern")
	}
	if !regexp.MustCompile("^" + controlplane.WorkerTokenPattern + "$").MatchString(w) {
		t.Error("a worker token does not match controlplane.WorkerTokenPattern")
	}
	found := map[string]bool{}
	for _, d := range scan.NewScanner(scan.WithWardenTokens(true)).ScanResponse([]byte(k + " " + w)) {
		found[d.Pattern] = true
	}
	if !found["warden_api_key"] || !found["warden_worker_token"] {
		t.Errorf("detected patterns = %v, want both warden patterns", found)
	}
}
