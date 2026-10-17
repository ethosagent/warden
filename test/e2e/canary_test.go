//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
	"github.com/ethosagent/warden/test/harness/compose"
)

// TestCanaryNeedles proves the scanner this package uses (canaryNeedles and
// leaksIn over the compose package) finds the secret under every encoding
// the leak hunt claims, at every base64 alignment, with and without padding.
// "\xfb\xff?>>" forces '+' '/' (std) and '-' '_' (url) into the output.
func TestCanaryNeedles(t *testing.T) {
	for _, secret := range []string{canary, "\xfb\xff?>>tail-secret\xfe\xfd"} {
		needles := canaryNeedles(secret)
		enc := map[string]func([]byte) string{
			"std-padded":   base64.StdEncoding.EncodeToString,
			"std-raw":      base64.RawStdEncoding.EncodeToString,
			"url-padded":   base64.URLEncoding.EncodeToString,
			"url-raw":      base64.RawURLEncoding.EncodeToString,
			"hex":          hex.EncodeToString,
			"hex-upper":    func(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) },
			"query-escape": func(b []byte) string { return url.QueryEscape(string(b)) },
		}
		for name, f := range enc {
			for pre := 0; pre < 3; pre++ {
				for _, post := range []string{"", "x", "yz", "Zm9v"} {
					text := "header: " + f(append([]byte(strings.Repeat("A", pre)), append([]byte(secret), post...)...)) + " trailer"
					if strings.HasPrefix(name, "hex") || name == "query-escape" {
						text = "k=" + strings.Repeat("A", pre) + f([]byte(secret)) + post
					}
					if len(leaksIn(text, needles)) == 0 {
						t.Errorf("%s secret %q pre=%d post=%q: not detected in %q", name, secret, pre, post, text)
					}
				}
			}
		}
		if hits := leaksIn("nothing to see: Zm9vYmFy 0123abcd", needles); len(hits) > 0 {
			t.Errorf("false positive on clean text: %v", hits)
		}
	}
}

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

// TestCanarySweepCoversUnregisteredHosts: the raw canary the agent sends to
// mcp.example.test — a host OUTSIDE the secret's MatchHosts that this scenario
// never registered a view for — must fail the harness canary sweep. The stack's
// recorder sees every host the fake DNS serves, registered or not, so the sweep
// reads its whole /_recorded view (harness.WholeRecorder); before that, a
// worker bug that swapped the secret toward this host passed both sweeps clean.
// The harness boots FIRST: its target Start resets the recorder, so the sweep's
// view holds exactly this scenario's traffic.
func TestCanarySweepCoversUnregisteredHosts(t *testing.T) {
	h := harness.New(t, harness.WithTarget(compose.New()))
	res := agentRun(t, svcAgent1, "curl", "-sS", "--max-time", "10",
		"-H", "Authorization: Bearer "+canary, "-o", "/dev/null",
		"https://mcp.example.test/")
	if res.exit != 0 {
		t.Fatalf("the canary request to mcp.example.test did not go through: exit %d: %s", res.exit, res.stderr)
	}

	leaks := strings.Join(h.CanaryLeaks(), "\n")
	if !strings.Contains(leaks, "mcp.example.test") || !strings.Contains(leaks, "raw") {
		t.Fatalf("the raw canary reached the out-of-scope, unregistered mcp.example.test and the sweep said:\n%s", leaks)
	}
}
