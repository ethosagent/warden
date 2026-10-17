//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

// TestCanaryNeedles proves the scanner finds the secret under every encoding
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
