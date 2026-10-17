//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// canaryNeedles returns every encoding of secret a leak could take, keyed by
// a label for the failure message: raw, URL-encoded (query form and every
// byte percent-encoded), hex (lower and upper), and base64 in the standard
// and URL alphabets at all three byte alignments.
//
// A base64 stream can start the secret at byte offset 0, 1 or 2 of a 3-byte
// group, which changes every character. For each alignment the needle is the
// run of characters that depend on secret bytes ONLY (not on the unknown
// bytes before/after it), so it matches whether the surrounding text was
// padded ("=") or not: a padded and an unpadded encoding share this run.
func canaryNeedles(secret string) map[string]string {
	n := map[string]string{
		"raw":              secret,
		"url-query":        queryEscape(secret),
		"url-all-bytes":    percentAll(secret),
		"hex-lower":        hex.EncodeToString([]byte(secret)),
		"hex-upper":        strings.ToUpper(hex.EncodeToString([]byte(secret))),
		"hex-0x-separated": hexSeparated(secret),
	}
	for k := 0; k < 3; k++ {
		in := append(make([]byte, k), secret...)
		lo := (8*k + 5) / 6             // first char made of secret bits only
		hi := 8 * (k + len(secret)) / 6 // chars made of whole secret bits
		for name, enc := range map[string]*base64.Encoding{"std": base64.RawStdEncoding, "url": base64.RawURLEncoding} {
			s := enc.EncodeToString(in)
			n[fmt.Sprintf("base64-%s-align%d", name, k)] = s[lo:hi]
		}
	}
	return n
}

func queryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func percentAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// hexSeparated is the "\x43\x41…" spelling of the secret.
func hexSeparated(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "\\x%02x", s[i])
	}
	return b.String()
}

// leaksIn reports the labels of every needle found in text. Hex and percent
// needles are compared case-insensitively where the encoding allows either.
func leaksIn(text string, needles map[string]string) []string {
	var hits []string
	lower := strings.ToLower(text)
	for label, needle := range needles {
		if strings.Contains(text, needle) ||
			((strings.HasPrefix(label, "hex") || strings.HasPrefix(label, "url")) &&
				strings.Contains(lower, strings.ToLower(needle))) {
			hits = append(hits, label)
		}
	}
	return hits
}

// AssertCanaryNeverLeaked fails the test if the canary, in any encoding,
// appears in:
//   - agentOutputs: the stdout the caller captured from agent commands, plus
//     each agent's environment (read here);
//   - `docker compose logs` of EVERY service;
//   - each worker's /dashboard/api/traffic;
//   - every control-plane fleet-API path.
//
// The fake upstream's recorder (GET /_recorded) is EXCLUDED on purpose: it
// stands in for the real upstream, which is the ONE place the swapped secret
// must arrive. Its container's logs ARE scanned. A sanity check proves the
// scanner can see the canary (see TestCanaryScannerSeesTheRecorder).
func AssertCanaryNeverLeaked(tb testing.TB, agentOutputs ...string) {
	tb.Helper()
	needles := canaryNeedles(canary)
	check := func(where, text string) {
		tb.Helper()
		if hits := leaksIn(text, needles); len(hits) > 0 {
			tb.Errorf("canary leaked in %s (encodings: %v)", where, hits)
		}
	}
	for i, out := range agentOutputs {
		check(fmt.Sprintf("agent output #%d", i+1), out)
	}
	for _, agent := range []string{svcAgent1, svcAgent2, svcAgent3} {
		env, exit := agentExec(tb, agent, "env")
		if exit != 0 {
			tb.Fatalf("e2e: env in %s exited %d", agent, exit)
		}
		check(agent+" environment", env)
	}
	for _, svc := range allServices {
		check("logs of "+svc, logs(tb, svc))
	}
	for w := range workerAdmin {
		check(w+" traffic API", string(workerTraffic(tb, w)))
	}
	for _, p := range fleetPaths {
		check("control-plane fleet API "+p, string(fleetGet(tb, p)))
	}
}
