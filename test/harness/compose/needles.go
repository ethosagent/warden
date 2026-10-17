package compose

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// The canary needles: every encoding of a secret value a leak could take in
// the stack's surfaces. Moved here from test/e2e (#368) so BOTH suites share
// one scanner — the e2e sweep, the whole-stack leak hunt and this package's
// own surfaces all match the same set, and its proof (TestNeedlesDetectsEvery
//Encoding) runs in the default gate.

// Needles returns every encoding of secret a leak could take, keyed by a label
// for the failure message: raw, URL-encoded (query form and every byte
// percent-encoded), hex (lower and upper), and base64 in the standard and URL
// alphabets at all three byte alignments.
//
// A base64 stream can start the secret at byte offset 0, 1 or 2 of a 3-byte
// group, which changes every character. For each alignment the needle is the
// run of characters that depend on secret bytes ONLY (not on the unknown bytes
// before/after it), so it matches whether the surrounding text was padded
// ("=") or not: a padded and an unpadded encoding share this run.
func Needles(secret string) map[string]string {
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

// LeaksIn reports the labels of every needle found in text. Hex and percent
// needles are compared case-insensitively where the encoding allows either.
func LeaksIn(text string, needles map[string]string) []string {
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
