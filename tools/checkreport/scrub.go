package main

import (
	"encoding/base64"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/scan"
)

const (
	truncMarker = "\n…[truncated]"
	redacted    = "[REDACTED]"
	withheld    = "[withheld: contains an encoded credential]"

	withheldBlock = "[withheld: base64 text]"

	// maxScrubInput bounds what the scanner reads. Everything beyond it is
	// dropped, never emitted, so a secret split at the boundary cannot leak.
	maxScrubInput = 512 << 10

	// minEnvSecret is the shortest env value scrubbed; shorter values match
	// ordinary text too often to be worth redacting.
	minEnvSecret = 8
)

var (
	envSecretName = regexp.MustCompile(`(?i)(token|secret|passw|credential|api_?key|private_?key|auth)`)
	// pemPrivateKey matches a whole PEM private-key block, body included: the
	// scanner only flags the BEGIN line, and the body is the actual secret.
	// base64Block is a base64/base64url run of 40+ characters, the shortest
	// withheld when it decodes to text.
	base64Block   = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
	pemPrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)
)

// Scrubber removes secrets from text before it enters a report. It reuses
// Warden's own credential detectors (internal/scan), so the report scrub and the
// proxy's DLP can never disagree about what a credential looks like, and also
// redacts the values of secret-looking environment variables.
type Scrubber struct {
	scanner scan.RequestScanner
	env     []string
}

// NewScrubber builds a scrubber from an environment (KEY=value entries).
func NewScrubber(environ []string) *Scrubber {
	s := &Scrubber{}
	s.scanner, _ = scan.NewScanner().(scan.RequestScanner)
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && len(v) >= minEnvSecret && envSecretName.MatchString(k) {
			s.env = append(s.env, v)
		}
	}
	// Longest first, so a value that contains another is redacted whole.
	slices.SortFunc(s.env, func(a, b string) int { return len(b) - len(a) })
	return s
}

// Clean returns text with credentials redacted. It fails closed: if the scanner
// is unavailable or finds a credential inside an encoded layer (which cannot be
// redacted in place), the whole text is withheld.
func (s *Scrubber) Clean(text string) string {
	out := s.clean(text)
	if out == withheld {
		return out
	}
	return withholdBase64(out)
}

func (s *Scrubber) clean(text string) string {
	if text == "" {
		return text
	}
	if len(text) > maxScrubInput {
		text = trimToRune(text[:maxScrubInput])
	}
	for _, v := range s.env {
		text = strings.ReplaceAll(text, v, redacted)
	}
	text = pemPrivateKey.ReplaceAllString(text, redacted)
	if s.scanner == nil {
		return withheld
	}
	spans, encoded := s.scanner.ScanRequestSpans([]byte(text))
	for _, d := range encoded {
		if d.Category == "credential_leak" {
			return withheld
		}
	}
	var cuts [][2]int
	for _, sp := range spans {
		if sp.Category == "credential_leak" {
			cuts = append(cuts, [2]int{sp.Start, sp.End})
		}
	}
	if len(cuts) == 0 {
		return text
	}
	slices.SortFunc(cuts, func(a, b [2]int) int { return a[0] - b[0] })
	var b strings.Builder
	pos := 0
	for _, c := range cuts {
		if c[1] <= pos {
			continue
		}
		if c[0] > pos {
			b.WriteString(text[pos:c[0]])
		}
		b.WriteString(redacted)
		pos = c[1]
	}
	b.WriteString(text[pos:])
	return b.String()
}

// capBytes truncates s to at most max bytes (on a rune boundary) plus a marker.
func capBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return trimToRune(s[:max]) + truncMarker
}

// trimToRune drops a trailing partial UTF-8 sequence.
func trimToRune(s string) string {
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			return s
		}
		s = s[:len(s)-1]
	}
	return s
}

// withholdBase64 replaces every base64 or base64url run of 40 or
// more characters (base64Block) that decodes to mostly printable text. It does not look at
// what the text says: a secret split from its label ("password: x") matches no
// credential pattern, and a report excerpt loses little by dropping the block.
func withholdBase64(text string) string {
	return base64Block.ReplaceAllStringFunc(text, func(m string) string {
		if decodesToText(strings.TrimRight(m, "=")) {
			return withheldBlock
		}
		return m
	})
}

// decodesToText reports whether unpadded base64 (either alphabet) decodes to
// mostly printable bytes.
func decodesToText(b64 string) bool {
	if len(b64)%4 == 1 {
		b64 = b64[:len(b64)-1] // a lone trailing character carries no byte
	}
	enc := base64.RawStdEncoding
	if strings.ContainsAny(b64, "-_") {
		enc = base64.RawURLEncoding
	}
	raw, err := enc.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		return false
	}
	printable := 0
	for _, c := range raw {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return printable*10 >= len(raw)*9
}
