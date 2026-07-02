// Package scan detects sensitive content — credential leakage, prompt injection,
// and PII — in request and response bodies. Findings omit the matched content by
// default; a MASKED sample (last-4 + length, never the raw value) is captured only
// when the Scanner is built WithEvidence.
package scan

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Detection represents a single finding from scanning response content.
// It omits matched content by default; Evidence is populated (with a MASKED
// sample — never the raw value) only when the Scanner is built WithEvidence.
type Detection struct {
	Category string // "injection", "credential_leak", or "pii"
	Pattern  string // pattern name
	Severity string // "high", "medium", "low"
	Evidence string // masked sample (opt-in): "•••• + last-4 (len N)" — never raw
}

const maxScanSize = 1 << 20 // 1 MB

// Scanner is the content-scanning seam consumed by the MCP subsystem. The
// concrete implementation is patternScanner (regex-based); consumers depend on
// this interface so scanning can be faked/swapped in tests.
type Scanner interface {
	// ScanResponse scans body and returns any detections (deduplicated).
	ScanResponse(body []byte) []Detection
}

// patternScanner holds compiled regex patterns for injection, credential, and
// PII detection. It is safe for concurrent use after construction and satisfies
// the Scanner interface.
type patternScanner struct {
	injectionPatterns  []compiledPattern
	credentialPatterns []compiledPattern
	piiPatterns        []compiledPattern
	evidence           bool // capture a MASKED evidence sample per detection
}

// compiledPattern is a single detection rule. An optional validator may further
// vet a regex match before a Detection is emitted (e.g. Luhn check, structural
// SSN validity); regex alone is too noisy for some PII categories. When
// validate is nil the regex match alone is sufficient.
type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
	category string
	validate func(match string) bool
}

// options holds Scanner construction settings configured via Option values.
type options struct {
	phonePII bool
	evidence bool
}

// Option configures a Scanner at construction time.
type Option func(*options)

// WithPhonePII enables (or disables) the opt-in PII phone-number detector.
// Phone detection is off by default because bare digit runs over-match.
func WithPhonePII(enabled bool) Option {
	return func(o *options) { o.phonePII = enabled }
}

// WithEvidence enables capturing a MASKED sample per detection (last-4 + length;
// never the raw value), so an operator can judge a real leak from a false
// positive. Off by default.
func WithEvidence(enabled bool) Option {
	return func(o *options) { o.evidence = enabled }
}

// NewScanner compiles all detection patterns and returns a ready-to-use Scanner.
// By default it runs injection, credential, and PII (email/card/SSN) detectors;
// the noisy phone detector is opt-in via WithPhonePII(true). It returns the
// Scanner interface so callers depend on the seam, not the concrete type.
func NewScanner(opts ...Option) Scanner {
	var cfg options
	for _, opt := range opts {
		opt(&cfg)
	}

	s := &patternScanner{evidence: cfg.evidence}

	// Injection patterns
	s.injectionPatterns = []compiledPattern{
		{
			name:     "ignore_previous_instructions",
			re:       regexp.MustCompile(`(?i)(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|your)\s+instructions`),
			severity: "high",
			category: "injection",
		},
		{
			name:     "system_prompt_override",
			re:       regexp.MustCompile(`(?i)(?:you\s+are\s+now|your\s+new\s+role\s+is|forget\s+your\s+system\s+prompt)`),
			severity: "high",
			category: "injection",
		},
		{
			name:     "instruction_injection",
			re:       regexp.MustCompile(`(?i)(?:IMPORTANT\s*:|INSTRUCTION\s*:|\[SYSTEM\])`),
			severity: "medium",
			category: "injection",
		},
		{
			name:     "delimiter_attack",
			re:       regexp.MustCompile(`(?:<\|endoftext\|>|<\|im_start\|>|<\|im_end\|>|\[/INST\]|<\|system\|>)`),
			severity: "high",
			category: "injection",
		},
	}

	// Credential patterns
	s.credentialPatterns = []compiledPattern{
		{
			name:     "aws_access_key",
			re:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			severity: "high",
			category: "credential_leak",
		},
		{
			name:     "aws_secret_key",
			re:       regexp.MustCompile(`(?i)(?:aws|amazon).{0,40}[A-Za-z0-9/+=]{40}`),
			severity: "medium",
			category: "credential_leak",
		},
		{
			name:     "github_token",
			re:       regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}`),
			severity: "high",
			category: "credential_leak",
		},
		{
			name:     "stripe_key",
			re:       regexp.MustCompile(`(?:sk|rk)_live_[A-Za-z0-9]{24,}`),
			severity: "high",
			category: "credential_leak",
		},
		{
			name:     "jwt",
			re:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
			severity: "medium",
			category: "credential_leak",
		},
		{
			name:     "private_key",
			re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`),
			severity: "high",
			category: "credential_leak",
		},
		{
			name:     "generic_api_key",
			re:       regexp.MustCompile(`(?i)(?:key|token|secret|password)\s*[:=]\s*["']?[A-Za-z0-9/+=_-]{32,}["']?`),
			severity: "low",
			category: "credential_leak",
		},
	}

	// PII patterns. Some carry a post-match validator because the regex alone
	// over-matches (random 16-digit numbers, structurally invalid SSNs).
	s.piiPatterns = []compiledPattern{
		{
			name:     "email",
			re:       regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
			severity: "medium",
			category: "pii",
		},
		{
			name:     "card",
			re:       regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`),
			severity: "medium",
			category: "pii",
			validate: validLuhn,
		},
		{
			name:     "ssn",
			re:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			severity: "medium",
			category: "pii",
			validate: validSSN,
		},
	}

	if cfg.phonePII {
		s.piiPatterns = append(s.piiPatterns, compiledPattern{
			name:     "phone",
			re:       regexp.MustCompile(`\+[1-9]\d{7,14}\b|\(\d{3}\)\s*\d{3}[ .-]\d{4}\b|\b\d{3}[ .-]\d{3}[ .-]\d{4}\b`),
			severity: "low",
			category: "pii",
		})
	}

	return s
}

// validLuhn reports whether the digits in match (separators stripped) pass the
// Luhn checksum. The match must contain 13–19 digits.
func validLuhn(match string) bool {
	digits := make([]int, 0, len(match))
	for _, r := range match {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// validSSN reports whether match is a structurally valid US SSN of the form
// AAA-GG-SSSS. It rejects area 000, 666, and 900–999; group 00; and serial 0000.
func validSSN(match string) bool {
	// Format is guaranteed by the regex: \d{3}-\d{2}-\d{4}.
	if len(match) != 11 {
		return false
	}
	area := match[0:3]
	group := match[4:6]
	serial := match[7:11]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" {
		return false
	}
	if serial == "0000" {
		return false
	}
	return true
}

// ScanResponse scans the response body for injection and credential patterns.
// It also decodes base64 blocks and URL-encoded content for deeper inspection.
// Detections are deduplicated before returning.
func (s *patternScanner) ScanResponse(body []byte) []Detection {
	if len(body) > maxScanSize {
		body = body[:maxScanSize]
	}

	seen := make(map[string]struct{})
	var detections []Detection

	addDetection := func(d Detection) {
		key := d.Category + "|" + d.Pattern + "|" + d.Severity
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			detections = append(detections, d)
		}
	}

	allPatterns := make([]compiledPattern, 0, len(s.injectionPatterns)+len(s.credentialPatterns)+len(s.piiPatterns))
	allPatterns = append(allPatterns, s.injectionPatterns...)
	allPatterns = append(allPatterns, s.credentialPatterns...)
	allPatterns = append(allPatterns, s.piiPatterns...)

	scanLayer := func(data []byte) {
		for _, p := range allPatterns {
			m, ok := firstMatch(p, data)
			if !ok {
				continue
			}
			det := Detection{Category: p.category, Pattern: p.name, Severity: p.severity}
			if s.evidence {
				det.Evidence = maskMatch(m)
			}
			addDetection(det)
		}
	}

	// 1. Scan raw body
	scanLayer(body)

	// 2. Decode base64 blocks and scan each
	for _, block := range decodeBase64Blocks(body) {
		scanLayer(block)
	}

	// 3. URL-decode and scan
	if urlDecoded := decodeURLEncoded(body); urlDecoded != nil {
		scanLayer(urlDecoded)
	}

	return detections
}

// firstMatch returns the first matching substring for p — the first that also
// satisfies p.validate when present (Luhn, SSN structure) — and whether one was
// found. A regex match alone suffices when p has no validator.
func firstMatch(p compiledPattern, data []byte) (string, bool) {
	if p.validate == nil {
		m := p.re.Find(data)
		if m == nil {
			return "", false
		}
		return string(m), true
	}
	for _, m := range p.re.FindAll(data, -1) {
		if p.validate(string(m)) {
			return string(m), true
		}
	}
	return "", false
}

// maskMatch returns a value-free, MASKED form of a matched secret/PII string:
// the last 4 characters plus the length, everything else replaced with •. Short
// matches are fully masked. The raw value is never revealed — this mirrors the
// secret-by-reference model (last-4 + length) applied to scan findings.
func maskMatch(s string) string {
	r := []rune(s)
	n := len(r)
	if n == 0 {
		return ""
	}
	const reveal = 4
	if n <= reveal*2 {
		return strings.Repeat("•", min(n, 8)) + " (len " + strconv.Itoa(n) + ")"
	}
	return strings.Repeat("•", 8) + string(r[n-reveal:]) + " (len " + strconv.Itoa(n) + ")"
}

// base64BlockRe matches contiguous runs of 64+ base64 characters.
var base64BlockRe = regexp.MustCompile(`[A-Za-z0-9+/=]{64,}`)

const maxBase64Blocks = 10
const maxBase64BlockSize = 64 * 1024

// decodeBase64Blocks finds contiguous runs of 64+ base64 characters in data,
// attempts to decode each, and returns successfully decoded blocks.
// At most maxBase64Blocks blocks are decoded, and each decoded block is
// capped at maxBase64BlockSize bytes.
func decodeBase64Blocks(data []byte) [][]byte {
	matches := base64BlockRe.FindAll(data, -1)
	var results [][]byte
	for _, m := range matches {
		if len(results) >= maxBase64Blocks {
			break
		}
		s := string(m)
		// Try standard decoding first
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// Try with padding adjustment
			s = strings.TrimRight(s, "=")
			switch len(s) % 4 {
			case 2:
				s += "=="
			case 3:
				s += "="
			}
			decoded, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				// Try URL-safe encoding as last resort
				decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(string(m), "="))
				if err != nil {
					continue
				}
			}
		}
		if len(decoded) > maxBase64BlockSize {
			decoded = decoded[:maxBase64BlockSize]
		}
		results = append(results, decoded)
	}
	return results
}

// decodeURLEncoded checks if data contains percent-encoded sequences and
// returns the URL-decoded form. Returns nil if no encoding is present or
// decoding fails. Output is capped at maxScanSize.
func decodeURLEncoded(data []byte) []byte {
	s := string(data)
	if !strings.Contains(s, "%") {
		return nil
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return nil
	}
	// Only return if decoding actually changed something
	if decoded == s {
		return nil
	}
	b := []byte(decoded)
	if len(b) > maxScanSize {
		b = b[:maxScanSize]
	}
	return b
}
