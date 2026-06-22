package scan

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// Detection represents a single finding from scanning response content.
// It intentionally omits matched content to avoid leaking sensitive data.
type Detection struct {
	Category string // "injection" or "credential_leak"
	Pattern  string // pattern name
	Severity string // "high", "medium", "low"
}

const maxScanSize = 1 << 20 // 1 MB

// Scanner holds compiled regex patterns for injection and credential detection.
// It is safe for concurrent use after construction.
type Scanner struct {
	injectionPatterns  []compiledPattern
	credentialPatterns []compiledPattern
}

type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
	category string
}

// NewScanner compiles all detection patterns and returns a ready-to-use Scanner.
func NewScanner() *Scanner {
	s := &Scanner{}

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

	return s
}

// ScanResponse scans the response body for injection and credential patterns.
// It also decodes base64 blocks and URL-encoded content for deeper inspection.
// Detections are deduplicated before returning.
func (s *Scanner) ScanResponse(body []byte) []Detection {
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

	allPatterns := make([]compiledPattern, 0, len(s.injectionPatterns)+len(s.credentialPatterns))
	allPatterns = append(allPatterns, s.injectionPatterns...)
	allPatterns = append(allPatterns, s.credentialPatterns...)

	// 1. Scan raw body
	for _, p := range allPatterns {
		if p.re.Match(body) {
			addDetection(Detection{
				Category: p.category,
				Pattern:  p.name,
				Severity: p.severity,
			})
		}
	}

	// 2. Decode base64 blocks and scan each
	decoded := decodeBase64Blocks(body)
	for _, block := range decoded {
		for _, p := range allPatterns {
			if p.re.Match(block) {
				addDetection(Detection{
					Category: p.category,
					Pattern:  p.name,
					Severity: p.severity,
				})
			}
		}
	}

	// 3. URL-decode and scan
	urlDecoded := decodeURLEncoded(body)
	if urlDecoded != nil {
		for _, p := range allPatterns {
			if p.re.Match(urlDecoded) {
				addDetection(Detection{
					Category: p.category,
					Pattern:  p.name,
					Severity: p.severity,
				})
			}
		}
	}

	return detections
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
