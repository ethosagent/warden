package policy

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// fuzzPolicy mixes the matcher dialects: exact, wildcard, regex and port-pinned
// entries on both lists. There is no catch-all allow: a catch-all would let any
// string through by design, which says nothing about the matcher.
func fuzzPolicy() config.Policy {
	return config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "httpbin.org"},
			{Domain: "api.openai.com"},
			{Domain: "example.com", Port: 8443},
			{Domain: "*.corp.test"},
			{Domain: `~^svc-\d+\.mesh\.test$`},
		},
		Denylist: []config.DenylistEntry{
			{Domain: "bad.corp.test"},
			{Domain: "*.evil.test"},
			{Domain: "denied.example.com", Port: 8443},
			{Domain: `~^blocked-\d+\.mesh\.test$`},
		},
	}
}

func asciiUpper(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, s)
}

func asciiAlternate(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 1 && b[i] >= 'a' && b[i] <= 'z' {
			b[i] = b[i] - 'a' + 'A'
		}
	}
	return string(b)
}

func percentEncode(s string, all bool) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if all || c == '.' {
			fmt.Fprintf(&sb, "%%%02x", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// variants are the respellings an agent could try on a host name: ASCII case,
// one extra trailing dot, and percent-encoding. (Unicode case folding is left
// out on purpose: "ſ" and "s" are different DNS names, not spellings of one.)
func variants(d string) map[string]string {
	return map[string]string{
		"upper":         asciiUpper(d),
		"alternating":   asciiAlternate(d),
		"trailing-dot":  d + ".",
		"upper+dot":     asciiUpper(d) + ".",
		"pct-dots":      percentEncode(d, false),
		"pct-all":       percentEncode(d, true),
		"query-escaped": url.QueryEscape(d),
		"path-escaped":  url.PathEscape(d),
		"pct-all+dot":   percentEncode(d, true) + ".",
	}
}

// FuzzPolicyMatch checks the matcher on arbitrary host and port inputs:
//   - it never panics;
//   - a Deny never becomes an Allow under case, trailing-dot or encoding variants;
//   - the case and single-trailing-dot variants of a host decide the same way as
//     the host itself, in both directions (Allow stays Allow, Deny stays Deny).
func FuzzPolicyMatch(f *testing.F) {
	// Seeds live in testdata/fuzz/FuzzPolicyMatch: exact/wildcard/regex hosts in
	// every case, dot and encoding spelling, plus the red-team playbook CONNECT
	// tricks (.agents/playbooks/red-team.md §2.2): obfuscated IPs, userinfo,
	// trailing dots and NULs.
	ev := NewEvaluator(fuzzPolicy())
	f.Fuzz(func(t *testing.T, host string, port int) {
		got := ev.Evaluate(host, port, SchemeHTTPS)
		_ = ev.Evaluate(host, port, SchemeHTTP)
		for name, v := range variants(host) {
			vd := ev.Evaluate(v, port, SchemeHTTPS)
			if got == Deny && vd == Allow {
				t.Fatalf("Deny became Allow under %s variant: host %q -> %q port %d", name, host, v, port)
			}
		}
		// Case and one trailing dot must not change the verdict, either way.
		if !strings.HasSuffix(host, ".") {
			for name, v := range map[string]string{"upper": asciiUpper(host), "alternating": asciiAlternate(host), "trailing-dot": host + "."} {
				if vd := ev.Evaluate(v, port, SchemeHTTPS); vd != got {
					t.Fatalf("%s variant changed the verdict: host %q (%v) -> %q (%v) port %d", name, host, got, v, vd, port)
				}
			}
		}
	})
}
