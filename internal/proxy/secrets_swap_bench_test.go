package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// BenchmarkSecretSwap measures the request-body secret-substitution cost, the
// before/after comparand for Phase 3's one-pass swap.
//
// The "Old" sub-benchmarks reproduce the pre-Phase-3 mechanism: one
// strings.ReplaceAll pass over the body per configured placeholder (N full scans
// for N placeholders). The "New" sub-benchmarks call the real production swap,
// swapBodySecrets, which collapses those into a single strings.NewReplacer pass.
// Each runs over a 1KB and a 1MB body so the scan-cost scaling with body size is
// visible.
func BenchmarkSecretSwap(b *testing.B) {
	placeholders := []string{
		"WARDEN_PLACEHOLDER_001",
		"WARDEN_PLACEHOLDER_002",
		"WARDEN_PLACEHOLDER_003",
		"WARDEN_PLACEHOLDER_004",
		"WARDEN_PLACEHOLDER_005",
	}
	reals := map[string]string{
		"WARDEN_PLACEHOLDER_001": "sk-real-secret-value-0000000000000001",
		"WARDEN_PLACEHOLDER_002": "sk-real-secret-value-0000000000000002",
		"WARDEN_PLACEHOLDER_003": "sk-real-secret-value-0000000000000003",
		"WARDEN_PLACEHOLDER_004": "sk-real-secret-value-0000000000000004",
		"WARDEN_PLACEHOLDER_005": "sk-real-secret-value-0000000000000005",
	}
	// The flat [placeholder, value, ...] slice swapBodySecrets consumes, built in
	// the same PlaceholderNames order the hot path uses.
	pairs := make([]string, 0, len(placeholders)*2)
	for _, ph := range placeholders {
		pairs = append(pairs, ph, reals[ph])
	}

	cases := []struct {
		name string
		size int
	}{
		{"1KB", 1 << 10},
		{"1MB", 1 << 20},
	}
	for _, tc := range cases {
		body := makeSwapBody(tc.size, placeholders)
		// Old: per-placeholder ReplaceAll (N scans of the body).
		b.Run("Old/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := body
				for _, ph := range placeholders {
					s = strings.ReplaceAll(s, ph, reals[ph])
				}
				_ = s
			}
		})
		// New: the real one-pass swap (single NewReplacer scan).
		b.Run("New/"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = swapBodySecrets(body, pairs)
			}
		})
	}
}

// makeSwapBody builds a body of about size bytes that scatters each placeholder
// through the content, so every ReplaceAll pass does real matching+rewriting
// work rather than scanning a placeholder-free string.
func makeSwapBody(size int, placeholders []string) string {
	var sb strings.Builder
	sb.Grow(size + 64)
	const filler = `{"messages":[{"role":"user","content":"lorem ipsum dolor sit amet "}],`
	i := 0
	for sb.Len() < size {
		sb.WriteString(filler)
		sb.WriteString(placeholders[i%len(placeholders)])
		sb.WriteString(`",`)
		i++
	}
	return sb.String()
}

// BenchmarkSwapSecretsScoped measures the per-request swapSecrets cost with and
// without destination scoping (#373): "Unscoped" is the legacy path (no scope
// map), "InScope" adds the matcher lookup, "OutOfScope" adds the matcher plus the
// presence probe and the out-of-scope analytics record.
func BenchmarkSwapSecretsScoped(b *testing.B) {
	names := []string{"WARDEN_PLACEHOLDER_001", "WARDEN_PLACEHOLDER_002", "WARDEN_PLACEHOLDER_003"}
	values := map[string]string{}
	for _, n := range names {
		values[n] = "sk-real-secret-value-" + n
	}
	for _, tc := range []struct {
		name   string
		scopes map[string][]string
	}{
		{"Unscoped", nil},
		{"InScope", map[string][]string{names[0]: {"backend.test"}, names[1]: {"*.test"}, names[2]: {`~^back.*\.test$`}}},
		{"OutOfScope", map[string][]string{names[0]: {"other.test"}, names[1]: {"*.other.test"}, names[2]: {`~^other\.test$`}}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p, _ := startTestProxyWithScopedSecrets(b, []string{"backend.test"}, nil, nil, values, names, tc.scopes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req, _ := http.NewRequest("GET", "https://backend.test/v1?k=WARDEN_PLACEHOLDER_002", nil)
				req.Header.Set("Authorization", "Bearer WARDEN_PLACEHOLDER_001")
				req.Header.Set("X-Other", "WARDEN_PLACEHOLDER_003")
				s := &requestScope{domain: "backend.test", port: 443, req: req}
				if p.swapSecrets(s) {
					b.Fatal("swapSecrets ended the session")
				}
			}
		})
	}
}
