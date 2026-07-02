package proxy

import (
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
