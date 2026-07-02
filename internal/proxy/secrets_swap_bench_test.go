package proxy

import (
	"strings"
	"testing"
)

// BenchmarkSecretSwap measures the request-body secret-substitution cost.
//
// The production swap is inline inside handleHTTP (http.go:~195-249) and is not
// exposed as a separately callable function, so this benchmarks a FAITHFUL
// reconstruction using the SAME mechanism the hot path uses: one
// strings.ReplaceAll pass over the body per configured placeholder. With N
// placeholders that is N full scans of the body. Phase 3 collapses this into a
// single strings.NewReplacer pass; this benchmark is that change's before/after
// comparand. Sub-benchmarks cover a 1KB and a 1MB body so the scan-cost scaling
// with body size is visible.
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

	cases := []struct {
		name string
		size int
	}{
		{"1KB", 1 << 10},
		{"1MB", 1 << 20},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			body := makeSwapBody(tc.size, placeholders)
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
