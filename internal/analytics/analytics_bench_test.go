package analytics

import (
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkStoreEvent measures the current synchronous per-event write cost of
// SQLiteStore.StoreEvent: one INSERT followed by a prune (SELECT COUNT(*) +
// DELETE), all through a single connection. This is the Phase-0 baseline for the
// D1 async-writer change — it uses a temp-FILE DB (not :memory:) so the fsync
// cost the async batcher amortizes is actually in the measurement.
func BenchmarkStoreEvent(b *testing.B) {
	store, err := NewSQLiteStore(filepath.Join(b.TempDir(), "bench.db"), 0)
	if err != nil {
		b.Fatalf("store: %v", err)
	}
	b.Cleanup(func() { _ = store.Close() })

	// A realistic allow event carrying the fields the hot path populates.
	e := Event{
		Timestamp:      time.Now(),
		Domain:         "api.openai.com",
		Port:           443,
		Protocol:       "https",
		Method:         "POST",
		URL:            "https://api.openai.com/v1/chat/completions",
		Decision:       "allow",
		ResponseStatus: 200,
		SecretRef:      "sha256:abc123def456:last4=7890:v1",
		JudgeReason:    "",
		Tool:           "",
		Reason:         "",
		CostUSD:        0.0021,
		Provider:       "openai",
		Compliance:     []string{"owasp:LLM01", "mitre:T1048"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.StoreEvent(e); err != nil {
			b.Fatalf("StoreEvent: %v", err)
		}
	}
}
