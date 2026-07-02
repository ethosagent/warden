package worker

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
)

// TestAnalyticsDecoratorChainOrder asserts the load-bearing write-chain order
// wired in Run: tagging → signing → async → sqlite (outer→inner). The ordering
// is a plan invariant, not a convention, so it is asserted by test:
//
//   - tagging BEFORE signing: the signed receipt's event carries the compliance
//     tags, proving tagging ran first (the receipt covers the tags).
//   - async ABOVE the base store: right after StoreEvent the event is NOT yet in
//     the base store (it is buffered in the async queue); only after Close does
//     it land — proving the async layer sits between signing and the store.
//   - async → store: the persisted event still carries the tags, so the exact
//     tagged+signed event is what gets written.
func TestAnalyticsDecoratorChainOrder(t *testing.T) {
	base, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	// Build the exact chain Run assembles (a long flush interval so a single
	// event is not flushed by the ticker — only Close's drain persists it).
	async := analytics.NewAsyncWriter(base, analytics.WithFlushInterval(time.Hour))
	signer, err := audit.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	var receiptSink bytes.Buffer
	signed := audit.NewSigningStore(async, signer, &receiptSink)
	tagged := audit.NewTaggingStore(signed, audit.NewMapper())

	// A deny event maps to compliance controls via the Mapper, so a non-empty
	// Compliance slice after the chain proves tagging happened.
	ev := analytics.Event{Domain: "api.openai.com", Protocol: "https", Decision: "deny", Reason: "policy"}
	if err := tagged.StoreEvent(ev); err != nil {
		t.Fatalf("StoreEvent: %v", err)
	}

	// async is above the store: not persisted yet.
	if got, _ := base.GetEvents(analytics.EventFilter{}); len(got) != 0 {
		t.Fatalf("async layer missing: event reached base store before flush/Close (%d rows)", len(got))
	}

	// The receipt was written synchronously by the signing layer and must carry
	// the compliance tags — proving tagging ran BEFORE signing.
	if receiptSink.Len() == 0 {
		t.Fatal("no receipt written: signing layer not in chain")
	}
	var receipt struct {
		EventJSON []byte `json:"event_json"`
	}
	if err := json.Unmarshal(receiptSink.Bytes(), &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	var signedEvent analytics.Event
	if err := json.Unmarshal(receipt.EventJSON, &signedEvent); err != nil {
		t.Fatalf("unmarshal signed event: %v", err)
	}
	if len(signedEvent.Compliance) == 0 {
		t.Fatal("signed receipt has no compliance tags: tagging did not run before signing")
	}

	// Close drains: the event now lands in the base store, still tagged — the
	// async layer wrote the exact tagged+signed event.
	if err := async.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	persisted, err := base.GetEvents(analytics.EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(persisted) != 1 {
		t.Fatalf("expected 1 persisted event after Close, got %d", len(persisted))
	}
	if len(persisted[0].Compliance) == 0 {
		t.Fatal("persisted event lost its compliance tags: chain did not persist the tagged event")
	}
}
