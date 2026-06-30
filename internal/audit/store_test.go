package audit

import (
	"bytes"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
)

// recordStore is a fake AnalyticsStore that captures stored events.
type recordStore struct{ events []analytics.Event }

func (r *recordStore) StoreEvent(e analytics.Event) error {
	r.events = append(r.events, e)
	return nil
}

func (r *recordStore) GetEvents(analytics.EventFilter) ([]analytics.Event, error) {
	return r.events, nil
}

// TestTaggingStoreTagsCompliance verifies a denied event is tagged with
// compliance control IDs before being passed to the wrapped store.
func TestTaggingStoreTagsCompliance(t *testing.T) {
	rec := &recordStore{}
	ts := NewTaggingStore(rec, NewMapper())
	if err := ts.StoreEvent(analytics.Event{Decision: "deny", Protocol: "https"}); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("stored %d events, want 1", len(rec.events))
	}
	if len(rec.events[0].Compliance) == 0 {
		t.Fatal("expected compliance tags on a denied event, got none")
	}
}

// TestSigningStoreWritesVerifiableReceipt verifies each stored event yields a
// signed receipt that verifies against the signer's public key.
func TestSigningStoreWritesVerifiableReceipt(t *testing.T) {
	rec := &recordStore{}
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	ss := NewSigningStore(rec, signer, &buf)
	if err := ss.StoreEvent(analytics.Event{Domain: "x.com", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("event not forwarded to inner store: %d", len(rec.events))
	}
	if buf.Len() == 0 {
		t.Fatal("no receipt written")
	}
	r, err := UnmarshalReceipt(bytes.TrimSpace(buf.Bytes()))
	if err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if !Verify(r, signer.PubKey()) {
		t.Fatal("receipt does not verify against signer public key")
	}
}
