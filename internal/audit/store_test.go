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

// hasComplianceTag reports whether the encoded compliance IDs on an event
// contain the given "framework:controlID" tag — the exact form aggregateCompliance
// splits on the first ':' to build a coverage tile.
func hasComplianceTag(ids []string, tag string) bool {
	for _, id := range ids {
		if id == tag {
			return true
		}
	}
	return false
}

// TestTaggingStoreTagsSecretBrokering verifies an event that swapped a real
// secret at the edge (non-empty SwappedRefs) is tagged with the protective
// M1041 control, encoded as the "mitre:M1041" tag the dashboard aggregation
// consumes — without synthesizing the T1552/LLM02 leakage pair.
func TestTaggingStoreTagsSecretBrokering(t *testing.T) {
	rec := &recordStore{}
	ts := NewTaggingStore(rec, NewMapper())
	e := analytics.Event{
		Decision:    "allow",
		Protocol:    "https",
		SwappedRefs: []string{"{{OPENAI_API_KEY}}"},
	}
	if err := ts.StoreEvent(e); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("stored %d events, want 1", len(rec.events))
	}
	got := rec.events[0].Compliance
	if !hasComplianceTag(got, "mitre:M1041") {
		t.Errorf("expected mitre:M1041 tag on a secret-brokered event, got %v", got)
	}
	if hasComplianceTag(got, "mitre:T1552") || hasComplianceTag(got, "owasp:LLM02") {
		t.Errorf("secret-brokered event must not carry the leakage pair, got %v", got)
	}
}

// TestTaggingStoreNoSwapNoBrokeringTag verifies an event with no swap carries
// no secrets-brokering tag.
func TestTaggingStoreNoSwapNoBrokeringTag(t *testing.T) {
	rec := &recordStore{}
	ts := NewTaggingStore(rec, NewMapper())
	if err := ts.StoreEvent(analytics.Event{Decision: "allow", Protocol: "https"}); err != nil {
		t.Fatal(err)
	}
	if hasComplianceTag(rec.events[0].Compliance, "mitre:M1041") {
		t.Errorf("expected no mitre:M1041 tag without a swap, got %v", rec.events[0].Compliance)
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
