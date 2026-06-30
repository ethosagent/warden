package audit

import (
	"fmt"
	"io"
	"sync"

	"github.com/ethosagent/warden/internal/analytics"
)

// TaggingStore is an analytics.AnalyticsStore decorator that tags every event
// with the compliance-framework control IDs it maps to (via Mapper) before
// delegating to the wrapped store. It is the lowest-touch way to wire
// compliance mapping: a single seam tags all events, so no proxy call site has
// to know about frameworks. Reads pass straight through.
type TaggingStore struct {
	inner  analytics.AnalyticsStore
	mapper *Mapper
}

var _ analytics.AnalyticsStore = (*TaggingStore)(nil)

// NewTaggingStore wraps inner so that every stored event is tagged with its
// compliance mappings. A nil mapper is treated as "no mappings" (pass-through).
func NewTaggingStore(inner analytics.AnalyticsStore, mapper *Mapper) *TaggingStore {
	return &TaggingStore{inner: inner, mapper: mapper}
}

// StoreEvent tags the event with compliance control IDs, then stores it.
func (t *TaggingStore) StoreEvent(e analytics.Event) error {
	if t.mapper != nil {
		mappings := t.mapper.MapEvent(e.Decision, e.Protocol, detectionsFor(e))
		if len(mappings) > 0 {
			ids := make([]string, 0, len(mappings))
			for _, m := range mappings {
				ids = append(ids, fmt.Sprintf("%s:%s", m.Framework, m.ControlID))
			}
			e.Compliance = ids
		}
	}
	return t.inner.StoreEvent(e)
}

// GetEvents delegates to the wrapped store unchanged.
func (t *TaggingStore) GetEvents(filter analytics.EventFilter) ([]analytics.Event, error) {
	return t.inner.GetEvents(filter)
}

// detectionsFor derives the bounded detection labels the Mapper matches on from
// an event's metadata fields. It deliberately uses only bounded enum fields
// (Reason, Tool) — never free-text or bodies — so tagging adds no content to
// the audit trail.
func detectionsFor(e analytics.Event) []string {
	var dets []string
	if e.Reason != "" {
		dets = append(dets, e.Reason)
	}
	if e.Tool != "" {
		dets = append(dets, e.Tool)
	}
	return dets
}

// SigningStore is an analytics.AnalyticsStore decorator that emits a signed,
// independently-verifiable receipt for every stored event. The receipt is
// written as one JSON object per line (JSONL) to the configured sink before the
// event is persisted, so the audit log and the analytics store stay in lockstep.
//
// Wrap order matters: put SigningStore INSIDE TaggingStore so the signed event
// already carries its compliance tags.
type SigningStore struct {
	inner  analytics.AnalyticsStore
	signer *Signer
	mu     sync.Mutex
	sink   io.Writer
}

var _ analytics.AnalyticsStore = (*SigningStore)(nil)

// NewSigningStore wraps inner so each stored event is signed and its receipt
// appended to sink (one JSON receipt per line).
func NewSigningStore(inner analytics.AnalyticsStore, signer *Signer, sink io.Writer) *SigningStore {
	return &SigningStore{inner: inner, signer: signer, sink: sink}
}

// StoreEvent signs the event, appends its receipt to the sink, then stores it.
// A signing or write failure never drops the event: the analytics record is the
// system of record and the receipt log is best-effort durable evidence.
func (s *SigningStore) StoreEvent(e analytics.Event) error {
	if s.signer != nil && s.sink != nil {
		if receipt, err := s.signer.Sign(e); err == nil {
			if data, mErr := MarshalReceipt(receipt); mErr == nil {
				s.mu.Lock()
				_, _ = s.sink.Write(append(data, '\n'))
				s.mu.Unlock()
			}
		}
	}
	return s.inner.StoreEvent(e)
}

// GetEvents delegates to the wrapped store unchanged.
func (s *SigningStore) GetEvents(filter analytics.EventFilter) ([]analytics.Event, error) {
	return s.inner.GetEvents(filter)
}
