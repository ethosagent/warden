package analytics

import (
	"sync"
	"time"
)

// AggregatedEvent wraps an Event with multi-node metadata.
type AggregatedEvent struct {
	Event
	ProxyID string
	AgentID string
}

// AggregatedFilter extends EventFilter with multi-node filter fields.
type AggregatedFilter struct {
	EventFilter
	ProxyID string
	AgentID string
}

// CentralStore is an in-memory AnalyticsStore that aggregates events from
// multiple proxy nodes. It is safe for concurrent use.
type CentralStore struct {
	mu     sync.RWMutex
	events []AggregatedEvent
	// seen indexes the non-empty EventUIDs of currently retained events so a
	// worker re-sending a batch whose ack was lost does not store duplicates —
	// the same dedup contract FleetSQLiteStore's partial unique index enforces.
	// Entries are removed as their events age out of the cap, so it is bounded
	// by maxEvents.
	seen      map[string]struct{}
	maxEvents int
}

var (
	_ AnalyticsStore = (*CentralStore)(nil)
	// CentralStore is the in-memory FleetStore: NewFleetStore("memory") returns it.
	_ FleetStore = (*CentralStore)(nil)
)

// NewCentralStore returns a new CentralStore. maxEvents <= 0 uses defaultMaxEvents.
func NewCentralStore(maxEvents int) *CentralStore {
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	return &CentralStore{maxEvents: maxEvents, seen: make(map[string]struct{})}
}

// StoreEvent satisfies the AnalyticsStore interface. The event is stored with
// empty ProxyID and AgentID.
func (c *CentralStore) StoreEvent(e Event) error {
	return c.StoreAggregatedEvent(AggregatedEvent{Event: e})
}

// StoreAggregatedEvent stores an event with proxy and agent metadata. An event
// whose non-empty EventUID was already stored is silently skipped (a retried
// batch after a lost ack); events with an empty uid are always stored.
func (c *CentralStore) StoreAggregatedEvent(e AggregatedEvent) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if uid := e.EventUID(); uid != "" {
		if _, dup := c.seen[uid]; dup {
			return nil
		}
		c.seen[uid] = struct{}{}
	}
	c.events = append(c.events, e)
	// Prune oldest (beginning of slice) if over cap, forgetting their uids so
	// seen stays bounded by maxEvents.
	if len(c.events) > c.maxEvents {
		for _, old := range c.events[:len(c.events)-c.maxEvents] {
			if uid := old.EventUID(); uid != "" {
				delete(c.seen, uid)
			}
		}
		c.events = c.events[len(c.events)-c.maxEvents:]
	}
	return nil
}

// GetEvents satisfies the AnalyticsStore interface. Returns unwrapped Events,
// newest first.
func (c *CentralStore) GetEvents(filter EventFilter) ([]Event, error) {
	agg, err := c.GetAggregatedEvents(AggregatedFilter{EventFilter: filter, ProxyID: filter.ProxyID})
	if err != nil {
		return nil, err
	}
	out := make([]Event, len(agg))
	for i, a := range agg {
		out[i] = a.Event
		// Surface the originating proxy so the fleet dashboard can group/slice by
		// worker (the embedded Event carries no proxy id of its own).
		out[i].ProxyID = a.ProxyID
	}
	return out, nil
}

// GetAggregatedEvents returns aggregated events matching filter, newest first.
func (c *CentralStore) GetAggregatedEvents(filter AggregatedFilter) ([]AggregatedEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var out []AggregatedEvent
	// Iterate in reverse for newest-first ordering.
	for i := len(c.events) - 1; i >= 0; i-- {
		e := c.events[i]
		if filter.Domain != "" && e.Domain != filter.Domain {
			continue
		}
		if filter.Decision != "" && e.Decision != filter.Decision {
			continue
		}
		if !filter.Since.IsZero() && e.Timestamp.Before(filter.Since) {
			continue
		}
		if !filter.MatchesUser(e.Event) {
			continue
		}
		if filter.ProxyID != "" && e.ProxyID != filter.ProxyID {
			continue
		}
		if filter.AgentID != "" && e.AgentID != filter.AgentID {
			continue
		}
		out = append(out, e)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

// Close is a no-op for the in-memory store.
func (c *CentralStore) Close() error { return nil }
