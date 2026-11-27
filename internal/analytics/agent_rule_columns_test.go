package analytics

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// An old warden.db opens with agent_id and limit_rule added and the cost seed
// index created (W-P3-PUL-04 dropped W-P3-PUL-02's (user_sub, limit_rule, ts)
// index), old rows are kept, the values
// round-trip through every write and read path, and a second open is a no-op
// (W-P3-PUL-02).
func TestMigrate_AgentIDLimitRule(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "warden.db")
	createLegacyEventsDB(t, dsn)
	s, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	for _, c := range []string{"agent_id", "limit_rule"} {
		if !hasColumn(t, s, c) {
			t.Errorf("column %s not added", c)
		}
	}
	var idx int
	// W-P3-PUL-04 replaced the (user_sub, limit_rule, ts) index with the
	// covering ts-leading cost seed index and drops the old one.
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_ts_user_rule_cost'`).Scan(&idx); err != nil || idx != 1 {
		t.Errorf("idx_events_ts_user_rule_cost: count %d, err %v", idx, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_user_rule_ts'`).Scan(&idx); err != nil || idx != 0 {
		t.Errorf("idx_events_user_rule_ts: count %d, err %v; want dropped", idx, err)
	}
	ev := attributedEvent()
	ev.AgentID, ev.LimitRule = "claude-code", "eng-llm"
	if err := s.StoreEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreEventsBatch([]Event{ev}); err != nil {
		t.Fatal(err)
	}
	count := func(evs []Event) int {
		n := 0
		for _, e := range evs {
			switch {
			case e.AgentID == "claude-code" && e.LimitRule == "eng-llm":
				n++
			case e.AgentID != "" || e.LimitRule != "":
				t.Errorf("a row picked up the wrong values: %+v", e)
			}
		}
		return n
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil || len(got) != 3 || count(got) != 2 {
		t.Fatalf("GetEvents: %d events, %d tagged, err %v; want 3 and 2", len(got), count(got), err)
	}
	_, oldest, err := s.GetOldestEventIDs(10)
	if err != nil || len(oldest) != 3 || count(oldest) != 2 {
		t.Fatalf("GetOldestEventIDs: %d events, %d tagged, err %v; want 3 and 2", len(oldest), count(oldest), err)
	}
	shape := func(st *SQLiteStore) [3]int {
		var rows, cols, idxs int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events')`).Scan(&cols); err != nil {
			t.Fatal(err)
		}
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='events'`).Scan(&idxs); err != nil {
			t.Fatal(err)
		}
		return [3]int{rows, cols, idxs}
	}
	before := shape(s)
	if before[0] != 3 {
		t.Fatalf("rows = %d, want 3", before[0])
	}
	_ = s.Close()
	s2, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("second open must be a no-op: %v", err)
	}
	if after := shape(s2); after != before {
		t.Errorf("second open changed rows/columns/indexes: %v -> %v", before, after)
	}
	_ = s2.Close()
}

// An Event with no AgentID and no LimitRule marshals without either key, so
// receipts and sync payloads written before this change stay byte-identical.
func TestEventMarshal_NoAgentIDLimitRuleKeys(t *testing.T) {
	b, err := json.Marshal(Event{Domain: "x.com", Decision: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "agent_id") || strings.Contains(string(b), "limit_rule") {
		t.Errorf("event without the fields carries the keys: %s", b)
	}
	b, _ = json.Marshal(Event{AgentID: "a", LimitRule: "r"})
	if !strings.Contains(string(b), `"agent_id":"a"`) || !strings.Contains(string(b), `"limit_rule":"r"`) {
		t.Errorf("tags wrong: %s", b)
	}
}
