package analytics

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func scanAll(t *testing.T, s ReplayScanner, since time.Time, limit int) []Event {
	t.Helper()
	var got []Event
	if err := s.ScanReplayEvents(context.Background(), since, limit, func(e Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("ScanReplayEvents: %v", err)
	}
	return got
}

func TestScanReplayEvents_FieldsOrderLimitAndSince(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	base := time.Unix(10_000, 0).UTC()
	for i := 0; i < 6; i++ {
		e := aggEvent("p", "a", fmt.Sprintf("h%d.example.com", i), "allow", base.Add(time.Duration(i)*time.Second))
		e.Method = "POST"
		e.URL = "https://secret.example.com/path?token=abc"
		e.SecretRef = "sha256:abcd"
		e.UserSub, e.UserEmail, e.IdentityStatus = "u1", "u1@corp.example", "valid"
		e.UserGroups = []string{"eng", "ops"}
		e.UID = fmt.Sprintf("uid-%020d", i)
		if err := s.StoreAggregatedEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	mcp := aggEvent("p", "a", "mcp.example.com", "allow", base.Add(time.Hour))
	mcp.Protocol = "mcp"
	if err := s.StoreAggregatedEvent(mcp); err != nil {
		t.Fatal(err)
	}

	got := scanAll(t, s, time.Time{}, 100)
	if len(got) != 6 {
		t.Fatalf("events = %d, want 6 (MCP rows are left out)", len(got))
	}
	if got[0].Domain != "h5.example.com" || got[5].Domain != "h0.example.com" {
		t.Errorf("order = %s ... %s, want newest first", got[0].Domain, got[5].Domain)
	}
	e := got[0]
	if e.Port != 443 || e.Protocol != "https" || e.Method != "POST" || e.Decision != "allow" ||
		e.UserSub != "u1" || e.UserEmail != "u1@corp.example" || e.IdentityStatus != "valid" ||
		len(e.UserGroups) != 2 || !e.Timestamp.Equal(base.Add(5*time.Second)) {
		t.Errorf("event = %+v", e)
	}
	// Only the replay columns are read.
	if e.URL != "" || e.SecretRef != "" || e.ProxyID != "" {
		t.Errorf("event carries more than the replay columns: %+v", e)
	}

	if got := scanAll(t, s, time.Time{}, 2); len(got) != 2 || got[0].Domain != "h5.example.com" {
		t.Errorf("limit 2 = %d events", len(got))
	}
	if got := scanAll(t, s, base.Add(3*time.Second), 100); len(got) != 3 {
		t.Errorf("since = %d events, want 3", len(got))
	}
	if got := scanAll(t, s, time.Time{}, 0); len(got) != 0 {
		t.Errorf("limit 0 = %d events", len(got))
	}
}

func TestScanReplayEvents_PagesAndStops(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	seedEvents(t, s, 2*replayPageSize+37)
	got := scanAll(t, s, time.Time{}, 3*replayPageSize)
	if len(got) != 2*replayPageSize+37 {
		t.Fatalf("events = %d, want %d across pages", len(got), 2*replayPageSize+37)
	}
	if got := scanAll(t, s, time.Time{}, replayPageSize+1); len(got) != replayPageSize+1 {
		t.Fatalf("limit across a page edge = %d", len(got))
	}
	stop := errors.New("stop")
	n := 0
	err := s.ScanReplayEvents(context.Background(), time.Time{}, 100, func(Event) error {
		n++
		if n == 3 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 3 {
		t.Errorf("err = %v after %d events, want the callback error after 3", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.ScanReplayEvents(ctx, time.Time{}, 100, func(Event) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ctx err = %v", err)
	}
}

// seedEvents bulk-inserts n https events in one transaction.
func seedEvents(t *testing.T, s *FleetSQLiteStore, n int) {
	t.Helper()
	_, err := s.db.Exec(`WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < ?)
INSERT INTO events (ts, domain, port, protocol, method, decision) SELECT ?+i, 'h.example.com', 443, 'https', 'GET', 'allow' FROM c`,
		n, time.Unix(20_000, 0).UnixNano())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// A 100k-event scan never holds up ingest. The proof is ordering, not latency:
// the scan is parked inside its callback (mid-scan, on page boundaries) while
// the test ingests on the read/write handle. Those ingests must all complete,
// with no SQLITE_BUSY, before the scan is allowed to resume. If a scan blocked
// writers, an ingest would hang here and the test would time out.
func TestScanReplayEvents_DoesNotBlockIngest(t *testing.T) {
	s, err := NewFleetSQLiteStore(filepath.Join(t.TempDir(), "fleet.db"), 0, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	const total = 100_000
	seedEvents(t, s, total)

	// The scan parks at these delivered-event counts: the very first event and
	// the first event of the third page.
	parkAt := map[int]bool{0: true, 2 * replayPageSize: true}
	parked := make(chan int)
	resume := make(chan struct{})
	done := make(chan error, 1)
	var delivered int
	go func() {
		done <- s.ScanReplayEvents(context.Background(), time.Time{}, total, func(Event) error {
			if parkAt[delivered] {
				parked <- delivered
				<-resume
			}
			delivered++
			return nil
		})
	}()

	for range parkAt {
		select {
		case <-parked:
		case err := <-done:
			t.Fatalf("scan ended before parking: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("scan never reached its park point")
		}
		ingested := make(chan error, 1)
		go func() {
			for i := 0; i < 25; i++ {
				if err := s.StoreAggregatedEvent(aggEvent("p", "a", "ingest.example.com", "allow", time.Now())); err != nil {
					ingested <- err
					return
				}
			}
			ingested <- nil
		}()
		// The scan is still parked and has not resumed: ingest must finish first.
		select {
		case err := <-ingested:
			if err != nil {
				t.Fatalf("ingest while the scan is mid-flight: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("ingest blocked while the scan was mid-flight")
		}
		resume <- struct{}{}
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("scan did not finish")
	}
	if delivered != total {
		t.Errorf("scan delivered %d events, want %d", delivered, total)
	}
}

// A store without ReplayScanner falls back to GetEvents, but delivers what the
// SQLite scan does: no MCP rows and no URL.
func TestScanReplayFallbackMatchesScanner(t *testing.T) {
	s := NewCentralStore(100)
	now := time.Now()
	for _, e := range []Event{
		{Timestamp: now, Domain: "a.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://a.example.com/x?y=1", Decision: "allow"},
		{Timestamp: now, Domain: "mcp.example.com", Protocol: "mcp", Decision: "allow"},
	} {
		if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
			t.Fatal(err)
		}
	}
	var got []Event
	if err := ScanReplay(context.Background(), s, now.Add(-time.Hour), 10, func(e Event) error { got = append(got, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Domain != "a.example.com" || got[0].URL != "" {
		t.Errorf("fallback delivered %+v, want one event without a URL", got)
	}
}
