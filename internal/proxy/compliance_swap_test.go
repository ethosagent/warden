package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
)

// hasCompliance reports whether an event carries the given compliance tag.
func hasCompliance(e analytics.Event, tag string) bool {
	for _, c := range e.Compliance {
		if c == tag {
			return true
		}
	}
	return false
}

// TestProxy_SetAnalytics_ComplianceToggle verifies the live compliance toggle:
// with the tagging layer wrapped around the base store a deny event is tagged
// (mitre:T1048), and after swapping the bare base store back in the same event is
// untagged — while the base store (the dashboard/central data source) keeps
// receiving every event throughout, undisturbed by the swap.
func TestProxy_SetAnalytics_ComplianceToggle(t *testing.T) {
	base := &syncStore{} // stands in for the shared base store + dashboard/central source
	mapper := audit.NewMapper()

	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		// Seed with compliance ON: tagging wraps the base.
		Analytics: audit.NewTaggingStore(base, mapper),
	})
	if err != nil {
		t.Fatal(err)
	}

	denyEvent := analytics.Event{Decision: "deny", Protocol: "tcp"}

	// Enabled: the deny event is tagged with the exfiltration control.
	if err := p.analyticsStore().StoreEvent(denyEvent); err != nil {
		t.Fatal(err)
	}
	got := base.snapshot()
	if len(got) != 1 || !hasCompliance(got[0], "mitre:T1048") {
		t.Fatalf("compliance ON: expected tagged event, got %+v", got)
	}

	// Disable: swap the BARE base store in (rebuild dropped the tagging layer).
	p.SetAnalytics(base)
	if err := p.analyticsStore().StoreEvent(denyEvent); err != nil {
		t.Fatal(err)
	}
	got = base.snapshot()
	if len(got) != 2 {
		t.Fatalf("compliance OFF: base store should still receive the event, got %d events", len(got))
	}
	if len(got[1].Compliance) != 0 {
		t.Fatalf("compliance OFF: event should be untagged, got tags %v", got[1].Compliance)
	}

	// Re-enable: rebuild the tagging layer around the SAME base and swap it back.
	p.SetAnalytics(audit.NewTaggingStore(base, mapper))
	if err := p.analyticsStore().StoreEvent(denyEvent); err != nil {
		t.Fatal(err)
	}
	got = base.snapshot()
	if len(got) != 3 || !hasCompliance(got[2], "mitre:T1048") {
		t.Fatalf("compliance re-ON: expected tagged event, got %+v", got[2])
	}
}

// TestProxy_SetAnalytics_RaceFree drives the hot-path store read
// (p.analyticsStore().StoreEvent) concurrently with SetAnalytics toggling the
// tagging layer around a shared base. Under `go test -race` the atomic pointer
// must show no data race, and the base store (dashboard/central consumer) keeps
// receiving every event regardless of which layer is live.
func TestProxy_SetAnalytics_RaceFree(t *testing.T) {
	base := &syncStore{}
	mapper := audit.NewMapper()
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  base,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: alternate tagging-on (wrap base) and tagging-off (bare base).
	wg.Add(1)
	go func() {
		defer wg.Done()
		stores := []analytics.AnalyticsStore{audit.NewTaggingStore(base, mapper), base}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				p.SetAnalytics(stores[i%len(stores)])
				i++
			}
		}
	}()

	// Readers: snapshot the live store and record an event.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = p.analyticsStore().StoreEvent(analytics.Event{Decision: "deny", Protocol: "tcp"})
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The shared base consumer received events throughout; the swap never desynced it.
	if len(base.snapshot()) == 0 {
		t.Fatal("base store received no events across the swap")
	}
}

// TestProxy_Analytics_SeededUntouched confirms a worker that never swaps reads the
// seeded store through the atomic pointer (back-compat for a local-only worker
// whose apply loop never runs).
func TestProxy_Analytics_SeededUntouched(t *testing.T) {
	base := &syncStore{}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.analyticsStore() != base {
		t.Fatal("expected seeded analytics store through atomic pointer")
	}
}
