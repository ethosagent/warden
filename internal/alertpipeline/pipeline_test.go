package alertpipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/detect"
	"github.com/ethosagent/warden/internal/integration"

	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook sink
)

// newStore opens a temp-file alert store the test owns (the pipeline never closes
// it). t.Cleanup closes it once, mirroring the CP Server's ownership.
func newStore(t *testing.T) *integration.Store {
	t.Helper()
	store, err := integration.NewStore(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatalf("open alert store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// deliveredAlert is the subset of the webhook payload a sink asserts on.
type deliveredAlert struct {
	DedupKey string `json:"dedupKey"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// webhookSink starts an HTTP server that decodes each delivered alert onto a
// channel, plus the InstanceConfig routing security alerts to it.
func webhookSink(t *testing.T, name string) (*httptest.Server, chan deliveredAlert, integration.InstanceConfig) {
	t.Helper()
	ch := make(chan deliveredAlert, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a deliveredAlert
		_ = json.NewDecoder(r.Body).Decode(&a)
		w.WriteHeader(http.StatusOK)
		ch <- a
	}))
	t.Cleanup(srv.Close)
	inst := integration.InstanceConfig{
		Type:   "webhook",
		Name:   name,
		Config: map[string]any{"url": srv.URL},
		Match:  []integration.MatchClause{{Category: "security"}},
	}
	return srv, ch, inst
}

func blockEvent(domain string) analytics.Event {
	// A reason-less "deny" is what the proxy writes for a plain allowlist block.
	return analytics.Event{
		Timestamp: time.Now(), Domain: domain, Decision: "deny",
		Method: "POST",
	}
}

// TestNew_FailOpenNilStore asserts New with no store yields a Pipeline whose
// methods are safe no-ops — the fail-open contract that keeps a broken alert
// subsystem from ever aborting startup.
func TestNew_FailOpenNilStore(t *testing.T) {
	p := New(Config{Store: nil, Detect: true, Detection: detect.DefaultConfig()})
	if p == nil {
		t.Fatal("New must never return nil")
	}
	if p.CurrentManager() != nil {
		t.Fatal("nil store ⇒ no manager")
	}
	if p.Detectors() != nil {
		t.Fatal("nil store ⇒ no engine (nothing to publish onto)")
	}
	// All methods must be safe no-ops (no panic).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	p.Observe("w1", []analytics.Event{blockEvent("evil.example.com")})
	p.RunTick()
	if err := p.StopInstances(context.Background()); err != nil {
		t.Fatalf("StopInstances no-op should not error: %v", err)
	}
	if err := p.ReloadManager(nil); err == nil {
		t.Fatal("ReloadManager without a store should return an error, not panic")
	}
}

// TestObserve_BridgesBlockEvent asserts Observe fans a block event through the
// bridge onto the current manager's bus, landing an egress_blocked Alert in the
// store (persist is synchronous in AlertManager.Ingest).
func TestObserve_BridgesBlockEvent(t *testing.T) {
	p := New(Config{Store: newStore(t), Logger: nil})
	if p.CurrentManager() == nil {
		t.Fatal("a non-nil store should build a manager")
	}
	p.Observe("worker-1", []analytics.Event{
		{Domain: "api.openai.com", Decision: "allow", Method: "GET"}, // benign ⇒ no finding
		blockEvent("evil.example.com"),
	})
	if !hasDedup(p.CurrentManager().ListAlerts(0), "egress_blocked:evil.example.com") {
		t.Fatal("Observe should have bridged the block event into an egress_blocked alert")
	}
}

// TestRunTick_PublishesDetectorFindings asserts the tick Evaluates the engine and
// publishes detector Findings: a burst of 401s crosses auth_fail_burst, and one
// RunTick lands the temporal alert in the store.
func TestRunTick_PublishesDetectorFindings(t *testing.T) {
	p := New(Config{Store: newStore(t), Detect: true, Detection: detect.DefaultConfig()})
	if len(p.Detectors()) == 0 {
		t.Fatal("detection ON should build the engine")
	}
	now := time.Now()
	var events []analytics.Event
	for i := 0; i < 12; i++ {
		events = append(events, analytics.Event{
			Timestamp: now, Domain: "attacker.example.com", Decision: "allow", ResponseStatus: 401,
		})
	}
	p.Observe("worker-1", events)
	p.RunTick()
	if !hasDedup(p.CurrentManager().ListAlerts(0), "auth_fail_burst:attacker.example.com") {
		t.Fatal("RunTick should have published the auth_fail_burst finding")
	}
}

// TestReload_RepointsObserveAndTick is the regression guard: after a live manager
// swap, BOTH Observe (bridge) and RunTick (detector) must publish to the NEW
// manager, not a captured-once old one. Each manager has its OWN webhook sink; the
// old sink is stopped by the reload, so an alert arriving at sinkB (and not sinkA)
// proves the tick + bridge re-point to the swapped manager.
func TestReload_RepointsObserveAndTick(t *testing.T) {
	_, sinkA, instA := webhookSink(t, "A")
	_, sinkB, instB := webhookSink(t, "B")

	p := New(Config{
		Store:     newStore(t),
		Instances: []integration.InstanceConfig{instA},
		Detect:    true,
		Detection: detect.DefaultConfig(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	m1 := p.CurrentManager()
	if m1 == nil {
		t.Fatal("manager should exist after Start")
	}
	// Drain any startup noise on sinkA (there should be none yet).

	// Reload to a DIFFERENT sink over the SAME store.
	if err := p.ReloadManager([]integration.InstanceConfig{instB}); err != nil {
		t.Fatalf("ReloadManager: %v", err)
	}
	m2 := p.CurrentManager()
	if m2 == m1 {
		t.Fatal("reload must swap the manager pointer")
	}

	// Bridge path: a block event Observed AFTER the reload must reach sinkB.
	p.Observe("worker-1", []analytics.Event{blockEvent("evil.example.com")})
	awaitDedup(t, sinkB, "egress_blocked:evil.example.com")

	// Tick path: a 401 burst + RunTick AFTER the reload must reach sinkB.
	now := time.Now()
	var burst []analytics.Event
	for i := 0; i < 12; i++ {
		burst = append(burst, analytics.Event{
			Timestamp: now, Domain: "attacker.example.com", Decision: "allow", ResponseStatus: 401,
		})
	}
	p.Observe("worker-1", burst)
	p.RunTick()
	awaitDedup(t, sinkB, "auth_fail_burst:attacker.example.com")

	// sinkA (the pre-reload manager) must have received NOTHING — proving delivery
	// did not go to the captured-once old manager.
	select {
	case a := <-sinkA:
		t.Fatalf("stale manager sinkA received a delivery after reload: %+v", a)
	case <-time.After(200 * time.Millisecond):
	}
}

// hasDedup reports whether any alert carries the given DedupKey.
func hasDedup(alerts []integration.Alert, dedup string) bool {
	for _, a := range alerts {
		if a.DedupKey == dedup {
			return true
		}
	}
	return false
}

// awaitDedup waits for an alert with dedup to arrive on ch, or fails.
func awaitDedup(t *testing.T, ch chan deliveredAlert, dedup string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case a := <-ch:
			if a.DedupKey == dedup {
				if a.Category != "security" {
					t.Errorf("delivered %q category = %q, want security", dedup, a.Category)
				}
				return
			}
			// A different alert on the same sink is fine; keep waiting for ours.
		case <-deadline:
			t.Fatalf("timed out waiting for %q at the sink", dedup)
		}
	}
}
