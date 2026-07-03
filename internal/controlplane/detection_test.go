package controlplane

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
)

// detectionConfig returns the config for an always-on detection control plane:
// engine enabled with defaults, an on-disk alert store, and NO integrations. It
// exercises the always-on Alert Store gate (Manager built with zero instances).
func detectionConfig(t *testing.T, allowDomain string) Config {
	t.Helper()
	return Config{
		PolicyPath:       writePolicyFile(t, allowDomain),
		AlertDBPath:      filepath.Join(t.TempDir(), "warden-alerts.db"),
		DetectionEnabled: true,
		Detection:        detect.DefaultConfig(),
		DetectionTick:    50 * time.Millisecond,
	}
}

// TestDetection_AlwaysOnStore asserts the gate change: with detection ON and an
// alert DB path, the Manager (bus + AlertManager + always-on Alert Store) AND the
// engine are built even with ZERO integration instances.
func TestDetection_AlwaysOnStore(t *testing.T) {
	srv := New(detectionConfig(t, "api.openai.com"))
	if srv.currentManager() == nil {
		t.Fatal("always-on Alert Store: Manager should be built with zero integrations when detection is ON")
	}
	if len(srv.pipeline.Detectors()) == 0 {
		t.Fatal("detection engine should be built when detection is ON")
	}
	// A zero-instance Manager must start and stop cleanly (Router binds nothing).
	ctx, cancel := context.WithCancel(context.Background())
	srv.Start(ctx)
	cancel()
}

// TestDetection_OffIsBackCompat asserts detection OFF builds NO detection engine
// (so the pipeline reports no active detectors and no tick loop starts),
// regardless of whether an alert store exists. It also pins the genuine "no
// Manager" case. NOTE: after the always-on merge, an AlertDBPath being SET ALWAYS
// builds the alert pipeline (the always-on Alert Store design), so "no Manager" is
// now keyed on an EMPTY AlertDBPath — not on detection being off.
func TestDetection_OffIsBackCompat(t *testing.T) {
	// Detection off + alert DB path set: the always-on Alert Store still builds the
	// Manager, but NO detection engine is constructed and NO detector tick runs.
	withStore := New(Config{
		PolicyPath:       writePolicyFile(t, "api.openai.com"),
		AlertDBPath:      filepath.Join(t.TempDir(), "warden-alerts.db"),
		DetectionEnabled: false, // explicitly off
	})
	if len(withStore.pipeline.Detectors()) != 0 {
		t.Fatal("detection OFF should build NO engine (and thus no detector tick)")
	}

	// Genuine no-Manager case: detection off, NO alert DB path, zero integrations ⇒
	// no alert pipeline is constructed at all (pre-alerts back-compat).
	bare := New(Config{
		PolicyPath:       writePolicyFile(t, "api.openai.com"),
		DetectionEnabled: false,
	})
	if bare.pipeline != nil {
		t.Fatal("no AlertDBPath + zero integrations should build NO pipeline/Manager (back-compat)")
	}
	if bare.currentManager() != nil {
		t.Fatal("no AlertDBPath should yield a nil current manager (back-compat)")
	}
}

// alertRow is the subset of the dashboard /alerts payload we assert on.
type alertRow struct {
	DedupKey string `json:"dedupKey"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// TestDetection_EndToEnd is the money test: a TRIPPING batch (a burst of 401s to
// one domain, enough to cross the auth_fail_burst threshold) fed through the
// ingest events callback feeds the temporal engine; a single tick then Evaluates
// and publishes the Finding through bus → AlertManager → Alert Store. We assert
// the store (and GET /dashboard/api/alerts, wired to this Manager) now carries the
// detector's alert with the expected DedupKey/severity — WITHOUT any integration
// sink configured (always-on store). In the SAME batch a block event must still
// fire the M1 bridge, proving the two producers run side by side.
func TestDetection_EndToEnd(t *testing.T) {
	srv := New(detectionConfig(t, "api.openai.com"))
	if srv.currentManager() == nil || len(srv.pipeline.Detectors()) == 0 {
		t.Fatal("detection ON should build both the Manager and the engine")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx)

	cp := httptest.NewServer(srv.Handler())
	defer cp.Close()

	now := time.Now()
	// A burst of 401s to one domain (crosses the default CountThreshold of 10) plus
	// one blocked egress (bridge → egress_blocked). The 401s are Decision "allow"
	// (request allowed; upstream rejected auth) so the bridge does NOT fire on them.
	var events []analytics.Event
	for i := 0; i < 12; i++ {
		events = append(events, analytics.Event{
			Timestamp: now, Domain: "attacker.example.com", Decision: "allow",
			Method: "GET", ResponseStatus: 401,
		})
	}
	events = append(events, analytics.Event{
		Timestamp: now, Domain: "evil.example.com", Decision: "deny",
		Method: "POST",
	})
	postIngest(t, cp.URL, "worker-1", events)

	// Drive exactly one detection tick (Evaluate + publish). The Alert Store persist
	// in AlertManager.Ingest is synchronous, so the alert is queryable immediately.
	srv.pipeline.RunTick()

	alerts := srv.currentManager().ListAlerts(0)
	var sawAuth, sawBridge bool
	for _, a := range alerts {
		switch a.DedupKey {
		case "auth_fail_burst:attacker.example.com":
			sawAuth = true
			if a.Severity.String() != "high" {
				t.Errorf("auth_fail_burst severity = %q, want high", a.Severity.String())
			}
			if a.Category != "security" {
				t.Errorf("auth_fail_burst category = %q, want security", a.Category)
			}
		case "egress_blocked:evil.example.com":
			sawBridge = true
		}
	}
	if !sawAuth {
		t.Fatalf("Alert Store missing the temporal auth_fail_burst alert; got %d alerts", len(alerts))
	}
	if !sawBridge {
		t.Fatal("M1 bridge should still fire for the block event in the same batch")
	}

	// The dashboard /alerts endpoint (wired to this Manager) must return both.
	resp, err := http.Get(cp.URL + "/dashboard/api/alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rows []alertRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	var apiAuth, apiBridge bool
	for _, r := range rows {
		switch r.DedupKey {
		case "auth_fail_burst:attacker.example.com":
			apiAuth = true
		case "egress_blocked:evil.example.com":
			apiBridge = true
		}
	}
	if !apiAuth || !apiBridge {
		t.Fatalf("/dashboard/api/alerts missing rows: auth=%v bridge=%v (got %d)", apiAuth, apiBridge, len(rows))
	}
}

// TestDetection_TickLoopLifecycle asserts the tick loop starts and stops cleanly
// on ctx cancel (no goroutine leak; -race clean). A tripping batch is observed,
// and the fast 50ms ticker is left to auto-fire and land the alert; cancelling
// the context must stop the loop.
func TestDetection_TickLoopLifecycle(t *testing.T) {
	srv := New(detectionConfig(t, "api.openai.com"))
	ctx, cancel := context.WithCancel(context.Background())
	srv.Start(ctx)

	cp := httptest.NewServer(srv.Handler())
	defer cp.Close()

	now := time.Now()
	var events []analytics.Event
	for i := 0; i < 12; i++ {
		events = append(events, analytics.Event{
			Timestamp: now, Domain: "attacker.example.com", Decision: "allow",
			ResponseStatus: 403,
		})
	}
	postIngest(t, cp.URL, "worker-1", events)

	// Poll briefly for the auto-ticker (50ms) to Evaluate and publish the alert.
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.currentManager().ListAlerts(0)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("auto tick loop did not land the alert within the deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Cancelling stops the loop cleanly (no panic, no leak — verified under -race).
	cancel()
	// Give the goroutine a moment to observe ctx.Done and return.
	time.Sleep(100 * time.Millisecond)
}
