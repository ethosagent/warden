package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
)

func newBundleMetrics(t *testing.T) (*observability.Metrics, *sdkmetric.ManualReader) {
	t.Helper()
	rd := sdkmetric.NewManualReader()
	m, _, shutdown, err := observability.New(observability.Config{Enabled: true, ServiceName: "warden-test", MetricsEnabled: true, Reader: rd})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })
	return m, rd
}

// bundleSeries returns the bundle metrics as name -> label-free value, and the
// rejected counter as "rejected{reason}" -> count.
func bundleSeries(t *testing.T, rd *sdkmetric.ManualReader) map[string]float64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, sm := range rm.ScopeMetrics {
		for _, mt := range sm.Metrics {
			switch d := mt.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					if mt.Name == "warden.bundle.rejected.total" {
						r, _ := dp.Attributes.Value("reason")
						out["rejected{"+r.AsString()+"}"] = float64(dp.Value)
					}
				}
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					out[mt.Name] = float64(dp.Value)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range d.DataPoints {
					out[mt.Name] = dp.Value
				}
			}
		}
	}
	return out
}

// TestBundleMetricsFollowStatus: the counter and gauges come from
// BundleStatus on every tick. A rejected seq 6 leaves seq at 5; invalid_policy
// (not a bundle.Err*) is counted under its own reason; age and staleness move
// with the clock alone, with no new bundle; the counter never double-counts.
func TestBundleMetricsFollowStatus(t *testing.T) {
	m, rd := newBundleMetrics(t)
	clk := clocktest.NewFake(bundleStart.Add(time.Minute))
	cp := &hookClient{status: config.BundleStatus{
		Enabled: true, Applied: true, Seq: 5, IssuedAt: bundleStart, ExpiresAt: bundleStart.Add(time.Hour),
		Rejected: map[string]int64{"bad_signature": 1}, LastRejectReason: "bad_signature",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { reportBundleMetrics(ctx, clk, cp, m); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	await(t, 2*time.Second, "the first report", func() bool {
		s := bundleSeries(t, rd)
		return s["rejected{bad_signature}"] == 1 && s["warden.bundle.seq"] == 5 && s["warden.bundle.age_seconds"] == 60
	})
	if s := bundleSeries(t, rd); s["warden.bundle.stale"] != 0 {
		t.Fatalf("stale = %v, want 0", s["warden.bundle.stale"])
	}
	await(t, 2*time.Second, "the loop to arm", func() bool { return clk.PendingTimers() == 1 })

	// No new bundle: the ticks alone age the gauge and flip stale.
	cp.mu2.Lock()
	cp.status.Rejected = map[string]int64{"bad_signature": 1, config.BundleReasonInvalidPolicy: 2}
	cp.mu2.Unlock()
	await(t, 2*time.Second, "age, stale and the new reason", func() bool {
		clk.Advance(bundleExpiryInterval)
		cp.mu2.Lock()
		if clk.Now().After(bundleStart.Add(time.Hour)) {
			cp.status.Expired = true
		}
		cp.mu2.Unlock()
		s := bundleSeries(t, rd)
		return s["rejected{invalid_policy}"] == 2 && s["warden.bundle.age_seconds"] >= 3600 && s["warden.bundle.stale"] == 1
	})
	if s := bundleSeries(t, rd); s["rejected{bad_signature}"] != 1 || s["warden.bundle.seq"] != 5 {
		t.Fatalf("series = %v: a repeated tick double-counted, or seq moved", s)
	}
}

// TestBundleMetricsReasonSetCoversBundleReasons pins the observability
// allowlist to the bundle package: every bundle.Reason value and
// invalid_policy is accepted, so none is silently recorded as "other".
func TestBundleMetricsReasonSetCoversBundleReasons(t *testing.T) {
	want := map[string]bool{config.BundleReasonInvalidPolicy: true}
	for _, e := range []error{
		bundle.ErrMalformed, bundle.ErrTooLarge, bundle.ErrUnsupportedFormat, bundle.ErrUnsigned,
		bundle.ErrUnknownKid, bundle.ErrBadSignature, bundle.ErrIssuerMismatch, bundle.ErrCredentialMismatch,
		bundle.ErrRollback, bundle.ErrEquivocation, bundle.ErrExpired, bundle.ErrFuture,
	} {
		want[bundle.Reason(e)] = true
	}
	got := observability.BundleRejectReasons()
	if len(got) != len(want) {
		t.Fatalf("observability reasons = %v, want %d bundle reasons", got, len(want))
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("observability accepts %q, which is not a bundle reason", r)
		}
	}
}

func TestBundleMetricsReporterSkipsWorkerWithoutPins(t *testing.T) {
	m, rd := newBundleMetrics(t)
	r := newBundleMetricsReporter(m, &hookClient{}, clocktest.NewFake(bundleStart))
	r.report()
	for name := range bundleSeries(t, rd) {
		if strings.Contains(name, "bundle") {
			t.Fatalf("a worker without pins reported %s", name)
		}
	}
}
