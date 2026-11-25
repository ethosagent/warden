package worker

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/observability"
)

func TestClockSkewObserver(t *testing.T) {
	rd := sdkmetric.NewManualReader()
	m, _, shutdown, err := observability.New(observability.Config{Enabled: true, ServiceName: "t", MetricsEnabled: true, Reader: rd})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clockSkewObserver(m, clocktest.NewFake(now))(now.Add(120 * time.Second))

	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, mt := range sm.Metrics {
			if mt.Name != "warden.controlplane.clock_skew_seconds" {
				continue
			}
			g := mt.Data.(metricdata.Gauge[float64])
			if len(g.DataPoints) != 1 || g.DataPoints[0].Value != 120 {
				t.Fatalf("gauge = %+v, want 120", g.DataPoints)
			}
			return
		}
	}
	t.Fatal("clock skew gauge not exported")
}

func TestClockSkewObserverNilMetrics(t *testing.T) {
	now := time.Now()
	clockSkewObserver(nil, clocktest.NewFake(now))(now) // must not panic
}
