package worker

import (
	"context"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/observability"
)

// bundleMetricsReporter publishes the signed-bundle metrics (W-P2-SBND-05) from
// one BundleStatus read: the warden_bundle_seq, _age_seconds and _stale gauges
// and the warden_bundle_rejected_total counter. Everything comes from the
// provider's own state, never from classifying an error, so a rejection the
// provider counted (including invalid_policy, which is not a bundle.Err*) is
// always reported under its recorded reason.
type bundleMetricsReporter struct {
	m   *observability.Metrics
	cp  ControlPlaneClient
	clk clock.Clock
	// seen is the per-reason count already added to the counter; Rejected
	// counts since the provider was created, so only the difference is new.
	seen map[string]int64
}

func newBundleMetricsReporter(m *observability.Metrics, cp ControlPlaneClient, clk clock.Clock) *bundleMetricsReporter {
	return &bundleMetricsReporter{m: m, cp: cp, clk: clk, seen: map[string]int64{}}
}

// report records the current state. It is called every tick, whether or not a
// bundle changed, because age and staleness move with time alone.
func (r *bundleMetricsReporter) report() {
	st := r.cp.BundleStatus()
	if !st.Enabled {
		return
	}
	for reason, n := range st.Rejected {
		for ; r.seen[reason] < n; r.seen[reason]++ {
			r.m.RecordBundleRejected(reason)
		}
	}
	var age time.Duration
	if st.Applied {
		age = r.clk.Now().Sub(st.IssuedAt)
	}
	r.m.SetBundleState(st.Seq, age, st.Applied && st.Expired)
}

// reportBundleMetrics reports once at start and then every
// bundleExpiryInterval until ctx is cancelled. It runs only on a worker that
// verifies bundles and has metrics on.
func reportBundleMetrics(ctx context.Context, clk clock.Clock, cp ControlPlaneClient, m *observability.Metrics) {
	r := newBundleMetricsReporter(m, cp, clk)
	r.report()
	t := clk.NewTimer(bundleExpiryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			t.Reset(bundleExpiryInterval)
			r.report()
		}
	}
}
