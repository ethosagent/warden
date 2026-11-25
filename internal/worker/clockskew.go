package worker

import (
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/observability"
)

// clockSkewObserver returns the callback that turns the control plane's Date
// header into warden.controlplane.clock_skew_seconds: the CP time minus the
// worker clock (positive: the CP is ahead). A nil *Metrics makes it a no-op.
func clockSkewObserver(m *observability.Metrics, clk clock.Clock) func(time.Time) {
	return func(cpNow time.Time) {
		m.RecordControlPlaneClockSkew(cpNow.Sub(clk.Now()))
	}
}
