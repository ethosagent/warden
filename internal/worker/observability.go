package worker

import "github.com/ethosagent/warden/internal/config"

// resolveObservability picks the observability config a MANAGED worker boots OTel
// from. The control-plane-distributed settings.Observability wins when present
// (so central config actually takes effect on restart); otherwise it falls back
// to the worker's LOCAL pol.Observability (e.g. the CP sent no observability
// block, or was unreachable at boot so distributed is nil). It is a pure function
// (no OTel side effects) so the precedence is unit-testable without standing up a
// meter provider.
//
// Apply-on-RESTART, not live: OTel meter/exporter providers initialize once per
// process and cannot be safely hot-swapped on the long-poll, so a later
// distributed change is honored only when the worker re-pulls settings at its
// next (re)start.
func resolveObservability(distributed *config.SettingsWire, local config.Policy) config.ObservabilityConfig {
	if distributed != nil && distributed.Observability != nil {
		return config.ObservabilityConfigFromSettings(distributed.Observability)
	}
	return local.Observability
}

// observabilityConfigsEqual reports whether two resolved observability configs are
// equivalent, including their ResourceAttributes maps. Used by the long-poll to
// detect a distributed observability change worth surfacing as a pending-restart
// log (OTel is never reconfigured live).
func observabilityConfigsEqual(a, b config.ObservabilityConfig) bool {
	if a.Enabled != b.Enabled ||
		a.ServiceName != b.ServiceName ||
		a.MetricsEnabled != b.MetricsEnabled ||
		a.OTLPEndpoint != b.OTLPEndpoint ||
		len(a.ResourceAttributes) != len(b.ResourceAttributes) {
		return false
	}
	for k, v := range a.ResourceAttributes {
		if b.ResourceAttributes[k] != v {
			return false
		}
	}
	return true
}
