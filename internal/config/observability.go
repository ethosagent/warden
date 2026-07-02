package config

import (
	"os"
	"strings"
)

// ObservabilityConfig configures the OTel emission seam (Phase 1: metrics +
// structured logging). Everything is off by default; a zero value is harmless.
// Traces (Phase 2) and collector recipes (Phase 3) are deferred.
type ObservabilityConfig struct {
	// Enabled gates the entire subsystem.
	Enabled bool
	// ServiceName populates the OTel resource (defaults to "warden").
	ServiceName string
	// MetricsEnabled gates the Prometheus /metrics exporter on the admin
	// listener. Defaults to true when the block is present.
	MetricsEnabled bool
	// OTLPEndpoint, when non-empty, enables an outbound OTLP/grpc metric push to
	// a collector (e.g. "otel-collector:4317").
	OTLPEndpoint string
	// ResourceAttributes are extra bounded resource key/value pairs. Never put
	// secrets here.
	ResourceAttributes map[string]string
}

// rawObservability mirrors the on-disk `observability:` block. Pointer so an
// absent block is distinct from an explicit (disabled) block. KnownFields(true)
// is strict, so this MUST be registered or configs with the block fail to parse.
type rawObservability struct {
	Enabled     bool   `yaml:"enabled"`
	ServiceName string `yaml:"serviceName"`
	Metrics     *struct {
		Enabled      *bool  `yaml:"enabled"`
		OTLPEndpoint string `yaml:"otlpEndpoint"`
	} `yaml:"metrics"`
	ResourceAttributes map[string]string `yaml:"resourceAttributes"`
}

// parseObservability converts the raw observability block into a typed config,
// applying defaults and honoring standard OTEL_* env vars (which override the
// file). An absent block yields a disabled, harmless zero value.
func parseObservability(r *rawObservability) ObservabilityConfig {
	var oc ObservabilityConfig
	if r != nil {
		oc.Enabled = r.Enabled
		oc.ServiceName = r.ServiceName
		// Metrics default ON when the block is present (served at /metrics).
		oc.MetricsEnabled = true
		if r.Metrics != nil {
			if r.Metrics.Enabled != nil {
				oc.MetricsEnabled = *r.Metrics.Enabled
			}
			oc.OTLPEndpoint = r.Metrics.OTLPEndpoint
		}
		oc.ResourceAttributes = r.ResourceAttributes
	}
	if oc.ServiceName == "" {
		oc.ServiceName = "warden"
	}
	// Env wins over config (standard OTel precedence).
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		oc.ServiceName = v
	}
	if v := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); v != "" {
		oc.OTLPEndpoint = v
	}
	return oc
}
