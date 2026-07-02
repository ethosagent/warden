package config

import (
	"fmt"
	"strings"
	"time"
)

// CentralConfig configures fleet analytics aggregation.
//   - mode: aggregator — run an ingest endpoint that receives event batches into
//     an in-memory central store the dashboard reads from.
//   - mode: worker — forward this proxy's local events to a remote aggregator.
//   - mode: off (default) — single-node, no aggregation.
type CentralConfig struct {
	Mode string // off | aggregator | worker

	// aggregator
	TokenEnv  string // env var holding the bearer token ingest requests must present
	MaxEvents int    // central store retention cap (0 = default)

	// worker
	Endpoint  string        // aggregator ingest URL
	ProxyID   string        // label this worker's events with
	BatchSize int           // events per forward batch (default 100)
	BufferCap int           // local buffer cap before dropping oldest (default 10000)
	Interval  time.Duration // forward interval (default 10s)
	// CACert is an optional CA certificate (PEM) added to the forwarding client's
	// trust pool ONLY for the aggregator connection (same rationale as
	// ControlPlaneConfig.CACert).
	CACert string
	// MCPPushInterval is how often a worker forwards its MCP inventory + observed
	// schema to the aggregator (push-on-change is automatic; default 30s).
	MCPPushInterval time.Duration
	// ForwardSecretInventory, when true, forwards the worker's configured secrets
	// BY REFERENCE (sha256/last4/length, never values) so the CP can show them.
	// Default false.
	ForwardSecretInventory bool
}

// rawCentral mirrors the on-disk `central:` block.
type rawCentral struct {
	Mode                   string `yaml:"mode"`
	TokenEnv               string `yaml:"tokenEnv"`
	MaxEvents              int    `yaml:"maxEvents"`
	Endpoint               string `yaml:"endpoint"`
	ProxyID                string `yaml:"proxyID"`
	BatchSize              int    `yaml:"batchSize"`
	BufferCap              int    `yaml:"bufferCap"`
	Interval               string `yaml:"interval"`
	CACert                 string `yaml:"caCert"`
	MCPPushInterval        string `yaml:"mcpPushInterval"`
	ForwardSecretInventory bool   `yaml:"forwardSecretInventory"`
}

// central defaults applied when the corresponding field is omitted (worker mode).
const (
	defaultCentralBatchSize       = 100
	defaultCentralBufferCap       = 10000
	defaultCentralInterval        = 10 * time.Second
	defaultCentralMCPPushInterval = 30 * time.Second
)

// parseCentral converts the raw central block into typed config, normalizing the
// mode and applying worker-side defaults. An absent block yields mode "off".
func parseCentral(r *rawCentral) (CentralConfig, error) {
	c := CentralConfig{Mode: "off"}
	if r == nil {
		return c, nil
	}
	if m := strings.ToLower(strings.TrimSpace(r.Mode)); m != "" {
		c.Mode = m
	}
	c.TokenEnv = r.TokenEnv
	c.MaxEvents = r.MaxEvents
	c.Endpoint = strings.TrimSpace(r.Endpoint)
	c.ProxyID = r.ProxyID
	c.CACert = strings.TrimSpace(r.CACert)
	c.BatchSize = defaultCentralBatchSize
	if r.BatchSize > 0 {
		c.BatchSize = r.BatchSize
	}
	c.BufferCap = defaultCentralBufferCap
	if r.BufferCap > 0 {
		c.BufferCap = r.BufferCap
	}
	c.Interval = defaultCentralInterval
	if err := parseDurationField("central.interval", r.Interval, &c.Interval); err != nil {
		return CentralConfig{}, err
	}
	c.MCPPushInterval = defaultCentralMCPPushInterval
	if err := parseDurationField("central.mcpPushInterval", r.MCPPushInterval, &c.MCPPushInterval); err != nil {
		return CentralConfig{}, err
	}
	c.ForwardSecretInventory = r.ForwardSecretInventory
	return c, nil
}

// validateCentral enforces the central block's requirements per mode.
func validateCentral(c CentralConfig) error {
	switch c.Mode {
	case "", "off":
		return nil
	case "aggregator":
		return nil
	case "worker":
		if c.Endpoint == "" {
			return fmt.Errorf("config: central.endpoint is required when central.mode is worker")
		}
		return nil
	default:
		return fmt.Errorf("config: central.mode %q is invalid; must be one of: off, aggregator, worker", c.Mode)
	}
}
