package config

import (
	"fmt"
	"strings"
	"time"
)

// ControlPlaneConfig configures the remote ConfigProvider. When Endpoint is set,
// the proxy pulls allow/deny policy from it at startup and re-pulls every
// PollInterval, hot-swapping the live evaluator. A pull failure preserves the
// last-known-good policy so a worker keeps running if the control plane is down.
type ControlPlaneConfig struct {
	Endpoint     string        // https control-plane URL ("" disables)
	TokenEnv     string        // env var holding the bearer token
	PollInterval time.Duration // re-pull interval (default 30s) — legacy/fallback
	// CACert is an optional CA certificate (PEM) added to this worker's trust
	// pool ONLY for the control-plane connection, so a control plane serving a
	// privately-signed cert is trusted without altering upstream TLS trust.
	CACert string
	// LongPollWait is how long the worker asks the CP to hold a /policy request
	// open before returning 304 (default 30s).
	LongPollWait time.Duration
	// HeartbeatInterval is how often the worker pings /control/heartbeat so the CP
	// lists it as online even when idle (default 10s).
	HeartbeatInterval time.Duration
	// LocalOnly, when true, makes the worker ignore the control plane and enforce
	// its LOCAL policy (standalone). Default false = CP-managed: policy comes only
	// from the control plane and the worker fails closed until the first pull.
	LocalOnly bool
}

// rawControlPlane mirrors the on-disk `controlPlane:` block.
type rawControlPlane struct {
	Endpoint          string `yaml:"endpoint"`
	TokenEnv          string `yaml:"tokenEnv"`
	PollInterval      string `yaml:"pollInterval"`
	CACert            string `yaml:"caCert"`
	LongPollWait      string `yaml:"longPollWait"`
	HeartbeatInterval string `yaml:"heartbeatInterval"`
	LocalOnly         bool   `yaml:"localOnly"`
}

// control-plane defaults applied when the corresponding field is omitted.
const (
	defaultControlPlanePollInterval = 30 * time.Second
	defaultLongPollWait             = 30 * time.Second
	defaultHeartbeatInterval        = 10 * time.Second
)

// parseControlPlane converts the raw controlPlane block into typed config,
// applying defaults. An absent block yields a disabled value.
func parseControlPlane(r *rawControlPlane) (ControlPlaneConfig, error) {
	var c ControlPlaneConfig
	if r == nil {
		return c, nil
	}
	c.Endpoint = strings.TrimSpace(r.Endpoint)
	c.TokenEnv = r.TokenEnv
	c.CACert = strings.TrimSpace(r.CACert)
	c.LocalOnly = r.LocalOnly
	c.PollInterval = defaultControlPlanePollInterval
	c.LongPollWait = defaultLongPollWait
	c.HeartbeatInterval = defaultHeartbeatInterval
	if err := parseDurationField("controlPlane.pollInterval", r.PollInterval, &c.PollInterval); err != nil {
		return ControlPlaneConfig{}, err
	}
	if err := parseDurationField("controlPlane.longPollWait", r.LongPollWait, &c.LongPollWait); err != nil {
		return ControlPlaneConfig{}, err
	}
	if err := parseDurationField("controlPlane.heartbeatInterval", r.HeartbeatInterval, &c.HeartbeatInterval); err != nil {
		return ControlPlaneConfig{}, err
	}
	return c, nil
}

// validateControlPlane enforces the control-plane block's requirements only when
// it is enabled (Endpoint set), so an absent/empty block is always valid.
func validateControlPlane(c ControlPlaneConfig) error {
	if c.Endpoint == "" {
		return nil
	}
	if !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("config: controlPlane.endpoint must use https, got %q", c.Endpoint)
	}
	if c.PollInterval <= 0 {
		return fmt.Errorf("config: controlPlane.pollInterval must be greater than 0")
	}
	return nil
}
