package harness

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
)

// WithUserLimits adds per-user limit rules (W-P3-PUL-09) to the control
// plane's served policy at boot: userLimits plus the optional
// defaultUserLimit and anonymousLimit. Workers receive them on the policy wire
// like any other served policy and enforce them per request.
func WithUserLimits(rules []config.UserLimit, def, anon *config.UserLimit) Option {
	return func(h *H) {
		h.userLimits = &userLimitsSpec{UserLimits: rules, DefaultUserLimit: def, AnonymousLimit: anon}
	}
}

// userLimitsSpec is the YAML of the three policy keys.
type userLimitsSpec struct {
	UserLimits       []config.UserLimit `yaml:"userLimits,omitempty"`
	DefaultUserLimit *config.UserLimit  `yaml:"defaultUserLimit,omitempty"`
	AnonymousLimit   *config.UserLimit  `yaml:"anonymousLimit,omitempty"`
}

// userLimitsYAML renders the spec as lines inside the CP config's policy block
// (two-space indented), or "" when no limits were asked for.
func (h *H) userLimitsYAML() string {
	if h.userLimits == nil {
		return ""
	}
	raw, err := yaml.Marshal(h.userLimits)
	if err != nil {
		h.tb.Fatalf("harness: encode user limits: %v", err)
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

// WithFleetCostBlocks boots the control plane with the persistent (sqlite)
// fleet analytics store, a state dir and the harness fake clock, so the fleet
// cost aggregator (W-P3-PUL-08) runs: it rolls up the events the workers
// forward (pair it with WithCentralForwarding) and serves the users over a
// dailyCostUSD cap as costBlockedUsers. Its 30s debounce and the UTC-midnight
// timer run on h.Clock(). In-process only.
func WithFleetCostBlocks() Option {
	return func(h *H) { h.wantFleetCostBlocks = true }
}

func (h *H) applyFleetCostBlocks(p *controlplane.Params) {
	if !h.wantFleetCostBlocks {
		return
	}
	p.AnalyticsProvider = "sqlite"
	p.AnalyticsDB = filepath.Join(h.root, "cp-fleet.db")
	p.StateDir = filepath.Join(h.root, "cp-state")
	p.Clock = h.fake
}

// AgentAt is Agent against worker i (0-based): the same trust and transcript,
// no proxy token, so the agent carries its user token as a header
// (identity mode attribute) or none at all.
func (h *H) AgentAt(i int) *http.Client {
	h.tb.Helper()
	if h.agentClients != nil {
		h.tb.Fatal("harness: AgentAt is in-process only; this target supplies its own agent clients")
	}
	proxyURL := &url.URL{Scheme: "http", Host: h.workerProxyAddr(i)}
	base := &http.Transport{
		Proxy:           func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		TLSClientConfig: h.AgentTLSConfig(),
	}
	cl := &http.Client{Timeout: defaultAgentTimeout, Transport: &recordingTransport{base: base, h: h}}
	h.mu.Lock()
	h.tokenClients = append(h.tokenClients, cl)
	h.mu.Unlock()
	return cl
}

// WithFakeClockStart starts the fake clock at f(real now) instead of the real
// now, so a scenario can run from a chosen wall-clock time (for example just
// before a UTC midnight) on every CI pass. Prefer a start at or after the real
// time: the workers' certificates and tokens are checked against the fake clock.
func WithFakeClockStart(f func(time.Time) time.Time) Option {
	return func(h *H) { h.clockStart = f }
}
