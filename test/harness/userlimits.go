package harness

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
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
