package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Identity modes. Phase 1 supports off and attribute only; "require" is a
// Phase 2 mode and is rejected with an explicit message. The strings live here
// (not in internal/identity) so config carries no dependency on the verifier.
const (
	// IdentityModeOff is the default: no token is read or verified.
	IdentityModeOff = "off"
	// IdentityModeAttribute verifies a presented token and records the result.
	// It never blocks a request.
	IdentityModeAttribute = "attribute"

	identityModeRequire = "require"

	// MaxIdentityClockSkewSeconds bounds identity.clockSkewSeconds.
	MaxIdentityClockSkewSeconds = 300
)

// IdentitySettings is the `identity:` block: which issuer a worker trusts to
// attribute a caller. It is the same shape on the CP-to-worker wire
// (SettingsWire.Identity) and in local YAML (Policy.Identity), and it holds no
// secrets: an issuer URL, an audience and claim names only.
//
// The zero value (no block) means identity is off, byte-identical to before.
type IdentitySettings struct {
	// DefaultMode is off|attribute; "" means off. An agent's own Identity field
	// overrides it.
	DefaultMode string `json:"defaultMode,omitempty" yaml:"defaultMode"`
	// Issuer is the expected token `iss`. Required when any mode is attribute.
	Issuer string `json:"issuer,omitempty" yaml:"issuer"`
	// Audience is the expected token `aud`. Required when any mode is attribute.
	Audience string `json:"audience,omitempty" yaml:"audience"`
	// AllowedAZP restricts the token `azp`. No built-in default: empty means no
	// azp check (reference configs set [agent-harness, warden-cli]).
	AllowedAZP []string `json:"allowedAZP,omitempty" yaml:"allowedAZP"`
	// JWKSURL overrides the key-set location; empty means discover from Issuer.
	JWKSURL string `json:"jwksURL,omitempty" yaml:"jwksURL"`
	// GroupsClaim names the claim holding group membership; empty means the
	// verifier's default.
	GroupsClaim string `json:"groupsClaim,omitempty" yaml:"groupsClaim"`
	// ClockSkewSeconds is 0..300; 0 means the default (60).
	ClockSkewSeconds int `json:"clockSkewSeconds,omitempty" yaml:"clockSkewSeconds"`
	// MaxTokenTTLSeconds > 0 overrides the default maximum token lifetime (3600).
	MaxTokenTTLSeconds int `json:"maxTokenTTLSeconds,omitempty" yaml:"maxTokenTTLSeconds"`
	// InternalIssuerURL is the origin containers use to reach the issuer when it
	// differs from Issuer (for example http://dex:5556). It is what permits a
	// plain-http Issuer in development; there is no insecure-issuer key.
	InternalIssuerURL string `json:"internalIssuerURL,omitempty" yaml:"internalIssuerURL"`
}

// identityEnabled reports whether any mode other than off is configured, either
// as the default or on an agent.
func identityEnabled(s IdentitySettings, agents []AgentPolicy) bool {
	if s.DefaultMode != "" && s.DefaultMode != IdentityModeOff {
		return true
	}
	for _, a := range agents {
		if a.Identity != "" && a.Identity != IdentityModeOff {
			return true
		}
	}
	return false
}

// validateIdentityMode accepts "", off and attribute. require is a Phase 2 mode.
func validateIdentityMode(key, mode string) error {
	switch mode {
	case "", IdentityModeOff, IdentityModeAttribute:
		return nil
	case identityModeRequire:
		return fmt.Errorf("config: %s %q is not supported in Phase 1 (it arrives in Phase 2); use %q or %q",
			key, mode, IdentityModeOff, IdentityModeAttribute)
	default:
		return fmt.Errorf("config: %s %q is invalid (want %q or %q)",
			key, mode, IdentityModeOff, IdentityModeAttribute)
	}
}

// validateIdentity enforces the identity block's invariants at startup. The
// per-agent mode values are checked by validateAgents; agents is read here only
// to know whether any agent turns identity on.
func validateIdentity(s IdentitySettings, agents []AgentPolicy) error {
	if err := validateIdentityMode("identity.defaultMode", s.DefaultMode); err != nil {
		return err
	}
	if s.ClockSkewSeconds < 0 || s.ClockSkewSeconds > MaxIdentityClockSkewSeconds {
		return fmt.Errorf("config: identity.clockSkewSeconds %d out of range (0..%d)",
			s.ClockSkewSeconds, MaxIdentityClockSkewSeconds)
	}
	if s.MaxTokenTTLSeconds < 0 {
		return fmt.Errorf("config: identity.maxTokenTTLSeconds %d must not be negative", s.MaxTokenTTLSeconds)
	}
	if s.InternalIssuerURL != "" {
		if strings.TrimSpace(s.Issuer) == "" {
			return fmt.Errorf("config: identity.internalIssuerURL requires identity.issuer")
		}
		if err := validateInternalIssuerURL(s.InternalIssuerURL); err != nil {
			return err
		}
	}
	if identityEnabled(s, agents) {
		if strings.TrimSpace(s.Issuer) == "" {
			return fmt.Errorf("config: identity.issuer is required when an identity mode is attribute")
		}
		if strings.TrimSpace(s.Audience) == "" {
			return fmt.Errorf("config: identity.audience is required when an identity mode is attribute")
		}
	}
	if strings.TrimSpace(s.Issuer) == "" {
		return nil
	}
	// Same rule as identity.CheckIssuer: https always passes, plain http only
	// when an internal issuer URL is configured.
	iss, err := url.Parse(s.Issuer)
	if err != nil || iss.Host == "" {
		return fmt.Errorf("config: identity.issuer %q must be an absolute https URL", s.Issuer)
	}
	switch iss.Scheme {
	case "https":
	case "http":
		if s.InternalIssuerURL == "" {
			return fmt.Errorf("config: identity.issuer %q is plain http; use https, or set identity.internalIssuerURL for a development split-horizon issuer", s.Issuer)
		}
	default:
		return fmt.Errorf("config: identity.issuer %q must use https", s.Issuer)
	}
	return nil
}

// validateInternalIssuerURL requires an absolute http(s) origin: empty path or
// "/", no userinfo, query or fragment.
func validateInternalIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("config: identity.internalIssuerURL %q must be an absolute http or https URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("config: identity.internalIssuerURL %q must be an origin only (no path, userinfo, query or fragment)", raw)
	}
	return nil
}

// identitySettingsFromPolicy projects the block onto the wire, or nil when it is
// the zero value so a config without one emits no `identity` key.
func identitySettingsFromPolicy(s IdentitySettings) *IdentitySettings {
	if s.isZero() {
		return nil
	}
	return s.clone()
}

// IdentityFromSettings is the reverse projection used by the worker. A nil input
// is the zero value (identity off).
func IdentityFromSettings(s *IdentitySettings) IdentitySettings {
	if s == nil {
		return IdentitySettings{}
	}
	return *s.clone()
}

func (s IdentitySettings) isZero() bool {
	return s.DefaultMode == "" && s.Issuer == "" && s.Audience == "" && len(s.AllowedAZP) == 0 &&
		s.JWKSURL == "" && s.GroupsClaim == "" && s.ClockSkewSeconds == 0 &&
		s.MaxTokenTTLSeconds == 0 && s.InternalIssuerURL == ""
}

func (s IdentitySettings) clone() *IdentitySettings {
	if s.AllowedAZP != nil {
		s.AllowedAZP = append([]string(nil), s.AllowedAZP...)
	}
	return &s
}
