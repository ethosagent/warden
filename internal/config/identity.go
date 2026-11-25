package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Identity modes. "require" (Phase 2) is served by the control plane and
// enforced by a managed worker; a standalone worker's local YAML rejects it
// (ValidateStandaloneIdentity). The strings live here (not in internal/identity)
// so config carries no dependency on the verifier.
const (
	// IdentityModeOff is the default: no token is read or verified.
	IdentityModeOff = "off"
	// IdentityModeAttribute verifies a presented token and records the result.
	// It never blocks a request.
	IdentityModeAttribute = "attribute"
	// IdentityModeChallenge verifies a presented token like attribute, but
	// refuses a CONNECT without a valid one with a 407 that carries a sign-in
	// URL (docs/identity-contract.md).
	IdentityModeChallenge = "challenge"

	// IdentityModeRequire refuses a CONNECT without a valid Warden token bound
	// to the worker's agent with a 407 (no sign-in), and a terminated request
	// whose identity is not valid with a 403. Only a control-plane-managed
	// worker enforces it: it needs the signed bundle's keys and agents.
	IdentityModeRequire = "require"

	// Where an effective identity mode came from (EffectiveIdentityMode).
	IdentitySourceAgent   = "agents[].identity"
	IdentitySourceDefault = "identity.defaultMode"
	IdentitySourceUnset   = "unset"

	// MaxIdentityClockSkewSeconds bounds identity.clockSkewSeconds.
	MaxIdentityClockSkewSeconds = 300

	// Defaults of the identity.signIn block.
	DefaultSignInClientID        = "warden-cli"
	DefaultSignInMaxPending      = 32
	DefaultSignInStartsPerMinute = 30
	// maxSignInLimit bounds maxPending and startsPerMinute so a typo cannot
	// turn the sign-in start into an unbounded fan-out at the issuer.
	maxSignInLimit = 10000
)

// DefaultSignInScopes are requested by the worker's device authorization when
// identity.signIn.scopes is empty. The last one asks the issuer for a token
// whose aud holds the "warden" client.
var DefaultSignInScopes = []string{"openid", "email", "profile", "groups", "offline_access", "audience:server:client_id:warden"}

// IdentitySettings is the `identity:` block: which issuer a worker trusts to
// attribute a caller. It is the same shape on the CP-to-worker wire
// (SettingsWire.Identity) and in local YAML (Policy.Identity), and it holds no
// secrets: an issuer URL, an audience and claim names only.
//
// The zero value (no block) means identity is off, byte-identical to before.
type IdentitySettings struct {
	// DefaultMode is off|attribute|challenge|require; "" means off. An agent's own Identity field
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
	// differs from Issuer (for example http://idp:5556). It is what permits a
	// plain-http Issuer in development; there is no insecure-issuer key.
	InternalIssuerURL string `json:"internalIssuerURL,omitempty" yaml:"internalIssuerURL"`
	// SignIn tunes the device authorization a worker in challenge mode starts
	// for a caller with no valid identity. It holds no secrets.
	SignIn *SignInSettings `json:"signIn,omitempty" yaml:"signIn"`
	// AcceptDexTokens says whether a worker accepts a user token straight from
	// the IdP (the P1 flow) next to the Warden tokens the control plane mints.
	// nil means unset: true when Issuer is set, false otherwise (see
	// AcceptIdPTokens). false turns each IdP token away as unbound_token, which
	// is what an agent in require mode needs; the key name keeps the first
	// IdP the flow was built against.
	AcceptDexTokens *bool `json:"acceptDexTokens,omitempty" yaml:"acceptDexTokens"`
}

// AcceptIdPTokens resolves identity.acceptDexTokens: the explicit value, else
// true when identity.issuer is set and false otherwise.
func (s IdentitySettings) AcceptIdPTokens() bool {
	if s.AcceptDexTokens != nil {
		return *s.AcceptDexTokens
	}
	return strings.TrimSpace(s.Issuer) != ""
}

// SignInSettings is the `identity.signIn` block (challenge mode only). Zero
// fields take the defaults above.
type SignInSettings struct {
	// ClientID is the issuer's PUBLIC device-flow client (no secret on workers);
	// default warden-cli. It must be in AllowedAZP when that list is not empty,
	// or every token from the flow would fail with wrong_azp.
	ClientID string `json:"clientID,omitempty" yaml:"clientID"`
	// Scopes requested by the device authorization; empty means DefaultSignInScopes.
	Scopes []string `json:"scopes,omitempty" yaml:"scopes"`
	// MaxPending bounds the open device authorizations per worker (default 32).
	MaxPending int `json:"maxPending,omitempty" yaml:"maxPending"`
	// StartsPerMinute bounds device_authorization calls per worker (default 30).
	StartsPerMinute int `json:"startsPerMinute,omitempty" yaml:"startsPerMinute"`
}

// Effective returns the settings with every default applied; a nil receiver is
// all defaults. The result shares no memory with s.
func (s *SignInSettings) Effective() SignInSettings {
	var out SignInSettings
	if s != nil {
		out = *s
	}
	if out.ClientID == "" {
		out.ClientID = DefaultSignInClientID
	}
	if len(out.Scopes) == 0 {
		out.Scopes = DefaultSignInScopes
	}
	out.Scopes = append([]string(nil), out.Scopes...)
	if out.MaxPending == 0 {
		out.MaxPending = DefaultSignInMaxPending
	}
	if out.StartsPerMinute == 0 {
		out.StartsPerMinute = DefaultSignInStartsPerMinute
	}
	return out
}

// EffectiveIdentityMode resolves the identity mode of the agent a worker is
// bound to and says where it came from: the agent's own agents[].identity, then
// identity.defaultMode, then off (source unset). An empty value at either level
// falls through. It is the one resolver the worker applies and logs.
func EffectiveIdentityMode(agentID string, agents []AgentPolicy, s IdentitySettings) (mode, source string) {
	for _, a := range agents {
		if a.ID == agentID && a.Identity != "" {
			return a.Identity, IdentitySourceAgent
		}
	}
	if s.DefaultMode != "" {
		return s.DefaultMode, IdentitySourceDefault
	}
	return IdentityModeOff, IdentitySourceUnset
}

// ValidateStandaloneIdentity refuses require anywhere in the identity config of
// a worker that has no control plane (no controlPlane.endpoint, or --local-only).
// Such a worker has no signed bundle, so it has no Warden token keys or
// registered agents to enforce require with; the mode is served by a control
// plane only. Call it on the local policy of a worker that is not managed.
func ValidateStandaloneIdentity(p Policy) error {
	if p.Identity.DefaultMode == IdentityModeRequire {
		return fmt.Errorf("config: identity.defaultMode %q needs a control-plane-managed worker (controlPlane.endpoint): a standalone worker has no signed bundle to verify Warden tokens with; use %q or %q",
			IdentityModeRequire, IdentityModeAttribute, IdentityModeChallenge)
	}
	for i, a := range p.Agents {
		if a.Identity == IdentityModeRequire {
			return fmt.Errorf("config: agents[%d].identity %q needs a control-plane-managed worker (controlPlane.endpoint): a standalone worker has no signed bundle to verify Warden tokens with; use %q or %q",
				i, IdentityModeRequire, IdentityModeAttribute, IdentityModeChallenge)
		}
	}
	return nil
}

// idpModeEnabled reports whether any mode that verifies IdP tokens (attribute
// or challenge) is configured, as the default or on an agent. require alone
// does not: it accepts Warden tokens only unless acceptDexTokens is set.
func idpModeEnabled(s IdentitySettings, agents []AgentPolicy) bool {
	on := func(m string) bool { return m == IdentityModeAttribute || m == IdentityModeChallenge }
	if on(s.DefaultMode) {
		return true
	}
	for _, a := range agents {
		if on(a.Identity) {
			return true
		}
	}
	return false
}

// validateIdentityMode accepts "", off, attribute, challenge and require.
func validateIdentityMode(key, mode string) error {
	switch mode {
	case "", IdentityModeOff, IdentityModeAttribute, IdentityModeChallenge, IdentityModeRequire:
		return nil
	default:
		return fmt.Errorf("config: %s %q is invalid (want %q, %q, %q or %q)",
			key, mode, IdentityModeOff, IdentityModeAttribute, IdentityModeChallenge, IdentityModeRequire)
	}
}

// validateSignIn checks identity.signIn. It is validated whatever the mode, so
// a bad block is caught before challenge is switched on.
func validateSignIn(s IdentitySettings) error {
	if s.SignIn == nil {
		return nil
	}
	if s.SignIn.MaxPending < 0 || s.SignIn.MaxPending > maxSignInLimit {
		return fmt.Errorf("config: identity.signIn.maxPending %d out of range (0..%d)", s.SignIn.MaxPending, maxSignInLimit)
	}
	if s.SignIn.StartsPerMinute < 0 || s.SignIn.StartsPerMinute > maxSignInLimit {
		return fmt.Errorf("config: identity.signIn.startsPerMinute %d out of range (0..%d)", s.SignIn.StartsPerMinute, maxSignInLimit)
	}
	for _, sc := range s.SignIn.Scopes {
		if sc == "" || strings.ContainsAny(sc, " \t\r\n") {
			return fmt.Errorf("config: identity.signIn.scopes entries must be non-empty single tokens")
		}
	}
	if id := s.SignIn.ClientID; id != "" && strings.ContainsAny(id, " \t\r\n") {
		return fmt.Errorf("config: identity.signIn.clientID must not contain whitespace")
	}
	return nil
}

// validateChallengeAZP rejects a sign-in client the verifier would refuse: when
// allowedAZP is set it must hold the client the device flow signs users in with.
func validateChallengeAZP(s IdentitySettings) error {
	if len(s.AllowedAZP) == 0 {
		return nil
	}
	id := s.SignIn.Effective().ClientID
	for _, a := range s.AllowedAZP {
		if a == id {
			return nil
		}
	}
	return fmt.Errorf("config: identity.signIn.clientID %q is not in identity.allowedAZP; every token from the sign-in flow would fail with wrong_azp (add it to allowedAZP)", id)
}

// IdentityWarnings returns warnings about an identity block that is valid but
// likely not what the operator wants. Callers log each once.
func IdentityWarnings(s IdentitySettings, agents []AgentPolicy) []string {
	var out []string
	if s.AcceptDexTokens != nil && !*s.AcceptDexTokens && challengeEnabled(s, agents) {
		out = append(out, "identity: challenge mode with acceptDexTokens false: the sign-in flow hands out IdP tokens that this worker refuses (unbound_token); clients must exchange them for Warden tokens at the control plane's token endpoint")
	}
	return out
}

// challengeEnabled reports whether any mode is challenge, as the default or on an agent.
func challengeEnabled(s IdentitySettings, agents []AgentPolicy) bool {
	if s.DefaultMode == IdentityModeChallenge {
		return true
	}
	for _, a := range agents {
		if a.Identity == IdentityModeChallenge {
			return true
		}
	}
	return false
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
	if err := validateSignIn(s); err != nil {
		return err
	}
	if s.AcceptDexTokens != nil && *s.AcceptDexTokens && strings.TrimSpace(s.Issuer) == "" {
		return fmt.Errorf("config: identity.acceptDexTokens true requires identity.issuer")
	}
	// An explicit acceptDexTokens false means no IdP token is ever verified, so
	// the IdP issuer and audience are not needed to turn attribute on. Challenge
	// still signs users in at the IdP and needs both.
	if idpModeEnabled(s, agents) && (s.AcceptDexTokens == nil || *s.AcceptDexTokens || challengeEnabled(s, agents)) {
		if strings.TrimSpace(s.Issuer) == "" {
			return fmt.Errorf("config: identity.issuer is required when an identity mode is attribute or challenge")
		}
		if strings.TrimSpace(s.Audience) == "" {
			return fmt.Errorf("config: identity.audience is required when an identity mode is attribute or challenge")
		}
	}
	if challengeEnabled(s, agents) {
		if err := validateChallengeAZP(s); err != nil {
			return err
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
		s.MaxTokenTTLSeconds == 0 && s.InternalIssuerURL == "" && s.SignIn == nil && s.AcceptDexTokens == nil
}

func (s IdentitySettings) clone() *IdentitySettings {
	if s.AllowedAZP != nil {
		s.AllowedAZP = append([]string(nil), s.AllowedAZP...)
	}
	if s.AcceptDexTokens != nil {
		v := *s.AcceptDexTokens
		s.AcceptDexTokens = &v
	}
	if s.SignIn != nil {
		si := *s.SignIn
		if si.Scopes != nil {
			si.Scopes = append([]string(nil), si.Scopes...)
		}
		s.SignIn = &si
	}
	return &s
}
