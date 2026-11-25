package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Token service defaults and bounds (W-P2-TOKX-03). The numbers are the
// feature design's; the token service package (internal/tokensvc) repeats the
// ttl range because config cannot import it.
const (
	DefaultTokenServiceTTL             = 15 * time.Minute
	MinTokenServiceTTL                 = time.Minute
	MaxTokenServiceTTL                 = 15 * time.Minute
	DefaultTokenServiceAssertionMaxAge = 5 * time.Minute
	DefaultTokenServiceClockSkew       = 60 * time.Second
	DefaultTokenServiceSessionIdle     = 12 * time.Hour
	DefaultTokenServiceSessionAbsolute = 168 * time.Hour
	DefaultTokenServiceRatePerIP       = "120/minute"
	DefaultTokenServiceRatePerAgent    = "300/minute"
	DefaultTokenServiceRatePerUser     = "30/minute"
	DefaultTokenServiceMaxInFlight     = 64
	DefaultTokenServiceEventRetention  = 720 * time.Hour

	// MaxTokenServiceMaxInFlight bounds rateLimit.maxInFlight so a typo cannot
	// make the cap meaningless.
	MaxTokenServiceMaxInFlight = 10000
	// MinTokenServiceEventRetention keeps the issuance records long enough to
	// investigate an incident.
	MinTokenServiceEventRetention = 24 * time.Hour

	maxTokenServiceAllowedAZP = 16
	maxTokenServiceSession    = 720 * time.Hour
	maxTokenServiceSkew       = 5 * time.Minute
)

// DefaultTokenServiceAllowedAZP lists the OIDC clients whose ID tokens the
// token endpoint accepts as a subject token when tokenService.allowedAZP is
// unset.
func DefaultTokenServiceAllowedAZP() []string { return []string{"agent-harness"} }

// TokenServiceConfig is the control-plane-local `tokenService:` block: the
// RFC 8693 token endpoint (POST /oauth2/token). Like Console and Keys it is
// read by the control plane from --config only (LoadTokenService); Policy tags
// it json:"-", so it is on neither the worker wire nor the settings wire.
// Disabled by default: with the block absent or enabled false the route set
// and every response are unchanged and no tokensvc table is created.
type TokenServiceConfig struct {
	// Enabled turns the endpoint on. It needs --state-dir, a served identity
	// issuer and keys.enabled (checked by the control plane at startup).
	Enabled bool
	// Issuer is this token service's own issuer URL: the iss of every issued
	// token and the base of the accepted client assertion audience. An
	// absolute https URL with no trailing slash, query or fragment; http only
	// for a loopback host.
	Issuer string
	// TTL is the longest lifetime of an issued token (default 15m, 1m-15m).
	TTL time.Duration
	// AssertionMaxAge is the longest exp-iat a client assertion may claim.
	AssertionMaxAge time.Duration
	// ClockSkew is the leeway on assertion times.
	ClockSkew time.Duration
	// AllowedAZP narrows the served identity block's allowedAZP for subject
	// tokens: only ID tokens minted for these clients can be exchanged.
	AllowedAZP []string
	// Session bounds a token session.
	Session TokenServiceSession
	// RateLimit holds the abuse limits the control plane enforces per client IP,
	// per verified agent and per user (W-P2-TOKX-04).
	RateLimit TokenServiceRateLimit
	// EventRetention is how long issuance records are kept.
	EventRetention time.Duration
}

// TokenServiceSession is tokenService.session: Idle since last use, Absolute
// since creation.
type TokenServiceSession struct {
	Idle, Absolute time.Duration
}

// TokenServiceRateLimit is tokenService.rateLimit. Each rate is "N/second",
// "N/minute" or "N/hour", the grammar of a policy rate limit.
type TokenServiceRateLimit struct {
	PerIP, PerAgent, PerUser string
	// MaxInFlight caps concurrent exchanges.
	MaxInFlight int
}

// rawTokenService mirrors the on-disk block. Durations stay strings so a
// misspelled or negative value is an error rather than a silent default.
type rawTokenService struct {
	Enabled         bool     `yaml:"enabled"`
	Issuer          string   `yaml:"issuer"`
	TTL             string   `yaml:"ttl"`
	AssertionMaxAge string   `yaml:"assertionMaxAge"`
	ClockSkew       string   `yaml:"clockSkew"`
	AllowedAZP      []string `yaml:"allowedAZP"`
	Session         struct {
		Idle     string `yaml:"idle"`
		Absolute string `yaml:"absolute"`
	} `yaml:"session"`
	RateLimit struct {
		PerIP       string `yaml:"perIP"`
		PerAgent    string `yaml:"perAgent"`
		PerUser     string `yaml:"perUser"`
		MaxInFlight *int   `yaml:"maxInFlight"`
	} `yaml:"rateLimit"`
	EventRetention string `yaml:"eventRetention"`
}

// DefaultTokenService returns the block with every default applied and enabled
// false: what an operator's config without the block means.
func DefaultTokenService() TokenServiceConfig {
	c, _ := parseTokenService(nil)
	return c
}

// parseTokenService converts the raw block and applies defaults. An absent
// block is the disabled default.
func parseTokenService(r *rawTokenService) (TokenServiceConfig, error) {
	c := TokenServiceConfig{
		TTL:             DefaultTokenServiceTTL,
		AssertionMaxAge: DefaultTokenServiceAssertionMaxAge,
		ClockSkew:       DefaultTokenServiceClockSkew,
		AllowedAZP:      DefaultTokenServiceAllowedAZP(),
		Session:         TokenServiceSession{Idle: DefaultTokenServiceSessionIdle, Absolute: DefaultTokenServiceSessionAbsolute},
		RateLimit: TokenServiceRateLimit{
			PerIP: DefaultTokenServiceRatePerIP, PerAgent: DefaultTokenServiceRatePerAgent,
			PerUser: DefaultTokenServiceRatePerUser, MaxInFlight: DefaultTokenServiceMaxInFlight,
		},
		EventRetention: DefaultTokenServiceEventRetention,
	}
	if r == nil {
		return c, nil
	}
	c.Enabled = r.Enabled
	c.Issuer = strings.TrimSpace(r.Issuer)
	durs := []struct {
		name string
		raw  string
		dst  *time.Duration
	}{
		{"tokenService.ttl", r.TTL, &c.TTL},
		{"tokenService.assertionMaxAge", r.AssertionMaxAge, &c.AssertionMaxAge},
		{"tokenService.clockSkew", r.ClockSkew, &c.ClockSkew},
		{"tokenService.session.idle", r.Session.Idle, &c.Session.Idle},
		{"tokenService.session.absolute", r.Session.Absolute, &c.Session.Absolute},
		{"tokenService.eventRetention", r.EventRetention, &c.EventRetention},
	}
	for _, d := range durs {
		if err := parseDurationField(d.name, d.raw, d.dst); err != nil {
			return TokenServiceConfig{}, err
		}
	}
	if r.AllowedAZP != nil {
		c.AllowedAZP = make([]string, 0, len(r.AllowedAZP))
		for _, a := range r.AllowedAZP {
			c.AllowedAZP = append(c.AllowedAZP, strings.TrimSpace(a))
		}
	}
	for _, rl := range []struct {
		raw string
		dst *string
	}{{r.RateLimit.PerIP, &c.RateLimit.PerIP}, {r.RateLimit.PerAgent, &c.RateLimit.PerAgent}, {r.RateLimit.PerUser, &c.RateLimit.PerUser}} {
		if v := strings.TrimSpace(rl.raw); v != "" {
			*rl.dst = v
		}
	}
	if r.RateLimit.MaxInFlight != nil {
		c.RateLimit.MaxInFlight = *r.RateLimit.MaxInFlight
	}
	return c, nil
}

// validateTokenService enforces the block's invariants. It runs whether or not
// the block is enabled, so a typo surfaces when the file is written rather
// than the day someone flips enabled; only the issuer is optional while
// disabled.
func validateTokenService(c TokenServiceConfig) error {
	if c.Enabled || c.Issuer != "" {
		if err := ValidateTokenServiceIssuer(c.Issuer); err != nil {
			return err
		}
	}
	if c.TTL < MinTokenServiceTTL || c.TTL > MaxTokenServiceTTL {
		return fmt.Errorf("config: tokenService.ttl %s must be between %s and %s", c.TTL, MinTokenServiceTTL, MaxTokenServiceTTL)
	}
	if c.AssertionMaxAge <= 0 || c.AssertionMaxAge > MaxTokenServiceTTL {
		return fmt.Errorf("config: tokenService.assertionMaxAge %s must be greater than 0 and at most %s", c.AssertionMaxAge, MaxTokenServiceTTL)
	}
	if c.ClockSkew <= 0 || c.ClockSkew > maxTokenServiceSkew {
		return fmt.Errorf("config: tokenService.clockSkew %s must be greater than 0 and at most %s", c.ClockSkew, maxTokenServiceSkew)
	}
	if len(c.AllowedAZP) == 0 || len(c.AllowedAZP) > maxTokenServiceAllowedAZP {
		return fmt.Errorf("config: tokenService.allowedAZP needs between 1 and %d client ids", maxTokenServiceAllowedAZP)
	}
	seen := map[string]bool{}
	for _, a := range c.AllowedAZP {
		if a == "" || strings.ContainsFunc(a, unicode.IsSpace) || seen[a] {
			return fmt.Errorf("config: tokenService.allowedAZP entries must be unique, non-empty and without whitespace")
		}
		seen[a] = true
	}
	if c.Session.Idle <= 0 || c.Session.Absolute <= 0 || c.Session.Absolute > maxTokenServiceSession || c.Session.Idle > c.Session.Absolute {
		return fmt.Errorf("config: tokenService.session needs 0 < idle <= absolute <= %s (idle %s, absolute %s)", maxTokenServiceSession, c.Session.Idle, c.Session.Absolute)
	}
	for _, rl := range []struct{ key, val string }{
		{"tokenService.rateLimit.perIP", c.RateLimit.PerIP},
		{"tokenService.rateLimit.perAgent", c.RateLimit.PerAgent},
		{"tokenService.rateLimit.perUser", c.RateLimit.PerUser},
	} {
		if err := validateTokenServiceRate(rl.key, rl.val); err != nil {
			return err
		}
	}
	if c.RateLimit.MaxInFlight < 1 || c.RateLimit.MaxInFlight > MaxTokenServiceMaxInFlight {
		return fmt.Errorf("config: tokenService.rateLimit.maxInFlight %d must be between 1 and %d", c.RateLimit.MaxInFlight, MaxTokenServiceMaxInFlight)
	}
	if c.EventRetention < MinTokenServiceEventRetention {
		return fmt.Errorf("config: tokenService.eventRetention %s is below the %s minimum", c.EventRetention, MinTokenServiceEventRetention)
	}
	return nil
}

// validateTokenServiceRate checks the "N/second|minute|hour" grammar of a
// policy rate limit (policy.parseRateLimit, which config cannot import).
func validateTokenServiceRate(key, s string) error {
	n, per, ok := strings.Cut(s, "/")
	count, err := strconv.Atoi(n)
	if !ok || err != nil || count <= 0 {
		return fmt.Errorf("config: %s %q must look like N/second, N/minute or N/hour with N greater than 0", key, s)
	}
	switch per {
	case "second", "minute", "hour":
		return nil
	}
	return fmt.Errorf("config: %s %q must look like N/second, N/minute or N/hour with N greater than 0", key, s)
}

// ValidateTokenServiceIssuer checks the token service's own issuer URL:
// absolute https with a host, no userinfo, query, fragment or trailing slash.
// http is accepted only for a loopback host (development); there is no
// insecure flag. internal/tokensvc.ValidateIssuer applies the same rule to the
// value the service signs with, and a controlplane test pins the two together.
func ValidateTokenServiceIssuer(s string) error {
	bad := func(why string) error {
		return fmt.Errorf("config: tokenService.issuer must be an absolute https URL without query, fragment or trailing slash: %s", why)
	}
	if s == "" {
		return bad("it is required when the token service is enabled")
	}
	if strings.ContainsAny(s, "?#") || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return bad("query, fragment or stray characters")
	}
	if strings.HasSuffix(s, "/") {
		return bad("trailing slash")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
		return bad("not an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !IsLoopbackHost(u.Hostname()) {
			return bad("http is allowed only for a loopback host")
		}
	default:
		return bad("scheme")
	}
	return nil
}

// IsLoopbackHost reports whether h is localhost or a loopback IP literal.
func IsLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

// clone returns a copy that shares no slice with c.
func (c TokenServiceConfig) clone() TokenServiceConfig {
	c.AllowedAZP = append([]string(nil), c.AllowedAZP...)
	return c
}

// LoadTokenService reads only the `tokenService:` block of the YAML file at
// path, with the same strict decoder and validation as a full config load. The
// control plane calls it on the operator-owned --config file (never the served
// copy), like LoadConsole.
func LoadTokenService(path string) (TokenServiceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TokenServiceConfig{}, fmt.Errorf("config: read %q: %w", path, err)
	}
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return TokenServiceConfig{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	c, err := parseTokenService(raw.TokenService)
	if err != nil {
		return TokenServiceConfig{}, err
	}
	if err := validateTokenService(c); err != nil {
		return TokenServiceConfig{}, err
	}
	return c, nil
}
