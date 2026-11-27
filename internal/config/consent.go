package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Consent defaults and bounds. The session defaults are SHORTER than the
// console's (1h idle / 12h absolute) on purpose: a portal session can approve
// third-party access for agents, so a stolen or forgotten browser session must
// stop being useful sooner. refreshLifetime matches the absolute refresh lifetime of
// the reference IdP recipe (720h).
const (
	DefaultConsentClientID        = "warden-portal"
	DefaultConsentIdle            = 30 * time.Minute
	DefaultConsentAbsolute        = 8 * time.Hour
	DefaultConsentRefreshLifetime = 720 * time.Hour
	// MaxConsentSession bounds the portal session's absolute lifetime.
	MaxConsentSession = 24 * time.Hour

	// ConsentCallbackPath is the only accepted path of consent.oidc.redirectURL.
	ConsentCallbackPath = "/portal/callback"
)

// ConsentConfig is the control-plane-local `consent:` block (P3 consent
// sign-in): the dedicated `warden-portal` OIDC client employees use to sign in
// to the consent portal, the portal session bounds, and the IdP-link switch.
// Like Console it is read by the control plane from the operator-owned --config
// only (LoadConsent) and json:"-" on Policy keeps it off the worker wire. With
// no block, or enabled: false, nothing is mounted and behaviour is unchanged.
//
// The struct deliberately leaves room for the keys later tickets add: `store`
// (the CP-only user credential store, W-P3-CSIG-06), `providers` and `connect`
// (W-P3-BRKR-01), `publicURL` (W-P3-JIT-01) and `offboarding` (W-P3-OFFB-02).
// A key not declared here fails the strict parse until its ticket adds it.
type ConsentConfig struct {
	Enabled bool
	OIDC    ConsentOIDC
	// AllowedGroups limits who may sign in. Empty means any user of the issuer.
	AllowedGroups []string
	Session       ConsentSession
	IdPLink       ConsentIdPLink
}

// ConsentOIDC is the portal's OIDC client registration. Scopes are not
// configurable: openid email profile groups, plus offline_access when the IdP
// link is enabled.
type ConsentOIDC struct {
	// Issuer must equal identity.issuer (the issuer workers verify against), or a
	// portal sub would never match a data-plane sub.
	Issuer string
	// ClientID defaults to warden-portal.
	ClientID string
	// ClientSecretEnv names the environment variable holding the client secret
	// (never the secret itself).
	ClientSecretEnv string
	// RedirectURL is <cp-browser-url>/portal/callback.
	RedirectURL string
	// InternalIssuerURL is the origin containers use to reach the issuer when it
	// differs from Issuer; same rule and meaning as console.oidc.internalIssuerURL.
	InternalIssuerURL string
}

// ConsentSession bounds a portal session: Idle since last use, Absolute since
// creation. The key names match console.session.
type ConsentSession struct {
	Idle     time.Duration
	Absolute time.Duration
}

// ConsentIdPLink controls whether the login requests offline_access and the CP
// keeps the user's refresh token (default true).
type ConsentIdPLink struct {
	Enabled bool
	// RefreshLifetime is how long the IdP keeps a refresh token alive (the IdP
	// absolute refresh lifetime); it dates relink_due_at.
	RefreshLifetime time.Duration
}

// rawConsent mirrors the on-disk `consent:` block. KnownFields(true) makes an
// unknown or misspelled key a parse error.
type rawConsent struct {
	Enabled bool `yaml:"enabled"`
	OIDC    struct {
		Issuer            string `yaml:"issuer"`
		ClientID          string `yaml:"clientID"`
		ClientSecretEnv   string `yaml:"clientSecretEnv"`
		RedirectURL       string `yaml:"redirectURL"`
		InternalIssuerURL string `yaml:"internalIssuerURL"`
	} `yaml:"oidc"`
	AllowedGroups []string `yaml:"allowedGroups"`
	Session       struct {
		Idle     string `yaml:"idle"`
		Absolute string `yaml:"absolute"`
	} `yaml:"session"`
	// A pointer tells an absent enabled (default true) from an explicit false.
	IdPLink struct {
		Enabled         *bool  `yaml:"enabled"`
		RefreshLifetime string `yaml:"refreshLifetime"`
	} `yaml:"idpLink"`
}

// defaultConsent is the block with every default applied (disabled).
func defaultConsent() ConsentConfig {
	return ConsentConfig{
		OIDC:    ConsentOIDC{ClientID: DefaultConsentClientID},
		Session: ConsentSession{Idle: DefaultConsentIdle, Absolute: DefaultConsentAbsolute},
		IdPLink: ConsentIdPLink{Enabled: true, RefreshLifetime: DefaultConsentRefreshLifetime},
	}
}

// parseConsent converts the raw block and applies defaults. An absent block is
// disabled with the defaults filled in, so it changes nothing.
func parseConsent(r *rawConsent) (ConsentConfig, error) {
	c := defaultConsent()
	if r == nil {
		return c, nil
	}
	c.Enabled = r.Enabled
	o := r.OIDC
	c.OIDC.Issuer = strings.TrimSpace(o.Issuer)
	if id := strings.TrimSpace(o.ClientID); id != "" {
		c.OIDC.ClientID = id
	}
	c.OIDC.ClientSecretEnv = strings.TrimSpace(o.ClientSecretEnv)
	c.OIDC.RedirectURL = strings.TrimSpace(o.RedirectURL)
	c.OIDC.InternalIssuerURL = strings.TrimSpace(o.InternalIssuerURL)
	for _, g := range r.AllowedGroups {
		c.AllowedGroups = append(c.AllowedGroups, strings.TrimSpace(g))
	}
	for _, d := range []struct {
		key string
		raw string
		dst *time.Duration
	}{
		{"session.idle", r.Session.Idle, &c.Session.Idle},
		{"session.absolute", r.Session.Absolute, &c.Session.Absolute},
		{"idpLink.refreshLifetime", r.IdPLink.RefreshLifetime, &c.IdPLink.RefreshLifetime},
	} {
		s := strings.TrimSpace(d.raw)
		if s == "" {
			continue
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return ConsentConfig{}, fmt.Errorf("config: consent.%s %q is not a valid duration: %w", d.key, s, err)
		}
		*d.dst = v
	}
	if r.IdPLink.Enabled != nil {
		c.IdPLink.Enabled = *r.IdPLink.Enabled
	}
	return c, nil
}

// validateConsent enforces the consent block's invariants when it is enabled
// (a disabled block is never validated, so a half-written one cannot stop a
// start that does not use it). consoleRedirect is console.oidc.redirectURL, which
// the portal's redirectURL must differ from. Every error names the key and none
// carries a secret.
func validateConsent(c ConsentConfig, consoleRedirect string) error {
	if !c.Enabled {
		return nil
	}
	o := c.OIDC
	if o.Issuer == "" {
		return fmt.Errorf("config: consent.oidc.issuer is required when consent.enabled is true")
	}
	if o.ClientSecretEnv == "" {
		return fmt.Errorf("config: consent.oidc.clientSecretEnv is required when consent.enabled is true")
	}
	if o.RedirectURL == "" {
		return fmt.Errorf("config: consent.oidc.redirectURL is required when consent.enabled is true")
	}
	if o.ClientID == "" {
		return fmt.Errorf("config: consent.oidc.clientID must not be empty")
	}
	if err := validateConsentIssuer(o); err != nil {
		return err
	}
	if err := validateConsentRedirect(o.RedirectURL); err != nil {
		return err
	}
	if consoleRedirect != "" && sameURL(o.RedirectURL, consoleRedirect) {
		return fmt.Errorf("config: consent.oidc.redirectURL must differ from console.oidc.redirectURL")
	}
	for _, g := range c.AllowedGroups {
		if g == "" {
			return fmt.Errorf("config: consent.allowedGroups must not contain an empty group name")
		}
	}
	s := c.Session
	if s.Idle <= 0 || s.Absolute <= 0 || s.Idle > s.Absolute || s.Absolute > MaxConsentSession {
		return fmt.Errorf("config: consent.session needs 0 < idle (%s) <= absolute (%s) <= %s", s.Idle, s.Absolute, MaxConsentSession)
	}
	if c.IdPLink.RefreshLifetime <= 0 {
		return fmt.Errorf("config: consent.idpLink.refreshLifetime (%s) must be > 0", c.IdPLink.RefreshLifetime)
	}
	return nil
}

func sameURL(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(a), "/"), strings.TrimRight(strings.TrimSpace(b), "/"))
}

// validateConsentIssuer applies the http-issuer rule of the shared OIDC client
// (https always passes; plain http only with an internal issuer URL) without
// importing internal/identity.
func validateConsentIssuer(o ConsentOIDC) error {
	if o.InternalIssuerURL != "" {
		u, err := url.Parse(o.InternalIssuerURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: consent.oidc.internalIssuerURL %q must be an absolute http or https URL", o.InternalIssuerURL)
		}
		if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("config: consent.oidc.internalIssuerURL %q must be an origin only (no path, userinfo, query or fragment)", o.InternalIssuerURL)
		}
	}
	iss, err := url.Parse(o.Issuer)
	if err != nil || iss.Host == "" {
		return fmt.Errorf("config: consent.oidc.issuer %q must be an absolute https URL", o.Issuer)
	}
	switch iss.Scheme {
	case "https":
	case "http":
		if o.InternalIssuerURL == "" {
			return fmt.Errorf("config: consent.oidc.issuer %q is plain http; use https, or set consent.oidc.internalIssuerURL for a development split-horizon issuer", o.Issuer)
		}
	default:
		return fmt.Errorf("config: consent.oidc.issuer %q must use https", o.Issuer)
	}
	return nil
}

// validateConsentRedirect requires an absolute callback URL whose path is
// exactly /portal/callback, over https unless the host is loopback.
func validateConsentRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("config: consent.oidc.redirectURL %q must be an absolute http(s) URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("config: consent.oidc.redirectURL %q must not carry userinfo, query or fragment", raw)
	}
	if u.Path != ConsentCallbackPath {
		return fmt.Errorf("config: consent.oidc.redirectURL %q must have the path exactly %s", raw, ConsentCallbackPath)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("config: consent.oidc.redirectURL %q must be https unless its host is loopback", raw)
	}
	return nil
}

// LoadConsent reads only the `consent:` block of the YAML file at path, with
// the same strict decoder and validation as a full config load. The control
// plane calls it on the operator-owned --config file (never the served copy).
func LoadConsent(path string) (ConsentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ConsentConfig{}, fmt.Errorf("config: read %q: %w", path, err)
	}
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return ConsentConfig{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	c, err := parseConsent(raw.Consent)
	if err != nil {
		return ConsentConfig{}, err
	}
	consoleRedirect := ""
	if raw.Console != nil {
		consoleRedirect = strings.TrimSpace(raw.Console.OIDC.RedirectURL)
	}
	if err := validateConsent(c, consoleRedirect); err != nil {
		return ConsentConfig{}, err
	}
	return c, nil
}
