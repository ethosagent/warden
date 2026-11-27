package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OAuth provider types of consent.providers[].type.
const (
	OAuthProviderGoogle    = "google"
	OAuthProviderGitHub    = "github"
	OAuthProviderGitHubApp = "githubApp"
	OAuthProviderGeneric   = "generic"
)

// Connect (OAuth broker) defaults and bounds.
const (
	// ConnectCallbackPath is the path of consent.connect.redirectURL.
	ConnectCallbackPath = "/connect/callback"
	// DefaultConnectPendingTTL is how long a pending authorization (and so a
	// JIT request) stays open.
	DefaultConnectPendingTTL = 15 * time.Minute
	MinConnectPendingTTL     = time.Minute
	MaxConnectPendingTTL     = time.Hour
)

// OAuthProviderConfig is one `consent.providers[]` entry: a third-party OAuth
// provider the control plane brokers per-user grants for. It is CP-local like
// the rest of the consent block and never reaches /policy. It carries no
// secret: the client secret is named by ClientSecretEnv (an environment
// variable) or ClientSecretKey (oauth-clients/<id> in consent.store).
// Endpoint defaults for the built-in types are applied by oauthbroker, not
// here, so a field left empty means "the type's default".
type OAuthProviderConfig struct {
	ID              string
	Type            string
	ClientID        string
	ClientSecretEnv string
	ClientSecretKey string
	AuthURL         string
	TokenURL        string
	// RevokeURL may contain the literal {client_id}, substituted with the
	// path-escaped client id.
	RevokeURL   string
	UserinfoURL string
	// AllowedScopes is the operator's cap: no agent, JIT request or portal
	// caller can obtain a scope outside it.
	AllowedScopes []string
	// DefaultScopes is a subset of AllowedScopes used when a request names none.
	DefaultScopes         []string
	ExtraAuthParams       map[string]string
	AllowedAccountDomains []string
	RequireEmailMatch     bool
}

// ConsentConnect is `consent.connect`: the OAuth broker's callback URL and the
// pending-authorization lifetime (also the JIT pending TTL).
type ConsentConnect struct {
	// RedirectURL defaults to the origin of consent.oidc.redirectURL plus
	// /connect/callback.
	RedirectURL string
	PendingTTL  time.Duration
}

type rawOAuthProvider struct {
	ID                    string            `yaml:"id"`
	Type                  string            `yaml:"type"`
	ClientID              string            `yaml:"clientID"`
	ClientSecretEnv       string            `yaml:"clientSecretEnv"`
	ClientSecretKey       string            `yaml:"clientSecretKey"`
	AuthURL               string            `yaml:"authURL"`
	TokenURL              string            `yaml:"tokenURL"`
	RevokeURL             string            `yaml:"revokeURL"`
	UserinfoURL           string            `yaml:"userinfoURL"`
	AllowedScopes         []string          `yaml:"allowedScopes"`
	DefaultScopes         []string          `yaml:"defaultScopes"`
	ExtraAuthParams       map[string]string `yaml:"extraAuthParams"`
	AllowedAccountDomains []string          `yaml:"allowedAccountDomains"`
	RequireEmailMatch     bool              `yaml:"requireEmailMatch"`
}

type rawConsentConnect struct {
	RedirectURL string `yaml:"redirectURL"`
	PendingTTL  string `yaml:"pendingTTL"`
}

func trimAll(in []string) []string {
	var out []string
	for _, s := range in {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

func parseOAuthProviders(in []rawOAuthProvider) []OAuthProviderConfig {
	var out []OAuthProviderConfig
	for _, r := range in {
		p := OAuthProviderConfig{
			ID:                    strings.TrimSpace(r.ID),
			Type:                  strings.TrimSpace(r.Type),
			ClientID:              strings.TrimSpace(r.ClientID),
			ClientSecretEnv:       strings.TrimSpace(r.ClientSecretEnv),
			ClientSecretKey:       strings.TrimSpace(r.ClientSecretKey),
			AuthURL:               strings.TrimSpace(r.AuthURL),
			TokenURL:              strings.TrimSpace(r.TokenURL),
			RevokeURL:             strings.TrimSpace(r.RevokeURL),
			UserinfoURL:           strings.TrimSpace(r.UserinfoURL),
			AllowedScopes:         trimAll(r.AllowedScopes),
			DefaultScopes:         trimAll(r.DefaultScopes),
			AllowedAccountDomains: trimAll(r.AllowedAccountDomains),
			RequireEmailMatch:     r.RequireEmailMatch,
		}
		for i, d := range p.AllowedAccountDomains {
			p.AllowedAccountDomains[i] = strings.ToLower(d)
		}
		if len(r.ExtraAuthParams) > 0 {
			p.ExtraAuthParams = make(map[string]string, len(r.ExtraAuthParams))
			for k, v := range r.ExtraAuthParams {
				p.ExtraAuthParams[strings.TrimSpace(k)] = v
			}
		}
		out = append(out, p)
	}
	return out
}

// parseConsentConnect converts consent.connect and applies the defaults. The
// redirect default is derived from consent.oidc.redirectURL when it parses;
// otherwise it stays empty and validation reports the OIDC redirect.
func parseConsentConnect(r rawConsentConnect, oidcRedirect string) (ConsentConnect, error) {
	c := ConsentConnect{PendingTTL: DefaultConnectPendingTTL, RedirectURL: strings.TrimSpace(r.RedirectURL)}
	if c.RedirectURL == "" {
		if u, err := url.Parse(oidcRedirect); err == nil && u.Scheme != "" && u.Host != "" {
			c.RedirectURL = u.Scheme + "://" + u.Host + ConnectCallbackPath
		}
	}
	if s := strings.TrimSpace(r.PendingTTL); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return ConsentConnect{}, fmt.Errorf("config: consent.connect.pendingTTL %q is not a valid duration: %w", s, err)
		}
		c.PendingTTL = d
	}
	return c, nil
}

// providerIDRE mirrors secrets.ValidProviderID (internal/secrets imports this
// package, so it cannot be called here); a test in internal/secrets/userkey_test.go pins the two.
var providerIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidOAuthProviderID reports whether id is a valid provider id.
func ValidOAuthProviderID(id string) bool { return providerIDRE.MatchString(id) }

// forbiddenExtraAuthParams are authorization-request parameters the broker owns.
var forbiddenExtraAuthParams = map[string]bool{
	"client_id": true, "redirect_uri": true, "response_type": true, "scope": true,
	"state": true, "code_challenge": true, "code_challenge_method": true,
	"nonce": true, "include_granted_scopes": true,
	"request": true, "request_uri": true, "response_mode": true, "claims": true,
}

// ForbiddenExtraAuthParam reports whether name (case-insensitive) may not be set
// through extraAuthParams.
func ForbiddenExtraAuthParam(name string) bool {
	return forbiddenExtraAuthParams[strings.ToLower(strings.TrimSpace(name))]
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validateProviderURL requires an absolute https URL (plain http only for a
// loopback host), with no userinfo or fragment.
func validateProviderURL(field, raw string, noQuery bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("config: %s %q must be an absolute https URL with a host", field, raw)
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("config: %s %q must not carry userinfo or a fragment", field, raw)
	}
	if noQuery && (u.RawQuery != "" || u.ForceQuery) {
		return fmt.Errorf("config: %s %q must not carry a query string (the broker owns the request parameters; use extraAuthParams)", field, raw)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("config: %s %q must be https unless its host is loopback", field, raw)
	}
	return nil
}

func validateProviderScopes(field string, scopes []string) error {
	for i, s := range scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n,") {
			return fmt.Errorf("config: %s[%d] %q must be non-empty with no whitespace or commas", field, i, s)
		}
	}
	return nil
}

func validateOAuthProvider(i int, p OAuthProviderConfig) error {
	f := func(k string) string { return fmt.Sprintf("consent.providers[%d].%s", i, k) }
	if !ValidOAuthProviderID(p.ID) {
		return fmt.Errorf("config: %s %q must match ^[a-z][a-z0-9-]{0,31}$", f("id"), p.ID)
	}
	switch p.Type {
	case OAuthProviderGoogle, OAuthProviderGitHub, OAuthProviderGitHubApp, OAuthProviderGeneric:
	default:
		return fmt.Errorf("config: %s %q is invalid; must be one of: google, github, githubApp, generic", f("type"), p.Type)
	}
	if p.ClientID == "" {
		return fmt.Errorf("config: %s is required", f("clientID"))
	}
	switch {
	case p.ClientSecretEnv != "" && p.ClientSecretKey != "":
		return fmt.Errorf("config: %s and %s are mutually exclusive", f("clientSecretEnv"), f("clientSecretKey"))
	case p.ClientSecretEnv == "" && p.ClientSecretKey == "":
		return fmt.Errorf("config: exactly one of %s or %s is required", f("clientSecretEnv"), f("clientSecretKey"))
	}
	if p.ClientSecretEnv != "" && !envNameRE.MatchString(p.ClientSecretEnv) {
		return fmt.Errorf("config: %s %q is not a valid environment variable name", f("clientSecretEnv"), p.ClientSecretEnv)
	}
	if want := ReservedClientSecretNamespace + "/" + p.ID; p.ClientSecretKey != "" && p.ClientSecretKey != want {
		return fmt.Errorf("config: %s %q must equal %q", f("clientSecretKey"), p.ClientSecretKey, want)
	}
	if p.Type == OAuthProviderGeneric {
		if p.AuthURL == "" {
			return fmt.Errorf("config: %s is required for a generic provider", f("authURL"))
		}
		if p.TokenURL == "" {
			return fmt.Errorf("config: %s is required for a generic provider", f("tokenURL"))
		}
	}
	for _, u := range []struct{ k, v string }{
		{"authURL", p.AuthURL}, {"tokenURL", p.TokenURL}, {"revokeURL", p.RevokeURL}, {"userinfoURL", p.UserinfoURL},
	} {
		if u.v == "" {
			continue
		}
		v := strings.ReplaceAll(u.v, "{client_id}", "client")
		if err := validateProviderURL(f(u.k), v, u.k == "authURL" || u.k == "tokenURL"); err != nil {
			return err
		}
	}
	if (p.Type == OAuthProviderGitHub || p.Type == OAuthProviderGitHubApp) && p.RevokeURL != "" {
		if ru, err := url.Parse(p.RevokeURL); err != nil || !strings.HasSuffix(ru.Path, "/applications/{client_id}/grant") {
			return fmt.Errorf("config: %s must end in /applications/{client_id}/grant for a github provider", f("revokeURL"))
		}
	}
	if (p.Type == OAuthProviderGitHub || p.Type == OAuthProviderGitHubApp) && p.RevokeURL == "" {
		// The built-in revoke URL is api.github.com; against a GitHub
		// Enterprise Server it would answer 404 and leave the token live.
		for _, u := range []struct{ k, v string }{{"authURL", p.AuthURL}, {"tokenURL", p.TokenURL}} {
			if u.v == "" {
				continue
			}
			if pu, err := url.Parse(u.v); err != nil || !strings.EqualFold(pu.Hostname(), "github.com") {
				return fmt.Errorf("config: %s is required: revokeURL is required for GitHub Enterprise (%s is not on github.com)", f("revokeURL"), f(u.k))
			}
		}
	}
	if p.Type == OAuthProviderGitHubApp && len(p.AllowedScopes) > 0 {
		return fmt.Errorf("config: %s must be empty for a githubApp provider (permissions come from the app)", f("allowedScopes"))
	}
	if err := validateProviderScopes(f("allowedScopes"), p.AllowedScopes); err != nil {
		return err
	}
	if err := validateProviderScopes(f("defaultScopes"), p.DefaultScopes); err != nil {
		return err
	}
	allowed := make(map[string]bool, len(p.AllowedScopes))
	for _, s := range p.AllowedScopes {
		allowed[s] = true
	}
	for i2, s := range p.DefaultScopes {
		if !allowed[s] {
			return fmt.Errorf("config: %s[%d] %q must be one of allowedScopes", f("defaultScopes"), i2, s)
		}
	}
	for k := range p.ExtraAuthParams {
		if k == "" || strings.ContainsAny(k, " \t\r\n") {
			return fmt.Errorf("config: %s has an empty or whitespace key", f("extraAuthParams"))
		}
		if ForbiddenExtraAuthParam(k) {
			return fmt.Errorf("config: %s.%s is set by the broker and may not be overridden", f("extraAuthParams"), k)
		}
	}
	for j, d := range p.AllowedAccountDomains {
		if !domainRE.MatchString(d) {
			return fmt.Errorf("config: %s[%d] %q must be a bare domain such as example.com", f("allowedAccountDomains"), j, d)
		}
	}
	return nil
}

// ValidateOAuthProviders applies the per-provider and uniqueness rules. The
// oauthbroker registry calls it too, so a registry built from a hand-made list
// is held to the same rules as one loaded from YAML.
func ValidateOAuthProviders(ps []OAuthProviderConfig) error {
	seen := map[string]bool{}
	for i, p := range ps {
		if err := validateOAuthProvider(i, p); err != nil {
			return err
		}
		if seen[p.ID] {
			return fmt.Errorf("config: consent.providers[%d].id %q is a duplicate", i, p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

// validateConsentProviders checks consent.providers and consent.connect of an
// enabled block. redirectURL (consent.oidc.redirectURL) has been validated
// already.
func validateConsentProviders(c ConsentConfig) error {
	if err := ValidateOAuthProviders(c.Providers); err != nil {
		return err
	}
	if t := c.Connect.PendingTTL; t < MinConnectPendingTTL || t > MaxConnectPendingTTL {
		return fmt.Errorf("config: consent.connect.pendingTTL (%s) must be between %s and %s", t, MinConnectPendingTTL, MaxConnectPendingTTL)
	}
	if len(c.Providers) == 0 && c.Connect.RedirectURL == "" {
		return nil
	}
	raw := c.Connect.RedirectURL
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("config: consent.connect.redirectURL %q must be an absolute http(s) URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("config: consent.connect.redirectURL %q must not carry userinfo, query or fragment", raw)
	}
	if u.Path != ConnectCallbackPath {
		return fmt.Errorf("config: consent.connect.redirectURL %q must have the path exactly %s", raw, ConnectCallbackPath)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("config: consent.connect.redirectURL %q must be https unless its host is loopback", raw)
	}
	if o, err := url.Parse(c.OIDC.RedirectURL); err == nil && (u.Scheme != o.Scheme || !strings.EqualFold(u.Host, o.Host)) {
		return fmt.Errorf("config: consent.connect.redirectURL %q must have the same origin as consent.oidc.redirectURL (the callback needs the portal session cookie)", raw)
	}
	return nil
}
