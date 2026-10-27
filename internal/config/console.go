package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Console auth modes. An absent `console:` block means ConsoleAuthNone, which
// keeps today's behaviour byte-for-byte.
const (
	// ConsoleAuthNone leaves the console as it is today: reads are open and every
	// dashboard write is gated by the CP admin bearer.
	ConsoleAuthNone = "none"
	// ConsoleAuthOIDC replaces the bearer with server-side sessions behind an
	// OIDC login.
	ConsoleAuthOIDC = "oidc"
)

// Console defaults. Idle 1h / Absolute 12h are the decided values (not 8h/24h);
// the client id is the reference console client of the dev identity profile.
const (
	DefaultConsoleClientID = "warden-console"
	DefaultConsoleIdle     = time.Hour
	DefaultConsoleAbsolute = 12 * time.Hour
	// MaxConsoleSession bounds both session lifetimes.
	MaxConsoleSession = 168 * time.Hour

	consoleCallbackSuffix = "/auth/callback"
)

// DefaultConsoleScopes are requested when console.oidc.scopes is unset.
// offline_access is deliberately absent: no refresh token is ever wanted.
func DefaultConsoleScopes() []string {
	return []string{"openid", "email", "profile", "groups"}
}

// Role is a console authorization level. The zero value is "no role"; the
// ordering RoleViewer < RoleEditor < RoleAdmin is what lets "highest wins" and
// "at least editor" checks be plain comparisons.
type Role int

const (
	RoleViewer Role = iota + 1
	RoleEditor
	RoleAdmin
)

// String returns the role name used in logs and APIs.
func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleEditor:
		return "editor"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ConsoleConfig is the control-plane-local `console:` block: how humans sign in
// to the dashboard. It is read by the control plane only, from the
// operator-owned --config file (Policy tags it json:"-", so it never reaches a
// worker, the dashboard's settings wire, or the writable --state-dir copy's
// editors). It holds an env-var NAME for the client secret, never the value.
type ConsoleConfig struct {
	// Auth is "none" (default) or "oidc".
	Auth    string
	OIDC    ConsoleOIDC
	Roles   ConsoleRoles
	Session ConsoleSession
	// AdminAudit gates the signed admin audit chain (default off).
	AdminAudit ConsoleAdminAudit
}

// ConsoleAdminAudit is the `console.adminAudit` sub-block. Enabled (default
// false) turns on the signed, hash-chained admin audit log in
// <state-dir>/warden-cp.db; it needs --state-dir. Off means no key file, no
// HMAC key file and no audit rows are ever created.
type ConsoleAdminAudit struct {
	Enabled bool
}

// ConsoleOIDC is the console's OIDC client registration.
type ConsoleOIDC struct {
	Issuer string
	// ClientID defaults to warden-console.
	ClientID string
	// ClientSecretEnv names the environment variable holding the client secret.
	ClientSecretEnv string
	// RedirectURL is the absolute callback URL registered with the IdP; it ends
	// in /auth/callback.
	RedirectURL string
	// Scopes default to openid, email, profile, groups.
	Scopes []string
	// InternalIssuerURL is the origin the CP container uses to reach the IdP
	// (for example http://idp:5556) when it differs from Issuer. It is what
	// permits a plain-http Issuer in development; there is no insecure-issuer key.
	InternalIssuerURL string
}

// ConsoleRoles maps IdP group names onto roles. Matching is exact and
// case-sensitive.
type ConsoleRoles struct {
	Admin, Editor, Viewer []string
}

// ConsoleSession bounds a console session: Idle since last use, Absolute since
// login.
type ConsoleSession struct {
	Idle, Absolute time.Duration
}

// RoleFor returns the highest role granted by any of groups, and false when none
// matches. It is pure: exact, case-sensitive comparison, no normalisation.
func (c ConsoleConfig) RoleFor(groups []string) (Role, bool) {
	var best Role
	for _, g := range groups {
		switch {
		case containsString(c.Roles.Admin, g):
			return RoleAdmin, true
		case containsString(c.Roles.Editor, g):
			best = max(best, RoleEditor)
		case containsString(c.Roles.Viewer, g):
			best = max(best, RoleViewer)
		}
	}
	return best, best != 0
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// rawConsole mirrors the on-disk `console:` block. Pointer-free leaves keep the
// strict KnownFields(true) decode honest: a removed or misspelled key (for
// example a former insecure-issuer toggle) fails to parse.
type rawConsole struct {
	Auth string `yaml:"auth"`
	OIDC struct {
		Issuer            string   `yaml:"issuer"`
		ClientID          string   `yaml:"clientID"`
		ClientSecretEnv   string   `yaml:"clientSecretEnv"`
		RedirectURL       string   `yaml:"redirectURL"`
		Scopes            []string `yaml:"scopes"`
		InternalIssuerURL string   `yaml:"internalIssuerURL"`
	} `yaml:"oidc"`
	Roles struct {
		Admin  []string `yaml:"admin"`
		Editor []string `yaml:"editor"`
		Viewer []string `yaml:"viewer"`
	} `yaml:"roles"`
	Session struct {
		Idle     string `yaml:"idle"`
		Absolute string `yaml:"absolute"`
	} `yaml:"session"`
	AdminAudit struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"adminAudit"`
}

// parseConsole converts the raw block and applies defaults. An absent block is
// Auth=none with the defaults filled in, so it is byte-identical to before.
func parseConsole(r *rawConsole) (ConsoleConfig, error) {
	c := ConsoleConfig{
		Auth: ConsoleAuthNone,
		OIDC: ConsoleOIDC{ClientID: DefaultConsoleClientID, Scopes: DefaultConsoleScopes()},
		Session: ConsoleSession{
			Idle: DefaultConsoleIdle, Absolute: DefaultConsoleAbsolute,
		},
	}
	if r == nil {
		return c, nil
	}
	if a := strings.TrimSpace(r.Auth); a != "" {
		c.Auth = a
	}
	o := r.OIDC
	c.OIDC.Issuer = strings.TrimSpace(o.Issuer)
	if id := strings.TrimSpace(o.ClientID); id != "" {
		c.OIDC.ClientID = id
	}
	c.OIDC.ClientSecretEnv = strings.TrimSpace(o.ClientSecretEnv)
	c.OIDC.RedirectURL = strings.TrimSpace(o.RedirectURL)
	if len(o.Scopes) > 0 {
		c.OIDC.Scopes = append([]string(nil), o.Scopes...)
	}
	c.OIDC.InternalIssuerURL = strings.TrimSpace(o.InternalIssuerURL)
	c.Roles = ConsoleRoles{Admin: r.Roles.Admin, Editor: r.Roles.Editor, Viewer: r.Roles.Viewer}
	if s := strings.TrimSpace(r.Session.Idle); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return ConsoleConfig{}, fmt.Errorf("config: console.session.idle %q is not a valid duration: %w", s, err)
		}
		c.Session.Idle = d
	}
	if s := strings.TrimSpace(r.Session.Absolute); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return ConsoleConfig{}, fmt.Errorf("config: console.session.absolute %q is not a valid duration: %w", s, err)
		}
		c.Session.Absolute = d
	}
	c.AdminAudit.Enabled = r.AdminAudit.Enabled
	return c, nil
}

// validateConsole enforces the console block's invariants at startup. The oidc
// rules apply only when Auth is oidc; the auth value itself is always checked.
func validateConsole(c ConsoleConfig) error {
	switch c.Auth {
	case "", ConsoleAuthNone:
		return nil
	case ConsoleAuthOIDC:
	default:
		return fmt.Errorf("config: console.auth %q is invalid (want %q or %q)", c.Auth, ConsoleAuthNone, ConsoleAuthOIDC)
	}
	o := c.OIDC
	if o.Issuer == "" {
		return fmt.Errorf("config: console.oidc.issuer is required when console.auth is oidc")
	}
	if o.ClientSecretEnv == "" {
		return fmt.Errorf("config: console.oidc.clientSecretEnv is required when console.auth is oidc")
	}
	if o.RedirectURL == "" {
		return fmt.Errorf("config: console.oidc.redirectURL is required when console.auth is oidc")
	}
	if o.ClientID == "" {
		return fmt.Errorf("config: console.oidc.clientID must not be empty")
	}
	if !containsString(o.Scopes, "openid") {
		return fmt.Errorf("config: console.oidc.scopes must include openid")
	}
	if err := validateConsoleIssuer(o); err != nil {
		return err
	}
	if err := validateConsoleRedirect(o.RedirectURL); err != nil {
		return err
	}
	if len(c.Roles.Admin) == 0 {
		return fmt.Errorf("config: console.roles.admin needs at least one group when console.auth is oidc")
	}
	for role, groups := range map[string][]string{"admin": c.Roles.Admin, "editor": c.Roles.Editor, "viewer": c.Roles.Viewer} {
		for _, g := range groups {
			if g == "" {
				return fmt.Errorf("config: console.roles.%s must not contain an empty group name", role)
			}
		}
	}
	s := c.Session
	if s.Idle <= 0 || s.Absolute <= 0 || s.Idle > s.Absolute || s.Absolute > MaxConsoleSession {
		return fmt.Errorf("config: console.session needs 0 < idle (%s) <= absolute (%s) <= %s", s.Idle, s.Absolute, MaxConsoleSession)
	}
	return nil
}

// validateConsoleIssuer applies the http-issuer rule of the shared OIDC client
// (https always passes; plain http only with an internal issuer URL) without
// importing internal/identity.
func validateConsoleIssuer(o ConsoleOIDC) error {
	if o.InternalIssuerURL != "" {
		u, err := url.Parse(o.InternalIssuerURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: console.oidc.internalIssuerURL %q must be an absolute http or https URL", o.InternalIssuerURL)
		}
		if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("config: console.oidc.internalIssuerURL %q must be an origin only (no path, userinfo, query or fragment)", o.InternalIssuerURL)
		}
	}
	iss, err := url.Parse(o.Issuer)
	if err != nil || iss.Host == "" {
		return fmt.Errorf("config: console.oidc.issuer %q must be an absolute https URL", o.Issuer)
	}
	switch iss.Scheme {
	case "https":
	case "http":
		if o.InternalIssuerURL == "" {
			return fmt.Errorf("config: console.oidc.issuer %q is plain http; use https, or set console.oidc.internalIssuerURL for a development split-horizon issuer", o.Issuer)
		}
	default:
		return fmt.Errorf("config: console.oidc.issuer %q must use https", o.Issuer)
	}
	return nil
}

// validateConsoleRedirect requires an absolute callback URL ending in
// /auth/callback, over https unless the host is loopback.
func validateConsoleRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("config: console.oidc.redirectURL %q must be an absolute http(s) URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("config: console.oidc.redirectURL %q must not carry userinfo, query or fragment", raw)
	}
	if !strings.HasSuffix(u.Path, consoleCallbackSuffix) {
		return fmt.Errorf("config: console.oidc.redirectURL %q must end in %s", raw, consoleCallbackSuffix)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("config: console.oidc.redirectURL %q must be https unless its host is loopback", raw)
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// LoadConsole reads only the `console:` block of the YAML file at path, with the
// same strict decoder and validation as a full config load. The control plane
// calls it on the operator-owned --config file (never the served copy).
func LoadConsole(path string) (ConsoleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ConsoleConfig{}, fmt.Errorf("config: read %q: %w", path, err)
	}
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return ConsoleConfig{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	c, err := parseConsole(raw.Console)
	if err != nil {
		return ConsoleConfig{}, err
	}
	if err := validateConsole(c); err != nil {
		return ConsoleConfig{}, err
	}
	return c, nil
}
