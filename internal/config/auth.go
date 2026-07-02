package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Auth transform type identifiers. Each corresponds to a concrete
// auth.RequestTransformer implementation.
const (
	AuthOAuth2ClientCredentials = "oauth2_client_credentials"
	AuthAWSSigV4                = "aws_sigv4"
	AuthHMAC                    = "hmac"
	AuthAPIKey                  = "api_key"
)

// AuthEntry maps a destination pattern to a request-authentication transform.
// Match uses the same syntax as the policy engine (exact / *.wildcard / ~regex).
// Credential-bearing fields support ${ENV_VAR} expansion, resolved at build time
// so secrets live in the environment, never in the config file or in logs.
type AuthEntry struct {
	Match string
	Type  string

	// oauth2_client_credentials
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string

	// aws_sigv4
	Region          string
	Service         string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// hmac
	Algorithm string // sha256 | sha512 | sha1
	Secret    string
	Header    string

	// api_key
	Location string // header | basic_auth
	Name     string
	Value    string
}

// rawAuthEntry mirrors one on-disk `auth:` list item. All credential fields are
// strings so ${ENV} placeholders survive parsing and are expanded at build time.
type rawAuthEntry struct {
	Match           string   `yaml:"match"`
	Type            string   `yaml:"type"`
	TokenURL        string   `yaml:"tokenURL"`
	ClientID        string   `yaml:"clientID"`
	ClientSecret    string   `yaml:"clientSecret"`
	Scopes          []string `yaml:"scopes"`
	Region          string   `yaml:"region"`
	Service         string   `yaml:"service"`
	AccessKeyID     string   `yaml:"accessKeyID"`
	SecretAccessKey string   `yaml:"secretAccessKey"`
	SessionToken    string   `yaml:"sessionToken"`
	Algorithm       string   `yaml:"algorithm"`
	Secret          string   `yaml:"secret"`
	Header          string   `yaml:"header"`
	Location        string   `yaml:"location"`
	Name            string   `yaml:"name"`
	Value           string   `yaml:"value"`
}

// parseAuth converts the raw auth list into typed AuthEntry values. Defaults are
// applied at build time (run.go); here we only normalize the type string.
func parseAuth(raw []rawAuthEntry) []AuthEntry {
	if len(raw) == 0 {
		return nil
	}
	out := make([]AuthEntry, 0, len(raw))
	for _, r := range raw {
		out = append(out, AuthEntry{
			Match:           r.Match,
			Type:            strings.ToLower(strings.TrimSpace(r.Type)),
			TokenURL:        r.TokenURL,
			ClientID:        r.ClientID,
			ClientSecret:    r.ClientSecret,
			Scopes:          append([]string(nil), r.Scopes...),
			Region:          r.Region,
			Service:         r.Service,
			AccessKeyID:     r.AccessKeyID,
			SecretAccessKey: r.SecretAccessKey,
			SessionToken:    r.SessionToken,
			Algorithm:       strings.ToLower(strings.TrimSpace(r.Algorithm)),
			Secret:          r.Secret,
			Header:          r.Header,
			Location:        strings.ToLower(strings.TrimSpace(r.Location)),
			Name:            r.Name,
			Value:           r.Value,
		})
	}
	return out
}

// validateMatchPattern checks an auth `match` uses the same syntax the policy
// engine accepts: exact host, "*.suffix" wildcard, or "~regex".
func validateMatchPattern(ctx, pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("config: %s: match is required", ctx)
	}
	if strings.HasPrefix(pattern, "~") {
		if _, err := regexp.Compile(pattern[1:]); err != nil {
			return fmt.Errorf("config: %s: match %q has invalid regex: %v", ctx, pattern, err)
		}
		return nil
	}
	if strings.Contains(pattern, "*") {
		if !strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1 {
			return fmt.Errorf("config: %s: match %q has invalid wildcard; only \"*.suffix\" is supported", ctx, pattern)
		}
	}
	return nil
}

// validateAuth enforces structural requirements per transform type. Credential
// values may be ${ENV} placeholders (resolved at build time), so presence — not
// the resolved secret — is what is checked here.
func validateAuth(entries []AuthEntry) error {
	for i, e := range entries {
		ctx := fmt.Sprintf("auth[%d]", i)
		if err := validateMatchPattern(ctx, e.Match); err != nil {
			return err
		}
		switch e.Type {
		case AuthOAuth2ClientCredentials:
			if e.TokenURL == "" || e.ClientID == "" || e.ClientSecret == "" {
				return fmt.Errorf("config: %s: type %s requires tokenURL, clientID, and clientSecret", ctx, e.Type)
			}
		case AuthAWSSigV4:
			if e.Region == "" || e.AccessKeyID == "" || e.SecretAccessKey == "" {
				return fmt.Errorf("config: %s: type %s requires region, accessKeyID, and secretAccessKey", ctx, e.Type)
			}
		case AuthHMAC:
			switch e.Algorithm {
			case "sha256", "sha512", "sha1":
			default:
				return fmt.Errorf("config: %s: hmac algorithm %q is invalid; must be sha256, sha512, or sha1", ctx, e.Algorithm)
			}
			if e.Secret == "" || e.Header == "" {
				return fmt.Errorf("config: %s: type %s requires secret and header", ctx, e.Type)
			}
		case AuthAPIKey:
			switch e.Location {
			case "header", "basic_auth":
			default:
				return fmt.Errorf("config: %s: api_key location %q is invalid; must be header or basic_auth", ctx, e.Location)
			}
			if e.Name == "" || e.Value == "" {
				return fmt.Errorf("config: %s: type %s requires name and value", ctx, e.Type)
			}
		case "":
			return fmt.Errorf("config: %s: type is required", ctx)
		default:
			return fmt.Errorf("config: %s: unknown type %q; must be one of: %s, %s, %s, %s", ctx, e.Type,
				AuthOAuth2ClientCredentials, AuthAWSSigV4, AuthHMAC, AuthAPIKey)
		}
	}
	return nil
}
