package controlplane

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// resolveConsent loads the consent block from configPath (the operator-owned
// --config file, never the served copy) and checks what the portal needs at
// startup. It returns nil when the block is absent or enabled is false, so
// nothing about the portal exists on that path. When enabled it requires
// console.auth oidc (an open console could edit the policy, scope caps and
// secret mappings the portal trusts; there is no dev or demo bypass), a
// --state-dir, a non-empty client-secret env var, and consent.oidc.issuer equal
// to identity.issuer (otherwise a portal sub never matches a data-plane sub).
// Error and log text name the env var, never its value. A served copy holding a
// different consent block is ignored with a warning.
func resolveConsent(logger *slog.Logger, configPath, servedPath, stateDir string, console config.ConsoleConfig, identityIssuer string, getenv func(string) string) (*config.ConsentConfig, error) {
	cc, err := config.LoadConsent(configPath)
	if err != nil {
		return nil, fmt.Errorf("control-plane: %w", err)
	}
	if stateDir != "" && servedPath != configPath {
		served, serr := config.LoadConsent(servedPath)
		if serr != nil || !reflect.DeepEqual(served, cc) {
			logger.Warn("control-plane: the served config copy holds a different consent block; ignoring it and using --config",
				"served", servedPath, "config", configPath)
		}
	}
	if !cc.Enabled {
		return nil, nil
	}
	if console.Auth != config.ConsoleAuthOIDC {
		return nil, errors.New("control-plane: consent.enabled requires console.auth oidc (an open console could edit the policy and secret mappings the portal trusts)")
	}
	if stateDir == "" {
		return nil, errors.New("control-plane: consent.enabled requires --state-dir (portal sessions and IdP links are stored in its database)")
	}
	if strings.TrimSpace(getenv(cc.OIDC.ClientSecretEnv)) == "" {
		return nil, fmt.Errorf("control-plane: consent.enabled but environment variable %s (consent.oidc.clientSecretEnv) is empty", cc.OIDC.ClientSecretEnv)
	}
	if strings.TrimSpace(identityIssuer) == "" {
		return nil, errors.New("control-plane: consent.enabled requires identity.issuer, which must equal consent.oidc.issuer")
	}
	if !sameIssuer(identityIssuer, cc.OIDC.Issuer) {
		return nil, fmt.Errorf("control-plane: consent.oidc.issuer %q must equal identity.issuer %q (a portal sub would never match a data-plane sub)", cc.OIDC.Issuer, identityIssuer)
	}
	if u, perr := url.Parse(cc.OIDC.Issuer); perr == nil && u.Scheme == "http" && cc.OIDC.InternalIssuerURL != "" {
		logger.Warn("control-plane: consent oidc is using a plain-http issuer via internalIssuerURL; this is the development profile, use an https issuer in production",
			"issuer", cc.OIDC.Issuer, "internalIssuerURL", cc.OIDC.InternalIssuerURL)
	}
	return &cc, nil
}

// checkConsentIssuer refuses identity settings whose issuer differs from
// consent.oidc.issuer while consent is enabled. resolveConsent checks the file
// at startup; this covers identity.issuer changing at runtime (settings writes,
// versioned publishes, rollbacks). A nil identity block leaves the issuer
// untouched and passes. It is a no-op while consent is off. The error text
// leads with the 400 code identity_issuer_mismatch.
func (s *Server) checkConsentIssuer(id *config.IdentitySettings) error {
	if id == nil || s.cfg.Consent == nil || sameIssuer(s.cfg.Consent.OIDC.Issuer, id.Issuer) {
		return nil
	}
	return &dashboard.InvalidPolicyError{Err: fmt.Errorf("identity_issuer_mismatch: identity.issuer %q must equal consent.oidc.issuer %q while consent is enabled", id.Issuer, s.cfg.Consent.OIDC.Issuer)}
}
