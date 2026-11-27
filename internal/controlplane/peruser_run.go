package controlplane

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// checkPerUserSecretsStartup refuses to start with perUserSecrets.enabled
// unless everything a per-user swap depends on is configured (W-P3-PUS-02).
// Each error names the missing key:
//   - consent.store, configured (consent.enabled) and persistent: grants live
//     only in the CP-only user credential store, never in the distributed
//     secretStore, and a store that keeps no value would lose every grant;
//   - tokenService.enabled: only a bound Warden token can release a user's
//     credential, so without the token service no request could ever qualify;
//   - --bundles offer or require: the mappings and the revocation epochs reach
//     workers only as signed-bundle sections (W-P3-PUS-08);
//   - every mapping's provider in consent.providers (the oauthbroker registry,
//     W-P3-BRKR-01), the only providers a user can connect a grant for.
//
// A disabled or absent block passes and is not inspected.
func checkPerUserSecretsStartup(pus config.PerUserSecretsConfig, consent *config.ConsentConfig, userStore secrets.SecretStore, tokenServiceEnabled bool, bundles BundlesConfig) error {
	if !pus.Enabled {
		return nil
	}
	switch {
	case consent == nil:
		return fmt.Errorf("control-plane: perUserSecrets.enabled requires consent.store (grants live only in the CP-only user credential store), but consent.enabled is false or the consent block is absent")
	case consent.Store == nil:
		return fmt.Errorf("control-plane: perUserSecrets.enabled requires consent.store (grants live only in the CP-only user credential store), but consent.store is not configured; configure it with backend aws or vault")
	case userStore == nil || !secrets.IsPersistent(userStore):
		return fmt.Errorf("control-plane: perUserSecrets.enabled requires a persistent consent.store, but consent.store.backend %s keeps no value; use aws or vault", consent.Store.Backend)
	}
	if !tokenServiceEnabled {
		return fmt.Errorf("control-plane: perUserSecrets.enabled requires tokenService.enabled (only a bound Warden token can release a user's credential)")
	}
	if !bundles.On() {
		return fmt.Errorf("control-plane: perUserSecrets.enabled requires --bundles offer or require (the per-user mappings and revocations reach workers only in the signed bundle), but --bundles resolved to %s", bundles.Mode)
	}
	known := make(map[string]bool, len(consent.Providers))
	ids := make([]string, 0, len(consent.Providers))
	for _, p := range consent.Providers {
		known[p.ID] = true
		ids = append(ids, p.ID)
	}
	for i, m := range pus.Mappings {
		if !known[m.Provider] {
			have := strings.Join(ids, ", ")
			if have == "" {
				have = "none"
			}
			return fmt.Errorf("control-plane: perUserSecrets.mappings[%d].provider %q is not in consent.providers (configured: %s)", i, m.Provider, have)
		}
	}
	return nil
}

// logPerUserSecrets logs the feature's state once at startup: whether it is
// on and how many mappings it serves (no placeholder, scope or domain).
func logPerUserSecrets(logger *slog.Logger, pus config.PerUserSecretsConfig) {
	if !pus.Enabled {
		return
	}
	logger.Info("control plane per-user secrets enabled",
		"mappings", len(pus.Mappings), "workerCacheTTL", pus.WorkerCacheTTL.String())
}
