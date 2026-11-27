package harness

import (
	"context"
	"fmt"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
)

// Per-user secrets on a Vault consent.store (W-P3-PUS-02): the control plane
// boots with consent enabled, consent.store on a fake Vault KV v2 server
// (fakes.FakeVaultKV), the google provider in consent.providers and the
// perUserSecrets block enabled with one mapping. The CP reads the Vault token
// from its environment only and probes the KV v2 mount before it serves, so a
// scenario can break the fake (KV v1, a 404) and see the restart refused.

const (
	// PerUserPlaceholder, PerUserProvider and PerUserAgent are the one mapping
	// the harness enables: GOOGLE_USER for google, bound to support-bot.
	PerUserPlaceholder = "GOOGLE_USER"
	PerUserProvider    = "google"
	PerUserAgent       = "support-bot"
	// PerUserDomain is the mapping's only destination.
	PerUserDomain = "gmail.googleapis.com"
	// ConsentVaultNamespace is consent.store.vault.namespace.
	ConsentVaultNamespace = "warden-harness"
	// ConsentVaultMount is consent.store.vault.mount (the fake's KV v2 mount).
	ConsentVaultMount = "secret"

	consentVaultTokenEnv   = "WARDEN_HARNESS_CONSENT_VAULT_TOKEN"
	consentPortalSecretEnv = "WARDEN_HARNESS_PORTAL_SECRET"
	consentGoogleSecretEnv = "WARDEN_HARNESS_GOOGLE_CLIENT_SECRET"
	// consentVaultToken is only ever in the CP environment and the fake.
	consentVaultToken = "hvs.harness-consent-store-token-91b2e7"
)

// WithPerUserSecretsVault boots the control plane with perUserSecrets enabled
// over a Vault KV v2 consent.store. It implies everything the feature needs:
// WithConsoleOIDC (consent needs console.auth oidc), WithIdentity("attribute")
// unless another mode is set (consent.oidc.issuer must equal identity.issuer),
// WithTokenService, and WithBundles(offer) unless a bundle mode is set.
// In-process only.
func WithPerUserSecretsVault() Option {
	return func(h *H) {
		h.wantPerUserVault = true
		h.wantIssuer = true
		h.wantConsole = true
		if h.identityMode == "" {
			h.identityMode = "attribute"
		}
		h.wantKeys = true
		h.wantTokenSvc = true
		if !h.bundleModeSet {
			h.bundleMode = controlplane.BundlesOffer
			h.bundleModeSet = true
			h.versionedPolicy = true
		}
	}
}

// preparePerUserVault starts the fake Vault and puts the token and the OAuth
// client secrets in the environment the control plane reads them from.
func (h *H) preparePerUserVault() {
	if h.suppliedTarget != nil {
		h.tb.Fatal("harness: WithPerUserSecretsVault boots an in-process control plane; it cannot combine with WithTarget")
	}
	h.consentVault = fakes.NewFakeVaultKV(h.tb, consentVaultToken)
	h.tb.Setenv(consentVaultTokenEnv, consentVaultToken)
	h.tb.Setenv(consentPortalSecretEnv, "harness-portal-client-secret")
	h.tb.Setenv(consentGoogleSecretEnv, "harness-google-client-secret")
}

// ConsentVault is the fake Vault behind consent.store (WithPerUserSecretsVault).
func (h *H) ConsentVault() *fakes.FakeVaultKV {
	h.tb.Helper()
	if h.consentVault == nil {
		h.tb.Fatal("harness: ConsentVault needs the WithPerUserSecretsVault option")
	}
	return h.consentVault
}

// ConsentVaultToken is the token the control plane reads from its
// environment; a scenario uses it only to prove it never leaks.
func (h *H) ConsentVaultToken() string { return consentVaultToken }

// perUserVaultYAML renders the consent block (with the vault consent.store and
// the google provider) and the perUserSecrets block.
func (h *H) perUserVaultYAML() string {
	if !h.wantPerUserVault {
		return ""
	}
	return fmt.Sprintf(`
consent:
  enabled: true
  oidc:
    issuer: %[1]s
    internalIssuerURL: %[1]s
    clientSecretEnv: %[2]s
    redirectURL: %[3]s
  store:
    backend: vault
    vault:
      addr: %[4]s
      mount: %[5]s
      namespace: %[6]s
      tokenEnv: %[7]s
  providers:
    - id: %[8]s
      type: google
      clientID: harness-google-client
      clientSecretEnv: %[9]s

perUserSecrets:
  enabled: true
  mappings:
    - placeholder: %[10]s
      provider: %[8]s
      scopes: [https://www.googleapis.com/auth/gmail.readonly]
      domains: [%[11]s]
      agents: [%[12]s]
`, h.issuer.Issuer(), consentPortalSecretEnv, h.ConsoleURL()+"/portal/callback",
		h.consentVault.URL(), ConsentVaultMount, ConsentVaultNamespace, consentVaultTokenEnv,
		PerUserProvider, consentGoogleSecretEnv, PerUserPlaceholder, PerUserDomain, PerUserAgent)
}

// TryStart is Start returning the boot error instead of failing the test, so
// a scenario can assert that the control plane refuses to come back.
func (c *CPClient) TryStart() error {
	c.h.tb.Helper()
	return c.h.target.StartControlPlane(context.Background())
}
