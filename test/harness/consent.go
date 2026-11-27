package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/fakes"
)

// The consent portal sign-in (W-P3-CSIG-02): the control plane boots with a
// CP-local consent block whose OIDC client is the issuer fake's warden-portal
// registration, and a scenario plays the browser through /portal/login, the
// issuer and /portal/callback.

const (
	// PortalClientID is the OIDC client the portal registers as.
	PortalClientID = "warden-portal"

	portalSecretEnv   = "WARDEN_HARNESS_PORTAL_SECRET"
	portalSecretValue = "harness-portal-client-secret"
)

// WithConsent boots the control plane with consent.enabled: true. It implies
// WithConsoleOIDC (consent needs console.auth oidc and a state dir) and, unless
// WithIdentity already chose a mode, an identity block in attribute mode, since
// consent.oidc.issuer must equal identity.issuer. The portal's redirect URL is
// the control plane's https origin + /portal/callback, so its cookies are the
// __Host- ones. The IdP link is on (the default): the issuer fake must return a
// refresh token (h.Issuer().SetRefreshToken) for a login to succeed, and
// consent.store is an aws backend with the default warden-cp/ prefix over an
// in-memory account (h.UserStoreAWS), so the link is persisted (W-P3-CSIG-03).
func WithConsent() Option {
	return func(h *H) {
		h.wantIssuer = true
		h.wantConsole = true
		h.wantConsent = true
		if h.identityMode == "" {
			h.identityMode = "attribute"
		}
	}
}

// prepareConsent sets the portal client secret and registers the client on
// the issuer fake. Called from prepareConsole.
func (h *H) prepareConsent() {
	if !h.wantConsent {
		return
	}
	h.userStoreAWS = fakes.NewFakeAWSSecretsClient()
	h.tb.Setenv(portalSecretEnv, portalSecretValue)
	h.issuer.RegisterClient(PortalClientID, portalSecretValue)
}

// consentYAML renders the consent block for the control plane's config file.
func (h *H) consentYAML() string {
	// WithPerUserSecretsVault renders the one consent block (vault store plus
	// providers) in perUserVaultYAML; a second block would be a duplicate key.
	if !h.wantConsent || h.wantPerUserVault {
		return ""
	}
	return fmt.Sprintf(`
consent:
  enabled: true
  oidc:
    issuer: %[1]s
    internalIssuerURL: %[1]s
    clientID: %[2]s
    clientSecretEnv: %[3]s
    redirectURL: %[4]s
  store:
    backend: aws
    aws:
      region: %[5]s
`, h.issuer.Issuer(), PortalClientID, portalSecretEnv, h.ConsoleURL()+"/portal/callback", userStoreRegion)
}

// userStoreRegion is consent.store.aws.region; the fake account ignores it.
const userStoreRegion = "us-east-1"

// applyConsent hands the control plane the consent.store account, as the CP's
// role scoped to the consent.store prefix sees it.
func (h *H) applyConsent(p *controlplane.Params) {
	if !h.wantConsent || h.userStoreAWS == nil {
		return
	}
	p.UserStoreAWSClient = h.userStoreAWS.View(config.DefaultConsentStoreNamePrefix)
}

// UserStoreAWS is the AWS account behind the control plane's consent.store,
// unscoped (it sees every name), for assertions on what was written where.
func (h *H) UserStoreAWS() *fakes.FakeAWSSecretsClient {
	h.tb.Helper()
	if !h.wantConsent {
		h.tb.Fatal("harness: UserStoreAWS needs the WithConsent option")
	}
	return h.userStoreAWS
}

// PortalSession is one row of the control plane's portal_sessions table.
type PortalSession struct {
	Iss, Sub, Email string
	CreatedAt       int64
	ExpiresAt       int64
}

// PortalSessions reads the portal_sessions table of the control plane's state
// database, read-only.
func (h *H) PortalSessions() []PortalSession {
	h.tb.Helper()
	if !h.wantConsent {
		h.tb.Fatal("harness: PortalSessions needs the WithConsent option")
	}
	path := filepath.Join(h.root, "cp-state", "warden-cp.db")
	if _, err := os.Stat(path); err != nil {
		h.tb.Fatalf("harness: control-plane state db: %v", err)
	}
	db, err := cpstate.OpenReadOnly(context.Background(), path, controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT iss, sub, email, created_at, expires_at FROM portal_sessions ORDER BY created_at, id_hash`)
	if err != nil {
		h.tb.Fatalf("harness: read portal sessions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PortalSession
	for rows.Next() {
		var s PortalSession
		if err := rows.Scan(&s.Iss, &s.Sub, &s.Email, &s.CreatedAt, &s.ExpiresAt); err != nil {
			h.tb.Fatalf("harness: scan a portal session: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read portal sessions: %v", err)
	}
	return out
}
