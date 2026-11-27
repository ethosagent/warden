package harness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/fakes"
)

// The OAuth broker (W-P3-BRKR-03): the control plane boots with
// consent.providers set, so it mounts /connect/start over the real sqlite
// GrantStore on its state database. consent.store is the in-memory AWS account
// WithConsent installs, which satisfies the persistent-store gate. The broker
// makes no outbound call at start, so no provider fake exists yet (the code
// exchange and its Google and GitHub fakes arrive with W-P3-BRKR-04 and
// W-P3-BRKR-09); a scenario reads the redirect it returns and the rows it
// stores.

const (
	// BrokerProviderID is the one provider WithOAuthBroker configures: type
	// google with the built-in endpoints.
	BrokerProviderID = "google"
	// BrokerAllowedScopes are its allowedScopes; the first is the default.
	BrokerAllowedScopes = "drive.readonly calendar.readonly"
	// BrokerAuthURL is where the start redirect points (Google's built-in).
	BrokerAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"

	brokerSecretEnv   = "WARDEN_HARNESS_OAUTH_GOOGLE_SECRET"
	brokerSecretValue = "harness-google-client-secret"
)

// WithOAuthProviderFake is WithOAuthBroker with the google provider pointed at
// a fake OAuth provider on loopback (OAuthProvider): its authorization and
// token endpoints replace Google's, the client id and secret are the fake's,
// and the control plane may dial loopback for the code exchange (the default
// dialer refuses it). The callback scenario (W-P3-BRKR-04) uses it.
func WithOAuthProviderFake() Option {
	return func(h *H) {
		WithOAuthBroker()(h)
		h.wantOAuthFake = true
	}
}

// OAuthProvider is the fake behind WithOAuthProviderFake.
func (h *H) OAuthProvider() *fakes.OAuthProvider {
	h.tb.Helper()
	if h.oauthFake == nil {
		h.tb.Fatal("harness: OAuthProvider needs the WithOAuthProviderFake option")
	}
	return h.oauthFake
}

// applyBroker lets the code exchange reach the loopback provider fake.
func (h *H) applyBroker(p *controlplane.Params) {
	if h.oauthFake != nil {
		p.OAuthAllowPrivateCIDRs = []string{"127.0.0.0/8"}
	}
}

// WithOAuthBroker boots the control plane with the OAuth broker enabled on top
// of WithConsent: one google provider (client id harness-google-client), the
// broker migrations and the real GrantStore.
func WithOAuthBroker() Option {
	return func(h *H) {
		WithConsent()(h)
		h.wantBroker = true
	}
}

// prepareBroker sets the provider's client secret environment variable.
func (h *H) prepareBroker() {
	if !h.wantBroker {
		return
	}
	secret := brokerSecretValue
	if h.oauthFake != nil {
		secret = fakes.OAuthDefaultSecret
	}
	h.tb.Setenv(brokerSecretEnv, secret)
}

// BrokerClientSecret is the configured provider client secret, for scenarios
// that assert it never appears in a log or response.
func BrokerClientSecret() string { return brokerSecretValue }

// brokerYAML continues the consent block consentYAML opened (it is written
// right after it): the providers list.
func (h *H) brokerYAML() string {
	if !h.wantBroker || h.wantPerUserVault {
		return ""
	}
	clientID, endpoints := "harness-google-client", ""
	if h.oauthFake != nil {
		clientID = fakes.OAuthDefaultClientID
		endpoints = "      authURL: " + h.oauthFake.AuthURL() + "\n      tokenURL: " + h.oauthFake.TokenURL() + "\n"
	}
	return `  providers:
    - id: ` + BrokerProviderID + `
      type: google
      clientID: ` + clientID + `
      clientSecretEnv: ` + brokerSecretEnv + `
` + endpoints + `      allowedScopes: [` + strings.ReplaceAll(BrokerAllowedScopes, " ", ", ") + `]
      defaultScopes: [drive.readonly]
`
}

// ConnectAttempt is one row of the control plane's connect_attempts table.
// Verifier is the PKCE code verifier in plaintext, exactly as the 0600 state
// file holds it.
type ConnectAttempt struct {
	StateHash, PendingID, UserKey, Iss, Sub, Provider string
	Scopes                                            []string
	Verifier, BrowserHash                             string
	ExpiresAt                                         int64
}

// ConnectAttempts reads the connect_attempts table of the control plane's
// state database, read-only.
func (h *H) ConnectAttempts() []ConnectAttempt {
	h.tb.Helper()
	db := h.openBrokerState()
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT state_hash, COALESCE(pending_id, ''), user_key, iss, sub, provider, scopes_json, verifier, browser_hash, expires_at
FROM connect_attempts ORDER BY created_at, state_hash`)
	if err != nil {
		h.tb.Fatalf("harness: read connect attempts: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ConnectAttempt
	for rows.Next() {
		var a ConnectAttempt
		var scopes string
		if err := rows.Scan(&a.StateHash, &a.PendingID, &a.UserKey, &a.Iss, &a.Sub, &a.Provider, &scopes, &a.Verifier, &a.BrowserHash, &a.ExpiresAt); err != nil {
			h.tb.Fatalf("harness: scan a connect attempt: %v", err)
		}
		if err := json.Unmarshal([]byte(scopes), &a.Scopes); err != nil {
			h.tb.Fatalf("harness: decode attempt scopes: %v", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read connect attempts: %v", err)
	}
	return out
}

// BrokerRowCounts returns the number of pending_authorizations and
// oauth_grants rows, so a scenario can show a refusal wrote none.
func (h *H) BrokerRowCounts() (pendings, grants int) {
	h.tb.Helper()
	db := h.openBrokerState()
	defer func() { _ = db.Close() }()
	for table, dst := range map[string]*int{"pending_authorizations": &pendings, "oauth_grants": &grants} {
		if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(dst); err != nil {
			h.tb.Fatalf("harness: count %s: %v", table, err)
		}
	}
	return pendings, grants
}

func (h *H) openBrokerState() *cpstate.DB {
	h.tb.Helper()
	if !h.wantBroker {
		h.tb.Fatal("harness: reading the broker tables needs the WithOAuthBroker option")
	}
	path := filepath.Join(h.root, "cp-state", "warden-cp.db")
	if _, err := os.Stat(path); err != nil {
		h.tb.Fatalf("harness: control-plane state db: %v", err)
	}
	db, err := cpstate.OpenReadOnly(context.Background(), path, controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	return db
}

// OAuthGrant is one row of the control plane's oauth_grants table.
type OAuthGrant struct {
	UserKey, Provider, GrantID, State string
	Scopes                            []string
}

// OAuthGrants reads the oauth_grants table of the control plane's state
// database, read-only.
func (h *H) OAuthGrants() []OAuthGrant {
	h.tb.Helper()
	db := h.openBrokerState()
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT user_key, provider, grant_id, state, scopes_json FROM oauth_grants ORDER BY user_key, provider`)
	if err != nil {
		h.tb.Fatalf("harness: read oauth grants: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OAuthGrant
	for rows.Next() {
		var g OAuthGrant
		var scopes string
		if err := rows.Scan(&g.UserKey, &g.Provider, &g.GrantID, &g.State, &scopes); err != nil {
			h.tb.Fatalf("harness: scan an oauth grant: %v", err)
		}
		if err := json.Unmarshal([]byte(scopes), &g.Scopes); err != nil {
			h.tb.Fatalf("harness: decode grant scopes: %v", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read oauth grants: %v", err)
	}
	return out
}

// StateFilesContain reports whether the control plane's state database file,
// its write-ahead log or its shared-memory file hold needle: the done-when
// check that no token bytes reach cpstate.
func (h *H) StateFilesContain(needle string) bool {
	h.tb.Helper()
	base := filepath.Join(h.root, "cp-state", "warden-cp.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(base + suffix)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}
