package harness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
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
	h.tb.Setenv(brokerSecretEnv, brokerSecretValue)
}

// BrokerClientSecret is the configured provider client secret, for scenarios
// that assert it never appears in a log or response.
func BrokerClientSecret() string { return brokerSecretValue }

// brokerYAML continues the consent block consentYAML opened (it is written
// right after it): the providers list.
func (h *H) brokerYAML() string {
	if !h.wantBroker {
		return ""
	}
	return `  providers:
    - id: ` + BrokerProviderID + `
      type: google
      clientID: harness-google-client
      clientSecretEnv: ` + brokerSecretEnv + `
      allowedScopes: [` + strings.ReplaceAll(BrokerAllowedScopes, " ", ", ") + `]
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
