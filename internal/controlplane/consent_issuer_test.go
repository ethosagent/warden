package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
)

const (
	consentIssuer     = "https://idp.example.com"
	identityBlockYAML = "identity:\n  defaultMode: attribute\n  issuer: " + consentIssuer + "\n  audience: warden\n"
	otherIssuerDoc    = "identity:\n  defaultMode: attribute\n  issuer: https://other.example.com\n  audience: warden\n"
)

func matchingIdentity() *config.IdentitySettings {
	return &config.IdentitySettings{DefaultMode: "attribute", Issuer: consentIssuer, Audience: "warden"}
}

// consentPolicyFile is a served config holding identity (matching the consent
// issuer) and the consent block, on top of base (or a plain policy).
func consentPolicyFile(t *testing.T, base string) string {
	t.Helper()
	if base == "" {
		base = writePolicyFile(t, "api.openai.com")
	}
	if err := os.WriteFile(base, []byte(readFile(t, base)+identityBlockYAML+consentBlockYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return base
}

// newConsentVersioned is a versioned CP after the initial import (head v1)
// over a served file and head that already hold the identity and consent blocks.
func newConsentVersioned(t *testing.T, path string) *Server {
	t.Helper()
	c := fullConsent()
	srv := New(Config{PolicyPath: path, Token: dashTestToken, State: openPolicyState(t), PolicyStore: PolicyStoreVersioned, Consent: &c})
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	return srv
}

func wantMismatch(t *testing.T, what string, err error) {
	t.Helper()
	var im *dashboard.IssuerMismatchError
	if !errors.As(err, &im) {
		t.Fatalf("%s: err = %v, want *dashboard.IssuerMismatchError", what, err)
	}
}

// TestConsentIssuerBindingNilIdentity: removing the identity block removes the
// binding the CP checks at its next start, so it is refused like a change, in
// file mode and in versioned mode, and a rollback to a version without identity
// is refused too.
func TestConsentIssuerBindingNilIdentity(t *testing.T) {
	t.Run("file mode", func(t *testing.T) {
		cfg := detectionEditorConfig(t)
		c := fullConsent()
		cfg.Consent = &c
		srv := New(cfg)
		wantMismatch(t, "nil identity", srv.writeSettings(config.SettingsWire{}))
		if strings.Contains(readFile(t, cfg.PolicyPath), "identity_issuer_mismatch") {
			t.Fatal("served file touched")
		}
		if err := srv.writeSettings(config.SettingsWire{Identity: matchingIdentity()}); err != nil {
			t.Fatalf("matching identity rejected: %v", err)
		}
	})
	t.Run("versioned publishSettings", func(t *testing.T) {
		srv := newConsentVersioned(t, consentPolicyFile(t, ""))
		wantMismatch(t, "nil identity", srv.writeSettings(config.SettingsWire{}))
		wantMismatch(t, "other issuer", srv.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{DefaultMode: "attribute", Issuer: "https://other.example.com", Audience: "warden"}}))
		if h := mustHead(t, srv.versions); h != 1 {
			t.Fatalf("head = %d after refused writes, want 1", h)
		}
		if err := srv.writeSettings(config.SettingsWire{Identity: matchingIdentity()}); err != nil {
			t.Fatalf("matching identity rejected: %v", err)
		}
	})
	t.Run("versioned rollback", func(t *testing.T) {
		// v1 has no identity block (as a head imported before consent was on).
		path := writePolicyFile(t, "api.openai.com")
		srv := newConsentVersioned(t, path)
		// Move head to a version that does hold identity: the served file gains it.
		if err := os.WriteFile(path, []byte(readFile(t, path)+identityBlockYAML), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := srv.writeSettings(config.SettingsWire{Identity: matchingIdentity()}); err != nil {
			t.Fatalf("seed v2: %v", err)
		}
		_, err := policyHistory{s: srv}.Rollback(context.Background(), 1, "", dashboard.WriteMeta{ExpectedHead: mustHead(t, srv.versions)})
		wantMismatch(t, "rollback to a version without identity", err)
	})
}

// TestConsentIssuerBindingDraft: applying a draft whose doc drops or changes the
// identity block is refused and creates no version.
func TestConsentIssuerBindingDraft(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	c := fullConsent()
	srv.cfg.Consent = &c
	d := pendingDraft(t, srv, 1, "new.example.com") // head has no identity block
	_, err := srv.Approvals().Apply(sessionCtx("bob", "bob@example.com"), d.ID, d.Revision, "bob")
	wantMismatch(t, "draft without identity", err)
	if n := versionCount(t, srv); n != 1 {
		t.Errorf("%d versions after the refused apply, want only the import", n)
	}
}

// TestConsentIssuerBindingHTTP: the settings writer and the rollback answer 400
// {"error":"identity_issuer_mismatch","detail":...} (a rollback is not the 422
// invalid_policy of a document that fails the loader).
func TestConsentIssuerBindingHTTP(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := newConsentVersioned(t, path)
	e := &contractEnv{srv: srv, h: srv.Handler()}
	decode := func(body string) map[string]string {
		t.Helper()
		m := map[string]string{}
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("body %q: %v", body, err)
		}
		return m
	}

	rec := e.send("", http.MethodPut, "/dashboard/api/settings", `{"identity":{"defaultMode":"attribute","issuer":"https://other.example.com","audience":"warden"}}`, ifMatch(1))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("settings PUT = %d %s, want 400", rec.Code, rec.Body.String())
	}
	if m := decode(rec.Body.String()); m["error"] != "identity_issuer_mismatch" || !strings.Contains(m["detail"], consentIssuer) {
		t.Fatalf("settings body = %v", m)
	}

	// v2 holds identity; rolling back to v1 (none) must be refused.
	if err := os.WriteFile(path, []byte(readFile(t, path)+identityBlockYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.writeSettings(config.SettingsWire{Identity: matchingIdentity()}); err != nil {
		t.Fatal(err)
	}
	rec = e.send("", http.MethodPost, rollbackPath(1), "", ifMatch(mustHead(t, srv.versions)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rollback = %d %s, want 400", rec.Code, rec.Body.String())
	}
	if m := decode(rec.Body.String()); m["error"] != "identity_issuer_mismatch" || m["detail"] == "" {
		t.Fatalf("rollback body = %v", m)
	}
}

// TestConsentIssuerHeadChecked: `warden policy import` can write a head with any
// issuer while the CP is stopped; the CP must refuse to start on it.
func TestConsentIssuerHeadChecked(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Stage 1: a head whose identity.issuer differs, written straight into the state DB.
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	other := writePolicyFile(t, "api.openai.com")
	if err := os.WriteFile(other, []byte(readFile(t, other)+otherIssuerDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	imp := New(Config{PolicyPath: other, State: db, PolicyStore: PolicyStoreVersioned})
	if err := imp.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Stage 2: --config is fully consistent (consent issuer == identity issuer).
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	body := basePolicy + identityBlockYAML + consoleBlock + consentBlockYAML
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_CONSOLE_SECRET", "console-secret")
	t.Setenv("WARDEN_PORTAL_DEX_CLIENT_SECRET", "portal-secret")
	err = bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir, PolicyStore: PolicyStoreVersioned})
	if !strings.Contains(err.Error(), "identity_issuer_mismatch") && !strings.Contains(err.Error(), "consent.oidc.issuer") {
		t.Fatalf("Run err = %v, want the head issuer mismatch", err)
	}
	if strings.Contains(err.Error(), "portal-secret") {
		t.Error("error carries the secret value")
	}
}
