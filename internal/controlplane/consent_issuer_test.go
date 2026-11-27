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
		before := readFile(t, cfg.PolicyPath)
		wantMismatch(t, "nil identity", srv.writeSettings(config.SettingsWire{}))
		if after := readFile(t, cfg.PolicyPath); after != before {
			t.Fatalf("served file changed by a refused write:\n%s\nvs\n%s", before, after)
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
	// idpLink off: this test boots without a persistent consent.store.
	body := basePolicy + identityBlockYAML + consoleBlock + consentBlockYAML + "  idpLink:\n    enabled: false\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_CONSOLE_SECRET", "console-secret")
	t.Setenv("WARDEN_PORTAL_DEX_CLIENT_SECRET", "portal-secret")
	err = bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir, PolicyStore: PolicyStoreVersioned})
	if !strings.Contains(err.Error(), "--policy-store=versioned: the head policy breaks an identity.issuer binding") {
		t.Fatalf("Run err = %v, want the head issuer mismatch", err)
	}
	if strings.Contains(err.Error(), "portal-secret") {
		t.Error("error carries the secret value")
	}
}

// TestConsentIssuerOfflineImport: `warden policy import` (OfflinePolicyStore.Import)
// refuses a doc whose identity.issuer breaks the consent binding recorded in
// the state dir's served config, and accepts a matching one.
func TestConsentIssuerOfflineImport(t *testing.T) {
	stateDir := t.TempDir()
	served := filepath.Join(stateDir, "config.yaml")
	if err := os.WriteFile(served, []byte(readFile(t, consentPolicyFile(t, ""))), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create the store as a CP of this build would, then close it.
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	write := func(identity string) string {
		p := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(p, []byte(readFile(t, writePolicyFile(t, "api.openai.com"))+identity), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	open := func() *OfflinePolicyStore {
		o, err := OpenPolicyStore(context.Background(), stateDir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		return o
	}
	o := open()
	for name, identity := range map[string]string{"other issuer": otherIssuerDoc, "no identity block": ""} {
		doc, err := ValidatePolicyDocFile(write(identity))
		if err != nil {
			t.Fatal(err)
		}
		_, err = o.Import(context.Background(), doc, "", -1, nil)
		wantMismatch(t, name, err)
		if h, _ := o.Head(context.Background()); h != 0 {
			t.Fatalf("%s: head = %d after a refused import, want 0", name, h)
		}
	}
	doc, err := ValidatePolicyDocFile(write(identityBlockYAML))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := o.Import(context.Background(), doc, "", -1, nil); err != nil || !res.Changed {
		t.Fatalf("matching import = %+v, %v", res, err)
	}
}

// TestConsentIssuerOfflineImportFailsClosed: a served config whose consent block
// is malformed refuses the import (the binding cannot be proved), while a served
// config with no consent block imports as before.
func TestConsentIssuerOfflineImportFailsClosed(t *testing.T) {
	setup := func(servedBody string) (*OfflinePolicyStore, PolicyDoc) {
		stateDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte(servedBody), 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		o, err := OpenPolicyStore(context.Background(), stateDir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		p := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(p, []byte(basePolicy), 0o600); err != nil {
			t.Fatal(err)
		}
		doc, err := ValidatePolicyDocFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return o, doc
	}

	o, doc := setup(basePolicy + "consent:\n  enabled: true\n  bogus: 1\n")
	if _, err := o.Import(context.Background(), doc, "", -1, nil); err == nil {
		t.Fatal("import against a malformed served consent block succeeded, want a refusal")
	}
	if h, _ := o.Head(context.Background()); h != 0 {
		t.Fatalf("head = %d after the refused import, want 0", h)
	}

	o, doc = setup(basePolicy)
	if res, err := o.Import(context.Background(), doc, "", -1, nil); err != nil || !res.Changed {
		t.Fatalf("import with no consent block = %+v, %v; want it to publish", res, err)
	}
}
