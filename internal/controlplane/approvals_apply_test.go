package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
)

// approvalsConsole is an enabled console.approvals block with test-sized limits.
func approvalsConsole() config.ConsoleConfig {
	ac := config.DefaultConsoleApprovals()
	ac.Enabled = true
	ac.MaxOpenDrafts = 20
	return config.ConsoleConfig{Approvals: ac}
}

// newApprovalsServer is a versioned Server with the approvals gate built, over
// a state DB that has the approvals migration applied. Head is version 1.
func newApprovalsServer(t *testing.T, console config.ConsoleConfig, clk *clocktest.Fake) *Server {
	t.Helper()
	console.Approvals.Enabled = true
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"),
		stateMigrationsWithApprovals(StateMigrations(), console.Approvals))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: db,
		PolicyStore: PolicyStoreVersioned, Console: console,
	}
	if clk != nil {
		cfg.Clock = clk
	}
	srv := New(cfg)
	if srv.Approvals() == nil {
		t.Fatal("approvals service not built")
	}
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	return srv
}

// newApprovalsServerRaw builds the Server without asserting the gate exists.
func newApprovalsServerRaw(t *testing.T, console config.ConsoleConfig) *Server {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"),
		stateMigrationsWithApprovals(StateMigrations(), console.Approvals))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: db, PolicyStore: PolicyStoreVersioned, Console: console})
}

var draftAuthor = approvals.Author{Iss: "https://idp", Sub: "ada", Email: "ada@example.com", Kind: AuthorKindOIDC}

// pendingDraft stores head plus one allow entry as a pending policy draft
// based on base.
func pendingDraft(t *testing.T, s *Server, base int64, domain string) approvals.Draft {
	t.Helper()
	ctx := context.Background()
	_, hd, err := s.headDoc(ctx)
	if err != nil {
		t.Fatal(err)
	}
	doc := draftDoc(hd)
	doc.Allowlist = append(slices.Clone(doc.Allowlist), config.AllowlistEntry{Domain: domain})
	d, err := s.Approvals().CreateDraft(ctx, approvals.TargetPolicy, doc, draftAuthor, approvals.Provenance{Message: "allow " + domain}, base)
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.Approvals().Store().Submit(ctx, d.ID, d.Revision, draftAuthor.Sub)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func versionCount(t *testing.T, s *Server) int {
	t.Helper()
	var n int
	if err := s.cfg.State.SQL().QueryRow("SELECT count(*) FROM policy_versions").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDraftApplyPublish: applying a pending draft creates exactly one policy
// version, source approval, authored by the draft's author, with the same
// doc_sha256 as the draft; a second Apply creates nothing.
func TestDraftApplyPublish(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	d := pendingDraft(t, srv, 1, "new.example.com")

	// The approver's own session is not the version author.
	approver := sessionCtx("bob", "bob@example.com")
	applied, err := srv.Approvals().Apply(approver, d.ID, d.Revision, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if applied.State != approvals.StateApplied || applied.AppliedVersion != 2 {
		t.Fatalf("applied draft = %s v%d, want applied v2", applied.State, applied.AppliedVersion)
	}
	if n := versionCount(t, srv); n != 2 {
		t.Fatalf("%d versions after Apply, want 2 (import + one)", n)
	}
	v := headVersion(t, srv)
	if v.Version != 2 || v.Source != SourceApproval || v.Author.Sub != "ada" || v.Author.Email != "ada@example.com" || v.Author.Kind != AuthorKindOIDC || v.Message != draftVersionPrefix(d.ID, d.Revision)+"allow new.example.com" {
		t.Fatalf("head = v%d source %q author %+v message %q", v.Version, v.Source, v.Author, v.Message)
	}
	if v.DocSHA256 != d.DocSHA256 {
		t.Errorf("version doc_sha256 %s != draft doc_sha256 %s", v.DocSHA256, d.DocSHA256)
	}
	if got := allowDomainsOf(v.Doc); !slices.Equal(got, []string{"api.openai.com", "new.example.com"}) {
		t.Errorf("head allowlist = %v", got)
	}

	if _, err := srv.Approvals().Apply(ctx, d.ID, d.Revision, "bob"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Fatalf("second Apply = %v, want ErrIllegalTransition", err)
	}
	if n := versionCount(t, srv); n != 2 {
		t.Errorf("%d versions after the second Apply, want still 2", n)
	}
}

// TestDraftApplyPublishStaleBase: a draft based on an older head is never
// applied; it becomes needs_rebase and the head is untouched.
func TestDraftApplyPublishStaleBase(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	d := pendingDraft(t, srv, 1, "late.example.com")

	// Someone else publishes first: head moves to 2.
	if err := srv.WritePolicy(sessionCtx("eve", "eve@example.com"), plusAllow(t, srv, "other.example.com"), dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	if h := mustHead(t, srv.versions); h != 2 {
		t.Fatalf("head = %d, want 2", h)
	}
	nd, err := srv.Approvals().Apply(ctx, d.ID, d.Revision, "bob")
	if !errors.Is(err, approvals.ErrRebaseRequired) {
		t.Fatalf("Apply on a stale base = %v, want ErrRebaseRequired", err)
	}
	if nd.State != approvals.StateNeedsRebase || nd.LastError == "" {
		t.Errorf("draft = %s %q, want needs_rebase with last_error", nd.State, nd.LastError)
	}
	if h := mustHead(t, srv.versions); h != 2 {
		t.Errorf("head = %d after the refused Apply, want 2", h)
	}
	if got := allowDomainsOf(headVersion(t, srv).Doc); slices.Contains(got, "late.example.com") {
		t.Errorf("head allowlist %v carries the stale draft", got)
	}
}

// TestDraftApplyPublishZeroBase: a draft whose base is 0 must not publish onto
// a non-empty store (publish itself reads ExpectedHead 0 as "the head I read").
func TestDraftApplyPublishZeroBase(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	d := pendingDraft(t, srv, 0, "zero.example.com")
	if _, err := srv.Approvals().Apply(context.Background(), d.ID, d.Revision, "bob"); !errors.Is(err, approvals.ErrRebaseRequired) {
		t.Fatalf("Apply with base 0 on head 1 = %v, want ErrRebaseRequired", err)
	}
	if n := versionCount(t, srv); n != 1 {
		t.Errorf("%d versions, want only the import", n)
	}
}

// TestDraftApplyPublishInvalid: a draft the loader rejects creates no version
// and stays pending with last_error.
func TestDraftApplyPublishInvalid(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	d := pendingDraft(t, srv, 1, "") // an empty domain fails validation
	_, err := srv.Approvals().Apply(ctx, d.ID, d.Revision, "bob")
	var inv *dashboard.InvalidPolicyError
	if !errors.As(err, &inv) {
		t.Fatalf("Apply of an invalid draft = %v, want *dashboard.InvalidPolicyError", err)
	}
	got, gerr := srv.Approvals().Store().Get(ctx, d.ID)
	if gerr != nil || got.State != approvals.StatePending || got.LastError == "" {
		t.Fatalf("draft = %s %q, %v; want pending with last_error", got.State, got.LastError, gerr)
	}
	if n := versionCount(t, srv); n != 1 {
		t.Errorf("%d versions, want only the import", n)
	}
}

// TestDraftApplyDocShape pins that the draft doc and the policy_versions doc
// share one JSON shape: the same doc hashes the same on both sides.
func TestDraftApplyDocShape(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	head := headVersion(t, srv)
	_, sha, err := approvals.EncodeDoc(draftDoc(head.Doc), redactDraftDoc)
	if err != nil {
		t.Fatal(err)
	}
	if sha != head.DocSHA256 {
		t.Fatalf("draft digest of the head doc = %s, policy_versions has %s", sha, head.DocSHA256)
	}
}

// TestDraftApplyRedactsCredential: the draft stores the credential
// fingerprint, never the value, with the redaction helper policy versions use.
func TestDraftApplyRedactsCredential(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	doc := approvals.Doc{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", SecretAccessKey: "raw-key-value"}}}
	d, err := srv.Approvals().CreateDraft(context.Background(), approvals.TargetPolicy, doc, draftAuthor, approvals.Provenance{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d.DocJSON), "raw-key-value") || !strings.Contains(string(d.DocJSON), redactCredential("raw-key-value")) {
		t.Fatalf("doc_json = %s, want the sha256 fingerprint only", d.DocJSON)
	}
	var stored string
	if err := srv.cfg.State.SQL().QueryRow("SELECT doc_json FROM change_drafts WHERE id = ?", d.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "raw-key-value") {
		t.Fatalf("change_drafts holds the raw credential: %s", stored)
	}
	// Neither the database file nor its WAL holds the value, after a checkpoint
	// or before one.
	for _, ckpt := range []bool{false, true} {
		if ckpt {
			if _, err := srv.cfg.State.SQL().Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
				t.Fatal(err)
			}
		}
		for _, f := range []string{srv.cfg.State.Path(), srv.cfg.State.Path() + "-wal"} {
			b, err := os.ReadFile(f)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(b, []byte("raw-key-value")) {
				t.Errorf("%s holds the raw credential (checkpointed=%v)", filepath.Base(f), ckpt)
			}
		}
	}
}

// TestDraftApplyRefusesCredentialChange: a draft whose credential differs from
// the served one cannot publish (the version would keep a fingerprint nothing
// serves); it stays pending with last_error naming fingerprints only.
func TestDraftApplyRefusesCredentialChange(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	_, hd, err := srv.headDoc(ctx)
	if err != nil {
		t.Fatal(err)
	}
	doc := draftDoc(hd)
	doc.Settings = &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", Region: "us-east-1", SecretAccessKey: "rotated-raw-value"}}
	d, err := srv.Approvals().CreateDraft(ctx, approvals.TargetPolicy, doc, draftAuthor, approvals.Provenance{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if d, err = srv.Approvals().Store().Submit(ctx, d.ID, d.Revision, "ada"); err != nil {
		t.Fatal(err)
	}
	_, err = srv.Approvals().Apply(ctx, d.ID, d.Revision, "bob")
	var inv *dashboard.InvalidPolicyError
	if !errors.As(err, &inv) || !strings.Contains(err.Error(), "credential changes cannot go through a draft") {
		t.Fatalf("Apply = %v, want the credential InvalidPolicyError", err)
	}
	if strings.Contains(err.Error(), "rotated-raw-value") {
		t.Error("the error names the raw credential")
	}
	got, _ := srv.Approvals().Store().Get(ctx, d.ID)
	if got.State != approvals.StatePending || !strings.Contains(got.LastError, redactCredential("rotated-raw-value")) {
		t.Errorf("draft = %s %q, want pending with the fingerprint in last_error", got.State, got.LastError)
	}
	if n := versionCount(t, srv); n != 1 {
		t.Errorf("%d versions, want only the import", n)
	}
}

// TestDraftApplyReconcile: a draft left in applying is settled at startup from
// the policy versions: applied when an approval version names it at that
// revision, pending again otherwise.
func TestDraftApplyReconcile(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	st := srv.Approvals().Store()

	// The publish happened, the outcome write did not.
	published := pendingDraft(t, srv, 1, "pub.example.com")
	if _, err := st.BeginApply(ctx, published.ID, published.Revision, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := (policyApplier{s: srv}).Apply(ctx, published); err != nil {
		t.Fatal(err)
	}
	if v := headVersion(t, srv); v.Message != draftVersionPrefix(published.ID, published.Revision)+"allow pub.example.com" {
		t.Fatalf("version message = %q, want the draft id and revision first", v.Message)
	}
	// The process died before publishing.
	lost := pendingDraft(t, srv, 2, "lost.example.com")
	if _, err := st.BeginApply(ctx, lost.ID, lost.Revision, "bob"); err != nil {
		t.Fatal(err)
	}

	n, err := srv.Approvals().Reconcile(ctx, srv.findDraftVersion)
	if err != nil || n != 2 {
		t.Fatalf("Reconcile = %d, %v; want 2", n, err)
	}
	if got, _ := st.Get(ctx, published.ID); got.State != approvals.StateApplied || got.AppliedVersion != 2 {
		t.Errorf("published draft = %s v%d, want applied v2", got.State, got.AppliedVersion)
	}
	if got, _ := st.Get(ctx, lost.ID); got.State != approvals.StatePending || got.LastError == "" {
		t.Errorf("unpublished draft = %s %q, want pending with last_error", got.State, got.LastError)
	}
	// A restart runs it from New too.
	if n := versionCount(t, srv); n != 2 {
		t.Errorf("%d versions, want import + the one published", n)
	}
}

// TestDraftApplyServiceFailureIsFatal: an enabled gate that cannot be built is
// an error Run refuses to start on, never a silently ungated control plane.
func TestDraftApplyServiceFailureIsFatal(t *testing.T) {
	console := approvalsConsole()
	console.Approvals.DraftTTL = 0 // NewService refuses it; config validation normally prevents it
	srv := newApprovalsServerRaw(t, console)
	if srv.approvalsErr == nil || srv.Approvals() != nil {
		t.Fatalf("approvalsErr = %v, service = %v; want an error and no service", srv.approvalsErr, srv.Approvals())
	}
	// Not versioned: also an error rather than a silent no-gate.
	srv = New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Console: approvalsConsole()})
	if srv.approvalsErr == nil {
		t.Error("enabled approvals without the versioned store left no error")
	}
}

// TestDraftApplyDisabled: without console.approvals.enabled there is no
// service and no table.
func TestDraftApplyDisabled(t *testing.T) {
	srv := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	if srv.Approvals() != nil {
		t.Fatal("approvals service built without console.approvals.enabled")
	}
	var n int
	if err := srv.cfg.State.SQL().QueryRow("SELECT count(*) FROM sqlite_master WHERE name LIKE 'change_%'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("change_* tables = %d, %v; want none", n, err)
	}
}

// TestDraftApplySweeper: Server.Start runs the expiry sweeper on the CP clock.
func TestDraftApplySweeper(t *testing.T) {
	clk := clocktest.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	console := approvalsConsole()
	console.Approvals.DraftTTL = 3 * time.Minute
	srv := newApprovalsServer(t, console, clk)
	d := pendingDraft(t, srv, 1, "soon-gone.example.com")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := srv.Approvals().Store().Get(ctx, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State == approvals.StateExpired {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("draft still %s after the sweeper should have expired it", got.State)
		}
		clk.Advance(time.Minute)
		time.Sleep(5 * time.Millisecond)
	}
}

func TestApprovalsStartupChecks(t *testing.T) {
	enabled := func(mut func(*config.ConsoleConfig)) config.ConsoleConfig {
		cc := config.ConsoleConfig{Auth: config.ConsoleAuthOIDC, AdminAudit: config.ConsoleAdminAudit{Enabled: true}, Approvals: config.DefaultConsoleApprovals()}
		cc.Approvals.Enabled = true
		if mut != nil {
			mut(&cc)
		}
		return cc
	}
	tests := []struct {
		name        string
		cc          config.ConsoleConfig
		store, dir  string
		wantContain string
	}{
		{"auth none", enabled(func(c *config.ConsoleConfig) { c.Auth = config.ConsoleAuthNone }), PolicyStoreVersioned, "/s", "console.auth"},
		{"file store", enabled(nil), PolicyStoreFile, "/s", "--policy-store=versioned"},
		{"no state dir", enabled(nil), PolicyStoreVersioned, "", "--state-dir"},
		{"no admin audit", enabled(func(c *config.ConsoleConfig) { c.AdminAudit.Enabled = false }), PolicyStoreVersioned, "/s", "console.adminAudit.enabled"},
		{"everything set hits the temporary guard", enabled(nil), PolicyStoreVersioned, "/s", "approvals enforcement is not available in this build"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkApprovalsStartup(tc.cc, tc.store, tc.dir)
			if err == nil || !strings.Contains(err.Error(), tc.wantContain) {
				t.Fatalf("error = %v, want one containing %q", err, tc.wantContain)
			}
		})
	}
	if err := checkApprovalsStartup(config.ConsoleConfig{Approvals: config.DefaultConsoleApprovals()}, PolicyStoreFile, ""); err != nil {
		t.Errorf("disabled approvals = %v, want nil", err)
	}
}

// writeApprovalsConfig writes a config whose console block is body.
func writeApprovalsConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := "policy:\n  allowlist:\n    - domain: api.openai.com\nconsole:\n" + body
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestApprovalsRunRefusesAuthNone: console.approvals.enabled with console.auth
// none exits before listening, naming console.auth.
func TestApprovalsRunRefusesAuthNone(t *testing.T) {
	cfg := writeApprovalsConfig(t, "  approvals:\n    enabled: true\n")
	err := bootErr(t, Params{ConfigPath: cfg, StateDir: filepath.Join(t.TempDir(), "state"), PolicyStore: PolicyStoreVersioned})
	if !strings.Contains(err.Error(), "console.auth") {
		t.Fatalf("Run err = %v, want one naming console.auth", err)
	}
}

// TestApprovalsRunTemporaryGuard: with every prerequisite met the build still
// refuses enabled (until W-P2-APPR-06), and creates no approvals table.
func TestApprovalsRunTemporaryGuard(t *testing.T) {
	t.Setenv("WARDEN_TEST_CONSOLE_SECRET", "s3cret-value")
	cfg := writeApprovalsConfig(t, `  auth: oidc
  oidc:
    issuer: https://idp.example.com
    clientSecretEnv: WARDEN_TEST_CONSOLE_SECRET
    redirectURL: https://warden.example.com/auth/callback
  roles:
    admin: [admins]
  adminAudit:
    enabled: true
  approvals:
    enabled: true
`)
	stateDir := filepath.Join(t.TempDir(), "state")
	err := bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir, PolicyStore: PolicyStoreVersioned})
	if !strings.Contains(err.Error(), "approvals enforcement is not available in this build") {
		t.Fatalf("Run err = %v, want the temporary guard", err)
	}
	if strings.Contains(err.Error(), "s3cret-value") {
		t.Error("the error leaks the client secret")
	}
	if _, serr := os.Stat(filepath.Join(stateDir, "warden-cp.db")); serr == nil {
		t.Error("the refused start opened the state database")
	}
}
