package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The versioned publish path (W-P1-PVER-02): in --policy-store=versioned the
// policy, settings and llmProviders writers create a policy version from head
// instead of rewriting the served YAML.

// newPublishServer is a versioned-mode Server over policyPath that has run the
// initial import, as Run does, so head is version 1. logs collects the JSON
// log lines.
func newPublishServer(t *testing.T, policyPath string, console config.ConsoleConfig) (*Server, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	srv := New(Config{
		PolicyPath:  policyPath,
		Token:       dashTestToken,
		State:       openPolicyState(t),
		PolicyStore: PolicyStoreVersioned,
		Console:     console,
		Logger:      testJSONLogger(&logs),
	})
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := mustHead(t, srv.versions); h != 1 {
		t.Fatalf("head after import = %d, want 1", h)
	}
	return srv, &logs
}

// headVersion reads the head version with its doc.
func headVersion(t *testing.T, s *Server) PolicyVersion {
	t.Helper()
	v, err := s.versions.Get(context.Background(), mustHead(t, s.versions))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// headDocJSON is the stored doc_json of the head version.
func headDocJSON(t *testing.T, s *Server) string {
	t.Helper()
	var doc string
	if err := s.cfg.State.SQL().QueryRow(
		"SELECT doc_json FROM policy_versions WHERE version = (SELECT version FROM policy_head)").Scan(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func sessionCtx(sub, email string) context.Context {
	return WithPrincipal(context.Background(), Principal{Kind: PrincipalSession, Sub: sub, Email: email, AuthMethod: "oidc"})
}

func plusAllow(t *testing.T, s *Server, domain string) config.Policy {
	t.Helper()
	w, _, _, _ := s.policy.snapshot()
	return config.Policy{
		Allowlist: append(slices.Clone(w.Allowlist), config.AllowlistEntry{Domain: domain}),
		Denylist:  w.Denylist,
	}
}

// TestVersionedWriters: a save in versioned mode creates a version with the
// author taken from the request: a session Principal (oidc), a break-glass
// session, or anonymous in console.auth none. Workers are served the new head,
// and the served YAML mirrors it (W-P1-PVER-05).
func TestVersionedWriters(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want PolicyAuthor
	}{
		{"oidc session", sessionCtx("u1", "a@x"), PolicyAuthor{Sub: "u1", Email: "a@x", Kind: AuthorKindOIDC}},
		{"break-glass", WithPrincipal(context.Background(), Principal{Kind: PrincipalBreakglass, Sub: "alice", AuthMethod: "breakglass"}),
			PolicyAuthor{Sub: "breakglass:alice", Kind: AuthorKindBreakglass}},
		{"console.auth none", context.Background(), PolicyAuthor{Sub: "anonymous", Kind: AuthorKindNone}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, "api.openai.com")
			srv, _ := newPublishServer(t, path, config.ConsoleConfig{})

			if err := srv.WritePolicy(tc.ctx, plusAllow(t, srv, "new.example.com"), dashboard.WriteMeta{Message: "add new"}); err != nil {
				t.Fatal(err)
			}
			v := headVersion(t, srv)
			if v.Version != 2 || v.Author != tc.want || v.Source != SourcePolicy || v.Message != "add new" {
				t.Fatalf("head = v%d author %+v source %q message %q, want v2 by %+v from %q", v.Version, v.Author, v.Source, v.Message, tc.want, SourcePolicy)
			}
			if got := allowDomainsOf(v.Doc); !slices.Equal(got, []string{"api.openai.com", "new.example.com"}) {
				t.Fatalf("v2 allowlist = %v", got)
			}
			// The served YAML is a write-through mirror of head (W-P1-PVER-05).
			if got := allowDomainsOf(yamlWire(t, path)); !slices.Equal(got, []string{"api.openai.com", "new.example.com"}) {
				t.Fatalf("served YAML allowlist = %v, want head v2 mirrored", got)
			}
			w, _, _, _ := srv.policy.snapshot()
			if got := allowDomainsOf(w); !slices.Contains(got, "new.example.com") {
				t.Fatalf("served allowlist = %v, want the new head", got)
			}
		})
	}

	t.Run("oidc without a principal is refused", func(t *testing.T) {
		srv, _ := newPublishServer(t, writePolicyFile(t, "api.openai.com"), authzConsole(defaultRoles()))
		if err := srv.WritePolicy(context.Background(), plusAllow(t, srv, "new.example.com"), dashboard.WriteMeta{}); err == nil {
			t.Fatal("a versioned write in oidc mode without a Principal succeeded")
		}
		if h := mustHead(t, srv.versions); h != 1 {
			t.Fatalf("head = %d, want 1 (nothing written)", h)
		}
	})
}

// TestVersionedWritersHTTP: dashboard writes authenticate as in production. In
// console.auth none the bearer opens the write and the author is anonymous; a
// write without it is refused and creates nothing. In oidc mode the author is
// the session's user.
func TestVersionedWritersHTTP(t *testing.T) {
	const body = `{"allowlist":[{"domain":"api.openai.com"},{"domain":"http.example.com"}],"denylist":[]}`
	t.Run("none", func(t *testing.T) {
		srv, _ := newPublishServer(t, writePolicyFile(t, "api.openai.com"), config.ConsoleConfig{})
		h := srv.Handler()
		send := func(auth string) int {
			req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", strings.NewReader(body))
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec.Code
		}
		if c := send(""); c != http.StatusUnauthorized {
			t.Fatalf("write without the bearer = %d, want 401", c)
		}
		if n := countRows(t, srv, "policy_versions"); n != 1 {
			t.Fatalf("%d versions after a refused write, want 1", n)
		}
		if c := send("Bearer " + dashTestToken); c != http.StatusOK {
			t.Fatalf("write with the bearer = %d, want 200", c)
		}
		if v := headVersion(t, srv); v.Version != 2 || v.Author != (PolicyAuthor{Sub: "anonymous", Kind: AuthorKindNone}) {
			t.Fatalf("head = v%d by %+v, want v2 by anonymous", v.Version, v.Author)
		}
	})
	t.Run("oidc session", func(t *testing.T) {
		db := openPolicyState(t)
		srv := New(Config{
			PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: db,
			PolicyStore: PolicyStoreVersioned, Console: authzConsole(defaultRoles()), Logger: testJSONLogger(nil),
		})
		if err := srv.importInitialVersion(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
		srv.sessionReader = srv.sessions
		e := &authzEnv{srv: srv, h: srv.Handler()}
		raw := e.session(t, groupAdmin)
		if rec := e.do(raw, http.MethodPost, "/dashboard/api/policy", body); rec.Code != http.StatusOK {
			t.Fatalf("session write = %d %s", rec.Code, rec.Body.String())
		}
		in := testSessionInput()
		if v := headVersion(t, srv); v.Version != 2 || v.Author != (PolicyAuthor{Sub: in.Sub, Email: in.Email, Kind: AuthorKindOIDC}) {
			t.Fatalf("head = v%d by %+v, want v2 by the session user", v.Version, v.Author)
		}
	})
}

// TestVersionedLLMProvidersReachWorkers: an llmProviders edit in versioned
// mode creates a version with source llmproviders, /policy serves the new
// registry, a blocked long-poll waiter wakes, the CP-local readers see head,
// and the served YAML mirrors it (W-P1-PVER-05).
func TestVersionedLLMProvidersReachWorkers(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, _ := newPublishServer(t, path, config.ConsoleConfig{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	auth := map[string]string{"Authorization": "Bearer " + dashTestToken}
	_, _, etag := getPolicy(t, ts.URL+"/policy", auth)

	type pollResult struct {
		code int
		body []byte
		err  error
	}
	woke := make(chan pollResult, 1)
	go func() {
		// No t.Fatal off the test goroutine: the result goes back on the channel.
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/policy?wait=20s", nil)
		if err != nil {
			woke <- pollResult{err: err}
			return
		}
		req.Header.Set("Authorization", auth["Authorization"])
		req.Header.Set("If-None-Match", etag)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			woke <- pollResult{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		woke <- pollResult{code: resp.StatusCode, body: b, err: err}
	}()
	// No sleep: a waiter already blocked is woken by the watch broadcast, and
	// one that snapshots after the write sees a new ETag and returns at once.
	ps := []config.LLMProvider{{Name: "p1", BaseURL: "https://llm.example.com/v1", Model: "m1", APIKeyEnv: "P1_KEY", Timeout: 7 * time.Second}}
	if err := srv.WriteLLMProviders(context.Background(), ps, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	v := headVersion(t, srv)
	if v.Version != 2 || v.Source != SourceLLMProviders {
		t.Fatalf("head = v%d source %q, want v2 from llmproviders", v.Version, v.Source)
	}
	select {
	case r := <-woke:
		if r.err != nil || r.code != http.StatusOK || !strings.Contains(string(r.body), `"name":"p1"`) {
			t.Fatalf("the woken waiter got %d %s (err %v), want 200 with the new registry", r.code, r.body, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the long-poll waiter was not woken by the llmProviders save")
	}
	if _, b, _ := getPolicy(t, ts.URL+"/policy", auth); !strings.Contains(string(b), `"llmProviders":[{"name":"p1"`) {
		t.Fatalf("GET /policy = %s, want the new registry", b)
	}
	if view := srv.llmProvidersView(); len(view.Providers) != 1 || view.Providers[0].Name != "p1" {
		t.Fatalf("llmProvidersView = %+v, want head's registry", view)
	}
	// The served YAML is a write-through mirror of head (W-P1-PVER-05).
	if got := wireJSON(t, yamlWire(t, path)); got != wireJSON(t, servedWire(srv)) {
		t.Fatalf("served YAML = %s, want head v2 mirrored", got)
	}
}

// writeRawPolicyFile writes body as the served config.
func writeRawPolicyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testJSONLogger logs JSON lines to w (nil discards).
func testJSONLogger(w io.Writer) *slog.Logger {
	if w == nil {
		w = io.Discard
	}
	return slog.New(slog.NewJSONHandler(w, nil))
}

const carryPolicyYAML = "policy:\n  allowlist:\n    - domain: api.openai.com\n" +
	"dlp:\n  mode: monitor\nadvisory:\n  enabled: true\n" +
	"llmProviders:\n  - name: p0\n    baseURL: https://llm0.example.com/v1\n    model: m0\n    apiKeyEnv: P0_KEY\n"

// TestVersionedSettingsCarryFields: a settings save changes only the blocks the
// settings form owns. dlp, advisory and llmProviders come from head, even when
// head no longer matches the served YAML (a later rollback or CLI publish).
func TestVersionedSettingsCarryFields(t *testing.T) {
	path := writeRawPolicyFile(t, carryPolicyYAML)
	srv, _ := newPublishServer(t, path, config.ConsoleConfig{})

	// Head v2 differs from the YAML in the carried blocks.
	v1 := headVersion(t, srv)
	doc := v1.Doc
	settings := *doc.Settings
	settings.DLP = &config.DLPSettings{Mode: "enforce"}
	settings.LLMProviders = []config.LLMProviderSettings{{Name: "p9", BaseURL: "https://llm9.example.com/v1", Model: "m9", APIKeyEnv: "P9_KEY"}}
	doc.Settings = &settings
	if _, _, err := srv.versions.Create(context.Background(), doc, testAuthor, "", SourcePolicy, 1); err != nil {
		t.Fatal(err)
	}
	v2 := headVersion(t, srv)

	in := config.SettingsWire{Agents: []config.AgentSettings{{ID: "a1", Policy: "read only"}}}
	if err := srv.WriteSettings(context.Background(), in, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	v3 := headVersion(t, srv)
	if v3.Version != 3 || v3.Source != SourceSettings {
		t.Fatalf("head = v%d source %q, want v3 from settings", v3.Version, v3.Source)
	}
	if v3.Doc.Settings == nil || len(v3.Doc.Settings.Agents) != 1 || v3.Doc.Settings.Agents[0].ID != "a1" {
		t.Fatalf("v3 agents = %+v, want the submitted agent", v3.Doc.Settings)
	}
	for name, pair := range map[string][2]any{
		"dlp":          {v2.Doc.Settings.DLP, v3.Doc.Settings.DLP},
		"advisory":     {v2.Doc.Settings.Advisory, v3.Doc.Settings.Advisory},
		"llmProviders": {v2.Doc.Settings.LLMProviders, v3.Doc.Settings.LLMProviders},
	} {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Errorf("%s: v3 has %s, want head's %s (carried)", name, mustJSON(t, pair[1]), mustJSON(t, pair[0]))
		}
	}
	if !reflect.DeepEqual(v2.Doc.Allowlist, v3.Doc.Allowlist) {
		t.Errorf("v3 allowlist %v, want head's %v", v3.Doc.Allowlist, v2.Doc.Allowlist)
	}
}

// TestSettingsFieldOwnership: every SettingsWire field is owned by exactly one
// versioned writer or listed as carried, so a field added later cannot be
// dropped by a publish; and composeSettings takes exactly the owned fields from
// the candidate and every other field from head.
func TestSettingsFieldOwnership(t *testing.T) {
	typ := reflect.TypeFor[config.SettingsWire]()
	names := map[string]bool{}
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		names[name] = true
		owner, ok := settingsFieldOwners[name]
		if !ok {
			t.Errorf("SettingsWire.%s is neither owned by a writer nor listed as carried in settingsFieldOwners", name)
			continue
		}
		if owner != SourceSettings && owner != SourceLLMProviders && owner != settingsFieldCarried {
			t.Errorf("SettingsWire.%s: owner %q is not a versioned writer", name, owner)
		}
	}
	for name := range settingsFieldOwners {
		if !names[name] {
			t.Errorf("settingsFieldOwners lists %s, which SettingsWire does not have", name)
		}
	}

	// head and cand hold distinct non-zero values in every field.
	var head, cand config.SettingsWire
	hv, cv := reflect.ValueOf(&head).Elem(), reflect.ValueOf(&cand).Elem()
	for i := range typ.NumField() {
		hv.Field(i).Set(nonZero(t, typ.Field(i).Type, 1))
		cv.Field(i).Set(nonZero(t, typ.Field(i).Type, 2))
	}
	for _, writer := range []string{SourcePolicy, SourceSettings, SourceLLMProviders} {
		out := reflect.ValueOf(composeSettings(&head, &cand, writer)).Elem()
		for i := range typ.NumField() {
			name := typ.Field(i).Name
			want := hv.Field(i)
			if settingsFieldOwners[name] == writer {
				want = cv.Field(i)
			}
			if !reflect.DeepEqual(out.Field(i).Interface(), want.Interface()) || !sameRef(out.Field(i), want) {
				t.Errorf("%s publish: SettingsWire.%s not taken from the right side", writer, name)
			}
		}
	}
	if got := composeSettings(nil, nil, SourceSettings); got != nil {
		t.Errorf("composeSettings of nothing = %+v, want nil (no settings key)", got)
	}
}

// nonZero returns a non-zero value of typ, distinct per seed by identity
// (pointers) or length (slices).
func nonZero(t *testing.T, typ reflect.Type, seed int) reflect.Value {
	t.Helper()
	switch typ.Kind() {
	case reflect.Pointer:
		return reflect.New(typ.Elem())
	case reflect.Slice:
		return reflect.MakeSlice(typ, seed, seed)
	default:
		t.Fatalf("SettingsWire field of kind %s: extend nonZero", typ.Kind())
		return reflect.Value{}
	}
}

func sameRef(a, b reflect.Value) bool {
	if a.Kind() == reflect.Pointer {
		return a.Pointer() == b.Pointer()
	}
	return a.Len() == b.Len()
}

// awsSettings is the dashboard's re-save of the aws secretStore block: the
// access key id, and the secret only when the user typed a new one.
func awsSettings(secret string) config.SettingsWire {
	return config.SettingsWire{Secrets: &config.SecretsSettings{
		Backend: "aws", Region: "us-east-1", NamePrefix: "warden/", AccessKeyID: "AKIAPVER01", SecretAccessKey: secret,
	}}
}

// servedSecret is the secretAccessKey GET /policy serves.
func servedSecret(t *testing.T, s *Server) string {
	t.Helper()
	w, _, _, _ := s.policy.snapshot()
	if w.Settings == nil || w.Settings.Secrets == nil {
		return ""
	}
	return w.Settings.Secrets.SecretAccessKey
}

// TestVersionedSettingsPreserveCredential: re-saving settings with an empty
// secretAccessKey keeps the live credential on the wire and stores only its
// fingerprint.
func TestVersionedSettingsPreserveCredential(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	in := awsSettings("")
	in.Agents = []config.AgentSettings{{ID: "a1", Policy: "read only"}} // force a new version
	if err := srv.WriteSettings(context.Background(), in, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	if h := mustHead(t, srv.versions); h != 2 {
		t.Fatalf("head = %d, want 2", h)
	}
	if got := servedSecret(t, srv); got != policyStoreSecret {
		t.Fatalf("served secretAccessKey changed after a re-save with an empty one")
	}
	doc := headDocJSON(t, srv)
	if strings.Contains(doc, policyStoreSecret) || !strings.Contains(doc, redactCredential(policyStoreSecret)) {
		t.Fatalf("doc_json must hold the credential's fingerprint only: %s", doc)
	}
	if strings.Contains(logs.String(), policyStoreSecret) {
		t.Fatal("the credential reached a log line")
	}
}

// TestVersionedSettingsNewCredential: a new secretAccessKey is written to the
// served YAML secretStore, served to workers, and never stored in doc_json.
func TestVersionedSettingsNewCredential(t *testing.T) {
	const newSecret = "sk-live-PVER02-rotated-never-stored"
	path := writeCredentialPolicyFile(t)
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	if err := srv.WriteSettings(context.Background(), awsSettings(newSecret), dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	if h := mustHead(t, srv.versions); h != 2 {
		t.Fatalf("head = %d, want 2", h)
	}
	if !strings.Contains(readFile(t, path), "secretAccessKey: "+newSecret) {
		t.Fatal("the new credential did not land in the served YAML secretStore")
	}
	if got := servedSecret(t, srv); got != newSecret {
		t.Fatal("workers are not served the new credential")
	}
	doc := headDocJSON(t, srv)
	if strings.Contains(doc, newSecret) || !strings.Contains(doc, redactCredential(newSecret)) {
		t.Fatalf("doc_json must hold the new credential's fingerprint only: %s", doc)
	}
	if rows := countRows(t, srv, "policy_versions"); rows != 2 {
		t.Fatalf("%d versions, want 2", rows)
	}
	if strings.Contains(logs.String(), newSecret) {
		t.Fatal("the credential reached a log line")
	}
}

// TestVersionedSettingsNewCredentialConflict: when the version cannot be
// created, a new credential already written to the YAML is put back.
func TestVersionedSettingsNewCredentialConflict(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	srv, _ := newPublishServer(t, path, config.ConsoleConfig{})
	yamlBefore := readFile(t, path)
	err := srv.WriteSettings(context.Background(), awsSettings("sk-conflicting"), dashboard.WriteMeta{ExpectedHead: 7})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale ExpectedHead: err = %v, want ErrConflict", err)
	}
	if got := readFile(t, path); got != yamlBefore {
		t.Fatalf("a refused save left the new credential in the YAML:\n%s", got)
	}
	if got := servedSecret(t, srv); got != policyStoreSecret {
		t.Fatal("a refused save changed the served credential")
	}
}

// TestVersionedPublishValidation: an invalid edit returns the loader error,
// creates no version and leaves the ETag unchanged; a stale ExpectedHead is
// ErrConflict.
func TestVersionedPublishValidation(t *testing.T) {
	srv, _ := newPublishServer(t, writePolicyFile(t, "api.openai.com"), config.ConsoleConfig{})
	etag := srv.policy.currentETag()

	err := srv.WritePolicy(context.Background(), config.Policy{}, dashboard.WriteMeta{})
	if err == nil || !strings.Contains(err.Error(), "invalid policy") || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("empty allowlist: err = %v, want the loader error", err)
	}
	err = srv.WriteLLMProviders(context.Background(), []config.LLMProvider{{Name: "p1"}}, dashboard.WriteMeta{})
	if err == nil || !strings.Contains(err.Error(), "invalid policy") {
		t.Fatalf("incomplete provider: err = %v, want the loader error", err)
	}
	if n := countRows(t, srv, "policy_versions"); n != 1 {
		t.Fatalf("%d versions after invalid edits, want 1", n)
	}
	if got := srv.policy.currentETag(); got != etag {
		t.Fatalf("ETag moved from %s to %s on an invalid edit", etag, got)
	}

	err = srv.WritePolicy(context.Background(), plusAllow(t, srv, "x.example.com"), dashboard.WriteMeta{ExpectedHead: 5})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale ExpectedHead: err = %v, want ErrConflict", err)
	}
	if err := srv.WritePolicy(context.Background(), plusAllow(t, srv, "x.example.com"), dashboard.WriteMeta{ExpectedHead: 1}); err != nil {
		t.Fatalf("current ExpectedHead: %v", err)
	}
	if h := mustHead(t, srv.versions); h != 2 {
		t.Fatalf("head = %d, want 2", h)
	}
}

// TestVersionedPublishLogsOnlyVersionLine: a versioned save logs the version
// line and none of the file-mode content summaries.
func TestVersionedPublishLogsOnlyVersionLine(t *testing.T) {
	srv, logs := newPublishServer(t, writePolicyFile(t, "api.openai.com"), config.ConsoleConfig{})
	logs.Reset()
	in := config.SettingsWire{Agents: []config.AgentSettings{{ID: "a1", Policy: "read only"}}}
	if err := srv.WriteSettings(context.Background(), in, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	if err := srv.WritePolicy(context.Background(), plusAllow(t, srv, "x.example.com"), dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for line := range strings.Lines(logs.String()) {
		var rec struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		msgs = append(msgs, rec.Msg)
	}
	if !slices.Equal(msgs, []string{"policy version created", "policy version created"}) {
		t.Fatalf("log messages = %q, want only the version line per save", msgs)
	}
}

// TestVersionedSettingsNewCredentialUnreadableYAML: in versioned mode the
// served YAML is the only home of the CP-local blocks, so a new credential is
// refused, not written over a file that does not parse.
func TestVersionedSettingsNewCredentialUnreadableYAML(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	srv, _ := newPublishServer(t, path, config.ConsoleConfig{})
	const broken = "policy: [unclosed\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.WriteSettings(context.Background(), awsSettings("sk-unwritten"), dashboard.WriteMeta{}); err == nil {
		t.Fatal("a new credential over a malformed served YAML was accepted")
	}
	if got := readFile(t, path); got != broken {
		t.Fatalf("the malformed served YAML was replaced:\n%s", got)
	}
	if h := mustHead(t, srv.versions); h != 1 {
		t.Fatalf("head = %d, want 1", h)
	}
}
