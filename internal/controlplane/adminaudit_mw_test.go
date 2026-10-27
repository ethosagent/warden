package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/secrets"
)

// fakeRecorder is an in-memory adminaudit.Recorder. fail makes Record return
// an error; probeErr is what its probe returns.
type fakeRecorder struct {
	mu       sync.Mutex
	rows     []adminaudit.Input
	fail     error
	probeErr error
}

func (f *fakeRecorder) Record(_ context.Context, in adminaudit.Input) (adminaudit.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return adminaudit.Entry{}, f.fail
	}
	f.rows = append(f.rows, in)
	return adminaudit.Entry{Seq: int64(len(f.rows))}, nil
}

func (f *fakeRecorder) probe(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probeErr
}

func (f *fakeRecorder) set(fail, probeErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail, f.probeErr = fail, probeErr
}

func (f *fakeRecorder) inputs() []adminaudit.Input {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]adminaudit.Input(nil), f.rows...)
}

// fakeMAC stands in for the store's keyed state hash.
func fakeMAC(target string, data []byte) (string, error) {
	sum := sha256.Sum256(append([]byte(target+"\x00"), data...))
	return adminaudit.StateHashPrefix + hex.EncodeToString(sum[:]), nil
}

// auditEnv is a control plane with admin audit on: oidc mode with in-process
// sessions (as authzEnv), an echo secret store and the alert pipeline (so the
// integrations and detection writers are mounted and Findings land).
type auditEnv struct {
	srv *Server
	h   http.Handler
	rec *fakeRecorder
	log *bytes.Buffer
}

type auditEnvOpts struct {
	console    config.ConsoleConfig
	token      string
	adminToken string
	db         *cpstate.DB
	store      *adminaudit.Store // nil: a fakeRecorder
}

func newAuditEnv(t *testing.T, o auditEnvOpts) *auditEnv {
	t.Helper()
	logger, buf := testLogger()
	if o.db == nil {
		o.db = openAuditDB(t)
	}
	cfg := detectionEditorConfig(t)
	cfg.Token, cfg.AdminToken = o.token, o.adminToken
	cfg.State, cfg.Console, cfg.Logger = o.db, o.console, logger
	cfg.Clock = clocktest.NewFake(time.Unix(1_800_000_000, 0))
	cfg.SecretStore, cfg.SecretStoreBackend = secrets.NewEchoStore(), "echo"
	if o.store != nil {
		cfg.AdminAudit = o.store
	}
	srv := New(cfg)
	t.Cleanup(func() {
		if srv.integrationsStore != nil {
			_ = srv.integrationsStore.Close()
		}
	})
	if srv.sessions != nil {
		srv.sessions = NewSessionStore(o.db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
		srv.sessionReader = srv.sessions
	}
	e := &auditEnv{srv: srv, log: buf}
	if o.store == nil {
		e.rec = &fakeRecorder{}
		srv.enableAdminAudit(e.rec, e.rec.probe, fakeMAC)
	}
	e.h = srv.Handler()
	return e
}

func newOIDCAuditEnv(t *testing.T) *auditEnv {
	t.Helper()
	return newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken})
}

func openAuditDB(t *testing.T) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (e *auditEnv) session(t *testing.T, group string) string {
	t.Helper()
	in := testSessionInput()
	in.Groups = []string{group}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// send issues one request. rawID is a session ("" none); bearer an
// Authorization bearer ("" none). Session writes carry their CSRF token.
func (e *auditEnv) send(rawID, bearer, method, target, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if rawID != "" {
		req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: rawID})
		if method != http.MethodGet {
			req.Header.Set(CSRFHeader, CSRFToken(rawID))
		}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// auditedRequest is a request that succeeds on an audited route.
type auditedRequest struct{ target, body string }

// auditedHeaders are the extra header name/value pairs an auditedRequests
// entry needs.
var auditedHeaders = map[routeKey][]string{
	{http.MethodPost, "/dashboard/api/policy/versions/{v}/rollback"}: {"If-Match", `"v1"`},
}

// auditedRequests maps every audited route to a request an admin can make
// successfully. A new audited route without an entry fails
// TestAdminAuditAllAuditedRoutes.
var auditedRequests = map[routeKey]auditedRequest{
	{http.MethodPost, "/dashboard/api/policy"}:         {"/dashboard/api/policy", policyBody},
	{http.MethodPut, "/dashboard/api/policy"}:          {"/dashboard/api/policy", `{"allowlist":[{"domain":"api.example.org"}],"denylist":[]}`},
	{http.MethodPost, "/dashboard/api/settings"}:       {"/dashboard/api/settings", `{}`},
	{http.MethodPut, "/dashboard/api/settings"}:        {"/dashboard/api/settings", `{}`},
	{http.MethodPost, "/dashboard/api/secretstore"}:    {"/dashboard/api/secretstore", `{"key":"DASH_KEY","value":"v1"}`},
	{http.MethodDelete, "/dashboard/api/secretstore"}:  {"/dashboard/api/secretstore?key=DASH_KEY", ""},
	{http.MethodPost, "/dashboard/api/integrations"}:   {"/dashboard/api/integrations", `{"type":"webhook","name":"ops","config":{"url":"https://ops.example/hook"}}`},
	{http.MethodDelete, "/dashboard/api/integrations"}: {"/dashboard/api/integrations?name=ops", ""},
	{http.MethodPost, "/dashboard/api/detection"}:      {"/dashboard/api/detection", `{"enabled":true,"errorRate":{"enabled":false}}`},
	{http.MethodPut, "/dashboard/api/detection"}:       {"/dashboard/api/detection", `{"enabled":true}`},
	{http.MethodPost, "/dashboard/api/llmproviders"}:   {"/dashboard/api/llmproviders", `[{"name":"p1","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY"}]`},
	{http.MethodPut, "/dashboard/api/llmproviders"}:    {"/dashboard/api/llmproviders", `[]`},
	{http.MethodDelete, "/dashboard/api/sessions"}:     {"/dashboard/api/sessions?sub=nobody", ""},
	// Served by the stub history TestAdminAuditAllAuditedRoutes installs.
	{http.MethodPost, "/dashboard/api/policy/versions/{v}/rollback"}: {"/dashboard/api/policy/versions/1/rollback", `{}`},
	{http.MethodPost, "/central/secrets"}:                            {"/central/secrets", `{"key":"CP_KEY","value":"v2"}`},
	{http.MethodDelete, "/central/secrets/"}:                         {"/central/secrets/CP_KEY", ""},
}

// allAuditedRoutes lists every audited row of both route tables in a stable
// order (creates before deletes, as auditedRequests needs).
func allAuditedRoutes() []routeKey {
	var out []routeKey
	add := func(table map[routeKey]authzRow) {
		for k, r := range table {
			if r.Audited {
				out = append(out, k)
			}
		}
	}
	add(authzTable())
	add(cpRouteTable())
	order := map[string]int{http.MethodPost: 0, http.MethodPut: 1, http.MethodDelete: 2}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.Path > b.Path || (a.Path == b.Path && order[a.Method] > order[b.Method]) {
				out[j-1], out[j] = b, a
			}
		}
	}
	return out
}

func auditRow(k routeKey) authzRow {
	if r, ok := authzTable()[k]; ok {
		return r
	}
	return cpRouteTable()[k]
}

func TestAdminAuditAllAuditedRoutes(t *testing.T) {
	e := newOIDCAuditEnv(t)
	e.srv.dash.SetPolicyHistory(stubHistory{})
	admin := e.session(t, groupAdmin)
	hashed := map[string]bool{"policy": true, "settings": true, "integrations": true, "detection": true, "llmproviders": true}
	routes := allAuditedRoutes()
	if len(routes) != len(auditedRequests) {
		t.Fatalf("%d audited routes but %d test requests; add the new route to auditedRequests", len(routes), len(auditedRequests))
	}
	for _, k := range routes {
		req, ok := auditedRequests[k]
		if !ok {
			t.Fatalf("audited route %s %s has no entry in auditedRequests", k.Method, k.Path)
		}
		row := auditRow(k)
		before := len(e.rec.inputs())
		rec := e.send(admin, "", k.Method, req.target, req.body, auditedHeaders[k]...)
		if rec.Code/100 != 2 {
			t.Fatalf("%s %s = %d %s, want 2xx", k.Method, req.target, rec.Code, rec.Body.String())
		}
		rows := e.rec.inputs()
		if len(rows) != before+1 {
			t.Fatalf("%s %s wrote %d rows, want 1", k.Method, req.target, len(rows)-before)
		}
		got := rows[len(rows)-1]
		if got.Action != row.Action || got.Target != row.Target || got.Outcome != adminaudit.OutcomeOK || got.HTTPStatus != rec.Code {
			t.Errorf("%s %s row = action %q target %q outcome %q status %d, want %q %q ok %d",
				k.Method, k.Path, got.Action, got.Target, got.Outcome, got.HTTPStatus, row.Action, row.Target, rec.Code)
		}
		if got.Actor.Sub != "u1" || got.ActorRole != "admin" || got.AuthMethod != adminaudit.AuthMethodOIDC {
			t.Errorf("%s %s actor = %+v role %q method %q", k.Method, k.Path, got.Actor, got.ActorRole, got.AuthMethod)
		}
		if got.RequestID == "" || got.RequestID != rec.Header().Get(RequestIDHeader) {
			t.Errorf("%s %s request_id %q, response header %q", k.Method, k.Path, got.RequestID, rec.Header().Get(RequestIDHeader))
		}
		if hashed[row.Target] != (got.BeforeHash != "" && got.AfterHash != "") {
			t.Errorf("%s %s hashes before=%q after=%q (hasher for %s: %v)", k.Method, k.Path, got.BeforeHash, got.AfterHash, row.Target, hashed[row.Target])
		}
	}
	// A policy edit moves the policy hash, and names the version written.
	var pol adminaudit.Input
	for _, in := range e.rec.inputs() {
		if in.Action == "policy.write" {
			pol = in
			break
		}
	}
	if pol.BeforeHash == pol.AfterHash {
		t.Errorf("policy write did not change the policy hash: %q", pol.BeforeHash)
	}
	if !strings.HasPrefix(pol.TargetRef, "policy@") || len(pol.TargetRef) != len("policy@")+16 {
		t.Errorf("policy target_ref = %q, want policy@<etag>", pol.TargetRef)
	}
}

func TestAdminAuditSkipsWorkerAndReadOnlyRoutes(t *testing.T) {
	e := newOIDCAuditEnv(t)
	e.srv.dash.SetQueryEngine(fakeQuery{})
	e.srv.dash.SetSQLGenerator(sqlGenFunc(func(string) (string, error) { return "SELECT 1", nil }))
	admin := e.session(t, groupAdmin)
	for range 100 {
		rec := e.send("", dashTestToken, http.MethodPost, "/control/heartbeat", `{"policyETag":""}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("heartbeat = %d", rec.Code)
		}
		if rec.Header().Get(RequestIDHeader) != "" {
			t.Fatal("a worker route went through the audit chain (it has a request id)")
		}
		e.send("", dashTestToken, http.MethodPost, "/central/ingest", `{"events":[]}`)
	}
	for range 10 {
		for _, c := range []struct{ path, body string }{
			{"/dashboard/api/query", `{"sql":"SELECT 1"}`},
			{"/dashboard/api/query/generate", `{"question":"count events"}`},
			{"/dashboard/api/audit/verify", `{}`},
		} {
			if rec := e.send(admin, "", http.MethodPost, c.path, c.body); rec.Code == http.StatusServiceUnavailable {
				t.Fatalf("read-only POST %s = 503", c.path)
			}
		}
	}
	if rec := e.send("", dashTestToken, http.MethodGet, "/policy", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d", rec.Code)
	}
	if n := len(e.rec.inputs()); n != 0 {
		t.Fatalf("worker and read-only routes wrote %d rows, want 0: %+v", n, e.rec.inputs())
	}
}

func TestAdminAuditDenied(t *testing.T) {
	e := newOIDCAuditEnv(t)
	viewer := e.session(t, groupViewer)
	rec := e.send(viewer, "", http.MethodPost, "/dashboard/api/policy", policyBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST policy = %d, want 403", rec.Code)
	}
	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Outcome != adminaudit.OutcomeDenied || r.HTTPStatus != http.StatusForbidden || r.ActorRole != "viewer" || r.Action != "policy.write" {
		t.Errorf("denied row = %+v", r)
	}
	if r.BeforeHash == "" || r.BeforeHash != r.AfterHash {
		t.Errorf("denied row hashes before=%q after=%q, want equal and set", r.BeforeHash, r.AfterHash)
	}

	// A CSRF refusal of an authenticated session is denied too, with the reason.
	admin := e.session(t, groupAdmin)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/settings", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: admin})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != `{"error":"csrf"}` {
		t.Fatalf("admin write without CSRF = %d %q", w.Code, w.Body.String())
	}
	rows = e.rec.inputs()
	if len(rows) != 2 || rows[1].Outcome != adminaudit.OutcomeDenied || rows[1].Details[detailReason] != "csrf" || rows[1].Action != "settings.write" {
		t.Fatalf("csrf refusal rows = %+v", rows)
	}

	// An editor's settings edit that needs admin (per-field authz) is denied.
	editor := e.session(t, groupEditor)
	if rec := e.send(editor, "", http.MethodPost, "/dashboard/api/settings", `{"explore":{"llmProvider":"p1"}}`); rec.Code != http.StatusForbidden {
		t.Fatalf("editor admin-field write = %d", rec.Code)
	}
	if rows = e.rec.inputs(); len(rows) != 3 || rows[2].Outcome != adminaudit.OutcomeDenied || rows[2].ActorRole != "editor" {
		t.Fatalf("per-field refusal rows = %+v", rows)
	}

	// A 4xx that is not a refusal is rejected, and still hashes after.
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", `not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad policy body = %d", rec.Code)
	}
	if rows = e.rec.inputs(); len(rows) != 4 || rows[3].Outcome != adminaudit.OutcomeRejected || rows[3].AfterHash == "" {
		t.Fatalf("rejected rows = %+v", rows)
	}
}

func TestAdminAuditUnauthenticatedNoRow(t *testing.T) {
	e := newOIDCAuditEnv(t)
	for range 3 {
		if rec := e.send("", "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusUnauthorized {
			t.Fatalf("no session POST policy = %d, want 401", rec.Code)
		}
	}
	// A bearer opens nothing in oidc mode and is not an actor either.
	if rec := e.send("", dashTestToken, http.MethodPost, "/central/secrets", `{"key":"K","value":"v"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer-only POST /central/secrets = %d, want 401", rec.Code)
	}
	if n := len(e.rec.inputs()); n != 0 {
		t.Fatalf("unauthenticated requests wrote %d rows", n)
	}
	if got := e.srv.audit.unauthenticated.Load(); got != 4 {
		t.Errorf("unauthenticated counter = %d, want 4", got)
	}
	// One log line per client address per minute.
	logs := e.log.String()
	if n := strings.Count(logs, "admin_audit_unauthenticated"); n != 1 {
		t.Errorf("unauthenticated log lines = %d, want 1 (rate limited):\n%s", n, logs)
	}
	if strings.Contains(logs, dashTestToken) {
		t.Error("the log contains the bearer token")
	}
}

func TestAdminAuditBearerActor(t *testing.T) {
	const adminTok = "cp-admin-s3cret"
	e := newAuditEnv(t, auditEnvOpts{token: dashTestToken, adminToken: adminTok})
	if rec := e.send("", adminTok, http.MethodPut, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("admin bearer PUT policy = %d %s", rec.Code, rec.Body.String())
	}
	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.AuthMethod != adminaudit.AuthMethodBearer || r.Actor.Sub != actorCPAdminToken || r.ActorRole != "admin" || r.Outcome != adminaudit.OutcomeOK {
		t.Errorf("bearer row = %+v", r)
	}
	for _, bad := range []string{"wrong", dashTestToken, ""} {
		if rec := e.send("", bad, http.MethodPut, "/dashboard/api/policy", policyBody); rec.Code != http.StatusUnauthorized {
			t.Fatalf("PUT policy with bearer %q = %d, want 401", bad, rec.Code)
		}
	}
	if rec := e.send("", "wrong", http.MethodDelete, "/central/secrets/K", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE /central/secrets/K with a wrong bearer = %d", rec.Code)
	}
	if n := len(e.rec.inputs()); n != 1 {
		t.Fatalf("wrong or missing bearer wrote rows: %d total, want 1", n)
	}
	if strings.Contains(e.log.String(), adminTok) || strings.Contains(fmt.Sprintf("%+v", e.rec.inputs()), adminTok) {
		t.Fatal("the admin token reached a log line or a row")
	}
}

// TestAdminAuditOpenWrites: with no token configured at all (development),
// /central/secrets accepts an anonymous write; it is recorded with
// auth_method none, while the dashboard's fail-closed 403 and an anonymous
// 400 write no row.
func TestAdminAuditOpenWrites(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{})
	if rec := e.send("", "", http.MethodPost, "/central/secrets", `{"key":"K","value":"v"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("open POST /central/secrets = %d", rec.Code)
	}
	if rec := e.send("", "", http.MethodPut, "/dashboard/api/policy", policyBody); rec.Code != http.StatusForbidden {
		t.Fatalf("open PUT policy = %d, want 403 (no token: fail closed)", rec.Code)
	}
	// An anonymous request that changes nothing is noise, not a change: no row.
	if rec := e.send("", "", http.MethodPost, "/central/secrets", `not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("open bad POST /central/secrets = %d", rec.Code)
	}
	rows := e.rec.inputs()
	if len(rows) != 1 || rows[0].AuthMethod != adminaudit.AuthMethodNone || rows[0].Actor.Sub != "" || rows[0].TargetRef != "secret:K" {
		t.Fatalf("rows = %+v, want one anonymous secrets row", rows)
	}
}

func TestAdminAuditNoSecretLeak(t *testing.T) {
	const canary = "s3cr3t-canary-123"
	var global bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&global, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	for _, c := range []struct{ path, key string }{
		{"/central/secrets", "OPENAI_KEY"},
		{"/dashboard/api/secretstore", "DASH_KEY"},
	} {
		body := `{"key":"` + c.key + `","value":"` + canary + `"}`
		if rec := e.send(admin, "", http.MethodPost, c.path, body); rec.Code/100 != 2 {
			t.Fatalf("POST %s = %d %s", c.path, rec.Code, rec.Body.String())
		}
	}
	// A failing append logs the entry: it must not carry the value either.
	e.rec.set(errors.New("disk full"), errors.New("disk full"))
	if rec := e.send(admin, "", http.MethodPost, "/central/secrets", `{"key":"LATE","value":"`+canary+`"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("POST with a failing append = %d", rec.Code)
	}

	rows := e.rec.inputs()
	if len(rows) != 2 || rows[0].TargetRef != "secret:OPENAI_KEY" || rows[1].TargetRef != "secret:DASH_KEY" {
		t.Fatalf("rows = %+v, want target_ref secret:<key>", rows)
	}
	ref := secrets.Ref(canary).String()
	dump := fmt.Sprintf("%+v", rows)
	for _, r := range rows {
		if r.BeforeHash != "" || r.AfterHash != "" || r.Details[adminaudit.DetailOp] != "put" {
			t.Errorf("secrets row hashes/details = %q %q %v, want empty hashes and op=put", r.BeforeHash, r.AfterHash, r.Details)
		}
	}
	for name, s := range map[string]string{"rows": dump, "control-plane log": e.log.String(), "global log": global.String()} {
		if strings.Contains(s, canary) || strings.Contains(s, canary[len(canary)-8:]) {
			t.Errorf("%s contains the canary value", name)
		}
	}
	if strings.Contains(dump, ref) || strings.Contains(dump, "sha256:") {
		t.Error("a row contains the secrets.Ref of the value")
	}
	for _, line := range strings.Split(e.log.String(), "\n") {
		if strings.Contains(line, "admin_audit") && (strings.Contains(line, ref) || strings.Contains(line, "sha256:")) {
			t.Errorf("an admin audit log line contains the secrets.Ref: %s", line)
		}
	}
	if !strings.Contains(e.log.String(), "persist_failed=true") {
		t.Error("the failed append was not logged")
	}
}

// TestAdminAuditSerializesMutations: two concurrent policy edits chain: one
// row's after_hash is the other's before_hash. The policy hasher holds the
// first edit's before-hash until a second before-hash starts or 300ms pass, so
// without the admin-mutation lock both edits hash the same "before" state.
func TestAdminAuditSerializesMutations(t *testing.T) {
	db := openAuditDB(t)
	store, err := adminaudit.Open(context.Background(), db, adminaudit.OpenOptions{KeyFile: filepath.Join(t.TempDir(), "cp-audit.key")})
	if err != nil {
		t.Fatal(err)
	}
	e := newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken, db: db, store: store})
	builtin := e.srv.audit.hashers["policy"]
	var (
		mu    sync.Mutex
		calls int
	)
	second := make(chan struct{})
	e.srv.RegisterStateHasher("policy", func(ctx context.Context) (string, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch n {
		case 1:
			h, err := builtin(ctx)
			select {
			case <-second:
			case <-time.After(300 * time.Millisecond):
			}
			return h, err
		case 2:
			close(second)
		}
		return builtin(ctx)
	})
	admin := e.session(t, groupAdmin)
	bodies := []string{
		`{"allowlist":[{"domain":"one.example"}],"denylist":[]}`,
		`{"allowlist":[{"domain":"two.example"}],"denylist":[]}`,
	}
	var wg sync.WaitGroup
	for _, b := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", b); rec.Code != http.StatusOK {
				t.Errorf("POST policy = %d %s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()
	items, err := store.List(context.Background(), adminaudit.Filter{Action: "policy.write"}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("policy rows = %d, want 2", len(items))
	}
	newer, older := items[0], items[1] // List is newest first
	if older.AfterHash != newer.BeforeHash || older.BeforeHash == older.AfterHash {
		t.Fatalf("rows do not chain: older %s -> %s, newer %s -> %s", older.BeforeHash, older.AfterHash, newer.BeforeHash, newer.AfterHash)
	}
	res, err := store.Verify(context.Background(), adminaudit.VerifyOptions{})
	if err != nil || !res.OK {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
	// The real store hashes with its HMAC key.
	if !strings.HasPrefix(older.BeforeHash, adminaudit.StateHashPrefix) {
		t.Errorf("before_hash %q is not an HMAC state hash", older.BeforeHash)
	}
}

func TestAdminAuditBusy(t *testing.T) {
	e := newOIDCAuditEnv(t)
	e.srv.audit.lockTimeout = 20 * time.Millisecond
	e.srv.audit.sem <- struct{}{} // another change holds the lock
	admin := e.session(t, groupAdmin)
	rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "admin_audit_busy") {
		t.Fatalf("POST policy while locked = %d %s, want 503 admin_audit_busy", rec.Code, rec.Body.String())
	}
	<-e.srv.audit.sem
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("POST policy after release = %d", rec.Code)
	}
}

// degradedFindings returns the alerts the admin_audit_degraded Finding raised.
func degradedFindings(e *auditEnv) int {
	n := 0
	for _, a := range e.srv.currentManager().ListAlerts(100) {
		if strings.HasPrefix(a.DedupKey, findingAdminAuditDegraded+":") {
			n++
		}
	}
	return n
}

func TestAdminAuditFailClosed(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	settingsBefore := e.send(admin, "", http.MethodGet, "/dashboard/api/settings", "").Body.String()

	e.srv.audit.degraded.Store(true)
	e.rec.set(nil, errors.New("database is locked"))
	rec := e.send(admin, "", http.MethodPost, "/dashboard/api/settings", `{"logging":{"level":"debug"}}`)
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(rec.Body.String()) != `{"error":"admin_audit_unavailable"}` {
		t.Fatalf("POST settings while unhealthy = %d %q", rec.Code, rec.Body.String())
	}
	if got := e.send(admin, "", http.MethodGet, "/dashboard/api/settings", "").Body.String(); got != settingsBefore {
		t.Fatalf("settings changed although the write was refused:\n%s\n%s", settingsBefore, got)
	}
	if rec := e.send("", dashTestToken, http.MethodGet, "/policy", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /policy while unhealthy = %d", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodGet, "/dashboard/api/policy", ""); rec.Code != http.StatusOK {
		t.Fatalf("dashboard read while unhealthy = %d", rec.Code)
	}
	if degradedFindings(e) != 1 {
		t.Fatal("no admin_audit_degraded Finding was published")
	}
	if len(e.rec.inputs()) != 0 {
		t.Fatal("a refused write was recorded")
	}

	// Once the store answers its probe again, writes resume and are recorded.
	e.rec.set(nil, nil)
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/settings", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("POST settings after recovery = %d %s", rec.Code, rec.Body.String())
	}
	if len(e.rec.inputs()) != 1 || e.srv.audit.degraded.Load() {
		t.Fatal("recovery did not record the write or clear the degraded flag")
	}
}

func TestAdminAuditAppendFailureDegrades(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	e.rec.set(errors.New("disk I/O error"), errors.New("disk I/O error"))
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("POST policy = %d (the change itself succeeds)", rec.Code)
	}
	logs := e.log.String()
	if !strings.Contains(logs, "admin_audit_persist_failed") || !strings.Contains(logs, "persist_failed=true") ||
		!strings.Contains(logs, "action=policy.write") || !strings.Contains(logs, "level=ERROR") {
		t.Fatalf("no persist_failed ERROR line:\n%s", logs)
	}
	if !e.srv.audit.degraded.Load() {
		t.Fatal("the store was not marked degraded")
	}
	if degradedFindings(e) != 1 {
		t.Fatal("no admin_audit_degraded Finding was published")
	}
	// The next audited write is refused before its handler while the probe fails.
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("next POST policy = %d, want 503", rec.Code)
	}
}

// TestAdminAuditDegradedWithoutPipeline: with no alert pipeline the ERROR line
// is the only signal, and nothing panics.
func TestAdminAuditDegradedWithoutPipeline(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, AdminToken: "adm", Logger: logger})
	rec := &fakeRecorder{fail: errors.New("boom"), probeErr: errors.New("boom")}
	srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", strings.NewReader(policyBody))
	req.Header.Set("Authorization", "Bearer adm")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(buf.String(), "persist_failed=true") {
		t.Fatalf("PUT policy = %d; logs:\n%s", w.Code, buf.String())
	}
}

func TestAdminAuditHashError(t *testing.T) {
	e := newOIDCAuditEnv(t)
	e.srv.RegisterStateHasher("policy", func(context.Context) (string, error) { return "", errors.New("unreadable") })
	admin := e.session(t, groupAdmin)
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("POST policy = %d", rec.Code)
	}
	rows := e.rec.inputs()
	if len(rows) != 1 || rows[0].BeforeHash != "" || rows[0].AfterHash != "" || rows[0].Details[detailHashError] != "true" {
		t.Fatalf("rows = %+v, want one row with empty hashes and hash_error=true", rows)
	}
}

func TestAdminAuditRequestID(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody, RequestIDHeader, "req-abc-123")
	if got := rec.Header().Get(RequestIDHeader); got != "req-abc-123" {
		t.Fatalf("echoed request id = %q", got)
	}
	for _, bad := range []string{"has space", "under_score", strings.Repeat("a", 65), ""} {
		rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody, RequestIDHeader, bad)
		got := rec.Header().Get(RequestIDHeader)
		if got == bad || !requestIDPattern.MatchString(got) {
			t.Errorf("incoming %q: response request id %q, want a fresh valid id", bad, got)
		}
	}
	rows := e.rec.inputs()
	if rows[0].RequestID != "req-abc-123" {
		t.Errorf("row request_id = %q", rows[0].RequestID)
	}
	if rows[1].RequestID == rows[2].RequestID {
		t.Error("generated request ids repeat")
	}
	// Reads on a wrapped mount get one too.
	if rec := e.send(admin, "", http.MethodGet, "/dashboard/api/policy", ""); rec.Header().Get(RequestIDHeader) == "" {
		t.Error("a dashboard read has no request id")
	}
}

func TestAdminAuditClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	for _, c := range []struct {
		name, remote, xff string
		want              string
	}{
		{"untrusted peer, xff ignored", "203.0.113.7:4000", "198.51.100.1", "203.0.113.7"},
		{"trusted proxy, left-most xff", "10.1.2.3:4000", "198.51.100.1, 10.9.9.9", "198.51.100.1"},
		{"trusted proxy, skips garbage", "10.1.2.3:4000", "garbage, 198.51.100.2", "198.51.100.2"},
		{"trusted proxy, no xff", "10.1.2.3:4000", "", "10.1.2.3"},
		{"trusted v6 proxy", "[fd00::1]:4000", "2001:db8::5", "2001:db8::5"},
		{"v4-mapped peer", "[::ffff:203.0.113.9]:1", "", "203.0.113.9"},
		{"not an ip", "pipe", "", ""},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r, trusted); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}

	// End to end: console.trustedProxies feeds the row's client_ip.
	cc := authzConsole(defaultRoles())
	cc.TrustedProxies = []string{"192.0.2.0/24"}
	e := newAuditEnv(t, auditEnvOpts{console: cc, token: dashTestToken})
	admin := e.session(t, groupAdmin)
	// httptest requests come from 192.0.2.1.
	e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody, "X-Forwarded-For", "198.51.100.77")
	e2 := newOIDCAuditEnv(t)
	admin2 := e2.session(t, groupAdmin)
	e2.send(admin2, "", http.MethodPost, "/dashboard/api/policy", policyBody, "X-Forwarded-For", "198.51.100.77")
	if got := e.rec.inputs()[0].ClientIP; got != "198.51.100.77" {
		t.Errorf("trusted proxy client_ip = %q", got)
	}
	if got := e2.rec.inputs()[0].ClientIP; got != "192.0.2.1" {
		t.Errorf("untrusted peer client_ip = %q, want the peer", got)
	}
}

// TestAdminAuditDisabledUnchanged: with cfg.AdminAudit nil nothing is wrapped:
// no request id, no lock, no recorder.
func TestAdminAuditDisabledUnchanged(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken})
	if srv.audit != nil {
		t.Fatal("admin audit state exists with AdminAudit nil")
	}
	srv.RegisterStateHasher("x", func(context.Context) (string, error) { return "", nil }) // no-op, no panic
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", strings.NewReader(policyBody))
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get(RequestIDHeader) != "" {
		t.Fatalf("PUT policy = %d, request id %q; want 200 and no request id", w.Code, w.Header().Get(RequestIDHeader))
	}
}

func TestOutcomeFor(t *testing.T) {
	for status, want := range map[int]string{
		200: adminaudit.OutcomeOK, 204: adminaudit.OutcomeOK, 302: adminaudit.OutcomeOK,
		401: adminaudit.OutcomeDenied, 403: adminaudit.OutcomeDenied,
		400: adminaudit.OutcomeRejected, 404: adminaudit.OutcomeRejected, 409: adminaudit.OutcomeRejected,
		500: adminaudit.OutcomeError, 503: adminaudit.OutcomeError,
	} {
		if got := outcomeFor(status); got != want {
			t.Errorf("outcomeFor(%d) = %q, want %q", status, got, want)
		}
	}
}

// hijackRecorder is a ResponseWriter that can be hijacked but not flushed.
type hijackRecorder struct{ http.ResponseWriter }

var errHijackTest = errors.New("hijack reached the underlying writer")

func (hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, errHijackTest }

func TestStatusWriterPreservesInterfaces(t *testing.T) {
	rec := httptest.NewRecorder() // a Flusher, not a Hijacker
	w := wrapStatus(rec).writer()
	if _, ok := w.(http.Flusher); !ok {
		t.Error("lost http.Flusher")
	}
	if _, ok := w.(http.Hijacker); ok {
		t.Error("gained http.Hijacker")
	}
	sw := wrapStatus(rec)
	sw.writer().(http.Flusher).Flush()
	if sw.code() != http.StatusOK || !rec.Flushed {
		t.Errorf("flush: code %d flushed %v", sw.code(), rec.Flushed)
	}

	plain := struct{ http.ResponseWriter }{httptest.NewRecorder()}
	if _, ok := wrapStatus(plain).writer().(http.Flusher); ok {
		t.Error("a plain writer gained http.Flusher")
	}

	hj := hijackRecorder{httptest.NewRecorder()}
	hw := wrapStatus(hj).writer()
	if _, ok := hw.(http.Hijacker); !ok {
		t.Error("lost http.Hijacker")
	}
	if _, ok := hw.(http.Flusher); ok {
		t.Error("gained http.Flusher")
	}
	if _, _, err := hw.(http.Hijacker).Hijack(); !errors.Is(err, errHijackTest) {
		t.Errorf("Hijack did not reach the underlying writer: %v", err)
	}

	both := struct {
		http.ResponseWriter
		http.Flusher
		http.Hijacker
	}{rec, rec, hj}
	bw := wrapStatus(both).writer()
	if _, ok := bw.(http.Flusher); !ok {
		t.Error("flush+hijack: lost Flusher")
	}
	if _, ok := bw.(http.Hijacker); !ok {
		t.Error("flush+hijack: lost Hijacker")
	}

	// WriteHeader is recorded once; a body-only handler is 200.
	sw = wrapStatus(httptest.NewRecorder())
	sw.WriteHeader(http.StatusTeapot)
	sw.WriteHeader(http.StatusOK)
	if sw.code() != http.StatusTeapot {
		t.Errorf("code = %d, want the first status", sw.code())
	}
	sw = wrapStatus(httptest.NewRecorder())
	_, _ = sw.Write([]byte("x"))
	if sw.code() != http.StatusOK {
		t.Errorf("body-only code = %d", sw.code())
	}
	if wrapStatus(rec).Unwrap() != rec {
		t.Error("Unwrap does not return the underlying writer")
	}
}

func TestAddrLimiter(t *testing.T) {
	clk := clocktest.NewFake(time.Unix(0, 0))
	l := newAddrLimiter(clk, time.Minute, 2)
	if !l.allow("a") || l.allow("a") || !l.allow("b") {
		t.Fatal("first per key allowed, repeat refused")
	}
	if l.allow("c") {
		t.Fatal("a full limiter admitted a new key inside the window")
	}
	clk.Advance(time.Minute)
	if !l.allow("c") || !l.allow("a") {
		t.Fatal("keys not allowed again after the window")
	}
}

// TestAdminAuditDetectionAndIntegrationHashes: the integrations and detection
// hashers follow their state.
func TestAdminAuditDetectionAndIntegrationHashes(t *testing.T) {
	e := newOIDCAuditEnv(t)
	ctx := context.Background()
	h1, err := e.srv.audit.stateHash(ctx, "detection")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.WriteDetection(config.DetectionConfig{Enabled: true, ErrorRate: config.DetectErrorRateConfig{Enabled: boolPtr(false)}}); err != nil {
		t.Fatal(err)
	}
	h2, _ := e.srv.audit.stateHash(ctx, "detection")
	if h1 == h2 || h1 == "" {
		t.Errorf("detection hash did not move: %q %q", h1, h2)
	}
	i1, err := e.srv.audit.stateHash(ctx, "integrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.WriteIntegrations([]config.IntegrationInstance{{Type: "webhook", Name: "x", Config: map[string]any{"url": "https://x.example/h"}}}); err != nil {
		t.Fatal(err)
	}
	i2, _ := e.srv.audit.stateHash(ctx, "integrations")
	if i1 == i2 {
		t.Errorf("integrations hash did not move: %q", i1)
	}
	if h, err := e.srv.audit.stateHash(ctx, "no-such-target"); h != "" || err != nil {
		t.Errorf("unregistered target = %q, %v", h, err)
	}
}
