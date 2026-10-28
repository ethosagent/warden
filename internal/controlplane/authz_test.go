package controlplane

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
)

const (
	groupViewer = "g-viewers"
	groupEditor = "g-editors"
	groupAdmin  = "g-admins"
)

// authzEnv is a control plane in oidc mode whose sessions are created in-process
// through SessionStore.Create on a fake clock; no login flow is involved.
type authzEnv struct {
	srv    *Server
	h      http.Handler
	log    *syncBuf
	policy string
	clk    *clocktest.Fake // the CP clock port (rate limits)
}

func authzConsole(roles config.ConsoleRoles) config.ConsoleConfig {
	return config.ConsoleConfig{
		Auth:    config.ConsoleAuthOIDC,
		OIDC:    config.ConsoleOIDC{RedirectURL: testRedirectHTTPS},
		Roles:   roles,
		Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
	}
}

func defaultRoles() config.ConsoleRoles {
	return config.ConsoleRoles{Viewer: []string{groupViewer}, Editor: []string{groupEditor}, Admin: []string{groupAdmin}}
}

func newAuthzEnvOn(t *testing.T, db *cpstate.DB, policy string, roles config.ConsoleRoles) *authzEnv {
	t.Helper()
	logger, buf := testLogger()
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	srv := New(Config{PolicyPath: policy, Token: dashTestToken, State: db, Console: authzConsole(roles), Logger: logger, Clock: clk})
	if srv.sessions == nil {
		t.Fatal("oidc mode with a state db must enable sessions")
	}
	srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
	srv.sessionReader = srv.sessions
	return &authzEnv{srv: srv, h: srv.Handler(), log: buf, policy: policy, clk: clk}
}

func newAuthzEnv(t *testing.T) *authzEnv {
	t.Helper()
	return newAuthzEnvOn(t, openSessionDB(t), writePolicyFile(t, "api.openai.com"), defaultRoles())
}

// session creates a session in group and returns its raw id.
func (e *authzEnv) session(t *testing.T, group string) string {
	t.Helper()
	in := testSessionInput()
	in.Groups = []string{group}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// do sends a request as the session rawID ("" for none), with its CSRF token on
// every method but GET.
func (e *authzEnv) do(rawID, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if rawID != "" {
		req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: rawID})
		if method != http.MethodGet {
			req.Header.Set(CSRFHeader, CSRFToken(rawID))
		}
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

const policyBody = `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[]}`

// servedDashboardRoutes is every /dashboard/ route in oidc mode: the
// dashboard's own plus the ones the control plane mounts ahead of it.
func servedDashboardRoutes() []dashboard.Route {
	return append(dashboard.Routes(), cpDashboardRoutes()...)
}

func TestAuthzMatrix(t *testing.T) {
	e := newAuthzEnv(t)
	table := authzTable()
	roles := []struct {
		name  string
		group string
		role  config.Role // 0: a group that maps to no role
	}{
		{"none", "g-unmapped", 0},
		{"viewer", groupViewer, config.RoleViewer},
		{"editor", groupEditor, config.RoleEditor},
		{"admin", groupAdmin, config.RoleAdmin},
	}
	for _, r := range roles {
		raw := e.session(t, r.group)
		for _, rt := range servedDashboardRoutes() {
			row, ok := table[routeKey{rt.Method, rt.Path}]
			if !ok {
				t.Fatalf("%s %s has no authz row", rt.Method, rt.Path)
			}
			rec := e.do(raw, rt.Method, rt.Path, "{}")
			wantDenied := r.role < row.MinRole
			if got := rec.Code == http.StatusForbidden; got != wantDenied {
				t.Errorf("%s %s as %s: status %d, denied=%v want %v", rt.Method, rt.Path, r.name, rec.Code, got, wantDenied)
			}
		}
	}
}

// missingRows names the routes with no table row or a different action.
func missingRows(table map[routeKey]authzRow, routes []dashboard.Route) []string {
	var out []string
	for _, rt := range routes {
		row, ok := table[routeKey{rt.Method, rt.Path}]
		switch {
		case !ok:
			out = append(out, rt.Method+" "+rt.Path+": no authz row")
		case row.Action != rt.Action:
			out = append(out, rt.Method+" "+rt.Path+": action "+row.Action+" != "+rt.Action)
		}
	}
	return out
}

func TestAuthzRouteCoverage(t *testing.T) {
	routes := servedDashboardRoutes()
	table := authzTable()
	if miss := missingRows(table, routes); len(miss) != 0 {
		t.Fatalf("routes without a matching authz row:\n%s", strings.Join(miss, "\n"))
	}
	// A table row for a route nothing serves is dead weight and hides a rename.
	served := map[routeKey]bool{}
	for _, rt := range routes {
		served[routeKey{rt.Method, rt.Path}] = true
	}
	var stale []string
	for k := range table {
		if !served[k] {
			stale = append(stale, k.Method+" "+k.Path)
		}
	}
	sort.Strings(stale)
	if len(stale) != 0 {
		t.Fatalf("authz rows for routes the dashboard does not serve: %v", stale)
	}

	// Every row is classified for the admin audit middleware, and the
	// control plane's own mux patterns are classified too.
	if bad := unclassified(table); len(bad) != 0 {
		t.Fatalf("authz rows without a valid audit classification:\n%s", strings.Join(bad, "\n"))
	}
	if bad := unclassified(cpRouteTable()); len(bad) != 0 {
		t.Fatalf("control-plane routes without a valid audit classification:\n%s", strings.Join(bad, "\n"))
	}
	if miss := unclassifiedPatterns(t, table, cpRouteTable()); len(miss) != 0 {
		t.Fatalf("mux patterns registered in Server.Handler with no classification: %v", miss)
	}
	// Red first: a route added to the dashboard without a classification, or an
	// audited row without its target, is reported by name.
	broken := authzTable()
	broken[routeKey{http.MethodPost, "/dashboard/api/new-writer"}] = authzRow{MinRole: config.RoleAdmin, Action: "new.write"}
	broken[routeKey{http.MethodPut, "/dashboard/api/policy"}] = authzRow{MinRole: config.RoleEditor, Action: "policy.write", Audited: true, Class: classAudited}
	if bad := unclassified(broken); len(bad) != 2 || !strings.Contains(strings.Join(bad, " "), "POST /dashboard/api/new-writer") ||
		!strings.Contains(strings.Join(bad, " "), "PUT /dashboard/api/policy") {
		t.Fatalf("classification check did not name the broken rows: %v", bad)
	}
	cp := cpRouteTable()
	delete(cp, routeKey{http.MethodPost, "/control/heartbeat"})
	if miss := unclassifiedPatterns(t, table, cp); len(miss) != 1 || miss[0] != "/control/heartbeat" {
		t.Fatalf("pattern check did not name the unclassified pattern: %v", miss)
	}

	// Red first: a deleted row is reported by name.
	trimmed := authzTable()
	delete(trimmed, routeKey{http.MethodPost, "/dashboard/api/policy"})
	miss := missingRows(trimmed, routes)
	if len(miss) != 1 || !strings.Contains(miss[0], "POST /dashboard/api/policy") {
		t.Fatalf("coverage check did not name the deleted row: %v", miss)
	}

	// Deny by default: even an admin gets 403 on an unlisted path or method, GET included.
	e := newAuthzEnv(t)
	admin := e.session(t, groupAdmin)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/brand-new"},
		{http.MethodGet, "/dashboard/anything.js"},
		{http.MethodGet, "/dashboard/api/policy/"},
		{http.MethodPatch, "/dashboard/api/policy"},
		{http.MethodDelete, "/dashboard/api/policy"},
		{http.MethodHead, "/dashboard/api/traffic"},
		{http.MethodOptions, "/dashboard/api/traffic"},
		{http.MethodPost, "/dashboard/api/traffic"},
	} {
		if rec := e.do(admin, c.method, c.path, "{}"); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as admin = %d, want 403 (unlisted)", c.method, c.path, rec.Code)
		}
	}
}

func TestOIDCModeBearerNeverOpensDashboard(t *testing.T) {
	e := newAuthzEnv(t)
	// The shared token and any other bearer, with no session, open nothing.
	for _, bearer := range []string{"Bearer " + dashTestToken, "Bearer a-cp-admin-token"} {
		for _, rt := range servedDashboardRoutes() {
			req := httptest.NewRequest(rt.Method, rt.Path, strings.NewReader("{}"))
			req.Header.Set("Authorization", bearer)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			want := http.StatusUnauthorized
			if rt.Path == "/dashboard/" {
				want = http.StatusFound // HTML routes redirect to login
			}
			if rec.Code != want {
				t.Errorf("%s %s with %q only = %d, want %d", rt.Method, rt.Path, bearer, rec.Code, want)
			}
		}
	}
	// A viewer session with CSRF reads.
	viewer := e.session(t, groupViewer)
	if rec := e.do(viewer, http.MethodGet, "/dashboard/api/traffic", ""); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET traffic = %d, want 200", rec.Code)
	}
	// A bearer next to a viewer session adds nothing: the role comes from the session.
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", strings.NewReader(policyBody))
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: viewer})
	req.Header.Set(CSRFHeader, CSRFToken(viewer))
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer + bearer POST policy = %d, want 403", rec.Code)
	}
	// A dead session cookie plus the bearer is still unauthenticated.
	req = httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", strings.NewReader(policyBody))
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: "not-a-session"})
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("dead cookie + bearer POST policy = %d, want 401", rec.Code)
	}
}

func TestAuthzDenials(t *testing.T) {
	e := newAuthzEnv(t)
	viewer := e.session(t, groupViewer)
	for _, c := range []struct{ path, need string }{
		{"/dashboard/api/secretstore", "admin"},
		{"/dashboard/api/policy", "editor"},
	} {
		rec := e.do(viewer, http.MethodPost, c.path, policyBody)
		want := `{"error":"role_required","need":"` + c.need + `"}`
		if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != want {
			t.Errorf("viewer POST %s = %d %q, want 403 %s", c.path, rec.Code, rec.Body.String(), want)
		}
	}

	rec := e.do("", http.MethodGet, "/dashboard/api/traffic", "")
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"unauthenticated"}` {
		t.Errorf("no session API = %d %q, want 401 unauthenticated", rec.Code, rec.Body.String())
	}
	rec = e.do("", http.MethodGet, "/dashboard/", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/auth/login?next=%2Fdashboard%2F" {
		t.Errorf("no session HTML = %d Location %q, want 302 to /auth/login?next=", rec.Code, rec.Header().Get("Location"))
	}
	// A query string survives in next, escaped, and cannot add a second parameter.
	rec = e.do("", http.MethodGet, "/dashboard/?tab=a&x=b", "")
	if loc := rec.Header().Get("Location"); loc != "/auth/login?next=%2Fdashboard%2F%3Ftab%3Da%26x%3Db" {
		t.Errorf("next = %q", loc)
	}

	// A session with no mapped role is refused as role_required, not let through.
	norole := e.session(t, "g-unmapped")
	rec = e.do(norole, http.MethodGet, "/dashboard/api/traffic", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"need":"viewer"`) {
		t.Errorf("unmapped group = %d %q, want 403 need viewer", rec.Code, rec.Body.String())
	}

	// Missing CSRF on a session write is a 403 before any role check.
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", strings.NewReader(policyBody))
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: e.session(t, groupAdmin)})
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != `{"error":"csrf"}` {
		t.Errorf("admin write without CSRF = %d %q, want 403 csrf", rec.Code, rec.Body.String())
	}

	// Denials are logged by route and subject, never with credentials.
	logs := e.log.String()
	for _, want := range []string{"console_authz_denied", "action=secretstore.write", "role=viewer", "sub=u1", "method=POST", "path=/dashboard/api/secretstore"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log missing %q:\n%s", want, logs)
		}
	}
	for _, banned := range []string{viewer, CSRFToken(viewer), dashTestToken, "api.openai.com"} {
		if strings.Contains(logs, banned) {
			t.Errorf("log leaks %q", banned)
		}
	}
}

func TestAuthzEditorSettingsAdminOnly(t *testing.T) {
	e := newAuthzEnv(t)
	e.srv.dash.SetQueryEngine(fakeQuery{})
	e.srv.dash.SetSQLGenerator(sqlGenFunc(func(string) (string, error) { return "SELECT 1", nil }))
	editor := e.session(t, groupEditor)

	// An editor's settings write that touches an admin-only field is refused
	// with that field named (per-field rules: TestAuthzSettingsPerField).
	rec := e.do(editor, http.MethodPost, "/dashboard/api/settings", `{"explore":{"llmProvider":"p1"}}`)
	if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != `{"error":"role_required","need":"admin","fields":["explore"]}` {
		t.Errorf("editor POST settings = %d %q, want 403 need admin fields [explore]", rec.Code, rec.Body.String())
	}
	if rec := e.do(editor, http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Errorf("editor POST policy = %d %s, want 200", rec.Code, rec.Body.String())
	}
	rec = e.do(editor, http.MethodPost, "/dashboard/api/query/generate", `{"question":"count events"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SELECT 1") {
		t.Errorf("editor POST generate = %d %s, want 200", rec.Code, rec.Body.String())
	}
	// And a viewer may not generate.
	if rec := e.do(e.session(t, groupViewer), http.MethodPost, "/dashboard/api/query/generate", `{"question":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("viewer POST generate = %d, want 403", rec.Code)
	}
}

type sqlGenFunc func(string) (string, error)

func (f sqlGenFunc) Evaluate(p string) (string, error) { return f(p) }

func TestAuthzRoleRecomputed(t *testing.T) {
	db := openSessionDB(t)
	policy := writePolicyFile(t, "api.openai.com")
	roles := config.ConsoleRoles{Editor: []string{"eng"}, Admin: []string{groupAdmin}}
	before := newAuthzEnvOn(t, db, policy, roles)
	raw := before.session(t, "eng")
	if rec := before.do(raw, http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("eng as editor POST policy = %d %s, want 200", rec.Code, rec.Body.String())
	}

	// Restart: same state db and the same live session, with eng demoted to viewer.
	after := newAuthzEnvOn(t, db, policy, config.ConsoleRoles{Viewer: []string{"eng"}, Admin: []string{groupAdmin}})
	after.srv.sessions = before.srv.sessions // the session store is the persisted one
	after.srv.sessionReader = before.srv.sessionReader
	after.h = after.srv.Handler()
	if rec := after.do(raw, http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusForbidden {
		t.Fatalf("eng as viewer POST policy = %d, want 403", rec.Code)
	}
	if rec := after.do(raw, http.MethodGet, "/dashboard/api/policy", ""); rec.Code != http.StatusOK {
		t.Fatalf("eng as viewer GET policy = %d, want 200", rec.Code)
	}
}

func TestAuthzActionOnContext(t *testing.T) {
	logger, _ := testLogger()
	var got string
	var found bool
	h := requireRole(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, found = ActionFrom(r.Context())
	}), authzTable(), authzConsole(defaultRoles()), logger)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{Kind: PrincipalSession, Sub: "u1", Groups: []string{groupEditor}}))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !found || got != "policy.write" {
		t.Fatalf("ActionFrom = %q, %v, want policy.write", got, found)
	}
	if _, ok := ActionFrom(context.Background()); ok {
		t.Fatal("ActionFrom must report no action on a bare context")
	}
}

func TestSessionWriteGuard(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "a.example"), Token: dashTestToken})
	g := srv.sessionWriteGuard()
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", nil)
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	if status, _ := g(req); status != http.StatusUnauthorized {
		t.Fatalf("bearer without Principal = %d, want 401", status)
	}
	req = req.WithContext(WithPrincipal(req.Context(), Principal{Kind: PrincipalSession, Sub: "u1"}))
	if status, _ := g(req); status != 0 {
		t.Fatalf("with Principal = %d, want allow", status)
	}
}

// TestNoneModeUnchanged: without console.auth oidc nothing of the authz layer is
// installed. Reads are open, writes need the bearer, and a stray session cookie
// or an unlisted dashboard path is not treated differently.
func TestNoneModeUnchanged(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: openSessionDB(t), Logger: logger})
	h := srv.Handler()
	send := func(method, path, auth string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(policyBody))
		req.AddCookie(&http.Cookie{Name: "__Host-warden_console", Value: "x"})
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := send(http.MethodGet, "/dashboard/api/traffic", ""); c != http.StatusOK {
		t.Errorf("open read = %d, want 200", c)
	}
	if c := send(http.MethodGet, "/dashboard/api/anything-else", ""); c != http.StatusOK {
		t.Errorf("unlisted GET = %d, want the index page (200), as before", c)
	}
	if c := send(http.MethodPut, "/dashboard/api/policy", ""); c != http.StatusUnauthorized {
		t.Errorf("write without bearer = %d, want 401", c)
	}
	if c := send(http.MethodPut, "/dashboard/api/policy", "Bearer "+dashTestToken); c != http.StatusOK {
		t.Errorf("write with bearer = %d, want 200", c)
	}
	if strings.Contains(buf.String(), "console_authz_denied") {
		t.Errorf("none mode ran the authz layer:\n%s", buf.String())
	}
	if _, err := os.Stat(srv.cfg.PolicyPath); err != nil {
		t.Fatal(err)
	}
}

// TestOIDCWithoutSessionsFailsClosed: oidc configured but sessions unavailable
// (no state db) must refuse the dashboard, not fall back to the bearer.
func TestOIDCWithoutSessionsFailsClosed(t *testing.T) {
	logger, _ := testLogger()
	srv := New(Config{PolicyPath: writePolicyFile(t, "a.example"), Token: dashTestToken, Console: authzConsole(defaultRoles()), Logger: logger})
	h := srv.Handler()
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(m, "/dashboard/api/policy", strings.NewReader(policyBody))
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with sessions unavailable = %d, want 401", m, rec.Code)
		}
	}
}

// unclassified names the rows whose audit classification is missing or
// inconsistent: an unknown Class, Audited disagreeing with Class, or an
// audited row without Action or Target.
func unclassified(table map[routeKey]authzRow) []string {
	valid := map[routeClass]bool{classAudited: true, classReadOnly: true, classWorkerPlane: true, classHandlerRecorded: true}
	var out []string
	for k, r := range table {
		name := k.Method + " " + k.Path
		switch {
		case !valid[r.Class]:
			out = append(out, name+": no classification")
		case r.Audited != (r.Class == classAudited):
			out = append(out, name+": Audited disagrees with Class "+string(r.Class))
		case r.Audited && (r.Action == "" || r.Target == ""):
			out = append(out, name+": audited without Action or Target")
		}
	}
	sort.Strings(out)
	return out
}

// unclassifiedPatterns walks the package's non-test sources for patterns
// passed to mux.Handle / mux.HandleFunc (string literals and string
// constants) and returns those neither table classifies. "/dashboard/" is the
// dashboard mount, whose routes the authz table covers row by row.
func unclassifiedPatterns(t *testing.T, dash, cp map[routeKey]authzRow) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot list package sources: %v", err)
	}
	consts := map[string]string{}
	var calls []ast.Expr
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ValueSpec:
				for i, name := range n.Names {
					if i < len(n.Values) {
						if lit, ok := n.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							consts[name.Name], _ = strconv.Unquote(lit.Value)
						}
					}
				}
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || len(n.Args) == 0 || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
					return true
				}
				if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == "mux" {
					calls = append(calls, n.Args[0])
				}
			}
			return true
		})
	}
	paths := map[string]bool{}
	for _, tbl := range []map[routeKey]authzRow{dash, cp} {
		for k := range tbl {
			paths[k.Path] = true
		}
	}
	var out []string
	seen := 0
	for _, arg := range calls {
		var p string
		switch a := arg.(type) {
		case *ast.BasicLit:
			p, _ = strconv.Unquote(a.Value)
		case *ast.Ident:
			p = consts[a.Name]
		}
		if p == "" {
			t.Fatalf("a mux registration uses a pattern the walk cannot resolve: %#v", arg)
		}
		seen++
		if p != "/dashboard/" && !paths[p] {
			out = append(out, p)
		}
	}
	if seen < 10 {
		t.Fatalf("pattern walk found only %d registrations", seen)
	}
	sort.Strings(out)
	return out
}
