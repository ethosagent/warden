package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// fakeWorkerTokens is a WorkerTokenAdmin over a slice. err, when set, is
// returned by every call.
type fakeWorkerTokens struct {
	toks    []WorkerTokenView
	err     error
	created []WorkerTokenRequest
	revoked []string
}

func (f *fakeWorkerTokens) List(context.Context) ([]WorkerTokenView, error) { return f.toks, f.err }

func (f *fakeWorkerTokens) Create(_ context.Context, r WorkerTokenRequest) (WorkerTokenView, string, error) {
	if f.err != nil {
		return WorkerTokenView{}, "", f.err
	}
	f.created = append(f.created, r)
	v := WorkerTokenView{ID: "wt_0123456789abcdef", Name: r.Name, ProxyID: r.ProxyID, CreatedBy: "admin", CreatedAt: "2027-01-01T00:00:00Z"}
	f.toks = append(f.toks, v)
	return v, "wwt_" + strings.Repeat("a", 52), nil
}

func (f *fakeWorkerTokens) Revoke(_ context.Context, id string) error {
	if f.err != nil {
		return f.err
	}
	f.revoked = append(f.revoked, id)
	return nil
}

func wtServer(t *testing.T, adm WorkerTokenAdmin, mode string) http.Handler {
	t.Helper()
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	if adm != nil {
		srv.SetWorkerTokens(adm)
	}
	srv.SetAuthMode(mode)
	return srv.Handler()
}

func wtDo(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestWorkerTokensAPI(t *testing.T) {
	f := &fakeWorkerTokens{toks: []WorkerTokenView{{ID: "wt_1", Name: "n", ProxyID: "p", CreatedBy: "u", CreatedAt: "2027-01-01T00:00:00Z", RevokedAt: "2027-01-02T00:00:00Z"}}}
	h := wtServer(t, f, "oidc")

	rec := wtDo(h, http.MethodGet, workerTokensPath, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET = %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0]["revokedAt"] == nil || list[0]["id"] != "wt_1" {
		t.Fatalf("GET body = %s (%v)", rec.Body.String(), err)
	}
	for _, k := range []string{"token", "hash", "tokenHash"} {
		if _, ok := list[0][k]; ok {
			t.Errorf("GET row has a %q field", k)
		}
	}

	rec = wtDo(h, http.MethodPost, workerTokensPath, `{"name":"w1","proxyID":"proxy-1","expiresIn":"720h"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST = %d %s, Cache-Control %q", rec.Code, rec.Body.String(), rec.Header().Get("Cache-Control"))
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || !strings.HasPrefix(created["token"].(string), "wwt_") || created["name"] != "w1" {
		t.Fatalf("POST body = %s (%v)", rec.Body.String(), err)
	}
	if len(f.created) != 1 || f.created[0].ExpiresIn != 720*time.Hour || f.created[0].ProxyID != "proxy-1" {
		t.Errorf("admin saw %+v", f.created)
	}
	if rec := wtDo(h, http.MethodGet, workerTokensPath, ""); strings.Contains(rec.Body.String(), "wwt_") {
		t.Error("a later GET carries the token")
	}

	if rec := wtDo(h, http.MethodDelete, workerTokensPath+"/wt_1", ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("DELETE = %d %q, want 204", rec.Code, rec.Body.String())
	}
	if len(f.revoked) != 1 || f.revoked[0] != "wt_1" {
		t.Errorf("revoked %v", f.revoked)
	}
}

func TestWorkerTokensAPIErrors(t *testing.T) {
	for _, c := range []struct {
		name         string
		method, path string
		body         string
		err          error
		want         int
	}{
		{"invalid input", http.MethodPost, workerTokensPath, `{"name":"a","proxyID":""}`, ErrWorkerTokenInvalid, 400},
		{"conflict", http.MethodPost, workerTokensPath, `{"name":"a","proxyID":"p"}`, ErrWorkerTokenConflict, 409},
		{"no actor", http.MethodPost, workerTokensPath, `{"name":"a","proxyID":"p"}`, ErrWorkerTokenNoActor, 401},
		{"store error", http.MethodPost, workerTokensPath, `{"name":"a","proxyID":"p"}`, context.DeadlineExceeded, 500},
		{"not found", http.MethodDelete, workerTokensPath + "/wt_x", "", ErrWorkerTokenNotFound, 404},
		{"list error", http.MethodGet, workerTokensPath, "", context.DeadlineExceeded, 500},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := wtDo(wtServer(t, &fakeWorkerTokens{err: c.err}, "oidc"), c.method, c.path, c.body)
			if rec.Code != c.want {
				t.Fatalf("= %d %s, want %d", rec.Code, rec.Body.String(), c.want)
			}
			if strings.Contains(rec.Body.String(), "deadline") {
				t.Errorf("a store error text reached the client: %s", rec.Body.String())
			}
		})
	}
}

func TestWorkerTokensAPIBadInput(t *testing.T) {
	f := &fakeWorkerTokens{}
	h := wtServer(t, f, "oidc")
	for name, body := range map[string]string{
		"unknown field":  `{"name":"a","proxyID":"p","proxyIDPrefix":"x-"}`,
		"not json":       `nope`,
		"trailing value": `{"name":"a","proxyID":"p"}{}`,
		"bad expiresIn":  `{"name":"a","proxyID":"p","expiresIn":"tomorrow"}`,
		"zero expiresIn": `{"name":"a","proxyID":"p","expiresIn":"0s"}`,
		"neg expiresIn":  `{"name":"a","proxyID":"p","expiresIn":"-5m"}`,
		"huge expiresIn": `{"name":"a","proxyID":"p","expiresIn":"900000h"}`,
		"wrong type":     `{"name":5,"proxyID":"p"}`,
	} {
		if rec := wtDo(h, http.MethodPost, workerTokensPath, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	big := `{"name":"` + strings.Repeat("a", maxWorkerTokenBody) + `","proxyID":"p"}`
	if rec := wtDo(h, http.MethodPost, workerTokensPath, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized = %d, want 413", rec.Code)
	}
	if len(f.created) != 0 {
		t.Errorf("a refused request reached the admin: %+v", f.created)
	}
	for _, p := range []string{workerTokensPath + "/", workerTokensPath + "/a/b"} {
		if rec := wtDo(h, http.MethodDelete, p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := wtDo(h, http.MethodGet, workerTokensPath+"/wt_1", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET one = %d, want 405", rec.Code)
	}
}

// Without sign-in there is no identity to attribute a mint to: writes are
// use_cli, reads are fine, and an unset mode fails closed like none.
func TestWorkerTokensAPIUseCLI(t *testing.T) {
	for _, mode := range []string{"none", ""} {
		f := &fakeWorkerTokens{}
		h := wtServer(t, f, mode)
		for _, c := range []struct{ method, path string }{{http.MethodPost, workerTokensPath}, {http.MethodDelete, workerTokensPath + "/wt_1"}} {
			rec := wtDo(h, c.method, c.path, `{"name":"a","proxyID":"p"}`)
			var body map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != http.StatusForbidden || body["error"] != "use_cli" || !strings.Contains(body["message"], "warden control-plane token") {
				t.Errorf("mode %q %s = %d %s, want 403 use_cli", mode, c.method, rec.Code, rec.Body.String())
			}
		}
		if len(f.created)+len(f.revoked) != 0 {
			t.Errorf("mode %q: a use_cli request reached the admin", mode)
		}
		if rec := wtDo(h, http.MethodGet, workerTokensPath, ""); rec.Code != http.StatusOK {
			t.Errorf("mode %q GET = %d, want 200", mode, rec.Code)
		}
	}
}

// A dashboard without SetWorkerTokens (a worker) does not serve the routes.
func TestWorkerTokensAPIAbsent(t *testing.T) {
	h := wtServer(t, nil, "oidc")
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, workerTokensPath}, {http.MethodPost, workerTokensPath}, {http.MethodDelete, workerTokensPath + "/wt_1"},
	} {
		if rec := wtDo(h, c.method, c.path, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}

// The shared write guard runs ahead of the handler: a write without
// credentials never reaches the admin.
func TestWorkerTokensAPIWriteGuard(t *testing.T) {
	f := &fakeWorkerTokens{}
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWorkerTokens(f)
	srv.SetAuthMode("oidc")
	srv.SetWriteGuard(func(r *http.Request) (int, string) {
		if r.Header.Get("Authorization") != "Bearer ok" {
			return http.StatusUnauthorized, "unauthorized"
		}
		return 0, ""
	})
	h := srv.Handler()
	if rec := wtDo(h, http.MethodPost, workerTokensPath, `{"name":"a","proxyID":"p"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("POST without credentials = %d, want 401", rec.Code)
	}
	if rec := wtDo(h, http.MethodDelete, workerTokensPath+"/wt_1", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("DELETE without credentials = %d, want 401", rec.Code)
	}
	if len(f.created)+len(f.revoked) != 0 {
		t.Error("a refused write reached the admin")
	}
}

func TestWorkerViewAuthFields(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWorkers(func() []WorkerView {
		return []WorkerView{
			{ProxyID: "t", AuthKind: "token", TokenName: "tok", TokenLastUsed: "2027-01-01T00:00:00Z"},
			{ProxyID: "l", AuthKind: "legacy", LegacyRequests: 7},
			{ProxyID: "n"},
		}
	})
	rec := wtDo(srv.Handler(), http.MethodGet, "/dashboard/api/workers", "")
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 3 {
		t.Fatalf("body = %s (%v)", rec.Body.String(), err)
	}
	if got[0]["authKind"] != "token" || got[0]["tokenName"] != "tok" || got[0]["tokenLastUsed"] != "2027-01-01T00:00:00Z" || got[0]["legacyRequests"] != float64(0) {
		t.Errorf("token worker = %v", got[0])
	}
	if got[1]["authKind"] != "legacy" || got[1]["legacyRequests"] != float64(7) {
		t.Errorf("legacy worker = %v", got[1])
	}
	if _, ok := got[2]["authKind"]; ok {
		t.Errorf("unauthenticated worker has an authKind: %v", got[2])
	}
}

// --- console panel and fleet badge (W-P1-WTOK-10): string-level tests on the
// served HTML, since the repo has no browser harness ---

func workerTokensJS(t *testing.T, html string) (load, create, revoke, show string) {
	t.Helper()
	js := html[strings.Index(html, "<script>"):]
	return funcBody(t, js, "async function loadWorkerTokens(){"),
		funcBody(t, js, "async function createWorkerToken(){"),
		funcBody(t, js, "async function revokeWorkerToken(id,name){"),
		funcBody(t, js, "function showWorkerToken(tok){")
}

func TestWorkerTokensPanelServedHTML(t *testing.T) {
	html := servedIndex(t)
	start := strings.Index(html, `id="wtok-card"`)
	if start < 0 {
		t.Fatal("Worker tokens panel (id=wtok-card) not found")
	}
	if !strings.Contains(html[start:start+600], "Worker tokens") {
		t.Error("panel has no Worker tokens heading")
	}
	// The card sits on the fleet page, outside demo-only so it shows before
	// the first worker connects.
	fleet := strings.Index(html, `id="page-fleet"`)
	end := strings.Index(html[fleet:], "</section>")
	if start < fleet || start > fleet+end {
		t.Fatal("panel is not inside the fleet page")
	}
	demo := strings.Index(html[fleet:], `class="demo-only"`)
	if demo >= 0 && start > fleet+demo && start < fleet+strings.Index(html[fleet:], "<!-- /demo-only -->") {
		t.Fatal("panel is inside the demo-only block, which hides it until a worker exists")
	}

	load, create, revoke, _ := workerTokensJS(t, html)
	if !strings.Contains(load, "api('GET','/dashboard/api/worker-tokens')") {
		t.Error("loadWorkerTokens must list through api('GET', ...)")
	}
	if !strings.Contains(create, "api('POST','/dashboard/api/worker-tokens'") {
		t.Error("createWorkerToken must POST through api()")
	}
	if !strings.Contains(revoke, "api('DELETE','/dashboard/api/worker-tokens/'+encodeURIComponent(id))") {
		t.Error("revokeWorkerToken must DELETE through api() with an encoded id")
	}
	if !strings.Contains(revoke, "window.confirm(") {
		t.Error("revoke must confirm first")
	}
	all := load + create + revoke
	if strings.Contains(strings.ToLower(all), "csrf") || strings.Contains(all, "fetch(") {
		t.Error("the panel must not handle CSRF or call fetch itself; api() sets X-Warden-CSRF")
	}
	if !strings.Contains(funcBody(t, html[strings.Index(html, "<script>"):], "async function api(method,url,body,hdrs){"), "X-Warden-CSRF") {
		t.Error("api() must set the CSRF header on writes")
	}

	// Writes are admin-only in oidc; none mode shows a read-only list and the CLI notice.
	if !strings.Contains(load, "authMode==='oidc'&&roleAllows('admin')") {
		t.Error("write controls must depend on an oidc admin")
	}
	if !strings.Contains(html, "warden control-plane token create") {
		t.Error("none-mode notice must point to `warden control-plane token create`")
	}
	for _, marker := range []string{`id="wtok-new"`, `wtok-revoke"`} {
		for _, loc := range regexp.MustCompile(regexp.QuoteMeta(marker)).FindAllStringIndex(html, -1) {
			if tag := tagAt(html, loc[0]); strings.HasPrefix(tag, "<button") && !strings.Contains(tag, `data-min-role="admin"`) {
				t.Errorf("%s: button without data-min-role=\"admin\": %.160s", marker, tag)
			}
		}
	}

	// Names and proxy ids reach the DOM only through esc().
	for _, f := range []string{"x.name", "x.proxyID", "x.id"} {
		for _, loc := range regexp.MustCompile(regexp.QuoteMeta(f)).FindAllStringIndex(load, -1) {
			if !strings.HasSuffix(load[:loc[0]], "esc(") {
				t.Errorf("%s rendered without esc(): %.80s", f, load[loc[0]-20:])
			}
		}
	}
}

func TestWorkerTokensPanelShowOnce(t *testing.T) {
	html := servedIndex(t)
	i := strings.Index(html, `id="wtokDialog"`)
	if i < 0 {
		t.Fatal("one-time token dialog (id=wtokDialog) not found")
	}
	dlg := html[i:]
	dlg = dlg[:strings.Index(dlg, "</dialog>")]
	low := strings.ToLower(dlg)
	if !strings.Contains(low, "only once") || !strings.Contains(low, "cannot be shown again") {
		t.Error("modal must carry the show-once warning")
	}
	for _, id := range []string{`id="wtok-value"`, `id="wtok-copy"`} {
		if !strings.Contains(dlg, id) {
			t.Errorf("modal lacks %s", id)
		}
	}

	load, create, revoke, show := workerTokensJS(t, html)
	js := html[strings.Index(html, "<script>"):]
	if !strings.Contains(show, "textContent=tok") {
		t.Error("the token must be set with textContent")
	}
	if strings.Contains(show, "innerHTML") {
		t.Error("the token must never go through innerHTML")
	}
	closer := funcBody(t, js, "function clearWorkerToken(){")
	if !strings.Contains(closer, "textContent=''") {
		t.Error("closing the modal must clear the token from the DOM")
	}
	if !strings.Contains(js, "'close',clearWorkerToken") {
		t.Error("the dialog's close event (Esc included) must clear the token")
	}
	// The token never reaches storage, a URL or a log.
	for name, body := range map[string]string{"load": load, "create": create, "revoke": revoke, "show": show, "clear": closer} {
		for _, bad := range []string{"localStorage", "sessionStorage", "location.", "history.", "console.", "encodeURIComponent(tok", "innerHTML=tok", "alert("} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: forbidden %q near the token", name, bad)
			}
		}
	}
	// The only .token read is the 201 body, passed straight to the modal.
	if strings.Count(create, ".token") != 1 || !strings.Contains(create, "showWorkerToken(") {
		t.Error("create must hand the 201 token only to showWorkerToken")
	}
}

func TestFleetLegacyBadgeServedHTML(t *testing.T) {
	html := servedIndex(t)
	js := html[strings.Index(html, "<script>"):]
	if !strings.Contains(html, "<th>Auth</th>") {
		t.Error("fleet table has no Auth column")
	}
	badge := funcBody(t, js, "function fleetAuthBadge(w){")
	for _, want := range []string{"'legacy'", "'none'", "legacy / unverified", "'token'", "esc(w.tokenName"} {
		if !strings.Contains(badge, want) {
			t.Errorf("fleetAuthBadge lacks %s", want)
		}
	}
	render := funcBody(t, js, "function renderFleet(ws){")
	if !strings.Contains(render, "fleetAuthBadge(w)") {
		t.Error("renderFleet must render the badge")
	}
}
