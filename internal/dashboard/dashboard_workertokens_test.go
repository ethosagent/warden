package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
