package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

type fakeKeys struct {
	rotateErr error
	got       KeyRotateRequest
}

func (f *fakeKeys) Keys(context.Context) KeysResponse { return KeysResponse{} }

func (f *fakeKeys) Rotate(_ context.Context, r KeyRotateRequest) error {
	f.got = r
	return f.rotateErr
}

func keysServer(src KeysSource, authMode string) http.Handler {
	s := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	s.SetWriteGuard(AllowUngatedWritesForTests)
	if src != nil {
		s.SetKeysSource(src)
	}
	s.SetAuthMode(authMode)
	return s.Handler()
}

func keysDo(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestKeysRoutesWithoutSource(t *testing.T) {
	h := keysServer(nil, "oidc")
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/keys"},
		{http.MethodPost, "/dashboard/api/keys/rotate"},
	} {
		if rec := keysDo(h, c.method, c.path, `{"purpose":"token"}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s without a key source = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}

func TestKeysListShape(t *testing.T) {
	rec := keysDo(keysServer(&fakeKeys{}, "oidc"), http.MethodGet, "/dashboard/api/keys", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"keys":[]`) || !strings.Contains(rec.Body.String(), `"purposes":[]`) {
		t.Errorf("empty list = %d %s, want empty arrays, not null", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestKeysRotateErrors(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{ErrKeysInvalid, http.StatusBadRequest},
		{ErrKeysConflict, http.StatusConflict},
		{ErrKeysNoActor, http.StatusUnauthorized},
		{errors.New("backend says: secret-looking detail"), http.StatusInternalServerError},
	} {
		rec := keysDo(keysServer(&fakeKeys{rotateErr: c.err}, "oidc"), http.MethodPost, "/dashboard/api/keys/rotate", `{"purpose":"token"}`)
		if rec.Code != c.want {
			t.Errorf("%v = %d, want %d", c.err, rec.Code, c.want)
		}
		if strings.Contains(rec.Body.String(), "secret-looking") {
			t.Errorf("manager error text leaked: %s", rec.Body)
		}
	}
}

func TestKeysRotateRefusals(t *testing.T) {
	f := &fakeKeys{}
	if rec := keysDo(keysServer(f, "none"), http.MethodPost, "/dashboard/api/keys/rotate", `{"purpose":"token"}`); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "use_cli") {
		t.Errorf("console.auth none = %d %s, want 403 use_cli", rec.Code, rec.Body)
	}
	if rec := keysDo(keysServer(f, ""), http.MethodPost, "/dashboard/api/keys/rotate", `{"purpose":"token"}`); rec.Code != http.StatusForbidden {
		t.Errorf("unset auth mode = %d, want 403 (fail closed)", rec.Code)
	}
	if rec := keysDo(keysServer(f, "oidc"), http.MethodPost, "/dashboard/api/keys/rotate", `{"purpose":"bundle","confirmPinned":true}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "use_cli") {
		t.Errorf("bundle = %d %s, want 409 use_cli", rec.Code, rec.Body)
	}
	if f.got != (KeyRotateRequest{}) {
		t.Errorf("a refused rotation reached the source: %+v", f.got)
	}
	if rec := keysDo(keysServer(f, "oidc"), http.MethodPost, "/dashboard/api/keys/rotate", `{"purpose":"token","emergency":true}`); rec.Code != http.StatusOK || !f.got.Emergency || f.got.Purpose != "token" {
		t.Errorf("emergency token rotate = %d, got %+v", rec.Code, f.got)
	}
	if rec := keysDo(keysServer(f, "oidc"), http.MethodGet, "/dashboard/api/keys/rotate", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET rotate = %d, want 405", rec.Code)
	}
	if rec := keysDo(keysServer(f, "oidc"), http.MethodPost, "/dashboard/api/keys", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST keys = %d, want 405", rec.Code)
	}
}
