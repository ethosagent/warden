package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubProvider is a minimal SecretProvider for handler tests.
type stubProvider struct {
	refreshErr error
}

func (s *stubProvider) GetSecret(string) (string, error) { return "", nil }
func (s *stubProvider) RefreshSecrets() error            { return s.refreshErr }

func doReq(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
	return rr
}

func TestHealthz_OK(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	rr := doReq(t, h, http.MethodGet, "/healthz")
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("healthz body = %q", rr.Body.String())
	}
}

func TestHealthz_MethodNotAllowed(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	if rr := doReq(t, h, http.MethodPost, "/healthz"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("healthz POST = %d, want 405", rr.Code)
	}
}

func TestRefreshSecrets_Success(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	rr := doReq(t, h, http.MethodPost, "/admin/refresh-secrets")
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", rr.Code)
	}
}

func TestRefreshSecrets_HardFail(t *testing.T) {
	h := NewServer(&stubProvider{refreshErr: errors.New("backend down")}).Handler()
	rr := doReq(t, h, http.MethodPost, "/admin/refresh-secrets")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("refresh failure status = %d, want 503", rr.Code)
	}
}

func TestRefreshSecrets_MethodNotAllowed(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	if rr := doReq(t, h, http.MethodGet, "/admin/refresh-secrets"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("refresh GET = %d, want 405", rr.Code)
	}
}
