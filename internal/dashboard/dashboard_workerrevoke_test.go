package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

type fakeWorkerCerts struct {
	n      int
	err    error
	worker string
	serial string
	calls  int
}

func (f *fakeWorkerCerts) Revoke(_ context.Context, w, s string) (int, error) {
	f.calls++
	f.worker, f.serial = w, s
	return f.n, f.err
}

func wcServer(t *testing.T, adm WorkerCertAdmin, mode string) http.Handler {
	t.Helper()
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	if adm != nil {
		srv.SetWorkerCertAdmin(adm)
	}
	srv.SetAuthMode(mode)
	return srv.Handler()
}

func TestWorkerRevokeAPI(t *testing.T) {
	f := &fakeWorkerCerts{n: 2}
	h := wcServer(t, f, "oidc")
	rec := wtDo(h, http.MethodPost, "/dashboard/api/workers/worker-1/revoke", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"revoked":2}` || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST = %d %q", rec.Code, rec.Body.String())
	}
	if f.worker != "worker-1" || f.serial != "" {
		t.Errorf("Revoke(%q, %q)", f.worker, f.serial)
	}
	if rec := wtDo(h, http.MethodPost, "/dashboard/api/workers/worker-1/revoke", `{"serial":"ab12"}`); rec.Code != http.StatusOK || f.serial != "ab12" {
		t.Errorf("POST with a serial = %d, serial %q", rec.Code, f.serial)
	}

	for name, c := range map[string]struct {
		method, path, body string
		want               int
	}{
		"get":          {http.MethodGet, "/dashboard/api/workers/w/revoke", "", http.StatusMethodNotAllowed},
		"unknown key":  {http.MethodPost, "/dashboard/api/workers/w/revoke", `{"id":"x"}`, http.StatusBadRequest},
		"trailing":     {http.MethodPost, "/dashboard/api/workers/w/revoke", `{} {}`, http.StatusBadRequest},
		"not json":     {http.MethodPost, "/dashboard/api/workers/w/revoke", `nope`, http.StatusBadRequest},
		"wrong action": {http.MethodPost, "/dashboard/api/workers/w/other", "", http.StatusNotFound},
		"nested":       {http.MethodPost, "/dashboard/api/workers/a/b/revoke", "", http.StatusNotFound},
		"too big":      {http.MethodPost, "/dashboard/api/workers/w/revoke", `{"serial":"` + strings.Repeat("a", 4096) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		before := f.calls
		if rec := wtDo(h, c.method, c.path, c.body); rec.Code != c.want {
			t.Errorf("%s = %d, want %d", name, rec.Code, c.want)
		}
		if f.calls != before {
			t.Errorf("%s reached the store", name)
		}
	}

	for _, c := range []struct {
		err  error
		want int
	}{
		{ErrWorkerCertNotFound, http.StatusNotFound},
		{ErrWorkerCertInvalid, http.StatusBadRequest},
		{ErrWorkerCertNoActor, http.StatusUnauthorized},
		{errors.New("disk on fire"), http.StatusInternalServerError},
	} {
		rec := wtDo(wcServer(t, &fakeWorkerCerts{err: c.err}, "oidc"), http.MethodPost, "/dashboard/api/workers/w/revoke", "")
		if rec.Code != c.want || strings.Contains(rec.Body.String(), "disk") {
			t.Errorf("error %v = %d %q, want %d", c.err, rec.Code, rec.Body.String(), c.want)
		}
	}
}

func TestWorkerRevokeAPIRefusals(t *testing.T) {
	f := &fakeWorkerCerts{n: 1}
	// Without sign-in there is nobody to attribute the revoke to.
	for _, mode := range []string{"none", ""} {
		rec := wtDo(wcServer(t, f, mode), http.MethodPost, "/dashboard/api/workers/w/revoke", "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "use_cli") || f.calls != 0 {
			t.Errorf("mode %q = %d %q, calls %d", mode, rec.Code, rec.Body.String(), f.calls)
		}
	}
	// No certificate admin (workerCA off): 404.
	if rec := wtDo(wcServer(t, nil, "oidc"), http.MethodPost, "/dashboard/api/workers/w/revoke", ""); rec.Code != http.StatusNotFound {
		t.Errorf("without workerCA = %d, want 404", rec.Code)
	}
}

func TestRoutePathWorkerRevoke(t *testing.T) {
	if got := RoutePath("/dashboard/api/workers/worker-1/revoke"); got != "/dashboard/api/workers/{id}/revoke" {
		t.Errorf("RoutePath = %q", got)
	}
	for _, p := range []string{"/dashboard/api/workers", "/dashboard/api/workers/", "/dashboard/api/workers/w", "/dashboard/api/workers/w/revoke/x"} {
		if got := RoutePath(p); got != p {
			t.Errorf("RoutePath(%q) = %q, want it unchanged", p, got)
		}
	}
}
