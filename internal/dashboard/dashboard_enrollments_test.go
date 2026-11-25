package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// fakeEnrollments is an EnrollmentAdmin over a slice. err, when set, is
// returned by every call.
type fakeEnrollments struct {
	toks    []EnrollmentView
	err     error
	created []EnrollmentRequest
	revoked []string
}

func (f *fakeEnrollments) List(context.Context) ([]EnrollmentView, error) { return f.toks, f.err }

func (f *fakeEnrollments) Create(_ context.Context, r EnrollmentRequest) (EnrollmentView, string, error) {
	if f.err != nil {
		return EnrollmentView{}, "", f.err
	}
	f.created = append(f.created, r)
	v := EnrollmentView{ID: "et_0123456789abcdef", Name: r.Name, WorkerID: r.WorkerID, WorkerIDPrefix: r.WorkerIDPrefix,
		MaxUses: max(r.MaxUses, 1), CreatedBy: "admin", CreatedAt: "2027-01-01T00:00:00Z", ExpiresAt: "2027-01-01T01:00:00Z"}
	f.toks = append(f.toks, v)
	return v, "wet_" + strings.Repeat("a", 52), nil
}

func (f *fakeEnrollments) Revoke(_ context.Context, id string) error {
	if f.err != nil {
		return f.err
	}
	f.revoked = append(f.revoked, id)
	return nil
}

func enServer(t *testing.T, adm EnrollmentAdmin, mode string) http.Handler {
	t.Helper()
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	if adm != nil {
		srv.SetWorkerEnrollments(adm)
	}
	srv.SetAuthMode(mode)
	return srv.Handler()
}

func TestWorkerEnrollmentsAPI(t *testing.T) {
	f := &fakeEnrollments{toks: []EnrollmentView{{ID: "et_1", Name: "n", WorkerIDPrefix: "pool-", MaxUses: 3, Uses: 1, CreatedBy: "u",
		CreatedAt: "2027-01-01T00:00:00Z", RevokedAt: "2027-01-02T00:00:00Z"}}}
	h := enServer(t, f, "oidc")

	rec := wtDo(h, http.MethodGet, workerEnrollmentsPath, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET = %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0]["revokedAt"] == nil ||
		list[0]["workerIdPrefix"] != "pool-" || list[0]["maxUses"] != float64(3) || list[0]["uses"] != float64(1) {
		t.Fatalf("GET body = %s (%v)", rec.Body.String(), err)
	}
	if _, ok := list[0]["workerId"]; ok {
		t.Error("a prefix token row has a workerId")
	}
	for _, k := range []string{"token", "hash", "tokenHash", "token_hash"} {
		if _, ok := list[0][k]; ok {
			t.Errorf("GET row has a %q field", k)
		}
	}

	rec = wtDo(h, http.MethodPost, workerEnrollmentsPath, `{"name":"w1","workerId":"worker-1","expiresIn":"2h"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST = %d %s, Cache-Control %q", rec.Code, rec.Body.String(), rec.Header().Get("Cache-Control"))
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || !strings.HasPrefix(created["token"].(string), "wet_") ||
		created["name"] != "w1" || created["workerId"] != "worker-1" {
		t.Fatalf("POST body = %s (%v)", rec.Body.String(), err)
	}
	if len(f.created) != 1 || f.created[0].ExpiresIn != 2*time.Hour || f.created[0].WorkerID != "worker-1" {
		t.Errorf("admin saw %+v", f.created)
	}
	rec = wtDo(h, http.MethodPost, workerEnrollmentsPath, `{"name":"pool","workerIdPrefix":"pool-","maxUses":5}`)
	if rec.Code != http.StatusCreated || f.created[1].WorkerIDPrefix != "pool-" || f.created[1].MaxUses != 5 {
		t.Fatalf("prefix POST = %d, admin saw %+v", rec.Code, f.created)
	}
	if rec := wtDo(h, http.MethodGet, workerEnrollmentsPath, ""); strings.Contains(rec.Body.String(), "wet_") {
		t.Error("a later GET carries the token")
	}

	if rec := wtDo(h, http.MethodDelete, workerEnrollmentsPath+"/et_1", ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("DELETE = %d %q, want 204", rec.Code, rec.Body.String())
	}
	if len(f.revoked) != 1 || f.revoked[0] != "et_1" {
		t.Errorf("revoked %v", f.revoked)
	}
}

func TestWorkerEnrollmentsAPIErrors(t *testing.T) {
	for _, c := range []struct {
		name         string
		method, path string
		body         string
		err          error
		want         int
	}{
		{"invalid input", http.MethodPost, workerEnrollmentsPath, `{"name":"a","workerId":"w"}`, ErrEnrollmentInvalid, 400},
		{"conflict", http.MethodPost, workerEnrollmentsPath, `{"name":"a","workerId":"w"}`, ErrEnrollmentConflict, 409},
		{"no actor", http.MethodPost, workerEnrollmentsPath, `{"name":"a","workerId":"w"}`, ErrEnrollmentNoActor, 401},
		{"store error", http.MethodPost, workerEnrollmentsPath, `{"name":"a","workerId":"w"}`, context.DeadlineExceeded, 500},
		{"not found", http.MethodDelete, workerEnrollmentsPath + "/et_x", "", ErrEnrollmentNotFound, 404},
		{"revoke error", http.MethodDelete, workerEnrollmentsPath + "/et_x", "", context.DeadlineExceeded, 500},
		{"list error", http.MethodGet, workerEnrollmentsPath, "", context.DeadlineExceeded, 500},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := wtDo(enServer(t, &fakeEnrollments{err: c.err}, "oidc"), c.method, c.path, c.body)
			if rec.Code != c.want {
				t.Fatalf("= %d %s, want %d", rec.Code, rec.Body.String(), c.want)
			}
			if strings.Contains(rec.Body.String(), "deadline") {
				t.Errorf("a store error text reached the client: %s", rec.Body.String())
			}
		})
	}
}

func TestWorkerEnrollmentsAPIBadInput(t *testing.T) {
	f := &fakeEnrollments{}
	h := enServer(t, f, "oidc")
	for name, body := range map[string]string{
		"unknown field":  `{"name":"a","workerId":"w","proxyID":"x"}`,
		"not json":       `nope`,
		"trailing value": `{"name":"a","workerId":"w"}{}`,
		"bad expiresIn":  `{"name":"a","workerId":"w","expiresIn":"tomorrow"}`,
		"zero expiresIn": `{"name":"a","workerId":"w","expiresIn":"0s"}`,
		"neg expiresIn":  `{"name":"a","workerId":"w","expiresIn":"-5m"}`,
		"huge expiresIn": `{"name":"a","workerId":"w","expiresIn":"900000h"}`,
		"string maxUses": `{"name":"a","workerId":"w","maxUses":"3"}`,
	} {
		if rec := wtDo(h, http.MethodPost, workerEnrollmentsPath, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	big := `{"name":"` + strings.Repeat("a", 9<<10) + `","workerId":"w"}`
	if rec := wtDo(h, http.MethodPost, workerEnrollmentsPath, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d, want 413", rec.Code)
	}
	if len(f.created) != 0 {
		t.Errorf("a refused body reached the admin: %+v", f.created)
	}
}

// Without sign-in there is nobody to attribute a mint to: writes are 403
// use_cli (the CLI named), the list still works.
func TestWorkerEnrollmentsAPIAuthNone(t *testing.T) {
	for _, mode := range []string{"none", "", "unknown"} {
		f := &fakeEnrollments{}
		h := enServer(t, f, mode)
		for _, c := range []struct{ method, path string }{
			{http.MethodPost, workerEnrollmentsPath},
			{http.MethodDelete, workerEnrollmentsPath + "/et_1"},
		} {
			rec := wtDo(h, c.method, c.path, `{"name":"a","workerId":"w"}`)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"use_cli"`) ||
				!strings.Contains(rec.Body.String(), "warden control-plane enroll-token") {
				t.Errorf("mode %q %s = %d %s, want 403 use_cli", mode, c.method, rec.Code, rec.Body.String())
			}
		}
		if rec := wtDo(h, http.MethodGet, workerEnrollmentsPath, ""); rec.Code != http.StatusOK {
			t.Errorf("mode %q GET = %d, want 200", mode, rec.Code)
		}
		if len(f.created)+len(f.revoked) != 0 {
			t.Errorf("mode %q: a refused write reached the admin", mode)
		}
	}
}

func TestWorkerEnrollmentsAPIRouting(t *testing.T) {
	// No admin wired (a worker, or workerCA off): every route is 404.
	h := enServer(t, nil, "oidc")
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, workerEnrollmentsPath},
		{http.MethodPost, workerEnrollmentsPath},
		{http.MethodDelete, workerEnrollmentsPath + "/et_1"},
	} {
		if rec := wtDo(h, c.method, c.path, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("unwired %s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
	h = enServer(t, &fakeEnrollments{}, "oidc")
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPut, workerEnrollmentsPath, http.StatusMethodNotAllowed},
		{http.MethodDelete, workerEnrollmentsPath, http.StatusMethodNotAllowed},
		{http.MethodGet, workerEnrollmentsPath + "/et_1", http.StatusMethodNotAllowed},
		{http.MethodPost, workerEnrollmentsPath + "/et_1", http.StatusMethodNotAllowed},
		{http.MethodDelete, workerEnrollmentsPath + "/", http.StatusNotFound},
		{http.MethodDelete, workerEnrollmentsPath + "/a/b", http.StatusNotFound},
	} {
		if rec := wtDo(h, c.method, c.path, ""); rec.Code != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
	if got := RoutePath(workerEnrollmentsPath + "/et_0123"); got != workerEnrollmentsPath+"/{id}" {
		t.Errorf("RoutePath = %q", got)
	}
	for _, p := range []string{workerEnrollmentsPath, workerEnrollmentsPath + "/", workerEnrollmentsPath + "/a/b"} {
		if got := RoutePath(p); got != p {
			t.Errorf("RoutePath(%q) = %q, want it unchanged", p, got)
		}
	}
}
