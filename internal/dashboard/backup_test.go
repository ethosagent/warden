package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func backupServer(b BackupStarter) http.Handler {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	if b != nil {
		srv.SetBackup(b)
	}
	return srv.Handler()
}

func postBackup(h http.Handler, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/dashboard/api/backup", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBackupHandler(t *testing.T) {
	var calls int
	for _, c := range []struct {
		name   string
		start  BackupStarter
		method string
		body   string
		status int
		want   string
	}{
		{"started", func() error { calls++; return nil }, http.MethodPost, "", 202, `{"started":true}`},
		{"body ignored and bounded", func() error { calls++; return nil }, http.MethodPost, strings.Repeat("x", 1<<20), 202, `{"started":true}`},
		{"in progress", func() error { return ErrBackupInProgress }, http.MethodPost, "", 409, `{"error":"backup_in_progress"}`},
		{"start failure is generic", func() error { return errors.New("secret detail /srv/x") }, http.MethodPost, "", 500, `{"error":"cannot start the backup"}`},
		{"disabled", nil, http.MethodPost, "", 404, `"error":"not found"`},
		{"get", func() error { return nil }, http.MethodGet, "", 405, "method not allowed"},
		{"put", func() error { return nil }, http.MethodPut, "", 405, "method not allowed"},
		{"delete disabled", nil, http.MethodDelete, "", 405, "method not allowed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := calls
			rec := postBackup(backupServer(c.start), c.method, c.body)
			if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.want) {
				t.Fatalf("%s = %d %s, want %d containing %s", c.method, rec.Code, rec.Body.String(), c.status, c.want)
			}
			if c.status != 202 && calls != before {
				t.Fatal("a refused request started a backup")
			}
		})
	}
	if calls != 2 {
		t.Fatalf("starter called %d times, want 2", calls)
	}
}

func TestBackupHandlerWriteGuard(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetBackup(func() error { t.Fatal("the guard let a write through"); return nil })
	rec := postBackup(srv.Handler(), http.MethodPost, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST backup with no write guard set = %d, want 403 (fail closed)", rec.Code)
	}
}
