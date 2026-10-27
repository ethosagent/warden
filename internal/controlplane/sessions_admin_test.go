package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sessionsPath = "/dashboard/api/sessions"

// sessionAs creates a session for sub in group and returns its raw id.
func (e *authzEnv) sessionAs(t *testing.T, sub, group string) string {
	t.Helper()
	in := testSessionInput()
	in.Sub, in.Email, in.Groups = sub, sub+"@example.com", []string{group}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// alive reports whether rawID still opens a viewer route.
func (e *authzEnv) alive(t *testing.T, rawID string) bool {
	t.Helper()
	switch rec := e.do(rawID, http.MethodGet, "/dashboard/api/traffic", ""); rec.Code {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	default:
		t.Fatalf("GET traffic = %d, want 200 or 401", rec.Code)
		return false
	}
}

func listSessions(t *testing.T, e *authzEnv, rawID string) ([]map[string]any, string) {
	t.Helper()
	rec := e.do(rawID, http.MethodGet, sessionsPath, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET sessions = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out, rec.Body.String()
}

func TestSessionsList(t *testing.T) {
	e := newAuthzEnv(t)
	admin := e.sessionAs(t, "admin-sub", groupAdmin)
	other := e.sessionAs(t, "a", groupViewer)

	rows, body := listSessions(t, e, admin)
	if len(rows) != 2 {
		t.Fatalf("listed %d sessions, want 2: %s", len(rows), body)
	}
	// No raw session id, no CSRF token, no csrf field.
	for _, raw := range []string{admin, other} {
		if strings.Contains(body, raw) || strings.Contains(body, CSRFToken(raw)) {
			t.Fatalf("list leaks a raw session id or its CSRF token: %s", body)
		}
	}
	if strings.Contains(strings.ToLower(body), "csrf") {
		t.Fatalf("list has a csrf field: %s", body)
	}
	want := []string{"handle", "iss", "sub", "email", "authMethod", "createdAt", "lastSeenAt", "expiresAt", "current"}
	byHandle := map[string]map[string]any{}
	for _, r := range rows {
		for _, k := range want {
			if _, ok := r[k]; !ok {
				t.Errorf("row %v lacks %q", r, k)
			}
		}
		if len(r) != len(want) {
			t.Errorf("row has fields %v, want exactly %v", r, want)
		}
		byHandle[r["handle"].(string)] = r
	}
	// handle is the hex id_hash.
	mine, ok := byHandle[hashID(admin)]
	if !ok {
		t.Fatalf("admin's session not listed by its id hash: %s", body)
	}
	if mine["current"] != true || mine["sub"] != "admin-sub" {
		t.Errorf("own row = %v, want current=true sub=admin-sub", mine)
	}
	if r := byHandle[hashID(other)]; r == nil || r["current"] != false || r["email"] != "a@example.com" {
		t.Errorf("other row = %v", r)
	}

	// An empty store lists [] (not null).
	if _, err := e.srv.sessions.DeleteBySub(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.sessions.DeleteBySub(context.Background(), "admin-sub"); err != nil {
		t.Fatal(err)
	}
	admin2 := e.sessionAs(t, "admin-sub", groupAdmin)
	if rows, _ := listSessions(t, e, admin2); len(rows) != 1 {
		t.Fatalf("listed %d, want 1", len(rows))
	}
}

func TestSessionsRevoke(t *testing.T) {
	e := newAuthzEnv(t)
	admin := e.sessionAs(t, "admin-sub", groupAdmin)
	a1 := e.sessionAs(t, "a", groupViewer)
	a2 := e.sessionAs(t, "a", groupEditor)
	b := e.sessionAs(t, "b", groupViewer)
	for _, raw := range []string{a1, a2, b} {
		if !e.alive(t, raw) {
			t.Fatal("session not live before revoke")
		}
	}

	rec := e.do(admin, http.MethodDelete, sessionsPath+"?sub=a", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE ?sub=a = %d: %s", rec.Code, rec.Body.String())
	}
	var got struct{ Revoked int }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Revoked != 2 {
		t.Fatalf("revoke body = %s (%v), want revoked 2", rec.Body.String(), err)
	}
	if e.alive(t, a1) || e.alive(t, a2) {
		t.Fatal("a revoked session still works")
	}
	if !e.alive(t, b) || !e.alive(t, admin) {
		t.Fatal("revoking a removed another subject's session")
	}
	logs := e.log.String()
	if !strings.Contains(logs, "msg=console_session_revoked") || !strings.Contains(logs, "by_sub=admin-sub") ||
		!strings.Contains(logs, "target_sub=a") || !strings.Contains(logs, "count=2") {
		t.Errorf("revoke log missing fields:\n%s", logs)
	}

	t.Run("by_handle", func(t *testing.T) {
		rec := e.do(admin, http.MethodDelete, sessionsPath+"?handle="+hashID(b), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("DELETE ?handle = %d: %s", rec.Code, rec.Body.String())
		}
		if e.alive(t, b) {
			t.Fatal("handle-revoked session still works")
		}
		if !e.alive(t, admin) {
			t.Fatal("admin session lost")
		}
		if strings.Contains(e.log.String(), hashID(b)) {
			t.Error("revoke log carries the full handle")
		}
		// The same handle again is unknown now.
		if rec := e.do(admin, http.MethodDelete, sessionsPath+"?handle="+hashID(b), ""); rec.Code != http.StatusNotFound {
			t.Fatalf("unknown handle = %d, want 404", rec.Code)
		}
	})

	t.Run("bad_input", func(t *testing.T) {
		for _, q := range []string{
			"",                                   // neither
			"?sub=a&handle=" + hashID(b),         // both
			"?handle=not-hex",                    // malformed
			"?handle=" + hashID(b)[:10],          // short
			"?handle=" + strings.Repeat("A", 64), // upper-case is not the stored form
			"?sub=" + strings.Repeat("x", maxRevokeSubLen+1),
		} {
			if rec := e.do(admin, http.MethodDelete, sessionsPath+q, ""); rec.Code != http.StatusBadRequest {
				t.Errorf("DELETE %q = %d, want 400", q, rec.Code)
			}
		}
		if !e.alive(t, admin) {
			t.Fatal("bad input revoked the caller")
		}
	})
}

// TestSessionsRoles: viewers and editors get 403 on both routes; no session is 401.
func TestSessionsRoles(t *testing.T) {
	e := newAuthzEnv(t)
	target := e.sessionAs(t, "a", groupViewer)
	for _, g := range []string{groupViewer, groupEditor} {
		raw := e.sessionAs(t, "u-"+g, g)
		for _, m := range []string{http.MethodGet, http.MethodDelete} {
			rec := e.do(raw, m, sessionsPath+"?sub=a", "")
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"need":"admin"`) {
				t.Errorf("%s as %s = %d %s, want 403 need admin", m, g, rec.Code, rec.Body.String())
			}
		}
	}
	if rec := e.do("", http.MethodGet, sessionsPath, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET with no session = %d, want 401", rec.Code)
	}
	// Other methods are not in the table: refused even for an admin.
	admin := e.sessionAs(t, "admin-sub", groupAdmin)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		if rec := e.do(admin, m, sessionsPath+"?sub=a", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s as admin = %d, want 403", m, rec.Code)
		}
	}
	if !e.alive(t, target) {
		t.Fatal("a refused request revoked a session")
	}
}

// TestSessionsRevokeBearerRefused: the shared token or any admin bearer without
// a session cannot revoke; the target's sessions stay.
func TestSessionsRevokeBearerRefused(t *testing.T) {
	e := newAuthzEnv(t)
	a := e.sessionAs(t, "a", groupViewer)
	for _, bearer := range []string{"Bearer " + dashTestToken, "Bearer a-cp-admin-token"} {
		req := httptest.NewRequest(http.MethodDelete, sessionsPath+"?sub=a", nil)
		req.Header.Set("Authorization", bearer)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("bearer-only DELETE = %d, want 401", rec.Code)
		}
	}
	if !e.alive(t, a) {
		t.Fatal("bearer-only DELETE revoked the session")
	}
}

// TestSessionsRevokeNeedsCSRF: an admin session without (or with a wrong)
// X-Warden-CSRF, or from a foreign Origin, gets 403 and revokes nothing.
func TestSessionsRevokeNeedsCSRF(t *testing.T) {
	e := newAuthzEnv(t)
	admin := e.sessionAs(t, "admin-sub", groupAdmin)
	a := e.sessionAs(t, "a", groupViewer)
	for _, c := range []struct{ name, csrf, origin string }{
		{"missing", "", ""},
		{"wrong", CSRFToken(a), ""},
		{"foreign_origin", CSRFToken(admin), "https://evil.example"},
	} {
		req := httptest.NewRequest(http.MethodDelete, sessionsPath+"?sub=a", nil)
		req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: admin})
		if c.csrf != "" {
			req.Header.Set(CSRFHeader, c.csrf)
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s CSRF: DELETE = %d, want 403", c.name, rec.Code)
		}
	}
	if !e.alive(t, a) {
		t.Fatal("a CSRF-refused DELETE revoked the session")
	}
}

// TestSessionsNoneMode404: in console.auth none the routes do not exist, even
// though the dashboard serves its index page for other unknown paths.
func TestSessionsNoneMode404(t *testing.T) {
	logger, _ := testLogger()
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: openSessionDB(t), Logger: logger})
	h := srv.Handler()
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		for _, auth := range []string{"", "Bearer " + dashTestToken} {
			req := httptest.NewRequest(m, sessionsPath+"?sub=a", nil)
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("none mode %s (auth %t) = %d, want 404", m, auth != "", rec.Code)
			}
		}
	}
}
