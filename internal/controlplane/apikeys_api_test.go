package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/dashboard"
)

const keysPath = "/dashboard/api/api-keys"

func TestAPIKeysPathMatchesDashboard(t *testing.T) {
	if apiKeysPath != dashboard.APIKeysPath || apiKeysSubtree != dashboard.APIKeysPath+"/" {
		t.Fatalf("apiKeysPath %q / %q diverged from dashboard.APIKeysPath %q", apiKeysPath, apiKeysSubtree, dashboard.APIKeysPath)
	}
}

// session creates a console session for sub in group (method oidc or
// breakglass) and returns its raw id.
func (e *keyEnv) session(sub, group, method string) string {
	e.t.Helper()
	raw, _, err := e.srv.sessions.Create(context.Background(), SessionInput{
		Iss: keyOwnerIss, Sub: sub, Email: sub + "@example.com", Groups: []string{group}, AuthMethod: method,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// as sends a request as the session raw, with its CSRF token on writes.
func (e *keyEnv) as(raw, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:4242"
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: raw})
	if method != http.MethodGet {
		req.Header.Set(CSRFHeader, CSRFToken(raw))
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

type createdKey struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"createdAt"`
	ExpiresAt string   `json:"expiresAt"`
	Key       string   `json:"key"`
}

func (e *keyEnv) create(raw, body string) (*httptest.ResponseRecorder, createdKey) {
	e.t.Helper()
	rec := e.as(raw, http.MethodPost, keysPath, body)
	var k createdKey
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &k); err != nil {
			e.t.Fatalf("create body: %v", err)
		}
	}
	return rec, k
}

func TestAPIKeysAPIPlaintextOnce(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	editor := e.session("alice", groupEditor, "oidc")
	rec, k := e.create(editor, `{"name":"ci","description":"deploys","scopes":["policy:read"],"expiresIn":"720h"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create = %d %q %s, want 201 no-store", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	if !apikeys.LooksLikeKey(k.Key) || k.ID == "" || k.Name != "ci" || len(k.Scopes) != 1 || k.ExpiresAt == "" || k.CreatedAt == "" {
		t.Fatalf("201 body = %+v", k)
	}
	if want := e.clk.Now().Add(720 * time.Hour).UTC().Format(time.RFC3339); k.ExpiresAt != want {
		t.Errorf("expiresAt = %s, want %s", k.ExpiresAt, want)
	}
	// The returned key works.
	wantStatus(t, e.do(k.Key, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "the new key")

	secret := k.Key[strings.LastIndex(k.Key, "_")+1:]
	// Neither the key, its secret nor a hash of either is in any later response,
	// audit row or log line.
	var seen strings.Builder
	for _, path := range []string{keysPath, keysPath + "/self"} {
		var rec *httptest.ResponseRecorder
		if strings.HasSuffix(path, "/self") {
			rec = e.do(k.Key, http.MethodGet, path, "")
		} else {
			rec = e.as(editor, http.MethodGet, path, "")
		}
		wantStatus(t, rec, http.StatusOK, "GET "+path)
		seen.WriteString(rec.Body.String())
	}
	for _, in := range e.rec.inputs() {
		fmt.Fprintf(&seen, "%+v\n", in)
	}
	seen.WriteString(e.logs.String())
	bad := []string{k.Key, secret}
	raw, derr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if derr != nil {
		t.Fatal(derr)
	}
	for _, in := range [][]byte{[]byte(k.Key), []byte(secret), raw} {
		sum := sha256.Sum256(in)
		bad = append(bad, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	for _, b := range bad {
		if strings.Contains(seen.String(), b) {
			t.Errorf("a response, audit row or log line holds %q...", b[:8])
		}
	}
	// The create itself is one audit row, naming the key but not the plaintext.
	rows := e.rec.inputs()
	if len(rows) != 1 || rows[0].Action != "api_key.create" || rows[0].Target != "api_keys" ||
		rows[0].TargetRef != "api_key:"+k.ID || rows[0].Details[adminaudit.DetailScopes] != "policy:read" ||
		rows[0].Details[adminaudit.DetailExpiresAt] != k.ExpiresAt || rows[0].AuthMethod != adminaudit.AuthMethodOIDC ||
		rows[0].Outcome != adminaudit.OutcomeOK {
		t.Fatalf("audit rows = %+v", rows)
	}
	// The row records the owner snapshot.
	got, err := e.store.Get(context.Background(), k.ID)
	if err != nil || got.OwnerIss != keyOwnerIss || got.OwnerSub != "alice" || got.OwnerEmail != "alice@example.com" ||
		len(got.OwnerGroups) != 1 || got.OwnerGroups[0] != groupEditor || got.Description != "deploys" {
		t.Fatalf("stored key = %+v (%v)", got, err)
	}
}

func TestAPIKeysCreateCaps(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	viewer := e.session("vic", groupViewer, "oidc")
	rec, _ := e.create(viewer, `{"name":"w","scopes":["policy:write"]}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "policy:write") {
		t.Fatalf("viewer asking policy:write = %d %s, want 403 naming policy:write", rec.Code, rec.Body.String())
	}
	if keys, _ := e.store.List(context.Background(), apikeys.ListFilter{}); len(keys) != 0 {
		t.Fatalf("a refused create left %d rows", len(keys))
	}
	rec, _ = e.create(viewer, `{"name":"r","scopes":["policy:read"]}`)
	wantStatus(t, rec, http.StatusCreated, "viewer asking policy:read")

	// The cap follows the creator's role: an editor may take editor scopes but not admin ones.
	editor := e.session("eve", groupEditor, "oidc")
	rec, _ = e.create(editor, `{"name":"d","scopes":["policy:draft","adminaudit:read","workers:admin"]}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "adminaudit:read") ||
		!strings.Contains(rec.Body.String(), "workers:admin") || strings.Contains(rec.Body.String(), "policy:draft") {
		t.Errorf("editor = %d %s, want 403 listing only the admin scopes", rec.Code, rec.Body.String())
	}
	admin := e.session("ada", groupAdmin, "oidc")
	rec, _ = e.create(admin, `{"name":"a","scopes":["workers:admin"]}`)
	wantStatus(t, rec, http.StatusCreated, "admin asking workers:admin")

	// A break-glass session and a key cannot mint a key.
	bg := e.session("breakglass-admin", groupAdmin, AuthMethodBreakglass)
	rec = e.as(bg, http.MethodPost, keysPath, `{"name":"bg","scopes":["policy:read"]}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"session_required"`) {
		t.Errorf("break-glass create = %d %s, want 403 session_required", rec.Code, rec.Body.String())
	}
	tok, _ := e.mint("ada", groupAdmin, e.allScopes()...)
	rec = e.do(tok, http.MethodPost, keysPath, `{"name":"k","scopes":["policy:read"]}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"session_required"`) {
		t.Errorf("key create = %d %s, want 403 session_required", rec.Code, rec.Body.String())
	}
	// A user with no console role is refused by the table before the handler.
	none := e.session("nobody", "g-unmapped", "oidc")
	wantStatus(t, e.as(none, http.MethodPost, keysPath, `{"name":"n","scopes":["policy:read"]}`), http.StatusForbidden, "no role")
}

func TestAPIKeysValidation(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	ed := e.session("eve", groupEditor, "oidc")
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"unknown scope":    {`{"name":"x","scopes":["foo:bar"]}`, http.StatusBadRequest},
		"no scopes":        {`{"name":"x","scopes":[]}`, http.StatusBadRequest},
		"missing scopes":   {`{"name":"x"}`, http.StatusBadRequest},
		"duplicate scope":  {`{"name":"x","scopes":["policy:read","policy:read"]}`, http.StatusBadRequest},
		"empty name":       {`{"name":"","scopes":["policy:read"]}`, http.StatusBadRequest},
		"long name":        {`{"name":"` + strings.Repeat("n", 65) + `","scopes":["policy:read"]}`, http.StatusBadRequest},
		"ttl too long":     {`{"name":"x","scopes":["policy:read"],"expiresIn":"9000h"}`, http.StatusBadRequest},
		"ttl too short":    {`{"name":"x","scopes":["policy:read"],"expiresIn":"1m"}`, http.StatusBadRequest},
		"ttl unparsable":   {`{"name":"x","scopes":["policy:read"],"expiresIn":"soon"}`, http.StatusBadRequest},
		"ttl negative":     {`{"name":"x","scopes":["policy:read"],"expiresIn":"-5h"}`, http.StatusBadRequest},
		"unknown field":    {`{"name":"x","scopes":["policy:read"],"owner":"root"}`, http.StatusBadRequest},
		"not json":         {`nope`, http.StatusBadRequest},
		"oversized":        {`{"name":"x","description":"` + strings.Repeat("d", 9000) + `","scopes":["policy:read"]}`, http.StatusBadRequest},
		"long description": {`{"name":"x","description":"` + strings.Repeat("d", 600) + `","scopes":["policy:read"]}`, http.StatusBadRequest},
	} {
		rec := e.as(ed, http.MethodPost, keysPath, c.body)
		if rec.Code != c.want {
			t.Errorf("%s = %d %s, want %d", name, rec.Code, rec.Body.String(), c.want)
		}
	}
	if keys, _ := e.store.List(context.Background(), apikeys.ListFilter{}); len(keys) != 0 {
		t.Fatalf("refused creates left %d rows", len(keys))
	}

	// Duplicate name: 409, even after the first key is revoked (the name stays taken).
	_, first := e.create(ed, `{"name":"dup","scopes":["policy:read"]}`)
	rec := e.as(ed, http.MethodPost, keysPath, `{"name":"dup","scopes":["policy:read"]}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate name = %d %s, want 409", rec.Code, rec.Body.String())
	}
	wantStatus(t, e.as(ed, http.MethodDelete, keysPath+"/"+first.ID, ""), http.StatusNoContent, "revoke")
	wantStatus(t, e.as(ed, http.MethodPost, keysPath, `{"name":"dup","scopes":["policy:read"]}`), http.StatusConflict, "name of a revoked key")

	// The default TTL applies without expiresIn, and the cap counts active keys.
	_, def := e.create(ed, `{"name":"default-ttl","scopes":["policy:read"]}`)
	if want := e.clk.Now().Add(2160 * time.Hour).UTC().Format(time.RFC3339); def.ExpiresAt != want {
		t.Errorf("default expiry = %s, want %s", def.ExpiresAt, want)
	}
	for i := 2; i <= 25; i++ { // default-ttl is the 1st active key
		rec, _ := e.create(ed, fmt.Sprintf(`{"name":"k%d","scopes":["policy:read"]}`, i))
		if rec.Code != http.StatusCreated {
			t.Fatalf("key %d = %d %s", i, rec.Code, rec.Body.String())
		}
	}
	before, _ := e.store.List(context.Background(), apikeys.ListFilter{})
	rec = e.as(ed, http.MethodPost, keysPath, `{"name":"k26","scopes":["policy:read"]}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("26th key = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if after, _ := e.store.List(context.Background(), apikeys.ListFilter{}); len(after) != len(before) {
		t.Errorf("the refused 26th key created a row")
	}
	// A failed request writes a rejected row, never an ok one.
	rows := e.rec.inputs()
	if last := rows[len(rows)-1]; last.Outcome != adminaudit.OutcomeRejected || last.HTTPStatus != http.StatusConflict {
		t.Errorf("last row = %+v, want rejected 409", last)
	}
}

func TestAPIKeysRevokeImmediate(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	ed := e.session("eve", groupEditor, "oidc")
	_, k := e.create(ed, `{"name":"ci","scopes":["policy:read"]}`)
	wantStatus(t, e.do(k.Key, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "before revoke")

	rec := e.as(ed, http.MethodDelete, keysPath+"/"+k.ID, "")
	wantStatus(t, rec, http.StatusNoContent, "revoke")
	// Same instant, no clock advance, no poll: the next request is already 401.
	rec = e.do(k.Key, http.MethodGet, "/dashboard/api/policy", "")
	wantStatus(t, rec, http.StatusUnauthorized, "after revoke")
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
	}
	got, _ := e.store.Get(context.Background(), k.ID)
	if got.RevokedAt.IsZero() || got.RevokedBy != "eve" {
		t.Errorf("stored key revoked_at %v by %q", got.RevokedAt, got.RevokedBy)
	}

	// Repeating the revoke is 204 and writes no second audit row.
	rows := len(e.rec.inputs())
	wantStatus(t, e.as(ed, http.MethodDelete, keysPath+"/"+k.ID, ""), http.StatusNoContent, "second revoke")
	if got := len(e.rec.inputs()); got != rows {
		t.Errorf("a repeated revoke wrote %d new rows", got-rows)
	}
	again, _ := e.store.Get(context.Background(), k.ID)
	if !again.RevokedAt.Equal(got.RevokedAt) {
		t.Errorf("a repeated revoke moved revoked_at %v -> %v", got.RevokedAt, again.RevokedAt)
	}
	// Unknown and malformed ids are 404.
	wantStatus(t, e.as(ed, http.MethodDelete, keysPath+"/0123456789abcdef", ""), http.StatusNotFound, "unknown id")
	wantStatus(t, e.as(ed, http.MethodDelete, keysPath+"/not-an-id", ""), http.StatusNotFound, "malformed id")

	// Ownership: another editor may not revoke it, an admin may, a key may not.
	_, mine := e.create(ed, `{"name":"mine","scopes":["policy:read"]}`)
	other := e.session("olga", groupEditor, "oidc")
	wantStatus(t, e.as(other, http.MethodDelete, keysPath+"/"+mine.ID, ""), http.StatusForbidden, "another editor")
	wantStatus(t, e.do(mine.Key, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "still valid")
	tok, _ := e.mint("eve", groupAdmin, e.allScopes()...)
	wantStatus(t, e.do(tok, http.MethodDelete, keysPath+"/"+mine.ID, ""), http.StatusForbidden, "a key revoking")
	admin := e.session("ada", groupAdmin, "oidc")
	wantStatus(t, e.as(admin, http.MethodDelete, keysPath+"/"+mine.ID, ""), http.StatusNoContent, "admin revoke")
	wantStatus(t, e.do(mine.Key, http.MethodGet, "/dashboard/api/policy", ""), http.StatusUnauthorized, "after admin revoke")
	// Revoking needs the CSRF token like any write.
	_, third := e.create(ed, `{"name":"third","scopes":["policy:read"]}`)
	req := httptest.NewRequest(http.MethodDelete, keysPath+"/"+third.ID, nil)
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: ed})
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNoContent {
		t.Errorf("revoke without CSRF = %d, want a refusal", rec.Code)
	}
}

func TestAPIKeysRevokeOwner(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	var toks []string
	for range 3 {
		tok, _ := e.mint("sam", groupEditor, "policy:read")
		toks = append(toks, tok)
	}
	bystander, _ := e.mint("bea", groupEditor, "policy:read")
	editor := e.session("eve", groupEditor, "oidc")
	wantStatus(t, e.as(editor, http.MethodDelete, keysPath+"?owner_sub=sam", ""), http.StatusForbidden, "editor revoke-by-owner")
	wantStatus(t, e.do(toks[0], http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "after refused revoke-by-owner")

	admin := e.session("ada", groupAdmin, "oidc")
	wantStatus(t, e.as(admin, http.MethodDelete, keysPath, ""), http.StatusBadRequest, "no owner_sub")
	rec := e.as(admin, http.MethodDelete, keysPath+"?owner_sub=sam", "")
	wantStatus(t, rec, http.StatusOK, "revoke-by-owner")
	var out map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["revoked"] != 3 {
		t.Fatalf("body = %s, want {revoked:3}", rec.Body.String())
	}
	for i, tok := range toks {
		wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusUnauthorized, fmt.Sprintf("key %d", i))
	}
	wantStatus(t, e.do(bystander, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "another owner's key")
	rows := e.rec.inputs()
	var found bool
	for _, r := range rows {
		if r.Action == "api_key.revoke_owner" && r.Outcome == adminaudit.OutcomeOK && r.Target == "api_keys" {
			found = true
		}
	}
	if !found {
		t.Errorf("no api_key.revoke_owner row in %+v", rows)
	}
	// Again: nothing left to revoke.
	rec = e.as(admin, http.MethodDelete, keysPath+"?owner_sub=sam", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["revoked"] != 0 {
		t.Errorf("second revoke-by-owner = %s, want {revoked:0}", rec.Body.String())
	}

	// W-P1-SSO-08: revoking a subject's sessions revokes that subject's keys too.
	tok, _ := e.mint("sally", groupEditor, "policy:read")
	e.session("sally", groupEditor, "oidc")
	wantStatus(t, e.as(admin, http.MethodDelete, "/dashboard/api/sessions?sub=sally", ""), http.StatusOK, "session revoke-by-sub")
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusUnauthorized, "key after session revoke-by-sub")
	wantStatus(t, e.do(bystander, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "bystander after session revoke")

	// The in-process entry point offboarding uses.
	tok2, _ := e.mint("sven", groupEditor, "policy:read")
	n, err := e.srv.RevokeAPIKeysForOwner(context.Background(), keyOwnerIss, "sven", "offboarder")
	if err != nil || n != 1 {
		t.Fatalf("RevokeAPIKeysForOwner = %d, %v", n, err)
	}
	wantStatus(t, e.do(tok2, http.MethodGet, "/dashboard/api/policy", ""), http.StatusUnauthorized, "key after RevokeAPIKeysForOwner")
	if n, err := e.srv.RevokeAPIKeysForOwner(context.Background(), "https://other.idp", "bea", "x"); err != nil || n != 0 {
		t.Errorf("a different issuer revoked %d keys (%v)", n, err)
	}
}

type listedKey struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Scopes          []string `json:"scopes"`
	EffectiveScopes []string `json:"effectiveScopes"`
	OwnerEmail      string   `json:"ownerEmail"`
	OwnerSub        string   `json:"ownerSub"`
	ExpiresAt       string   `json:"expiresAt"`
	LastUsedAt      string   `json:"lastUsedAt"`
	RevokedAt       string   `json:"revokedAt"`
	Status          string   `json:"status"`
}

func (e *keyEnv) list(raw, query string) []listedKey {
	e.t.Helper()
	rec := e.as(raw, http.MethodGet, keysPath+query, "")
	if rec.Code != http.StatusOK {
		e.t.Fatalf("list%s = %d %s", query, rec.Code, rec.Body.String())
	}
	var out []listedKey
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func TestAPIKeysList(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	mineTok, mine := e.mint("eve", groupEditor, "policy:read", "policy:write", "adminaudit:read")
	_, _ = e.mint("olga", groupEditor, "policy:read")
	ed := e.session("eve", groupEditor, "oidc")
	admin := e.session("ada", groupAdmin, "oidc")

	got := e.list(ed, "")
	if len(got) != 1 || got[0].ID != mine || got[0].OwnerSub != "" || got[0].OwnerEmail != "eve@example.com" || got[0].Status != "active" {
		t.Fatalf("editor list = %+v, want only their own key without ownerSub", got)
	}
	// adminaudit:read needs admin: an editor owner's key lists it as a scope but not as effective.
	if strings.Join(got[0].Scopes, ",") != "policy:read,policy:write,adminaudit:read" ||
		strings.Join(got[0].EffectiveScopes, ",") != "policy:read,policy:write" {
		t.Errorf("scopes %v effective %v", got[0].Scopes, got[0].EffectiveScopes)
	}
	// Last use shows in the list before the 60s flush.
	wantStatus(t, e.do(mineTok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "use")
	if got := e.list(ed, ""); got[0].LastUsedAt == "" {
		t.Error("lastUsedAt empty after a use")
	}
	if all := e.list(admin, ""); len(all) != 2 || all[0].OwnerSub == "" {
		t.Errorf("admin list = %+v, want both keys with ownerSub", all)
	}
	if f := e.list(admin, "?owner_sub=olga"); len(f) != 1 || f[0].OwnerSub != "olga" {
		t.Errorf("admin owner_sub filter = %+v", f)
	}
	wantStatus(t, e.as(ed, http.MethodGet, keysPath+"?owner_sub=olga", ""), http.StatusForbidden, "editor filtering by another owner")
	if f := e.list(ed, "?owner_sub=eve"); len(f) != 1 {
		t.Errorf("editor filtering by themselves = %+v", f)
	}
	// An expired and a revoked key report their status.
	e.clk.Advance(48 * time.Hour)
	if got := e.list(ed, ""); got[0].Status != "expired" {
		t.Errorf("status after expiry = %q", got[0].Status)
	}
	// A key cannot list keys, even a live one.
	live, _ := e.mint("eve", groupEditor, "policy:read")
	rec := e.do(live, http.MethodGet, keysPath, "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"need":"none"`) {
		t.Errorf("live key listing = %d %s, want 403 insufficient_scope", rec.Code, rec.Body.String())
	}
	wantStatus(t, e.do(mineTok, http.MethodGet, keysPath, ""), http.StatusUnauthorized, "expired key listing")
	// A role downgrade shows in effectiveScopes: eve's group moves to viewer.
	e.srv.cfg.Console.Roles.Editor = nil
	e.srv.cfg.Console.Roles.Viewer = append(e.srv.cfg.Console.Roles.Viewer, groupEditor)
	for _, k := range e.list(admin, "?owner_sub=eve") {
		if strings.Join(k.EffectiveScopes, ",") != "policy:read" {
			t.Errorf("effective scopes after a downgrade to viewer = %+v, want only policy:read", k)
		}
	}
}

func TestAPIKeysSelf(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	// policy:read alone needs no scope for /self.
	tok, id := e.mint("eve", groupEditor, "policy:read")
	rec := e.do(tok, http.MethodGet, keysPath+"/self", "")
	wantStatus(t, rec, http.StatusOK, "self")
	var self listedKey
	if err := json.Unmarshal(rec.Body.Bytes(), &self); err != nil {
		t.Fatal(err)
	}
	if self.ID != id || strings.Join(self.Scopes, ",") != "policy:read" || self.ExpiresAt == "" || self.OwnerEmail != "eve@example.com" || self.Status != "active" {
		t.Errorf("self = %+v", self)
	}
	if strings.Contains(rec.Body.String(), tok) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("self leaks the key or is cacheable: %v", rec.Header())
	}
	// A non-key caller has no key to introspect.
	ed := e.session("eve", groupEditor, "oidc")
	wantStatus(t, e.as(ed, http.MethodGet, keysPath+"/self", ""), http.StatusBadRequest, "session on /self")
	wantStatus(t, e.do("", http.MethodGet, keysPath+"/self", ""), http.StatusUnauthorized, "no credential")
	// Unsupported methods on the subtree.
	wantStatus(t, e.do(tok, http.MethodDelete, keysPath+"/self", ""), http.StatusForbidden, "delete self by key")
	// A revoked key is refused.
	if err := e.store.Revoke(context.Background(), id, "t"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.do(tok, http.MethodGet, keysPath+"/self", ""), http.StatusUnauthorized, "revoked key on /self")
	// An owner whose role was removed is refused (the row needs a role).
	tok2, _ := e.mint("gone", "g-unmapped", "policy:read")
	wantStatus(t, e.do(tok2, http.MethodGet, keysPath+"/self", ""), http.StatusForbidden, "owner without a role")
}

func TestAPIKeysDisabled404(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFile(t, "api.openai.com"), defaultRoles())
	admin := e.session(t, groupAdmin)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, keysPath},
		{http.MethodPost, keysPath},
		{http.MethodDelete, keysPath + "?owner_sub=x"},
		{http.MethodDelete, keysPath + "/0123456789abcdef"},
		{http.MethodGet, keysPath + "/self"},
	} {
		for who, raw := range map[string]string{"admin": admin, "anonymous": ""} {
			if rec := e.do(raw, c.method, c.path, `{"name":"x","scopes":["policy:read"]}`); rec.Code != http.StatusNotFound {
				t.Errorf("%s %s as %s with keys disabled = %d, want 404", c.method, c.path, who, rec.Code)
			}
		}
	}
	// RevokeAPIKeysForOwner is a no-op without a store.
	if n, err := e.srv.RevokeAPIKeysForOwner(context.Background(), "", "x", "y"); n != 0 || err != nil {
		t.Errorf("RevokeAPIKeysForOwner with keys off = %d, %v", n, err)
	}
	// console.auth none mounts the same 404.
	logger, _ := testLogger()
	none := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Logger: logger}).Handler()
	for _, p := range []string{keysPath, keysPath + "/self"} {
		rec := httptest.NewRecorder()
		none.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("none mode GET %s = %d, want 404", p, rec.Code)
		}
	}
}

func TestAPIKeysAdminAudit(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	// The state hasher is registered and moves with a key's state.
	h := e.srv.audit.hashers[auditTargetAPIKeys]
	if h == nil {
		t.Fatal("no api_keys state hasher registered")
	}
	ed := e.session("eve", groupEditor, "oidc")
	before, err := h(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, k := e.create(ed, `{"name":"ci","scopes":["policy:read"]}`)
	afterCreate, _ := h(context.Background())
	wantStatus(t, e.as(ed, http.MethodDelete, keysPath+"/"+k.ID, ""), http.StatusNoContent, "revoke")
	afterRevoke, _ := h(context.Background())
	if before == afterCreate || afterCreate == afterRevoke {
		t.Errorf("state hash did not move: %s %s %s", before, afterCreate, afterRevoke)
	}
	rows := e.rec.inputs()
	if len(rows) != 2 {
		t.Fatalf("%d rows, want create + revoke: %+v", len(rows), rows)
	}
	if rows[0].BeforeHash != before || rows[0].AfterHash != afterCreate || rows[1].BeforeHash != afterCreate || rows[1].AfterHash != afterRevoke {
		t.Errorf("row hashes do not chain the state: %+v", rows)
	}
	rv := rows[1]
	if rv.Action != "api_key.revoke" || rv.TargetRef != "api_key:"+k.ID || rv.Details[adminaudit.DetailScopes] != "policy:read" || rv.Details[adminaudit.DetailExpiresAt] == "" {
		t.Errorf("revoke row = %+v", rv)
	}
	// A refused create (viewer asking too much) is chained as denied.
	vw := e.session("vic", groupViewer, "oidc")
	e.as(vw, http.MethodPost, keysPath, `{"name":"x","scopes":["policy:write"]}`)
	rows = e.rec.inputs()
	if last := rows[len(rows)-1]; last.Action != "api_key.create" || last.Outcome != adminaudit.OutcomeDenied {
		t.Errorf("denied create row = %+v", last)
	}
}

func TestRevokeAPIKeysForOwnerInput(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	for _, c := range [][3]string{{"", "", "by"}, {keyOwnerIss, "", "by"}, {keyOwnerIss, "sub", ""}} {
		if n, err := e.srv.RevokeAPIKeysForOwner(context.Background(), c[0], c[1], c[2]); n != 0 || !errors.Is(err, apikeys.ErrInvalidInput) {
			t.Errorf("RevokeAPIKeysForOwner(%q,%q,%q) = %d, %v, want ErrInvalidInput", c[0], c[1], c[2], n, err)
		}
	}
	// An issuer whose keys have all expired is still swept (and counted).
	tok, id := e.mint("exp", groupEditor, "policy:read")
	e.clk.Advance(48 * time.Hour)
	n, err := e.srv.RevokeAPIKeysForOwner(context.Background(), "", "exp", "off")
	if err != nil || n != 1 {
		t.Fatalf("revoking an owner with only expired keys = %d, %v, want 1", n, err)
	}
	if k, _ := e.store.Get(context.Background(), id); k.RevokedAt.IsZero() {
		t.Error("the expired key stayed unrevoked")
	}
	_ = tok
}

// TestAuditSkipIsVerified: a handler's Skip is honoured only when the target's
// state provably did not move.
func TestAuditSkipIsVerified(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	state := 0
	e.srv.RegisterStateHasher("skiptest", func(context.Context) (string, error) { return fmt.Sprint(state), nil })
	row := authzRow{Action: "skip.test", Target: "skiptest", Audited: true, Class: classAudited}
	run := func(target string, h http.HandlerFunc) *httptest.ResponseRecorder {
		r := row
		r.Target = target
		mw := e.srv.adminAuditMiddleware(func(*http.Request) (authzRow, bool) { return r, true }, h)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Kind: PrincipalSession, Iss: keyOwnerIss, Sub: "ada", Groups: []string{groupAdmin}, AuthMethod: "oidc"}))
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		return rec
	}
	rows := func() int { return len(e.rec.inputs()) }

	// Verified no-op: no row.
	before := rows()
	run("skiptest", func(w http.ResponseWriter, r *http.Request) {
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	if rows() != before {
		t.Error("a verified idempotent repeat wrote a row")
	}
	// Skip while mutating hashed state: row written, claim refused.
	run("skiptest", func(w http.ResponseWriter, r *http.Request) {
		state++
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	in := e.rec.inputs()
	if len(in) != before+1 || in[before].Details[detailSkipRefused] != "true" || in[before].BeforeHash == in[before].AfterHash {
		t.Fatalf("a Skip over a real change = %+v", in)
	}
	// Skip on a target with no hasher cannot be verified: row written.
	before = rows()
	run("unhashed", func(w http.ResponseWriter, r *http.Request) {
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	if in = e.rec.inputs(); len(in) != before+1 || in[before].Details[detailSkipRefused] != "true" {
		t.Fatalf("a Skip with no hasher = %+v", in[before:])
	}
	// Skip with a non-ok outcome: row written.
	before = rows()
	run("skiptest", func(w http.ResponseWriter, r *http.Request) {
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusConflict)
	})
	if in = e.rec.inputs(); len(in) != before+1 || in[before].Outcome != adminaudit.OutcomeRejected {
		t.Fatalf("a Skip on a 409 = %+v", in[before:])
	}
	// A hasher error cannot verify either.
	e.srv.RegisterStateHasher("broken", func(context.Context) (string, error) { return "", errors.New("boom") })
	before = rows()
	run("broken", func(w http.ResponseWriter, r *http.Request) {
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	if rows() != before+1 {
		t.Error("a Skip with a failing hasher wrote no row")
	}
}

// TestAuditNoChangeScopedHashAndFollowUps: the NoChange check hashes the after
// state with the audit-scoped context (a per-object hasher such as
// change_draft answers "" without it, so a create would look like a no-op),
// and a request that queued follow-up rows is never silently skipped.
func TestAuditNoChangeScopedHashAndFollowUps(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	// Like change_draft: "" until the request names its object (a create sets
	// it during the handler), and "" with no audit scope at all.
	e.srv.RegisterStateHasher("scoped", func(ctx context.Context) (string, error) {
		if auditDraftID(ctx) == "" {
			return "", nil
		}
		return "h:" + auditDraftID(ctx), nil
	})
	e.srv.RegisterStateHasher("steady", func(context.Context) (string, error) { return "same", nil })
	run := func(target string, h http.HandlerFunc) {
		row := authzRow{Action: "nochange.test", Target: target, Audited: true, Class: classAudited}
		mw := e.srv.adminAuditMiddleware(func(*http.Request) (authzRow, bool) { return row, true }, h)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Kind: PrincipalSession, Iss: keyOwnerIss, Sub: "ada", Groups: []string{groupAdmin}, AuthMethod: "oidc"}))
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}
	rows := func() int { return len(e.rec.inputs()) }

	// A create that claims NoChange: before is "" (no object yet), after is
	// the new object's hash, so the claim is refused and the row is written.
	before := rows()
	run("scoped", func(w http.ResponseWriter, r *http.Request) {
		setAuditDraft(r.Context(), "cd_new")
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusCreated)
	})
	in := e.rec.inputs()
	if len(in) != before+1 || in[before].Details[detailSkipRefused] != "true" || in[before].AfterHash == "" {
		t.Fatalf("a NoChange create = %+v, want a row with the claim refused and an after hash", in[before:])
	}

	// Follow-ups queued: the hashes match, but skipping would drop them, so
	// the primary row and its follow-up are both written.
	before = rows()
	run("steady", func(w http.ResponseWriter, r *http.Request) {
		addAuditFollowUp(r.Context(), auditFollowUp{Action: "policy.write", Target: auditTargetPolicy})
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	in = e.rec.inputs()
	if len(in) != before+2 || in[before].Details[detailSkipRefused] != "true" || in[before+1].Action != "policy.write" {
		t.Fatalf("a NoChange with a follow-up = %+v, want the primary row and the follow-up", in[before:])
	}

	// Control: the same steady target with no follow-up is a verified no-op.
	before = rows()
	run("steady", func(w http.ResponseWriter, r *http.Request) {
		adminaudit.NoChange(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	if rows() != before {
		t.Error("a verified no-op without follow-ups wrote a row")
	}
}

// TestAPIKeysSessionRevokeAudit: the sessions row says keys were revoked too.
func TestAPIKeysSessionRevokeAudit(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	e.mint("sally", groupEditor, "policy:read")
	e.mint("sally", groupEditor, "policy:write")
	admin := e.session("ada", groupAdmin, "oidc")
	wantStatus(t, e.as(admin, http.MethodDelete, "/dashboard/api/sessions?sub=sally", ""), http.StatusOK, "revoke by sub")
	rows := e.rec.inputs()
	last := rows[len(rows)-1]
	if last.Action != "sessions.revoke" || last.Details[adminaudit.DetailOp] != "revoke_sub_and_api_keys" || last.Details[adminaudit.DetailAPIKeysRevoked] != "2" {
		t.Errorf("sessions row = %+v", last)
	}
}
