package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// The policy version contract (W-P1-PVER-08): in versioned mode the policy,
// settings and llmProviders GETs carry the head version, writes read If-Match
// into WriteMeta.ExpectedHead, and a stale write is a 409 naming the head and
// its author.

// versionedRoutes are the three endpoints that share the policy head, with a
// valid write body for each.
var versionedRoutes = map[string]string{
	"/dashboard/api/policy":       `{"allowlist":[{"domain":"x.com"}]}`,
	"/dashboard/api/settings":     `{}`,
	"/dashboard/api/llmproviders": `[]`,
}

// versionedServer is a dashboard whose three writers record the WriteMeta they
// receive and return writeErr, with head as the policy version (0 = file
// mode).
func versionedServer(head int64, writeErr error) (*Server, map[string]WriteMeta) {
	got := map[string]WriteMeta{}
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyWriter(func(_ context.Context, _ config.Policy, m WriteMeta) error {
		got["/dashboard/api/policy"] = m
		return writeErr
	})
	srv.SetSettingsWriter(func(_ context.Context, _ config.SettingsWire, m WriteMeta) error {
		got["/dashboard/api/settings"] = m
		return writeErr
	})
	srv.SetLLMProvidersWriter(func(_ context.Context, _ []config.LLMProvider, m WriteMeta) error {
		got["/dashboard/api/llmproviders"] = m
		return writeErr
	})
	srv.SetPolicyVersion(func(context.Context) (int64, error) { return head, nil })
	return srv, got
}

func sendWrite(h http.Handler, path, body, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPolicyVersionOnGets: in versioned mode each GET has the version field
// and the X-Warden-Policy-Version header.
func TestPolicyVersionOnGets(t *testing.T) {
	srv, _ := versionedServer(5, nil)
	h := srv.Handler()
	for path := range versionedRoutes {
		rec := doGet(t, h, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if got := rec.Header().Get(PolicyVersionHeader); got != "5" {
			t.Errorf("GET %s %s = %q, want 5", path, PolicyVersionHeader, got)
		}
		var body struct {
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Version != 5 {
			t.Errorf("GET %s version = %d (%v), want 5", path, body.Version, err)
		}
	}
}

// TestPolicyFileModeNoVersion: in file mode (version 0) the GETs have no
// version field and no header, and writes without If-Match succeed with an
// empty WriteMeta. An If-Match is ignored there.
func TestPolicyFileModeNoVersion(t *testing.T) {
	for _, withSource := range []bool{false, true} {
		srv, got := versionedServer(0, nil)
		if !withSource {
			srv.SetPolicyVersion(nil)
		}
		h := srv.Handler()
		for path, body := range versionedRoutes {
			rec := doGet(t, h, path)
			if v := rec.Header().Get(PolicyVersionHeader); v != "" {
				t.Errorf("file mode GET %s has %s: %q", path, PolicyVersionHeader, v)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if _, ok := raw["version"]; ok {
				t.Errorf("file mode GET %s body has a version field: %s", path, rec.Body.String())
			}
			for _, im := range []string{"", `"v3"`, "garbage"} {
				if rec := sendWrite(h, path, body, im); rec.Code != http.StatusOK {
					t.Fatalf("file mode write %s If-Match %q = %d %s", path, im, rec.Code, rec.Body.String())
				}
				if got[path] != (WriteMeta{}) {
					t.Errorf("file mode write %s meta = %+v, want empty", path, got[path])
				}
			}
		}
	}
}

// TestPolicyIfMatchParsed: "v<N>" becomes ExpectedHead N on every writer; no
// If-Match is a 428 (W-P1-PVER-04, TestPolicyWriteMissingIfMatch428) and a
// malformed one is 400; neither reaches the writer.
func TestPolicyIfMatchParsed(t *testing.T) {
	for path, body := range versionedRoutes {
		srv, got := versionedServer(5, nil)
		h := srv.Handler()
		if rec := sendWrite(h, path, body, `"v5"`); rec.Code != http.StatusOK {
			t.Fatalf("%s If-Match v5 = %d %s", path, rec.Code, rec.Body.String())
		}
		if got[path].ExpectedHead != 5 {
			t.Errorf("%s ExpectedHead = %d, want 5", path, got[path].ExpectedHead)
		}
		delete(got, path)
		if rec := sendWrite(h, path, body, ""); rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("%s without If-Match = %d, want 428", path, rec.Code)
		}
		if _, called := got[path]; called {
			t.Errorf("%s without If-Match reached the writer", path)
		}
		for _, bad := range []string{"v5", `"5"`, `"v0"`, `"v-1"`, `W/"v5"`, `"v5x"`, `*`, `"v5", "v6"`, `"v99999999999999999999"`} {
			delete(got, path)
			rec := sendWrite(h, path, body, bad)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s If-Match %q = %d, want 400", path, bad, rec.Code)
			}
			if _, called := got[path]; called {
				t.Errorf("%s If-Match %q reached the writer", path, bad)
			}
		}
	}
}

// TestPolicyWriteConflict: a writer's *ConflictError is a 409 policy_conflict
// naming the head and its author, on all three writers. The body carries no
// doc content and no error text.
func TestPolicyWriteConflict(t *testing.T) {
	conflict := &ConflictError{Head: 6, Author: ConflictAuthor{Sub: "u2", Email: "b@x"}, Err: errors.New("head is v6, expected v5 secret-ish detail")}
	for path, body := range versionedRoutes {
		srv, _ := versionedServer(6, conflict)
		rec := sendWrite(srv.Handler(), path, body, `"v5"`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s stale write = %d, want 409", path, rec.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		author, _ := got["author"].(map[string]any)
		if got["error"] != "policy_conflict" || got["head"] != float64(6) || author["sub"] != "u2" || author["email"] != "b@x" {
			t.Errorf("%s 409 body = %s", path, rec.Body.String())
		}
		if len(got) != 3 || strings.Contains(rec.Body.String(), "secret-ish") {
			t.Errorf("%s 409 body has extra content: %s", path, rec.Body.String())
		}
	}
	// A wrapped conflict maps the same way; an author without email omits it.
	srv, _ := versionedServer(6, errors.Join(errors.New("ctx"), &ConflictError{Head: 6, Author: ConflictAuthor{Sub: "anonymous"}}))
	rec := sendWrite(srv.Handler(), "/dashboard/api/policy", versionedRoutes["/dashboard/api/policy"], `"v5"`)
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "email") {
		t.Fatalf("wrapped conflict = %d %s", rec.Code, rec.Body.String())
	}
	if got := (&ConflictError{Head: 6}).Error(); !strings.Contains(got, "v6") {
		t.Errorf("ConflictError.Error() = %q", got)
	}
}

// TestPolicyVersionSourceError: a version source that fails is a 500 on GET
// and on a write, and the write never reaches the writer.
func TestPolicyVersionSourceError(t *testing.T) {
	srv, got := versionedServer(0, nil)
	srv.SetPolicyVersion(func(context.Context) (int64, error) { return 0, errors.New("db down") })
	h := srv.Handler()
	for path, body := range versionedRoutes {
		if rec := doGet(t, h, path); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "db down") {
			t.Errorf("GET %s with a failing version source = %d %s, want a generic 500", path, rec.Code, rec.Body.String())
		}
		if rec := sendWrite(h, path, body, `"v1"`); rec.Code != http.StatusInternalServerError {
			t.Errorf("write %s with a failing version source = %d, want 500", path, rec.Code)
		}
		if _, called := got[path]; called {
			t.Errorf("write %s reached the writer", path)
		}
	}
}
