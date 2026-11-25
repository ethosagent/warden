package controlplane

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/tokensvc"
)

const testTokenIssuer = "https://warden.example.com"

// fakeExchanger is a tokensvc.Service stand-in: it records the requests it
// gets and answers what the test configured.
type fakeExchanger struct {
	mu     sync.Mutex
	calls  []tokensvc.ExchangeRequest
	issued *tokensvc.Issued
	err    error
}

func (f *fakeExchanger) Exchange(_ context.Context, req tokensvc.ExchangeRequest) (*tokensvc.Issued, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	return f.issued, f.err
}

func (f *fakeExchanger) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func okIssued() *tokensvc.Issued {
	return &tokensvc.Issued{
		AccessToken: "header.payload.signature", IssuedTokenType: tokensvc.TokenTypeJWT,
		TokenType: tokensvc.BearerTokenType, ExpiresIn: 900, Scope: "read write",
	}
}

type tokenEnv struct {
	h    http.Handler
	fake *fakeExchanger
	logs *syncBuf
}

func newTokenEnv(t *testing.T, fake *fakeExchanger) *tokenEnv {
	t.Helper()
	logger, logs := testLogger()
	cfg := detectionEditorConfig(t)
	cfg.Logger = logger
	if fake != nil {
		cfg.Tokens, cfg.TokenIssuer = fake, testTokenIssuer
	}
	srv := New(cfg)
	t.Cleanup(func() {
		if srv.integrationsStore != nil {
			_ = srv.integrationsStore.Close()
		}
	})
	return &tokenEnv{h: srv.Handler(), fake: fake, logs: logs}
}

// validForm is a well-formed token exchange body.
func validForm() url.Values {
	return url.Values{
		"grant_type":            {grantTypeTokenExchange},
		"subject_token":         {"the.subject.token"},
		"subject_token_type":    {tokensvc.TokenTypeIDToken},
		"client_assertion_type": {clientAssertionJWT},
		"client_assertion":      {"the.client.assertion"},
	}
}

func (e *tokenEnv) post(target string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *tokenEnv) postForm(f url.Values) *httptest.ResponseRecorder {
	return e.post(tokenPath, f.Encode(), nil)
}

type oauthErr struct {
	Error string `json:"error"`
	Desc  string `json:"error_description"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) oauthErr {
	t.Helper()
	var e oauthErr
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("body %q is not an OAuth error: %v", rec.Body.String(), err)
	}
	return e
}

// requireTokenHeaders checks what every response of the endpoint carries.
func requireTokenHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	if h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v, want no-store, no-cache and application/json", h)
	}
}

func TestTokenEndpointRequestValidation(t *testing.T) {
	big := validForm()
	big.Set("subject_token", strings.Repeat("a", 33<<10))
	dup := validForm().Encode() + "&subject_token=another"
	withExtra := func(k, v string) string {
		f := validForm()
		f.Set(k, v)
		return f.Encode()
	}
	without := func(k string) string {
		f := validForm()
		f.Del(k)
		return f.Encode()
	}
	cases := []struct {
		name       string
		body       string
		target     string
		hdr        map[string]string
		status     int
		code, desc string
	}{
		{"password grant", withExtra("grant_type", "password"), tokenPath, nil, 400, "unsupported_grant_type", "unsupported_grant_type"},
		{"missing grant", without("grant_type"), tokenPath, nil, 400, "unsupported_grant_type", "unsupported_grant_type"},
		{"json content type", validForm().Encode(), tokenPath, map[string]string{"Content-Type": "application/json"}, 400, "invalid_request", reqContentType},
		{"no content type", validForm().Encode(), tokenPath, map[string]string{"Content-Type": ""}, 400, "invalid_request", reqContentType},
		{"query parameters", validForm().Encode(), tokenPath + "?client_id=x", nil, 400, "invalid_request", reqQueryParameters},
		{"empty query marker", validForm().Encode(), tokenPath + "?", nil, 400, "invalid_request", reqQueryParameters},
		{"duplicate subject_token", dup, tokenPath, nil, 400, "invalid_request", reqDuplicateParam},
		{"authorization bearer", validForm().Encode(), tokenPath, map[string]string{"Authorization": "Bearer wwt_abc"}, 400, "invalid_request", reqAuthorization},
		{"authorization basic", validForm().Encode(), tokenPath, map[string]string{"Authorization": "Basic Zm9vOmJhcg=="}, 400, "invalid_request", reqAuthorization},
		{"api key bearer", validForm().Encode(), tokenPath, map[string]string{"Authorization": "Bearer wak_abc"}, 400, "invalid_request", reqAuthorization},
		{"actor_token", withExtra("actor_token", "x"), tokenPath, nil, 400, "invalid_request", reqUnsupportedParam},
		{"resource", withExtra("resource", "https://x"), tokenPath, nil, 400, "invalid_request", reqUnsupportedParam},
		{"33 KiB body", big.Encode(), tokenPath, nil, 400, "invalid_request", reqBodyTooLarge},
		{"malformed escape", "grant_type=%zz", tokenPath, nil, 400, "invalid_request", reqMalformedBody},
		{"no client assertion", without("client_assertion"), tokenPath, nil, 401, "invalid_client", reqClientAuthFailed},
		{"wrong assertion type", withExtra("client_assertion_type", "urn:other"), tokenPath, nil, 401, "invalid_client", reqClientAuthFailed},
		{"no subject token", without("subject_token"), tokenPath, nil, 400, "invalid_request", reqMissingParameter},
		{"no subject token type", without("subject_token_type"), tokenPath, nil, 400, "invalid_request", reqMissingParameter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExchanger{issued: okIssued()}
			e := newTokenEnv(t, fake)
			rec := e.post(tc.target, tc.body, tc.hdr)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.status, rec.Body)
			}
			got := decodeErr(t, rec)
			if got.Error != tc.code || got.Desc != tc.desc {
				t.Fatalf("error = %+v, want %s/%s", got, tc.code, tc.desc)
			}
			requireTokenHeaders(t, rec)
			if n := fake.count(); n != 0 {
				t.Fatalf("the service was called %d times for a malformed request", n)
			}
		})
	}

	t.Run("a 33 KiB chunked body", func(t *testing.T) {
		fake := &fakeExchanger{issued: okIssued()}
		e := newTokenEnv(t, fake)
		req := httptest.NewRequest(http.MethodPost, tokenPath, io.NopCloser(strings.NewReader(big.Encode())))
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != 400 || decodeErr(t, rec).Desc != reqBodyTooLarge || fake.count() != 0 {
			t.Fatalf("got %d %s, calls %d", rec.Code, rec.Body, fake.count())
		}
	})

	t.Run("a content type with a charset is fine", func(t *testing.T) {
		fake := &fakeExchanger{issued: okIssued()}
		e := newTokenEnv(t, fake)
		rec := e.post(tokenPath, validForm().Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
		if rec.Code != 200 || fake.count() != 1 {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("methods other than POST", func(t *testing.T) {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
			e := newTokenEnv(t, &fakeExchanger{issued: okIssued()})
			req := httptest.NewRequest(m, tokenPath, nil)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
				t.Errorf("%s = %d Allow %q, want 405 with Allow: POST", m, rec.Code, rec.Header().Get("Allow"))
			}
			requireTokenHeaders(t, rec)
		}
	})

	t.Run("a session cookie is not client authentication", func(t *testing.T) {
		fake := &fakeExchanger{issued: okIssued()}
		e := newTokenEnv(t, fake)
		f := validForm()
		f.Del("client_assertion")
		f.Del("client_assertion_type")
		rec := e.post(tokenPath, f.Encode(), map[string]string{"Cookie": "warden_session=anything-at-all"})
		if rec.Code != 401 || decodeErr(t, rec).Error != "invalid_client" || fake.count() != 0 {
			t.Fatalf("got %d %s, calls %d", rec.Code, rec.Body, fake.count())
		}
	})
}

func TestTokenEndpointSuccess(t *testing.T) {
	fake := &fakeExchanger{issued: okIssued()}
	e := newTokenEnv(t, fake)
	f := validForm()
	f.Set("client_id", "agent-a")
	f.Set("scope", "read write")
	f.Set("audience", "warden-worker")
	f.Set("requested_token_type", tokensvc.TokenTypeJWT)
	f.Set("unknown_extra", "ignored")
	rec := e.postForm(f)
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	requireTokenHeaders(t, rec)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"access_token": "header.payload.signature", "issued_token_type": tokensvc.TokenTypeJWT,
		"token_type": "Bearer", "expires_in": float64(900), "scope": "read write",
	}
	if len(got) != len(want) {
		t.Fatalf("response = %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if fake.count() != 1 {
		t.Fatalf("calls = %d", fake.count())
	}
	req := fake.calls[0]
	if req.ClientAssertion != "the.client.assertion" || req.ClientID != "agent-a" || req.SubjectToken != "the.subject.token" ||
		req.SubjectTokenType != tokensvc.TokenTypeIDToken || req.Scope != "read write" || req.Audience != "warden-worker" ||
		req.RequestedTokenType != tokensvc.TokenTypeJWT {
		t.Fatalf("request = %+v", req)
	}

	t.Run("no scope member when none was issued", func(t *testing.T) {
		is := okIssued()
		is.Scope = ""
		e := newTokenEnv(t, &fakeExchanger{issued: is})
		rec := e.postForm(validForm())
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["scope"]; ok || rec.Code != 200 {
			t.Fatalf("got %d %v", rec.Code, m)
		}
	})
}

func TestTokenEndpointErrorMapping(t *testing.T) {
	cases := []struct {
		code   tokensvc.OAuthCode
		reason tokensvc.Reason
		status int
		desc   string
	}{
		{tokensvc.CodeInvalidRequest, tokensvc.ReasonUnsupportedTokenType, 400, "unsupported_token_type"},
		{tokensvc.CodeInvalidRequest, tokensvc.ReasonTokenTooLarge, 400, "token_too_large"},
		{tokensvc.CodeInvalidGrant, tokensvc.ReasonUserBlocked, 400, "user_blocked"},
		{tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectExpired, 400, "subject_expired"},
		{tokensvc.CodeInvalidGrant, tokensvc.ReasonSessionRevoked, 400, "session_revoked"},
		{tokensvc.CodeUnauthorizedClient, tokensvc.ReasonGroupNotAllowed, 400, "group_not_allowed"},
		{tokensvc.CodeInvalidScope, tokensvc.ReasonScopeNotAllowed, 400, "scope_not_allowed"},
		{tokensvc.CodeInvalidTarget, tokensvc.ReasonInvalidTarget, 400, "invalid_target"},
		{tokensvc.CodeUnsupportedGrantType, tokensvc.ReasonMalformed, 400, "malformed"},
		// invalid_client never says which of the four causes it was.
		{tokensvc.CodeInvalidClient, tokensvc.ReasonAgentUnknown, 401, reqClientAuthFailed},
		{tokensvc.CodeInvalidClient, tokensvc.ReasonUnknownKID, 401, reqClientAuthFailed},
		{tokensvc.CodeInvalidClient, tokensvc.ReasonBadSignature, 401, reqClientAuthFailed},
		{tokensvc.CodeInvalidClient, tokensvc.ReasonAgentDisabled, 401, reqClientAuthFailed},
		{tokensvc.CodeInvalidClient, tokensvc.ReasonReplay, 401, reqClientAuthFailed},
		{tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonIdPUnavailable, 503, "idp_unavailable"},
		{tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonBlockStoreUnavailable, 503, "block_store_unavailable"},
		{tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonSignerUnavailable, 503, "signer_unavailable"},
		{tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonReplayStoreUnavailable, 503, "replay_store_unavailable"},
		// A code this table does not know is a refusal, never a success.
		{tokensvc.OAuthCode("brand_new"), tokensvc.ReasonMalformed, 503, reqServiceUnavail},
	}
	for _, tc := range cases {
		t.Run(string(tc.code)+"/"+string(tc.reason), func(t *testing.T) {
			fake := &fakeExchanger{err: &tokensvc.Error{Code: tc.code, Reason: tc.reason, AgentID: "agent-secret-id", JTI: "deadbeef"}}
			e := newTokenEnv(t, fake)
			rec := e.postForm(validForm())
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body)
			}
			got := decodeErr(t, rec)
			if got.Error != string(tc.code) || got.Desc != tc.desc {
				t.Fatalf("error = %+v, want %s/%s", got, tc.code, tc.desc)
			}
			requireTokenHeaders(t, rec)
			ra := rec.Header().Get("Retry-After")
			if tc.status == 503 && ra == "" {
				t.Error("a 503 carries no Retry-After")
			}
			if tc.status != 503 && ra != "" {
				t.Errorf("Retry-After %q on a %d", ra, tc.status)
			}
			// Nothing but the OAuth members, and no agent id or jti.
			if body := rec.Body.String(); strings.Contains(body, "agent-secret-id") || strings.Contains(body, "deadbeef") {
				t.Errorf("the response leaks an internal value: %s", body)
			}
		})
	}

	t.Run("an error that is not a tokensvc error", func(t *testing.T) {
		fake := &fakeExchanger{err: errors.New("sql: connection refused at /var/lib/secret/warden-cp.db")}
		e := newTokenEnv(t, fake)
		rec := e.postForm(validForm())
		got := decodeErr(t, rec)
		if rec.Code != 503 || got.Error != "temporarily_unavailable" || got.Desc != reqServiceUnavail || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "secret") || strings.Contains(e.logs.String(), "connection refused") {
			t.Fatalf("driver text leaked: %s / %s", rec.Body, e.logs.String())
		}
	})

	t.Run("no secret reaches the log", func(t *testing.T) {
		fake := &fakeExchanger{err: &tokensvc.Error{Code: tokensvc.CodeInvalidGrant, Reason: tokensvc.ReasonUserBlocked, AgentID: "agent-a"}}
		e := newTokenEnv(t, fake)
		f := validForm()
		f.Set("subject_token", "SUBJECT-SECRET")
		f.Set("client_assertion", "ASSERTION-SECRET")
		e.postForm(f)
		for _, secret := range []string{"SUBJECT-SECRET", "ASSERTION-SECRET"} {
			if strings.Contains(e.logs.String(), secret) {
				t.Errorf("the log holds %s", secret)
			}
		}
	})
}

func TestTokenRoutesAbsentWhenDisabled(t *testing.T) {
	e := newTokenEnv(t, nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, tokenPath}, {http.MethodGet, tokenPath}, {http.MethodGet, asMetadataPath},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(validForm().Encode()))
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}

func TestASMetadata(t *testing.T) {
	e := newTokenEnv(t, &fakeExchanger{})
	req := httptest.NewRequest(http.MethodGet, asMetadataPath, nil)
	// The Host header never reaches the document.
	req.Host = "evil.example.net"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	asStrings := func(k string) []string {
		var out []string
		for _, v := range doc[k].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	if doc["issuer"] != testTokenIssuer || doc["token_endpoint"] != testTokenIssuer+"/oauth2/token" ||
		doc["jwks_uri"] != testTokenIssuer+"/.well-known/jwks.json" {
		t.Fatalf("urls = %v", doc)
	}
	if g := asStrings("grant_types_supported"); len(g) != 1 || g[0] != grantTypeTokenExchange {
		t.Errorf("grant_types_supported = %v", g)
	}
	if m := asStrings("token_endpoint_auth_methods_supported"); len(m) != 1 || m[0] != "private_key_jwt" {
		t.Errorf("auth methods = %v", m)
	}
	if a := asStrings("token_endpoint_auth_signing_alg_values_supported"); len(a) != 2 || a[0] != "EdDSA" || a[1] != "ES256" {
		t.Errorf("algs = %v", a)
	}
	if strings.Contains(rec.Body.String(), "evil.example.net") {
		t.Errorf("the Host header reached the document: %s", rec.Body)
	}

	for _, m := range []string{http.MethodPost, http.MethodDelete} {
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, httptest.NewRequest(m, asMetadataPath, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s = %d Allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, asMetadataPath, nil))
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes", rec.Code, rec.Body.Len())
	}
}

func TestTokenRoutesClassified(t *testing.T) {
	cp := cpRouteTable()
	row, ok := cp[routeKey{http.MethodPost, tokenPath}]
	if !ok || row.Class != classAssertionAuth || row.Audited {
		t.Fatalf("POST %s row = %+v (listed %v), want assertion-authenticated, Audited:false", tokenPath, row, ok)
	}
	if meta, ok := cp[routeKey{http.MethodGet, asMetadataPath}]; !ok || meta.Audited {
		t.Fatalf("GET %s row = %+v (listed %v)", asMetadataPath, meta, ok)
	}
}

// TestTokenIssuerValidatorsAgree: config cannot import tokensvc, so each has
// its own copy of the issuer rule; this pins them together.
func TestTokenIssuerValidatorsAgree(t *testing.T) {
	for _, iss := range []string{
		"", "/", "https://warden.example.com", "https://warden.example.com/", "https://warden.example.com/sso",
		"https://warden.example.com?x=1", "https://warden.example.com#f", "http://warden.example.com",
		"http://localhost:8080", "http://127.0.0.1", "http://[::1]:9", "ftp://x.example.com", "https://u@x.example.com",
		"https:///path", "https://x.example.com/a b", "warden.example.com", "https://", "HTTPS://Warden.Example.com",
	} {
		a, b := config.ValidateTokenServiceIssuer(iss), tokensvc.ValidateIssuer(iss)
		if (a == nil) != (b == nil) {
			t.Errorf("issuer %q: config says %v, tokensvc says %v", iss, a, b)
		}
	}
}

func newGuard(e *keysEnv) servedSigners {
	return servedSigners{inner: e.mgr.KeySet(), records: e.mgr.KeySet().Records, now: e.clk.Now, served: e.srv.servesTokenKID}
}

// TestServedSigners: the active token key mints only once it has been
// published for tokenKeyPublishWindow, judged from the persisted metadata.
func TestServedSigners(t *testing.T) {
	ctx := context.Background()
	actor := keys.Actor{Subject: "test", AuthMethod: "test"}
	e := newKeysEnv(t, keysEnvOpts{})
	guard := newGuard(e)

	t.Run("a first key does not mint until the window passes", func(t *testing.T) {
		if _, err := guard.Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("fresh key: err = %v, want ErrNoActiveKey", err)
		}
		e.clk.Advance(tokenKeyPublishWindow - time.Second)
		if _, err := guard.Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("a second early: err = %v, want ErrNoActiveKey", err)
		}
		e.clk.Advance(time.Second)
		if sg, err := guard.Active(keys.PurposeToken); err != nil || sg.KID() == "" {
			t.Fatalf("after the window: %v", err)
		}
	})
	t.Run("an emergency promotion of a barely published key waits", func(t *testing.T) {
		// The first emergency rotation promotes the old next key, published
		// with the first one; the second promotes the key the first just
		// published.
		for i := 0; i < 2; i++ {
			if err := e.mgr.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{Emergency: true, Actor: actor}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := guard.Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("barely published key: err = %v, want ErrNoActiveKey", err)
		}
		e.clk.Advance(tokenKeyPublishWindow)
		if _, err := guard.Active(keys.PurposeToken); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
	t.Run("a normal rotation never waits", func(t *testing.T) {
		e.clk.Advance(721 * time.Hour)
		before, _ := guard.Active(keys.PurposeToken)
		if err := e.mgr.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{Actor: actor}); err != nil {
			t.Fatal(err)
		}
		sg, err := guard.Active(keys.PurposeToken)
		if err != nil || sg.KID() == before.KID() {
			t.Fatalf("after a normal rotation: %v kid %q (was %q)", err, kidOrEmpty(sg), before.KID())
		}
	})
	t.Run("the JWKS hook still gates", func(t *testing.T) {
		g := guard
		g.served = func(string) bool { return false }
		if _, err := g.Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("err = %v, want ErrNoActiveKey", err)
		}
		// Only the token purpose is guarded.
		if _, err := g.Active(keys.PurposeBundle); err != nil {
			t.Fatalf("bundle purpose: %v", err)
		}
	})
	t.Run("before the JWKS is mounted", func(t *testing.T) {
		g := guard
		g.served = (&Server{}).servesTokenKID
		if _, err := g.Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("err = %v, want ErrNoActiveKey", err)
		}
	})
	t.Run("a key with no metadata row is not mintable", func(t *testing.T) {
		g := guard
		g.records = func(string) []keys.Record { return nil }
		if _, err := g.Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("err = %v, want ErrNoActiveKey", err)
		}
	})
	t.Run("a signing failure passes through", func(t *testing.T) {
		boom := errors.New("boom")
		g := servedSigners{inner: failingSigners{err: boom}, now: e.clk.Now}
		if _, err := g.Active(keys.PurposeToken); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestTokenServiceSharedAgentStore: the service reads agents through the one
// Store it is given, so a disable through that Store (what a dashboard write
// will do) refuses the very next exchange: no restart, no Watch tick.
func TestTokenServiceSharedAgentStore(t *testing.T) {
	ctx := context.Background()
	e := newKeysEnv(t, keysEnvOpts{tokens: true})
	db := e.srv.cfg.State
	agents := agentregsqlite.New(db, agentregsqlite.WithClock(e.clk))
	logger, _ := testLogger()
	tc := config.DefaultTokenService()
	tc.Enabled, tc.Issuer = true, testTokenIssuer
	ts, err := newTokenService(tc, config.IdentitySettings{Issuer: "http://127.0.0.1:9", InternalIssuerURL: "http://127.0.0.1:9", Audience: "warden"},
		db, agents, e.srv, e.mgr, e.clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Agents != agents || ts.Sessions == nil {
		t.Fatal("the assembly does not expose the store it was given and the session store")
	}

	priv, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := json.Marshal(map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "a-key",
		"x": base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))})
	created, err := agents.Create(ctx, agentreg.Agent{ID: "agent-a", Keys: []agentreg.Key{{KID: "a-key", JWK: jwk}}, AllowedGroups: []string{"eng"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	exchange := func() *tokensvc.Error {
		now := e.clk.Now().Unix()
		jti := make([]byte, 8)
		_, _ = rand.Read(jti)
		claims := map[string]any{"iss": "agent-a", "sub": "agent-a", "aud": testTokenIssuer + "/oauth2/token",
			"iat": now, "exp": now + 60, "jti": hex.EncodeToString(jti)}
		assertion, err := keys.SignCompact(ctx, priv, keys.Header{Alg: keys.AlgEdDSA, Kid: "a-key", Typ: "JWT"}, claims)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ts.Service.Exchange(ctx, tokensvc.ExchangeRequest{
			ClientAssertion: assertion, SubjectToken: "not.a.jwt", SubjectTokenType: tokensvc.TokenTypeIDToken,
		})
		var te *tokensvc.Error
		if !errors.As(err, &te) {
			t.Fatalf("err = %v, want a tokensvc error", err)
		}
		return te
	}
	// Active: the assertion authenticates and the exchange fails later, at the
	// subject token.
	if te := exchange(); te.Code != tokensvc.CodeInvalidGrant {
		t.Fatalf("active agent: %v, want to get as far as the subject token", te)
	}
	if _, err := agents.SetStatus(ctx, "agent-a", agentreg.StatusDisabled, created.Revision, "test"); err != nil {
		t.Fatal(err)
	}
	if te := exchange(); te.Code != tokensvc.CodeInvalidClient {
		t.Fatalf("disabled agent: %v, want invalid_client at once", te)
	}
}

// TestTokenEndpointSlowBody: a body that trickles in is cut at the read
// deadline instead of holding the connection.
func TestTokenEndpointSlowBody(t *testing.T) {
	old := tokenReadTimeout
	tokenReadTimeout = 300 * time.Millisecond
	t.Cleanup(func() { tokenReadTimeout = old })
	fake := &fakeExchanger{issued: okIssued()}
	e := newTokenEnv(t, fake)
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("POST /oauth2/token HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\ngrant_type="))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response to a stalled body: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest || fake.count() != 0 {
		t.Fatalf("status = %d, calls %d, want 400 and no exchange", resp.StatusCode, fake.count())
	}
}

type failingSigners struct{ err error }

func (f failingSigners) Active(string) (keys.Signer, error) { return nil, f.err }

func kidOrEmpty(sg keys.Signer) string {
	if sg == nil {
		return ""
	}
	return sg.KID()
}

func TestResolveTokenService(t *testing.T) {
	logger, _ := testLogger()
	id := config.IdentitySettings{Issuer: "https://idp.example.com", Audience: "warden"}
	kc := config.DefaultKeys()
	kc.Enabled = true
	write := func(block string) string {
		return writeConfigFile(t, "policy:\n  allowlist:\n    - domain: api.example.com\n"+block)
	}
	const on = "tokenService:\n  enabled: true\n  issuer: https://warden.example.com\n"

	t.Run("absent or disabled is the disabled default", func(t *testing.T) {
		for _, block := range []string{"", "tokenService:\n  enabled: false\n  issuer: https://warden.example.com\n"} {
			tc, err := resolveTokenService(logger, write(block), "", config.IdentitySettings{}, config.DefaultKeys())
			if err != nil || tc.Enabled {
				t.Fatalf("got %+v, %v", tc, err)
			}
		}
	})
	t.Run("enabled and complete", func(t *testing.T) {
		tc, err := resolveTokenService(logger, write(on), t.TempDir(), id, kc)
		if err != nil || !tc.Enabled || tc.Issuer != "https://warden.example.com" {
			t.Fatalf("got %+v, %v", tc, err)
		}
	})
	fails := []struct {
		name, block, stateDir, want string
		id                          config.IdentitySettings
		kc                          config.KeysConfig
	}{
		{"no state dir", on, "", "--state-dir", id, kc},
		{"no identity issuer", on, "x", "identity", config.IdentitySettings{Audience: "warden"}, kc},
		{"no identity audience", on, "x", "identity", config.IdentitySettings{Issuer: "https://idp.example.com"}, kc},
		{"keys disabled", on, "x", "keys.enabled", id, config.DefaultKeys()},
		{"overlap below ttl plus 2m", on + "  ttl: 15m\n", "x", "keys.token.overlap", id, shortOverlap(kc, 16*time.Minute)},
		{"bad ttl", on + "  ttl: 16m\n", "x", "tokenService.ttl", id, kc},
		{"bad issuer", "tokenService:\n  enabled: true\n  issuer: http://warden.example.com\n", "x", "loopback", id, kc},
	}
	for _, f := range fails {
		t.Run(f.name, func(t *testing.T) {
			_, err := resolveTokenService(logger, write(f.block), f.stateDir, f.id, f.kc)
			if err == nil || !strings.Contains(err.Error(), f.want) {
				t.Fatalf("err = %v, want it to name %q", err, f.want)
			}
		})
	}
	t.Run("overlap exactly ttl plus 2m is enough", func(t *testing.T) {
		if _, err := resolveTokenService(logger, write(on+"  ttl: 15m\n"), "x", id, shortOverlap(kc, 17*time.Minute)); err != nil {
			t.Fatal(err)
		}
	})
}

func shortOverlap(kc config.KeysConfig, d time.Duration) config.KeysConfig {
	kc.Token.Overlap = d
	return kc
}

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const tokenServiceBlock = `tokenService:
  enabled: true
  issuer: https://warden.example.com
  allowedAZP: [agent-harness]
  rateLimit:
    perIP: 120/minute
`

// TestTokenServiceNotOnWire: neither the worker policy wire nor the settings
// wire carries the block.
func TestTokenServiceNotOnWire(t *testing.T) {
	p := config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: "api.example.com"}},
		TokenService: config.TokenServiceConfig{Enabled: true, Issuer: "https://secret-issuer.example.com", AllowedAZP: []string{"secret-client"}},
		Identity:     config.IdentitySettings{DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden"},
	}
	sw := config.SettingsWireFromPolicy(p)
	if sw == nil {
		t.Fatal("SettingsWireFromPolicy returned nil; the check would be vacuous")
	}
	pw, err := json.Marshal(policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist, Settings: sw})
	if err != nil {
		t.Fatal(err)
	}
	sj, err := json.Marshal(sw)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"policyWire": pw, "SettingsWire": sj} {
		for _, banned := range []string{"tokenService", "secret-issuer", "secret-client", "allowedAZP"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s JSON contains %q: %s", name, banned, b)
			}
		}
	}
}

// TestWritersPreserveTokenServiceBlock: a dashboard write rewrites only the
// blocks it owns, so the operator's tokenService block survives byte for byte.
func TestWritersPreserveTokenServiceBlock(t *testing.T) {
	cfg := detectionEditorConfig(t)
	path := cfg.PolicyPath
	if err := os.WriteFile(path, []byte(readFile(t, path)+tokenServiceBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	node := func() string {
		root := map[string]yaml.Node{}
		if err := yaml.Unmarshal([]byte(readFile(t, path)), &root); err != nil {
			t.Fatal(err)
		}
		n, ok := root["tokenService"]
		if !ok {
			t.Fatal("tokenService node missing")
		}
		out, err := yaml.Marshal(&n)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	before := node()
	srv := New(cfg)
	t.Cleanup(func() {
		if srv.integrationsStore != nil {
			_ = srv.integrationsStore.Close()
		}
	})
	writers := []struct {
		name string
		fn   func() error
	}{
		{"WritePolicy", func() error {
			prov, err := config.NewLocalYAMLProvider(path)
			if err != nil {
				return err
			}
			p, err := prov.GetPolicy()
			if err != nil {
				return err
			}
			p.Allowlist = append(p.Allowlist, config.AllowlistEntry{Domain: "added.example.com"})
			return srv.writePolicy(p)
		}},
		{"WriteSettings", func() error {
			return srv.writeSettings(config.SettingsWire{Identity: &config.IdentitySettings{
				DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden",
			}})
		}},
		{"WriteIntegrations", func() error {
			return srv.WriteIntegrations([]config.IntegrationInstance{{
				Type: "webhook", Name: "x", Config: map[string]any{"url": "${WEBHOOK_URL}"},
				Match: []config.IntegrationMatch{{Category: "security"}},
			}})
		}},
		{"WriteDetection", func() error { return srv.WriteDetection(config.DetectionConfig{Enabled: false}) }},
	}
	for _, w := range writers {
		if err := w.fn(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if after := node(); after != before {
			t.Errorf("%s changed the tokenService block:\n%s\nvs\n%s", w.name, before, after)
		}
	}
}

// TestPolicyUnchangedByTokenService: the served /policy is byte-identical
// whether or not the operator's config carries a tokenService block, and
// whether or not the token routes are mounted: the block is CP-local.
func TestPolicyUnchangedByTokenService(t *testing.T) {
	serve := func(withBlock bool, tokens TokenExchanger) (string, string) {
		cfg := detectionEditorConfig(t)
		if withBlock {
			if err := os.WriteFile(cfg.PolicyPath, []byte(readFile(t, cfg.PolicyPath)+tokenServiceBlock), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if tokens != nil {
			cfg.Tokens, cfg.TokenIssuer = tokens, testTokenIssuer
		}
		srv := New(cfg)
		t.Cleanup(func() {
			if srv.integrationsStore != nil {
				_ = srv.integrationsStore.Close()
			}
		})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/policy = %d", rec.Code)
		}
		return rec.Body.String(), rec.Header().Get("ETag")
	}
	base, baseTag := serve(false, nil)
	for name, got := range map[string]func() (string, string){
		"block in the file":        func() (string, string) { return serve(true, nil) },
		"block and routes mounted": func() (string, string) { return serve(true, &fakeExchanger{}) },
	} {
		body, tag := got()
		if body != base || tag != baseTag {
			t.Errorf("%s: /policy changed:\n%s\nvs\n%s", name, base, body)
		}
	}
}

// slowExchanger blocks past the body read timeout and reports whether the
// request context was cancelled meanwhile.
type slowExchanger struct {
	delay     time.Duration
	cancelled bool
}

func (f *slowExchanger) Exchange(ctx context.Context, _ tokensvc.ExchangeRequest) (*tokensvc.Issued, error) {
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
	}
	f.cancelled = ctx.Err() != nil
	return okIssued(), nil
}

// TestTokenEndpointSlowExchangeKeepsContext: an exchange that runs past the
// body read timeout still completes with its context alive.
func TestTokenEndpointSlowExchangeKeepsContext(t *testing.T) {
	old := tokenReadTimeout
	tokenReadTimeout = 150 * time.Millisecond
	t.Cleanup(func() { tokenReadTimeout = old })
	logger, _ := testLogger()
	cfg := detectionEditorConfig(t)
	cfg.Logger = logger
	slow := &slowExchanger{delay: 600 * time.Millisecond}
	cfg.Tokens, cfg.TokenIssuer = slow, testTokenIssuer
	srv := New(cfg)
	t.Cleanup(func() {
		if srv.integrationsStore != nil {
			_ = srv.integrationsStore.Close()
		}
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+tokenPath, "application/x-www-form-urlencoded", strings.NewReader(validForm().Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || slow.cancelled {
		t.Fatalf("status %d, context cancelled %v; want 200 with a live context", resp.StatusCode, slow.cancelled)
	}
}

// TestRunTokenServiceStartupCheck: Run stops on a tokenService block that
// fails its startup checks (here: enabled without --state-dir) and names the
// setting, rather than starting with the endpoint silently off.
func TestRunTokenServiceStartupCheck(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	writeFileT(t, cfg, basePolicy+"tokenService:\n  enabled: true\n  issuer: https://warden.example.com\n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A deadline so a Run that starts instead of failing ends the test.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = Run(ctx, &lockedBuffer{}, Params{ConfigPath: cfg, Listener: ln, AnalyticsProvider: "memory"})
	if err == nil || !strings.Contains(err.Error(), "tokenService") {
		t.Fatalf("Run = %v, want an error naming tokenService", err)
	}
}
