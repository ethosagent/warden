package oauthbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// testDoer is an httptest-backed Requester (and FormPoster).
type testDoer struct {
	testPoster
	err error
}

func (d testDoer) Do(ctx context.Context, r Request) (int, []byte, error) {
	if d.err != nil {
		return 0, nil, d.err
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return 0, nil, err
	}
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	req.Header.Set("Accept", "application/json")
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	if r.BasicUser != "" {
		req.SetBasicAuth(r.BasicUser, r.BasicPass)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	limit := int64(MaxProviderResponseBytes)
	if r.MaxBytes > 0 {
		limit = int64(r.MaxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	return resp.StatusCode, b, err
}

// liveRecord is storedRecord with an unexpired access token.
func liveRecord() TokenRecord {
	r := storedRecord()
	r.Expiry = refreshNow.Unix() + 3600
	return r
}

type revokeFixture struct {
	srv    *httpTestServer
	reg    *Registry
	logs   *bytes.Buffer
	secret Secret
}

type httpTestServer struct {
	*httptest.Server
	hits   atomic.Int32
	method string
	path   string
	ctype  string
	accept string
	user   string
	pass   string
	body   string
}

func newRevokeFixture(t *testing.T, typ, revokePath string, doer Requester, reply func(w http.ResponseWriter)) *revokeFixture {
	t.Helper()
	s := &httpTestServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		s.method, s.path, s.body = r.Method, r.URL.Path, string(b)
		s.ctype, s.accept = r.Header.Get("Content-Type"), r.Header.Get("Accept")
		s.user, s.pass, _ = r.BasicAuth()
		reply(w)
	}))
	t.Cleanup(s.Close)
	cfg := config.OAuthProviderConfig{ID: "prov", Type: typ, ClientID: "cid", ClientSecretEnv: "SEC", TokenURL: s.URL + "/token"}
	if revokePath != "" {
		cfg.RevokeURL = s.URL + revokePath
	}
	switch typ {
	case config.OAuthProviderGoogle, config.OAuthProviderGitHub:
		cfg.AllowedScopes = []string{"a"}
	case config.OAuthProviderGeneric:
		cfg.AuthURL = s.URL + "/auth"
	}
	if doer == nil {
		doer = testDoer{}
	}
	r, logs := newReg(t, []config.OAuthProviderConfig{cfg}, Options{
		LookupEnv:  func(string) (string, bool) { return tClientSc, true },
		Now:        func() time.Time { return refreshNow },
		HTTPClient: doer.(FormPoster),
	})
	return &revokeFixture{srv: s, reg: r, logs: logs, secret: NewSecret(tClientSc)}
}

func (f *revokeFixture) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := f.reg.Get("prov")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func status(code int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func TestRevokeGoogle(t *testing.T) {
	f := newRevokeFixture(t, "google", "/revoke", nil, status(200, ""))
	p := f.provider(t)
	if err := Revoke(t.Context(), p, liveRecord(), f.secret, "uk1"); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(f.srv.body)
	if f.srv.method != "POST" || f.srv.path != "/revoke" || form.Get("token") != tRefresh ||
		!strings.HasPrefix(f.srv.ctype, "application/x-www-form-urlencoded") || f.srv.user != "" {
		t.Fatalf("bad google request: %s %s %q ct=%q user=%q", f.srv.method, f.srv.path, f.srv.body, f.srv.ctype, f.srv.user)
	}
	rec := liveRecord()
	rec.RefreshToken = ""
	if err := Revoke(t.Context(), p, rec, f.secret, "uk1"); err != nil {
		t.Fatal(err)
	}
	form, _ = url.ParseQuery(f.srv.body)
	if form.Get("token") != tAccess {
		t.Fatalf("want access-token fallback, got %q", f.srv.body)
	}
	if got := f.reg.RevokeCounters().Count("prov", RevokeOK); got != 2 {
		t.Fatalf("ok counter = %d", got)
	}
}

func TestRevokeGoogleAlready(t *testing.T) {
	f := newRevokeFixture(t, "google", "/revoke", nil, status(400, `{"error":"invalid_token","error_description":"Token expired or revoked"}`))
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); err != nil {
		t.Fatalf("invalid_token must count as already revoked: %v", err)
	}
	if f.reg.RevokeCounters().Count("prov", RevokeAlready) != 1 {
		t.Fatal("outcome must be already")
	}
	f = newRevokeFixture(t, "google", "/revoke", nil, status(400, `{"error":"invalid_request"}`))
	var re *RevokeError
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); !errors.As(err, &re) || re.Retryable || re.Status != 400 {
		t.Fatalf("other 400 must be permanent: %v", err)
	}
}

func TestRevokeGitHub(t *testing.T) {
	for _, typ := range []string{"github", "githubApp"} {
		f := newRevokeFixture(t, typ, "/applications/{client_id}/grant", nil, status(204, ""))
		if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		var body map[string]string
		if err := json.Unmarshal([]byte(f.srv.body), &body); err != nil || body["access_token"] != tAccess {
			t.Fatalf("%s: body %q", typ, f.srv.body)
		}
		if f.srv.method != "DELETE" || f.srv.path != "/applications/cid/grant" || f.srv.user != "cid" || f.srv.pass != tClientSc ||
			f.srv.accept != "application/vnd.github+json" || f.srv.ctype != "application/json" {
			t.Fatalf("%s: bad request %s %s user=%q accept=%q ct=%q", typ, f.srv.method, f.srv.path, f.srv.user, f.srv.accept, f.srv.ctype)
		}
	}
}

func TestRevokeGitHubStatuses(t *testing.T) {
	cases := []struct {
		code      int
		outcome   string
		wantErr   bool
		retryable bool
	}{
		{200, RevokeOK, false, false},
		{404, RevokeAlready, false, false}, // body is {"message":"Not Found"} below
		{422, RevokeFailed, true, false},
		{401, RevokeFailed, true, false},
		{403, RevokeFailed, true, false},
		{429, RevokeRetryable, true, true},
		{503, RevokeRetryable, true, true},
	}
	for _, c := range cases {
		f := newRevokeFixture(t, "github", "/applications/{client_id}/grant", nil, status(c.code, ghBody(c.code)))
		err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk")
		var re *RevokeError
		if c.wantErr != errors.As(err, &re) || (re != nil && (re.Retryable != c.retryable || re.Status != c.code)) {
			t.Fatalf("%d: err=%v", c.code, err)
		}
		if err != nil && strings.Contains(err.Error(), "SECRET-BODY") {
			t.Fatalf("%d: body leaked in error", c.code)
		}
		if f.reg.RevokeCounters().Count("prov", c.outcome) != 1 {
			t.Fatalf("%d: outcome counters %v", c.code, f.reg.RevokeCounters().Snapshot())
		}
	}
}

func TestRevokeRetryableAndPermanent(t *testing.T) {
	f := newRevokeFixture(t, "google", "/revoke", nil, status(503, ""))
	var re *RevokeError
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); !errors.As(err, &re) || !re.Retryable || re.Status != 503 {
		t.Fatalf("503 must be retryable: %v", err)
	}
	f = newRevokeFixture(t, "google", "/revoke", nil, status(401, ""))
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); !errors.As(err, &re) || re.Retryable || re.Status != 401 {
		t.Fatalf("401 must be permanent: %v", err)
	}
	// Transport failure: retryable, and the transport error text is dropped.
	f = newRevokeFixture(t, "google", "/revoke", testDoer{err: errors.New("dial tcp: " + tRefresh)}, status(200, ""))
	err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk")
	if !errors.As(err, &re) || !re.Retryable || re.Status != 0 || strings.Contains(err.Error(), tRefresh) {
		t.Fatalf("transport failure: %v", err)
	}
	// SSRF block: permanent, still ErrBlockedDestination, bounded.
	f = newRevokeFixture(t, "google", "/revoke", testDoer{err: &BlockedError{Reason: "blocked", AddrClass: "loopback"}}, status(200, ""))
	err = Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk")
	if !errors.As(err, &re) || re.Retryable || !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("blocked: %v", err)
	}
}

func TestRevokeGeneric(t *testing.T) {
	f := newRevokeFixture(t, "generic", "/revoke", nil, status(200, ""))
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(f.srv.body)
	if form.Get("token") != tRefresh || form.Get("token_type_hint") != "refresh_token" || f.srv.user != "cid" || f.srv.pass != tClientSc {
		t.Fatalf("bad generic request %q user=%q", f.srv.body, f.srv.user)
	}
	rec := liveRecord()
	rec.RefreshToken = ""
	if err := Revoke(t.Context(), f.provider(t), rec, f.secret, "uk"); err != nil {
		t.Fatal(err)
	}
	form, _ = url.ParseQuery(f.srv.body)
	if form.Get("token") != tAccess || form.Get("token_type_hint") != "access_token" {
		t.Fatalf("bad access fallback %q", f.srv.body)
	}
}

func TestRevokeGenericUnsupported(t *testing.T) {
	f := newRevokeFixture(t, "generic", "", nil, status(200, ""))
	err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk")
	if !errors.Is(err, ErrRevokeUnsupported) || f.srv.hits.Load() != 0 {
		t.Fatalf("want ErrRevokeUnsupported and no request: err=%v hits=%d", err, f.srv.hits.Load())
	}
	if f.reg.RevokeCounters().Count("prov", RevokeUnsupported) != 1 {
		t.Fatal("outcome must be unsupported")
	}
}

func TestRevokeUnconfiguredAndNoToken(t *testing.T) {
	// A FormPoster that is not a Requester.
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	cfg := config.OAuthProviderConfig{ID: "prov", Type: "google", ClientID: "cid", ClientSecretEnv: "SEC", AllowedScopes: []string{"a"}, RevokeURL: s.URL + "/r"}
	r, _ := newReg(t, []config.OAuthProviderConfig{cfg}, Options{
		LookupEnv: func(string) (string, bool) { return tClientSc, true }, Now: func() time.Time { return refreshNow }, HTTPClient: testPoster{},
	})
	p, _ := r.Get("prov")
	if err := Revoke(t.Context(), p, liveRecord(), NewSecret("x"), "uk"); !errors.Is(err, ErrRevokeUnconfigured) {
		t.Fatalf("want ErrRevokeUnconfigured, got %v", err)
	}
	f := newRevokeFixture(t, "google", "/revoke", nil, status(200, ""))
	var re *RevokeError
	if err := Revoke(t.Context(), f.provider(t), TokenRecord{V: 1}, f.secret, "uk"); !errors.As(err, &re) || re.Retryable || f.srv.hits.Load() != 0 {
		t.Fatalf("empty record must fail locally: %v", err)
	}
}

func TestRevokeNoSecretInLogsOrErrors(t *testing.T) {
	var buf bytes.Buffer
	f := newRevokeFixture(t, "github", "/applications/{client_id}/grant", nil, status(500, tAccess+tRefresh+tClientSc))
	p := f.provider(t)
	p.logger = slogTo(&buf)
	err := Revoke(t.Context(), p, liveRecord(), f.secret, "uk-hash")
	if err == nil {
		t.Fatal("want error")
	}
	for _, leak := range []string{tAccess, tRefresh, tClientSc} {
		if strings.Contains(err.Error(), leak) || strings.Contains(buf.String(), leak) || strings.Contains(f.logs.String(), leak) {
			t.Fatalf("secret %q leaked: err=%v log=%s", leak, err, buf.String())
		}
	}
	for _, want := range []string{`"msg":"oauth_revoke"`, `"provider":"prov"`, `"user_key":"uk-hash"`, `"status":500`, `"outcome":"retryable"`, `"duration_ms"`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log missing %s: %s", want, buf.String())
		}
	}
}

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }

func ghBody(code int) string {
	if code == 404 {
		return `{"message":"Not Found"}`
	}
	return `{"message":"SECRET-BODY"}`
}

func TestRevokeGitHub404MustBeGitHubNotFound(t *testing.T) {
	var re *RevokeError
	// HTML 404 from the right host.
	f := newRevokeFixture(t, "github", "/applications/{client_id}/grant", nil, status(404, "<html>not found</html>"))
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); !errors.As(err, &re) || re.Retryable || re.Status != 404 {
		t.Fatalf("HTML 404 must fail: %v", err)
	}
	// JSON Not Found from a host that is not the token host.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"Not Found"}`)
	}))
	defer other.Close()
	f = newRevokeFixture(t, "github", "/applications/{client_id}/grant", nil, status(404, `{"message":"Not Found"}`))
	p := f.provider(t)
	p.RevokeURL = strings.Replace(other.URL, "127.0.0.1", "localhost", 1) + "/applications/{client_id}/grant"
	if err := Revoke(t.Context(), p, liveRecord(), f.secret, "uk"); !errors.As(err, &re) || re.Retryable {
		t.Fatalf("404 from another host must fail: %v", err)
	}
	if f.reg.RevokeCounters().Count("prov", RevokeAlready) != 0 {
		t.Fatal("must not count as already")
	}
	// The built-in pair api.github.com next to github.com is accepted.
	d := &Provider{Type: "github", TokenURL: GitHubTokenURL, RevokeURL: GitHubRevokeURL, ClientID: "c"}
	if !d.githubNotFound([]byte(`{"message":"Not Found"}`)) || d.githubNotFound([]byte(`{"message":"Bad"}`)) {
		t.Fatal("default pair classification wrong")
	}
	d.TokenURL = "https://ghe.example.com/login/oauth/access_token"
	if d.githubNotFound([]byte(`{"message":"Not Found"}`)) {
		t.Fatal("GHES token host with api.github.com revoke must not be already")
	}
}

func TestRevoke404IsFailureForGoogleAndGeneric(t *testing.T) {
	for _, typ := range []string{"google", "generic"} {
		f := newRevokeFixture(t, typ, "/revoke", nil, status(404, `{"message":"Not Found"}`))
		var re *RevokeError
		if err := Revoke(t.Context(), f.provider(t), liveRecord(), f.secret, "uk"); !errors.As(err, &re) || re.Status != 404 {
			t.Fatalf("%s: 404 must fail: %v", typ, err)
		}
	}
}

func TestRevokeGitHubExpiredRecord(t *testing.T) {
	var revokedWith string
	var tokenReply func(w http.ResponseWriter)
	var f *revokeFixture
	f = newRevokeFixture(t, "github", "/applications/{client_id}/grant", nil, func(w http.ResponseWriter) {
		if f.srv.path == "/token" {
			tokenReply(w)
			return
		}
		var b map[string]string
		_ = json.Unmarshal([]byte(f.srv.body), &b)
		revokedWith = b["access_token"]
		w.WriteHeader(204)
	})
	p := f.provider(t)

	tokenReply = status(200, `{"access_token":"`+tNewAcc+`","expires_in":3600}`)
	if err := Revoke(t.Context(), p, storedRecord(), f.secret, "uk"); err != nil {
		t.Fatal(err)
	}
	if revokedWith != tNewAcc {
		t.Fatalf("must revoke with the refreshed access token, got %q", revokedWith)
	}

	revokedWith = ""
	hits := f.srv.hits.Load()
	tokenReply = status(400, `{"error":"bad_refresh_token"}`)
	if err := Revoke(t.Context(), p, storedRecord(), f.secret, "uk"); err != nil {
		t.Fatalf("invalid refresh token means already revoked: %v", err)
	}
	if revokedWith != "" || f.srv.hits.Load() != hits+1 || f.reg.RevokeCounters().Count("prov", RevokeAlready) != 1 {
		t.Fatalf("expected only the refresh call and outcome already: with=%q", revokedWith)
	}

	var re *RevokeError
	tokenReply = status(503, "")
	if err := Revoke(t.Context(), p, storedRecord(), f.secret, "uk"); !errors.As(err, &re) || !re.Retryable {
		t.Fatalf("retryable refresh must be retryable: %v", err)
	}
	tokenReply = status(400, `{"error":"invalid_client"}`)
	if err := Revoke(t.Context(), p, storedRecord(), f.secret, "uk"); !errors.As(err, &re) || re.Retryable {
		t.Fatalf("permanent refresh failure must be permanent: %v", err)
	}
}

func TestRevokeGitHubLocalFailures(t *testing.T) {
	f := newRevokeFixture(t, "githubApp", "/applications/{client_id}/grant", nil, status(204, ""))
	var re *RevokeError
	if err := Revoke(t.Context(), f.provider(t), liveRecord(), Secret{}, "uk"); !errors.As(err, &re) || re.Retryable {
		t.Fatalf("zero secret: %v", err)
	}
	rec := liveRecord()
	rec.AccessToken = ""
	if err := Revoke(t.Context(), f.provider(t), rec, f.secret, "uk"); !errors.As(err, &re) || re.Retryable {
		t.Fatalf("empty access token: %v", err)
	}
	if f.srv.hits.Load() != 0 {
		t.Fatal("no request may be sent")
	}
}

func TestRequestRedaction(t *testing.T) {
	r := Request{Method: "DELETE", URL: "https://x", Body: []byte(tAccess), BasicUser: "u", BasicPass: tClientSc}
	fr := FormRequest{URL: "https://x", Form: "refresh_token=" + tRefresh, BasicUser: "u", BasicPass: tClientSc}
	var buf bytes.Buffer
	lg := slogTo(&buf)
	lg.Info("x", "r", r, "fr", fr)
	out := fmt.Sprintf("%v %+v %#v %s %v %+v %#v", r, r, r, r, fr, fr, fr) + buf.String()
	for _, leak := range []string{tAccess, tClientSc, tRefresh} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q leaked: %s", leak, out)
		}
	}
}

func TestRevokeBlockedLogResets(t *testing.T) {
	f := newRevokeFixture(t, "google", "/revoke", testDoer{err: &BlockedError{Reason: "blocked", AddrClass: "loopback"}}, status(200, ""))
	p := f.provider(t)
	_ = Revoke(t.Context(), p, liveRecord(), f.secret, "uk")
	if !p.revokeBlockedLogged.Load() || p.blockedLogged.Load() {
		t.Fatal("revoke must use its own blocked-log flag")
	}
	p.httpc = testDoer{}
	if err := Revoke(t.Context(), p, liveRecord(), f.secret, "uk"); err != nil {
		t.Fatal(err)
	}
	if p.revokeBlockedLogged.Load() {
		t.Fatal("flag must reset after an ok revoke")
	}
}
