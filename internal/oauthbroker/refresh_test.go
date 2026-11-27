package oauthbroker

import (
	"bytes"
	"context"
	"encoding/base64"
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

const (
	tRefresh  = "r-stored-refresh-SECRET"
	tAccess   = "a-old-access-SECRET"
	tNewAcc   = "a-new-access-SECRET"
	tNewRef   = "r-rotated-refresh-SECRET"
	tClientSc = "client-secret-SECRET"
)

var refreshNow = time.Unix(1_800_000_000, 0)

type refreshFixture struct {
	srv   *httptest.Server
	hits  atomic.Int32
	last  *http.Request
	form  url.Values
	reg   *Registry
	logs  *bytes.Buffer
	reply func(w http.ResponseWriter)
}

func newRefreshFixture(t *testing.T, typ string, reply func(w http.ResponseWriter)) *refreshFixture {
	t.Helper()
	f := &refreshFixture{reply: reply}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		f.form, _ = url.ParseQuery(string(b))
		f.last = r
		f.reply(w)
	}))
	t.Cleanup(f.srv.Close)
	cfg := config.OAuthProviderConfig{ID: "prov", Type: typ, ClientID: "cid", ClientSecretEnv: "SEC", TokenURL: f.srv.URL + "/token"}
	switch typ {
	case config.OAuthProviderGoogle, config.OAuthProviderGitHub:
		cfg.AllowedScopes = []string{"a", "b"}
	case config.OAuthProviderGeneric:
		cfg.AuthURL = f.srv.URL + "/auth"
	}
	r, logs := newReg(t, []config.OAuthProviderConfig{cfg}, Options{
		LookupEnv:  func(string) (string, bool) { return tClientSc, true },
		Now:        func() time.Time { return refreshNow },
		HTTPClient: testPoster{},
	})
	f.reg, f.logs = r, logs
	return f
}

func (f *refreshFixture) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := f.reg.Get("prov")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func storedRecord() TokenRecord {
	return TokenRecord{V: 1, GrantID: "g1", Provider: "prov", ClientID: "cid", TokenType: "Bearer",
		AccessToken: tAccess, RefreshToken: tRefresh, Scope: "a b", Expiry: refreshNow.Unix() - 10,
		RefreshExpiry: 12345, ObtainedAt: 1}
}

func jsonReply(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func assertClean(t *testing.T, err error, logs *bytes.Buffer) {
	t.Helper()
	for _, s := range []string{tRefresh, tAccess, tNewAcc, tNewRef, tClientSc, "SENSITIVE-DESCRIPTION"} {
		if err != nil && strings.Contains(err.Error(), s) {
			t.Errorf("error leaks %q: %v", s, err)
		}
		if logs != nil && strings.Contains(logs.String(), s) {
			t.Errorf("log leaks %q", s)
		}
	}
}

func TestRefreshGoogle(t *testing.T) {
	f := newRefreshFixture(t, "google", jsonReply(200, `{"access_token":"`+tNewAcc+`","token_type":"Bearer","expires_in":3599,"scope":"b a"}`))
	p := f.provider(t)
	rec := storedRecord()
	out, err := Refresh(t.Context(), p, rec, NewSecret(tClientSc))
	if err != nil {
		t.Fatal(err)
	}
	if f.form.Get("grant_type") != "refresh_token" || f.form.Get("refresh_token") != tRefresh {
		t.Fatalf("form = %v", f.form)
	}
	if f.form.Get("client_secret") != "" || f.form.Get("client_id") != "" {
		t.Fatalf("google must use basic auth only: %v", f.form)
	}
	u, pw, ok := f.last.BasicAuth()
	if !ok || u != "cid" || pw != tClientSc {
		t.Fatalf("basic auth = %q %q %v", u, pw, ok)
	}
	if f.last.Header.Get("Accept") != "application/json" || f.last.Method != "POST" {
		t.Fatalf("headers = %v", f.last.Header)
	}
	if out.AccessToken != tNewAcc || out.RefreshToken != tRefresh {
		t.Fatalf("response without refresh_token must keep the stored one: %v", out)
	}
	if out.Expiry != refreshNow.Unix()+3599 || out.ObtainedAt != refreshNow.Unix() {
		t.Fatalf("expiry %d obtained %d", out.Expiry, out.ObtainedAt)
	}
	if out.RefreshExpiry != 12345 || out.GrantID != "g1" || out.Provider != "prov" || out.ClientID != "cid" || out.Scope != "a b" {
		t.Fatalf("kept fields wrong: %v", out)
	}
	if rec.AccessToken != tAccess {
		t.Fatal("input record mutated")
	}
	if got := f.reg.RefreshCounters().Count("prov", RefreshOK); got != 1 {
		t.Fatalf("counter ok = %d", got)
	}

	// A rotated refresh token is returned so the caller can store it.
	f2 := newRefreshFixture(t, "google", jsonReply(200, `{"access_token":"`+tNewAcc+`","refresh_token":"`+tNewRef+`","expires_in":"60"}`))
	out, err = Refresh(t.Context(), f2.provider(t), storedRecord(), NewSecret(tClientSc))
	if err != nil || out.RefreshToken != tNewRef || out.Expiry != refreshNow.Unix()+60 {
		t.Fatalf("rotated: %v %v", out, err)
	}
	if out.RefreshExpiry != 0 {
		t.Fatalf("rotated token without expiry must clear the old refresh_expiry, got %d", out.RefreshExpiry)
	}
}

func TestRefreshBasicAuthEscapesSpecials(t *testing.T) {
	f := newRefreshFixture(t, "generic", jsonReply(200, `{"access_token":"x","expires_in":1}`))
	_, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret("p:w d+/"))
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimPrefix(f.last.Header.Get("Authorization"), "Basic ")
	dec, _ := base64.StdEncoding.DecodeString(raw)
	if string(dec) != "cid:p%3Aw+d%2B%2F" {
		t.Fatalf("basic = %q", dec)
	}
}

func TestRefreshGitHubApp(t *testing.T) {
	f := newRefreshFixture(t, "githubApp", jsonReply(200, `{"access_token":"`+tNewAcc+`","refresh_token":"`+tNewRef+`","expires_in":28800,"refresh_token_expires_in":15897600,"token_type":"bearer"}`))
	out, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
	if err != nil {
		t.Fatal(err)
	}
	if f.form.Get("client_id") != "cid" || f.form.Get("client_secret") != tClientSc || f.form.Get("grant_type") != "refresh_token" {
		t.Fatalf("github must use client_secret_post: %v", f.form)
	}
	if _, _, ok := f.last.BasicAuth(); ok {
		t.Fatal("github must not send basic auth")
	}
	if out.RefreshExpiry != refreshNow.Unix()+15897600 || out.RefreshToken != tNewRef || out.TokenType != "bearer" {
		t.Fatalf("out = %v", out)
	}
}

func TestRefreshErrors(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    error
		notWant []error
		outcome string
	}{
		{"invalid_grant 400", 400, `{"error":"invalid_grant","error_description":"SENSITIVE-DESCRIPTION"}`, ErrRefreshInvalidGrant, []error{ErrRefreshRetryable}, RefreshInvalidGrant},
		{"invalid_grant 200", 200, `{"error":"invalid_grant"}`, ErrRefreshInvalidGrant, nil, RefreshInvalidGrant},
		{"bad_refresh_token 200", 200, `{"error":"bad_refresh_token","error_description":"SENSITIVE-DESCRIPTION"}`, ErrRefreshInvalidGrant, nil, RefreshInvalidGrant},
		{"invalid_client", 401, `{"error":"invalid_client"}`, ErrRefreshInvalidClient, []error{ErrRefreshInvalidGrant, ErrRefreshRetryable}, RefreshInvalidClient},
		{"other 4xx", 400, `{"error":"invalid_scope"}`, ErrRefreshPermanent, []error{ErrRefreshInvalidGrant, ErrRefreshRetryable}, RefreshPermanent},
		{"4xx no body", 403, `<html>SENSITIVE-DESCRIPTION</html>`, ErrRefreshPermanent, []error{ErrRefreshRetryable}, RefreshPermanent},
		{"503", 503, `{"error":"temporarily_unavailable","error_description":"SENSITIVE-DESCRIPTION"}`, ErrRefreshRetryable, []error{ErrRefreshPermanent, ErrRefreshInvalidGrant}, RefreshRetryable},
		{"500 html", 500, `<html>SENSITIVE-DESCRIPTION</html>`, ErrRefreshRetryable, nil, RefreshRetryable},
		{"429", 429, `{"error":"slow_down"}`, ErrRefreshRetryable, nil, RefreshRetryable},
		{"200 error field", 200, `{"error":"unsupported_thing","error_description":"SENSITIVE-DESCRIPTION"}`, ErrRefreshPermanent, []error{ErrRefreshRetryable}, RefreshPermanent},
		{"200 hostile error code", 200, `{"error":"has space ` + tClientSc + `"}`, ErrRefreshPermanent, nil, RefreshPermanent},
		{"200 no access token", 200, `{"token_type":"Bearer"}`, ErrRefreshPermanent, nil, RefreshPermanent},
		{"200 not json", 200, `SENSITIVE-DESCRIPTION`, ErrRefreshPermanent, nil, RefreshPermanent},
		{"github 200 incorrect_client_credentials", 200, `{"error":"incorrect_client_credentials","error_description":"SENSITIVE-DESCRIPTION"}`, ErrRefreshInvalidClient, []error{ErrRefreshInvalidGrant}, RefreshInvalidClient},
		{"redirect not followed", 302, ``, ErrRefreshPermanent, nil, RefreshPermanent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t, "google", jsonReply(tc.status, tc.body))
			_, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			for _, n := range tc.notWant {
				if errors.Is(err, n) {
					t.Errorf("err %v must not be %v", err, n)
				}
			}
			assertClean(t, err, f.logs)
			if got := f.reg.RefreshCounters().Count("prov", tc.outcome); got != 1 {
				t.Errorf("counter %s = %d", tc.outcome, got)
			}
		})
	}
}

func TestRefreshInvalidClientLogsHintNotSecret(t *testing.T) {
	f := newRefreshFixture(t, "google", jsonReply(401, `{"error":"invalid_client"}`))
	_, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
	if !errors.Is(err, ErrRefreshInvalidClient) {
		t.Fatal(err)
	}
	if !strings.Contains(f.logs.String(), "oauth_refresh_invalid_client") {
		t.Fatalf("no operator hint logged: %s", f.logs)
	}
	assertClean(t, err, f.logs)
}

func TestRefreshNotRefreshable(t *testing.T) {
	f := newRefreshFixture(t, "github", jsonReply(200, `{}`))
	rec := storedRecord()
	rec.RefreshToken, rec.Expiry, rec.RefreshExpiry = "", 0, 0 // GitHub OAuth app
	_, err := Refresh(t.Context(), f.provider(t), rec, NewSecret(tClientSc))
	if !errors.Is(err, ErrNotRefreshable) {
		t.Fatalf("err = %v", err)
	}
	if f.hits.Load() != 0 {
		t.Fatal("a not-refreshable record must make no HTTP call")
	}
	if f.reg.RefreshCounters().Count("prov", RefreshNotRefresh) != 1 {
		t.Fatal("counter")
	}
}

func TestRefreshTransportFailureRetryable(t *testing.T) {
	f := newRefreshFixture(t, "google", jsonReply(200, `{}`))
	f.srv.Close() // connection refused
	_, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
	if !errors.Is(err, ErrRefreshRetryable) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "token") {
		t.Fatalf("transport detail leaked: %v", err)
	}
}

func TestRefreshOversizedResponse(t *testing.T) {
	big := `{"access_token":"` + strings.Repeat("x", MaxProviderResponseBytes) + `"}`
	f := newRefreshFixture(t, "google", jsonReply(200, big))
	_, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
	if !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v", err)
	}
}

func TestRefreshNeverExpiringAccessToken(t *testing.T) {
	// A refreshable record whose response has no expires_in gets the short default, never "no expiry".
	f := newRefreshFixture(t, "github", jsonReply(200, `{"access_token":"`+tNewAcc+`"}`))
	out, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
	if err != nil || out.Expiry != refreshNow.Unix()+defaultAccessLifetime || out.RefreshToken != tRefresh {
		t.Fatalf("%v %v", out, err)
	}
}

func TestRefreshRequiresConfiguration(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "prov", Type: "google", ClientID: "cid", ClientSecretEnv: "S", AllowedScopes: []string{"a"}}}
	r, _ := newReg(t, cfg, Options{LookupEnv: func(string) (string, bool) { return "s", true }})
	p, _ := r.Get("prov")
	if _, err := Refresh(t.Context(), p, storedRecord(), NewSecret("s")); !errors.Is(err, ErrRefreshUnconfigured) {
		t.Fatalf("no client/clock: %v", err)
	}
	f := newRefreshFixture(t, "google", jsonReply(200, `{}`))
	if _, err := Refresh(t.Context(), f.provider(t), storedRecord(), Secret{}); !errors.Is(err, ErrRefreshUnconfigured) {
		t.Fatalf("no secret: %v", err)
	}
	if f.hits.Load() != 0 {
		t.Fatal("no call without a secret")
	}
}

func TestRefreshRefusesPlainHTTPNonLoopback(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://oauth2.googleapis.com/token": true, "http://127.0.0.1:9/t": true, "http://localhost/t": true,
		"http://example.com/t": false, "http://127.evil.com/t": false, "http://[::1]:9/t": true, "http://LOCALHOST/t": true, "ftp://x/t": false, "https://u:p@x/t": false, "": false,
	} {
		if refreshURLAllowed(raw) != want {
			t.Errorf("refreshURLAllowed(%q) != %v", raw, want)
		}
	}
	p := &Provider{ID: "prov", Type: "generic", TokenURL: "http://example.com/t", httpc: failDoer{}, now: time.Now}
	if _, err := Refresh(t.Context(), p, storedRecord(), NewSecret("s")); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v", err)
	}
}

type failDoer struct{}

func (failDoer) PostForm(context.Context, FormRequest) (int, []byte, error) {
	return 0, nil, fmt.Errorf("must not be called")
}

// testPoster is a plain, test-only FormPoster over the default transport
// (httptest servers are loopback http, which the production poster refuses).
type testPoster struct{}

func (testPoster) PostForm(ctx context.Context, r FormRequest) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, strings.NewReader(r.Form))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.BasicUser != "" {
		req.SetBasicAuth(r.BasicUser, r.BasicPass)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxProviderResponseBytes+1))
	return resp.StatusCode, b, err
}

func TestRefreshNoSecretInLogs(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&buf, nil))
	f := newRefreshFixture(t, "google", jsonReply(200, `{"access_token":"`+tNewAcc+`","refresh_token":"`+tNewRef+`","expires_in":1}`))
	p := f.provider(t)
	out, err := Refresh(t.Context(), p, storedRecord(), NewSecret(tClientSc))
	if err != nil {
		t.Fatal(err)
	}
	lg.Info("x", "rec", out, "p", p, "err", err)
	fmt.Fprintf(&buf, "%v %+v %#v %v", out, out, out, p)
	assertClean(t, nil, &buf)
	assertClean(t, nil, f.logs)
}

func TestRefreshLifetimeClamps(t *testing.T) {
	year := int64(maxLifetime)
	for _, tc := range []struct {
		name, body string
		wantExp    int64
		wantRefExp int64
		wantErr    bool
	}{
		{"1e19", `{"access_token":"x","expires_in":1e19,"refresh_token":"r","refresh_token_expires_in":1e19}`, refreshNow.Unix() + year, refreshNow.Unix() + year, false},
		{"huge int", `{"access_token":"x","expires_in":99999999999999999999}`, refreshNow.Unix() + year, 12345, false},
		{"zero", `{"access_token":"x","expires_in":0}`, refreshNow.Unix() + defaultAccessLifetime, 12345, false},
		{"negative", `{"access_token":"x","expires_in":-5}`, 0, 0, true},
		{"negative refresh", `{"access_token":"x","expires_in":5,"refresh_token_expires_in":-1}`, 0, 0, true},
		{"nan string", `{"access_token":"x","expires_in":"NaN"}`, 0, 0, true},
		{"inf string", `{"access_token":"x","expires_in":"Inf"}`, 0, 0, true},
		{"quoted ok", `{"access_token":"x","expires_in":"90"}`, refreshNow.Unix() + 90, 12345, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t, "google", jsonReply(200, tc.body))
			out, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
			if tc.wantErr {
				if !errors.Is(err, ErrRefreshPermanent) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || out.Expiry != tc.wantExp || out.RefreshExpiry != tc.wantRefExp {
				t.Fatalf("expiry %d refresh_expiry %d err %v", out.Expiry, out.RefreshExpiry, err)
			}
		})
	}
}

func TestRefreshErrorCodesAreClosedSet(t *testing.T) {
	for _, hostile := range []string{"ghu_" + strings.Repeat("a", 36), "GOCSPX-" + strings.Repeat("b", 28), tClientSc, tRefresh} {
		f := newRefreshFixture(t, "google", jsonReply(400, `{"error":"`+hostile+`"}`))
		_, err := Refresh(t.Context(), f.provider(t), storedRecord(), NewSecret(tClientSc))
		if !errors.Is(err, ErrRefreshPermanent) || !strings.HasSuffix(err.Error(), ": other") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), hostile) || strings.Contains(f.logs.String(), hostile) {
			t.Fatalf("token-shaped error code leaked: %v", err)
		}
	}
	for _, c := range []string{"invalid_scope", "slow_down", "temporarily_unavailable"} {
		if sanitizeOAuthCode(c) != c {
			t.Errorf("%s must be kept", c)
		}
	}
}

func TestRefreshInvalidClientHintRateLimited(t *testing.T) {
	f := newRefreshFixture(t, "google", jsonReply(401, `{"error":"invalid_client"}`))
	p := f.provider(t)
	for range 3 {
		_, _ = Refresh(t.Context(), p, storedRecord(), NewSecret(tClientSc))
	}
	if n := strings.Count(f.logs.String(), "oauth_refresh_invalid_client"); n != 1 {
		t.Fatalf("hint logged %d times, want 1", n)
	}
	f.reply = jsonReply(200, `{"access_token":"x","expires_in":60}`)
	if _, err := Refresh(t.Context(), p, storedRecord(), NewSecret(tClientSc)); err != nil {
		t.Fatal(err)
	}
	f.reply = jsonReply(401, `{"error":"invalid_client"}`)
	_, _ = Refresh(t.Context(), p, storedRecord(), NewSecret(tClientSc))
	if n := strings.Count(f.logs.String(), "oauth_refresh_invalid_client"); n != 2 {
		t.Fatalf("hint after a success logged %d times total, want 2", n)
	}
}

type blockedPoster struct{ n int }

func (b *blockedPoster) PostForm(context.Context, FormRequest) (int, []byte, error) {
	b.n++
	return 0, nil, fmt.Errorf("dial: %w", &BlockedError{Reason: "ssrf_blocked", AddrClass: "private"})
}

func TestRefreshBlockedDestination(t *testing.T) {
	var buf bytes.Buffer
	bp := &blockedPoster{}
	r, _ := newReg(t, []config.OAuthProviderConfig{{ID: "prov", Type: "generic", ClientID: "cid", ClientSecretEnv: "S",
		AuthURL: "https://idp.example.com/a", TokenURL: "https://idp.example.com/t"}}, Options{
		LookupEnv: func(string) (string, bool) { return "s", true }, Now: func() time.Time { return refreshNow },
		HTTPClient: bp, Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	p, _ := r.Get("prov")
	for range 2 {
		_, err := Refresh(t.Context(), p, storedRecord(), NewSecret("s"))
		if !errors.Is(err, ErrRefreshPermanent) || !errors.Is(err, ErrBlockedDestination) || errors.Is(err, ErrRefreshRetryable) {
			t.Fatalf("err = %v", err)
		}
	}
	if r.RefreshCounters().Count("prov", RefreshBlocked) != 2 {
		t.Fatal("blocked outcome not counted")
	}
	if strings.Count(buf.String(), "oauth_refresh_blocked_destination") != 1 || !strings.Contains(buf.String(), "private") || strings.Contains(buf.String(), "idp.example.com") {
		t.Fatalf("log = %s", buf.String())
	}
}
