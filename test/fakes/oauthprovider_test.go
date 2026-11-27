package fakes

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authReq(p *OAuthProvider, verifier string) string {
	q := url.Values{
		"client_id": {OAuthDefaultClientID}, "response_type": {"code"}, "redirect_uri": {"https://cp.example/connect/callback"},
		"state": {"st"}, "scope": {"a b"}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"},
	}
	return p.AuthURL() + "?" + q.Encode()
}

func exchangeForm(code, verifier, secret string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://cp.example/connect/callback"},
		"client_id": {OAuthDefaultClientID}, "client_secret": {secret}, "code_verifier": {verifier},
	}
}

func postToken(t *testing.T, p *OAuthProvider, form url.Values, accept string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, p.TokenURL(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// TestOAuthProvider: the authorization endpoint mints a one-time code bound to
// the PKCE challenge; the token endpoint checks the verifier, the secret, the
// redirect and Accept, issues once, and answers in the Google or GitHub style.
func TestOAuthProvider(t *testing.T) {
	p := NewOAuthProvider(t)
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	cb, err := p.Authorize(authReq(p, verifier), false)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(cb)
	code := u.Query().Get("code")
	if u.Query().Get("state") != "st" || code == "" || u.Host != "cp.example" {
		t.Fatalf("callback = %s", cb)
	}
	if _, err := p.Authorize(strings.Replace(authReq(p, verifier), "S256", "plain", 1), false); err == nil {
		t.Error("a plain challenge method was accepted")
	}

	if st, m := postToken(t, p, exchangeForm(code, "wrong-verifier-wrong-verifier-wrong-verifier", OAuthDefaultSecret), "application/json"); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier = %d %v", st, m)
	}
	if st, m := postToken(t, p, exchangeForm(code, verifier, "nope"), "application/json"); st != 401 || m["error"] != "invalid_client" {
		t.Fatalf("wrong secret = %d %v", st, m)
	}
	if st, m := postToken(t, p, exchangeForm(code, verifier, OAuthDefaultSecret), ""); st != 400 || m["error"] != "invalid_request" {
		t.Fatalf("no Accept = %d %v", st, m)
	}
	st, m := postToken(t, p, exchangeForm(code, verifier, OAuthDefaultSecret), "application/json")
	if st != 200 || m["access_token"] != p.AccessToken(1) || m["refresh_token"] != p.RefreshToken(1) || m["scope"] != "a b" || m["token_type"] != "Bearer" {
		t.Fatalf("exchange = %d %v", st, m)
	}
	if st, m := postToken(t, p, exchangeForm(code, verifier, OAuthDefaultSecret), "application/json"); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("code reuse = %d %v", st, m)
	}
	if p.Issued() != 1 || p.TokenRequests() != 5 || len(p.TokenForms()) != 5 || p.LastTokenForm().Get("code") != code {
		t.Fatalf("issued %d requests %d", p.Issued(), p.TokenRequests())
	}

	// Knobs: granted scope override, no refresh token, GitHub style, failures.
	p.GrantScopes("x y")
	p.OmitRefreshToken(true)
	cb, _ = p.Authorize(authReq(p, verifier), false)
	u, _ = url.Parse(cb)
	_, m = postToken(t, p, exchangeForm(u.Query().Get("code"), verifier, OAuthDefaultSecret), "application/json")
	if m["scope"] != "x y" || m["refresh_token"] != nil {
		t.Fatalf("overridden response = %v", m)
	}
	p.ClearGrantScopes()
	p.SetStyle(OAuthGitHub)
	cb, _ = p.Authorize(authReq(p, verifier), false)
	u, _ = url.Parse(cb)
	_, m = postToken(t, p, exchangeForm(u.Query().Get("code"), verifier, OAuthDefaultSecret), "application/json")
	if m["scope"] != "a,b" || m["token_type"] != "bearer" {
		t.Fatalf("github response = %v", m)
	}
	p.FailToken("bad_verification_code", 400)
	if st, m := postToken(t, p, exchangeForm("x", verifier, OAuthDefaultSecret), "application/json"); st != 200 || m["error"] != "bad_verification_code" {
		t.Fatalf("github failure = %d %v", st, m)
	}
	p.SetStyle(OAuthGoogle)
	if st, m := postToken(t, p, exchangeForm("x", verifier, OAuthDefaultSecret), "application/json"); st != 400 || m["error"] != "bad_verification_code" {
		t.Fatalf("google failure = %d %v", st, m)
	}

	// A denial redirects back with error=access_denied and no code.
	cb, _ = p.Authorize(authReq(p, verifier), true)
	u, _ = url.Parse(cb)
	if u.Query().Get("error") != "access_denied" || u.Query().Get("code") != "" {
		t.Fatalf("denied callback = %s", cb)
	}
}
