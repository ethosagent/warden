package fakes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func noFollow() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs the authorization endpoint and returns the redirect query.
func authorize(t *testing.T, iss *OIDCIssuer, verifier string) url.Values {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {"c1"}, "redirect_uri": {"https://cp.example/auth/callback"},
		"state": {"st"}, "nonce": {"nn"}, "code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}, "scope": {"openid"},
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, iss.URL()+"/auth?"+q.Encode(), nil)
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Host != "cp.example" {
		t.Fatalf("authorize Location = %q", resp.Header.Get("Location"))
	}
	return loc.Query()
}

func exchange(t *testing.T, iss *OIDCIssuer, code, verifier, secret string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {"https://cp.example/auth/callback"},
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, iss.URL()+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("c1", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestOIDCIssuerAuthorizationCodeFlow(t *testing.T) {
	iss := NewOIDCIssuer(t)
	iss.RegisterClient("c1", "s3cret")
	iss.SetLogin(Valid("bob", "bob@example.com", "admins"))

	q := authorize(t, iss, "verifier-1")
	if q.Get("state") != "st" || q.Get("code") == "" {
		t.Fatalf("redirect query = %v", q)
	}
	if got := iss.AuthRequests(); len(got) != 1 || got[0].Nonce != "nn" || got[0].Challenge != s256("verifier-1") {
		t.Fatalf("recorded requests = %+v", got)
	}

	if st, _ := exchange(t, iss, q.Get("code"), "wrong-verifier", "s3cret"); st != http.StatusBadRequest {
		t.Fatalf("wrong verifier status = %d, want 400", st)
	}
	// The failed attempt spent the code.
	if st, _ := exchange(t, iss, q.Get("code"), "verifier-1", "s3cret"); st != http.StatusBadRequest {
		t.Fatalf("spent code status = %d, want 400", st)
	}

	q = authorize(t, iss, "verifier-2")
	if st, _ := exchange(t, iss, q.Get("code"), "verifier-2", "wrong-secret"); st != http.StatusBadRequest {
		t.Fatalf("wrong secret status = %d, want 400", st)
	}

	q = authorize(t, iss, "verifier-3")
	st, body := exchange(t, iss, q.Get("code"), "verifier-3", "s3cret")
	if st != http.StatusOK {
		t.Fatalf("exchange status = %d", st)
	}
	tok, _ := body["id_token"].(string)
	_, claims, _, _ := decoded(t, tok)
	if claims["sub"] != "bob" || claims["aud"] != "c1" || claims["azp"] != "c1" || claims["nonce"] != "nn" || claims["iss"] != iss.Issuer() {
		t.Fatalf("id token claims = %v", claims)
	}
	if iss.TokenRequests() != 4 {
		t.Fatalf("token requests = %d, want 4", iss.TokenRequests())
	}
}

func TestOIDCIssuerFlowFailures(t *testing.T) {
	iss := NewOIDCIssuer(t)
	iss.RegisterClient("c1", "s")
	iss.FailAuthorize("access_denied")
	q := authorize(t, iss, "v")
	if q.Get("error") != "access_denied" || q.Get("code") != "" || q.Get("state") != "st" {
		t.Fatalf("error redirect query = %v", q)
	}
	iss.FailAuthorize("")
	code := authorize(t, iss, "v").Get("code")
	iss.SetTokenStatus(http.StatusInternalServerError)
	if st, _ := exchange(t, iss, code, "v", "s"); st != http.StatusInternalServerError {
		t.Fatalf("forced token status = %d", st)
	}
	iss.SetTokenStatus(0)
	if st, _ := exchange(t, iss, code, "v", "s"); st != http.StatusOK {
		t.Fatalf("token status after reset = %d", st)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, iss.URL()+"/auth?client_id=unknown&response_type=code&redirect_uri=https://x.example/cb", nil)
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown client status = %d, want 400", resp.StatusCode)
	}
}

func TestOIDCIssuerPublicIssuer(t *testing.T) {
	iss := NewOIDCIssuer(t, WithPublicIssuer("http://localhost:5556/dex/"))
	if iss.Issuer() != "http://localhost:5556/dex" {
		t.Fatalf("Issuer() = %q", iss.Issuer())
	}
	doc := getJSON(t, iss.URL()+"/dex/.well-known/openid-configuration")
	if doc["issuer"] != "http://localhost:5556/dex" || doc["jwks_uri"] != "http://localhost:5556/dex/jwks" ||
		doc["authorization_endpoint"] != "http://localhost:5556/dex/auth" {
		t.Fatalf("discovery = %v", doc)
	}
	if keys := getJSON(t, iss.URL()+"/dex/jwks"); keys["keys"] == nil {
		t.Fatal("no keys served under the public path")
	}
}
