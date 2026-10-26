package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	oidc "github.com/ethosagent/warden/internal/identity/adapters/oidc"
)

const publicIssuer = "http://localhost:5556/dex"

type rec struct {
	path, query, host, hdr, body, method string
}

func recorder(out *atomic.Pointer[rec], hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		out.Store(&rec{r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Get("X-Test"), string(b), r.Method})
		w.WriteHeader(http.StatusNoContent)
	})
}

func newClient(t *testing.T, internal string) *http.Client {
	t.Helper()
	c, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: publicIssuer, InternalIssuerURL: internal})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHTTPClientRewrite(t *testing.T) {
	var got atomic.Pointer[rec]
	var hits atomic.Int32
	srv := httptest.NewServer(recorder(&got, &hits))
	defer srv.Close()
	c := newClient(t, srv.URL)

	req, _ := http.NewRequest(http.MethodGet, "http://localhost:5556/dex/token?x=1", nil)
	req.Header.Set("X-Test", "v")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	r := got.Load()
	if r.path != "/dex/token" || r.query != "x=1" || r.host != "localhost:5556" || r.hdr != "v" {
		t.Fatalf("GET not preserved: %+v", r)
	}
	if req.URL.String() != "http://localhost:5556/dex/token?x=1" || req.Host != "localhost:5556" {
		t.Fatalf("caller request mutated: %s host=%q", req.URL, req.Host)
	}

	post, _ := http.NewRequest(http.MethodPost, "http://localhost:5556/dex/token", strings.NewReader("a=1&b=2"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = c.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	r = got.Load()
	if r.method != "POST" || r.body != "a=1&b=2" || r.host != "localhost:5556" {
		t.Fatalf("POST not preserved: %+v", r)
	}
}

func TestHTTPClientOtherOriginsUntouched(t *testing.T) {
	var gotI, gotO atomic.Pointer[rec]
	var hitsI, hitsO atomic.Int32
	internal := httptest.NewServer(recorder(&gotI, &hitsI))
	defer internal.Close()
	other := httptest.NewServer(recorder(&gotO, &hitsO))
	defer other.Close()
	c := newClient(t, internal.URL)

	resp, err := c.Get(other.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hitsO.Load() != 1 || hitsI.Load() != 0 {
		t.Fatalf("other=%d internal=%d", hitsO.Load(), hitsI.Load())
	}

	// Same host, different port: not the issuer origin.
	if resp, err := c.Get("http://localhost:5557/x"); err == nil {
		resp.Body.Close()
	}
	if hitsI.Load() != 0 {
		t.Fatal("same-host other-port request was rewritten")
	}

	// No internal URL: nothing is rewritten.
	c2, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: "https://idp.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = c2.Get(other.URL + "/y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hitsO.Load() != 2 {
		t.Fatalf("other=%d", hitsO.Load())
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestOIDCDiscoveryKeepsIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dex/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                publicIssuer,
			"jwks_uri":                              publicIssuer + "/keys",
			"authorization_endpoint":                publicIssuer + "/auth",
			"token_endpoint":                        publicIssuer + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/dex/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newClient(t, srv.URL)
	ctx := context.Background()

	// The red-first check needs nothing listening on the public origin; a dev
	// box running the Dex stack there would make it fail for the wrong reason.
	if ln, err := net.Listen("tcp", "localhost:5556"); err == nil {
		ln.Close()
		if _, err := gooidc.NewProvider(ctx, publicIssuer); err == nil {
			t.Fatal("discovery without WithHTTPClient must fail")
		}
	}
	p, err := gooidc.NewProvider(oidc.WithHTTPClient(ctx, c), publicIssuer)
	if err != nil {
		t.Fatal(err)
	}

	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": publicIssuer, "aud": "warden", "sub": "u1", "exp": time.Now().Add(5 * time.Minute).Unix()})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	tok, err := p.Verifier(&gooidc.Config{ClientID: "warden"}).Verify(oidc.WithHTTPClient(ctx, c), signing+"."+b64(sig))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Subject != "u1" || tok.Issuer != publicIssuer {
		t.Fatalf("token: %+v", tok)
	}
}

func TestOAuth2ExchangeUsesClient(t *testing.T) {
	var form atomic.Value
	var elsewhere atomic.Int32
	var redirect atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/dex/token", func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_ = r.ParseForm()
		form.Store(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/elsewhere", func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newClient(t, srv.URL)
	cfg := oauth2.Config{ClientID: "c", Endpoint: oauth2.Endpoint{TokenURL: "http://localhost:5556/dex/token"}}
	ctx := oidc.WithHTTPClient(context.Background(), c)

	if _, err := cfg.Exchange(ctx, "code"); err != nil {
		t.Fatal(err)
	}
	f := form.Load().(url.Values)
	if f["code"][0] != "code" || f["grant_type"][0] != "authorization_code" {
		t.Fatalf("form: %v", f)
	}

	redirect.Store(true)
	if _, err := cfg.Exchange(ctx, "code"); err == nil {
		t.Fatal("302 must fail the exchange")
	}
	if elsewhere.Load() != 0 {
		t.Fatal("redirect was followed")
	}
}

func TestNewHTTPClientRejectsHTTPIssuer(t *testing.T) {
	_, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: "http://x"})
	if err == nil || !strings.Contains(err.Error(), "internalIssuerURL") {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPClientNoTokenInErrors(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c := newClient(t, url)
	_, err := c.Post("http://localhost:5556/dex/token", "application/x-www-form-urlencoded", strings.NewReader("code=SECRET123"))
	if err == nil || strings.Contains(err.Error(), "SECRET123") {
		t.Fatalf("POST error: %v", err)
	}
}

// net/http's Client adds the request URL to every error it returns, so a code
// or token must never be placed in a URL by a caller. The transport this
// package owns must not add it to the errors it produces.
func TestHTTPClientTransportErrorOmitsURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	internal := srv.URL
	srv.Close()
	c := newClient(t, internal)
	req, err := http.NewRequest(http.MethodGet, "http://localhost:5556/dex/token?code=SECRET123", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Transport.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("want dial error")
	}
	if strings.Contains(err.Error(), "SECRET123") {
		t.Fatalf("transport error leaks URL query: %v", err)
	}
}
