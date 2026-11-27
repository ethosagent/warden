package oauthbroker_test

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/adapters/httpclient"
)

// TestRefreshOverSafeClient runs Refresh through the production poster against
// a loopback httptest server (allowed by CIDR) and asserts the wire headers.
func TestRefreshOverSafeClient(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1") // would fail if the env proxy were used
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	var hdr http.Header
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new","expires_in":60}`)
	}))
	defer srv.Close()

	poster, err := httpclient.New([]string{"127.0.0.0/8", "::1/128"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	reg, err := oauthbroker.NewRegistry([]config.OAuthProviderConfig{{
		ID: "g", Type: "google", ClientID: "cid", ClientSecretEnv: "S", TokenURL: srv.URL + "/token",
		AllowedScopes: []string{"a"},
	}}, oauthbroker.Options{
		LookupEnv:  func(string) (string, bool) { return "sec", true },
		Now:        func() time.Time { return now },
		HTTPClient: poster,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Get("g")
	rec := oauthbroker.TokenRecord{V: 1, GrantID: "g1", Provider: "g", ClientID: "cid", AccessToken: "old", RefreshToken: "rt", Scope: "a"}
	out, err := oauthbroker.Refresh(t.Context(), p, rec, oauthbroker.NewSecret("sec"))
	if err != nil {
		t.Fatal(err)
	}
	if out.AccessToken != "new" || out.Expiry != now.Unix()+60 {
		t.Fatalf("out = %v", out)
	}
	if hdr.Get("Accept") != "application/json" || hdr.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("headers = %v", hdr)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:sec")); hdr.Get("Authorization") != want {
		t.Fatalf("Authorization = %q", hdr.Get("Authorization"))
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt" {
		t.Fatalf("form = %v", form)
	}

	// With no CIDR allowance the same call is refused as a blocked destination.
	blocked, err := httpclient.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg2, _ := oauthbroker.NewRegistry([]config.OAuthProviderConfig{{
		ID: "g", Type: "google", ClientID: "cid", ClientSecretEnv: "S", TokenURL: srv.URL + "/token", AllowedScopes: []string{"a"},
	}}, oauthbroker.Options{LookupEnv: func(string) (string, bool) { return "sec", true }, Now: func() time.Time { return now }, HTTPClient: blocked})
	p2, _ := reg2.Get("g")
	_, err = oauthbroker.Refresh(t.Context(), p2, rec, oauthbroker.NewSecret("sec"))
	if !errors.Is(err, oauthbroker.ErrBlockedDestination) || !errors.Is(err, oauthbroker.ErrRefreshPermanent) {
		t.Fatalf("err = %v", err)
	}
	if reg2.RefreshCounters().Count("g", oauthbroker.RefreshBlocked) != 1 {
		t.Fatal("blocked counter")
	}
}
