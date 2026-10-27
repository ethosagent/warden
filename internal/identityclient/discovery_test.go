package identityclient_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

func TestDiscoveryIssuerMismatch(t *testing.T) {
	r := newRig(t)
	if _, err := identityclient.Discover(context.Background(), r.idp.srv.Client(), r.idp.URL()); err != nil {
		t.Fatalf("matching issuer: %v", err)
	}
	// One byte of difference: a trailing slash, or a changed character.
	for _, override := range []string{r.idp.URL() + "/", strings.Replace(r.idp.URL(), "http://", "http://x", 1), strings.ToUpper(r.idp.URL())} {
		r.idp.issuerOverride = override
		_, err := identityclient.Discover(context.Background(), r.idp.srv.Client(), r.idp.URL())
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("issuer %q: want mismatch error, got %v", override, err)
		}
	}
}

func TestDiscoveryRejects(t *testing.T) {
	good := func(u string) string {
		return fmt.Sprintf(`{"issuer":%q,"token_endpoint":%q,"device_authorization_endpoint":%q}`, u, u+"/token", u+"/device")
	}
	cases := []struct {
		name   string
		status int
		body   func(u string) string
		want   string
		err    error
	}{
		{"ok", 200, good, "", nil},
		{"server error", 503, func(string) string { return "down" }, "", identityclient.ErrIssuerUnreachable},
		{"not found", 404, func(string) string { return "nope" }, "answered", nil},
		{"not json", 200, func(string) string { return "<html>" }, "not a valid JSON", nil},
		{"no token endpoint", 200, func(u string) string { return fmt.Sprintf(`{"issuer":%q}`, u) }, "token_endpoint", nil},
		{"http non-loopback token endpoint", 200, func(u string) string {
			return fmt.Sprintf(`{"issuer":%q,"token_endpoint":"http://idp.example.com/token"}`, u)
		}, "token_endpoint", nil},
		{"http non-loopback device endpoint", 200, func(u string) string {
			return fmt.Sprintf(`{"issuer":%q,"token_endpoint":%q,"device_authorization_endpoint":"http://idp.example.com/d"}`, u, u+"/t")
		}, "device_authorization_endpoint", nil},
	}
	for _, tc := range cases {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = fmt.Fprint(w, tc.body(srv.URL))
		}))
		t.Cleanup(srv.Close)
		_, err := identityclient.Discover(context.Background(), srv.Client(), srv.URL)
		switch {
		case tc.err != nil:
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: got %v", tc.name, err)
			}
		case tc.want == "":
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
		case err == nil || !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
		if err != nil && strings.Contains(err.Error(), "down") && tc.name == "server error" {
			t.Errorf("error leaks body")
		}
	}
	// A non-loopback http issuer is refused before any request is made.
	if _, err := identityclient.Discover(context.Background(), http.DefaultClient, "http://idp.example.com"); err == nil {
		t.Fatal("http issuer accepted")
	}
}

func TestNewHTTPClientPolicy(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/big", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 2<<20)))
	}))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	c := identityclient.NewHTTPClient()
	resp, err := c.Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatalf("env proxy must be ignored: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits != 1 {
		t.Fatalf("redirect followed: status %d hits %d", resp.StatusCode, hits)
	}
	resp, err = c.Get(srv.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	total := 0
	var rerr error
	for rerr == nil {
		var n int
		n, rerr = resp.Body.Read(buf)
		total += n
	}
	if total > 1<<20+4096 || rerr.Error() == "EOF" {
		t.Fatalf("body not capped: read %d err %v", total, rerr)
	}
}
