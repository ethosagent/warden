package webauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/webauth"
)

func TestCSRFLabel(t *testing.T) {
	raw := []byte("session-id")
	console := webauth.CSRFToken(raw, "warden-csrf")
	portal := webauth.CSRFToken(raw, "warden-portal-csrf")
	if console == portal {
		t.Fatal("the same id gives the same token under two labels")
	}
	if console != webauth.CSRFToken(raw, "warden-csrf") || len(console) != 64 {
		t.Fatalf("token not a stable hex HMAC: %q", console)
	}
	if webauth.CSRFToken([]byte("other-id"), "warden-csrf") == console {
		t.Fatal("two ids give the same token")
	}

	// A console token never passes the portal's rule.
	req := httptest.NewRequest(http.MethodPost, "/portal/logout", nil)
	req.Header.Set(webauth.CSRFHeader, console)
	if (webauth.CSRF{Label: "warden-portal-csrf"}).Valid(req, string(raw)) {
		t.Fatal("a console-label token passed the portal CSRF rule")
	}
	if !(webauth.CSRF{Label: "warden-csrf"}).Valid(req, string(raw)) {
		t.Fatal("the console token failed the console rule")
	}
}

func TestCSRFValid(t *testing.T) {
	const raw, label, origin = "sid", "warden-portal-csrf", "https://cp.example"
	tok := webauth.CSRFToken([]byte(raw), label)
	header := webauth.CSRF{Label: label, Origin: origin}
	form := webauth.CSRF{Label: label, Origin: origin, FormField: "csrf"}
	post := func(body, ctype, hdr, org string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/portal/x", strings.NewReader(body))
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		if hdr != "" {
			r.Header.Set(webauth.CSRFHeader, hdr)
		}
		if org != "" {
			r.Header.Set("Origin", org)
		}
		return r
	}
	formBody := url.Values{"csrf": {tok}}.Encode()
	for _, tc := range []struct {
		name string
		rule webauth.CSRF
		req  *http.Request
		want bool
	}{
		{"GET passes", header, httptest.NewRequest(http.MethodGet, "/", nil), true},
		{"header", header, post("", "", tok, ""), true},
		{"header, own origin", header, post("", "", tok, origin), true},
		{"header, foreign origin", header, post("", "", tok, "https://evil.example"), false},
		{"no token", header, post("", "", "", ""), false},
		{"wrong token", header, post("", "", "nope", ""), false},
		{"form field ignored without FormField", header, post(formBody, "application/x-www-form-urlencoded", "", ""), false},
		{"form field", form, post(formBody, "application/x-www-form-urlencoded", "", ""), true},
		{"form field, charset", form, post(formBody, "application/x-www-form-urlencoded; charset=utf-8", "", ""), true},
		{"form field in a JSON body", form, post(formBody, "application/json", "", ""), false},
		{"wrong form field", form, post("csrf=nope", "application/x-www-form-urlencoded", "", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Valid(tc.req, raw); got != tc.want {
				t.Fatalf("Valid = %v, want %v", got, tc.want)
			}
		})
	}
}
