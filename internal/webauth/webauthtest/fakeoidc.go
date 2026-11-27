// Package webauthtest is the test support for internal/webauth consumers: an
// httptest OIDC provider (FakeOIDC) that plays the IdP side of a browser
// login, so a front door's tests can drive login and callback end to end.
package webauthtest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/fakes"
)

// Options configure NewFakeOIDC.
type Options struct {
	// ClientID and ClientSecret are the confidential client the token
	// endpoint accepts. Register more with RegisterClient.
	ClientID, ClientSecret string
	// Now is the clock tokens are minted with; nil is time.Now.
	Now func() time.Time
	// PublicIssuer, when set, is the issuer the fake presents; it is then
	// reachable only at URL() (the internalIssuerURL setup).
	PublicIssuer string
	// Down starts the fake stopped (Start brings it up).
	Down bool
}

// FakeOIDC is an httptest OIDC provider: discovery, JWKS, an authorization
// endpoint that requires S256 PKCE and a token endpoint for the
// authorization-code grant. Everything fakes.OIDCIssuer offers is promoted:
// SetLogin with fakes.WithAud / fakes.WithAlg / fakes.WithNonce and friends
// shapes the ID token, Stop and Start switch the provider off and on (the
// IdP-down tests), FailAuthorize and SetTokenStatus fail a leg, and
// SetRefreshToken makes the token response carry (or, with "", omit)
// refresh_token.
type FakeOIDC struct {
	*fakes.OIDCIssuer
	ClientID, ClientSecret string
}

// NewFakeOIDC starts the provider and registers the client. It stops with the
// test.
func NewFakeOIDC(tb testing.TB, o Options) *FakeOIDC {
	tb.Helper()
	var iopts []fakes.IssuerOption
	if o.Now != nil {
		iopts = append(iopts, fakes.WithIssuerClock(o.Now))
	}
	if o.PublicIssuer != "" {
		iopts = append(iopts, fakes.WithPublicIssuer(o.PublicIssuer))
	}
	idp := fakes.NewOIDCIssuer(tb, iopts...)
	if o.ClientID != "" {
		idp.RegisterClient(o.ClientID, o.ClientSecret)
	}
	if o.Down {
		idp.Stop()
	}
	return &FakeOIDC{OIDCIssuer: idp, ClientID: o.ClientID, ClientSecret: o.ClientSecret}
}

// Authorize plays the browser's IdP leg: location is the Location a front
// door's login answered with. It serves that request on the fake (in process,
// whatever host the URL names, so the public-issuer setup works too), expects
// the 302 back to the redirect URI and returns that redirect's path and query,
// ready to send to the front door's callback.
func (f *FakeOIDC) Authorize(tb testing.TB, location string) string {
	tb.Helper()
	loc, err := url.Parse(location)
	if err != nil {
		tb.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, loc.RequestURI(), nil))
	if rec.Code != http.StatusFound {
		tb.Fatalf("idp authorize = %d, want 302", rec.Code)
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		tb.Fatal(err)
	}
	return cb.RequestURI()
}
