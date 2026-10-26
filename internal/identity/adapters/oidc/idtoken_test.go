package oidc

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

func TestIDTokenVerifier(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	now := testNow
	const client = "warden-console"
	claims := func(mod func(map[string]any)) string {
		c := baseClaims(srv.URL, now)
		c["aud"], c["azp"], c["nonce"] = client, client, "n-1"
		if mod != nil {
			mod(c)
		}
		return sg.sign(c)
	}
	tests := []struct {
		name   string
		token  string
		nonce  identity.VerifyOption
		wantSt identity.Status
		wantR  identity.Reason
	}{
		{name: "valid", token: claims(nil), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusValid},
		{name: "wrong nonce", token: claims(nil), nonce: identity.WithNonce("n-2"), wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongNonce},
		{name: "no nonce in token", token: claims(func(c map[string]any) { delete(c, "nonce") }), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongNonce},
		{name: "empty expected nonce", token: claims(func(c map[string]any) { c["nonce"] = "" }), nonce: identity.WithNonce(""), wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongNonce},
		{name: "aud is another client", token: claims(func(c map[string]any) { c["aud"] = "agent-harness" }), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongAud},
		{name: "two auds, azp other client", token: claims(func(c map[string]any) {
			c["aud"] = []string{client, "agent-harness"}
			c["azp"] = "agent-harness"
		}), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongAZP},
		{name: "two auds, azp missing", token: claims(func(c map[string]any) {
			c["aud"] = []string{client, "agent-harness"}
			delete(c, "azp")
		}), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongAZP},
		{name: "two auds, azp is the client", token: claims(func(c map[string]any) { c["aud"] = []string{client, "agent-harness"} }), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusValid},
		{name: "expired", token: claims(func(c map[string]any) {
			c["iat"] = now.Add(-time.Hour).Unix()
			c["exp"] = now.Add(-5 * time.Minute).Unix()
		}), nonce: identity.WithNonce("n-1"), wantSt: identity.StatusExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewIDTokenVerifier(IDTokenConfig{Issuer: srv.URL, ClientID: client, InternalIssuerURL: srv.URL, Now: (&clock{t: now}).now})
			if err != nil {
				t.Fatal(err)
			}
			_, st, r := v.Verify(ctx2s(t), tc.token, tc.nonce)
			if st != tc.wantSt || r != tc.wantR {
				t.Fatalf("got %s/%q, want %s/%q", st, r, tc.wantSt, tc.wantR)
			}
		})
	}
	if _, err := NewIDTokenVerifier(IDTokenConfig{Issuer: srv.URL, InternalIssuerURL: srv.URL}); err == nil {
		t.Fatal("an empty client id was accepted")
	}
}

func TestDiscover(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	client, err := NewHTTPClient(HTTPClientConfig{Issuer: srv.URL, InternalIssuerURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	// The test server's document has no authorization or token endpoint.
	if _, err := Discover(context.Background(), client, srv.URL); err == nil {
		t.Fatal("a document without endpoints was accepted")
	}
	down := &http.Client{Transport: failingTransport{}}
	if _, err := Discover(context.Background(), down, srv.URL); err == nil {
		t.Fatal("an unreachable provider was accepted")
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrHandlerTimeout
}
