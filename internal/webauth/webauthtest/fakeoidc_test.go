package webauthtest_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/webauth/webauthtest"
)

func authorizeURL(t *testing.T, idp *webauthtest.FakeOIDC, verifier string) (*oauth2.Config, string) {
	t.Helper()
	oc := &oauth2.Config{
		ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURL: "http://127.0.0.1:7070/portal/callback",
		Endpoint: oauth2.Endpoint{AuthURL: idp.URL() + "/auth", TokenURL: idp.URL() + "/token", AuthStyle: oauth2.AuthStyleInHeader},
		Scopes:   []string{"openid"},
	}
	return oc, oc.AuthCodeURL("st", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "n"))
}

func TestFakeOIDCAuthorizeAndRefreshToken(t *testing.T) {
	idp := webauthtest.NewFakeOIDC(t, webauthtest.Options{ClientID: "warden-portal", ClientSecret: "s"})
	exchange := func() *oauth2.Token {
		t.Helper()
		verifier := oauth2.GenerateVerifier()
		oc, loc := authorizeURL(t, idp, verifier)
		cb := idp.Authorize(t, loc)
		u, err := url.Parse(cb)
		if err != nil || u.Path != "/portal/callback" || u.Query().Get("state") != "st" || u.Query().Get("code") == "" {
			t.Fatalf("callback = %q %v", cb, err)
		}
		tok, err := oc.Exchange(context.Background(), u.Query().Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if id, _ := tok.Extra("id_token").(string); id == "" {
			t.Fatal("no id_token")
		}
		return tok
	}
	if tok := exchange(); tok.RefreshToken != "" {
		t.Fatalf("refresh_token %q without SetRefreshToken", tok.RefreshToken)
	}
	idp.SetRefreshToken("rt-1")
	if tok := exchange(); tok.RefreshToken != "rt-1" {
		t.Fatalf("refresh_token = %q, want rt-1", tok.RefreshToken)
	}
	idp.SetRefreshToken("")
	if tok := exchange(); tok.RefreshToken != "" {
		t.Fatalf("refresh_token %q after clearing it", tok.RefreshToken)
	}
}

func TestFakeOIDCOnOff(t *testing.T) {
	idp := webauthtest.NewFakeOIDC(t, webauthtest.Options{ClientID: "c", ClientSecret: "s", Down: true})
	disc := func() error {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, idp.URL()+"/.well-known/openid-configuration", nil)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if disc() == nil {
		t.Fatal("a fake started Down answered discovery")
	}
	idp.Start()
	if err := disc(); err != nil {
		t.Fatalf("discovery after Start: %v", err)
	}
}
