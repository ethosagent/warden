package harness

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/offboard"
	"github.com/ethosagent/warden/internal/offboard/adapters/oidcrefresh"
	"github.com/ethosagent/warden/test/fakes"
)

// The offboarding refresh job (W-P3-OFFB-02). Its IdP boundary,
// offboard.TokenClient, is faked by the issuer fake's Dex-shaped
// refresh_token grant (fakes.OIDCIssuer.AddRefreshChain and friends), reached
// through the production oidcrefresh client.

// WithOffboarding boots the control plane with consent.offboarding.mode set
// to mode (observe or enforce) and the minimum interval (5m). It implies
// WithConsent. The job runs on the harness clock: its first run is one minute
// after the control plane starts (drive it with h.Clock().Advance).
func WithOffboarding(mode string) Option {
	return func(h *H) {
		WithConsent()(h)
		h.offboardingMode = mode
	}
}

// offboardingYAML renders consent.offboarding (inside the consent block).
func (h *H) offboardingYAML() string {
	if h.offboardingMode == "" {
		return ""
	}
	return "  offboarding:\n    mode: " + h.offboardingMode + "\n    interval: 5m\n    requestTimeout: 5s\n"
}

// tokenClientFake is the TokenClient port's fake: the production client
// against the issuer fake's refresh grant.
type tokenClientFake struct {
	client offboard.TokenClient
	idp    *fakes.OIDCIssuer
}

const tokenClientFakeClient, tokenClientFakeSecret = "warden-portal", "conformance-secret"

func newTokenClientFake(tb testing.TB) *tokenClientFake {
	idp := fakes.NewOIDCIssuer(tb)
	idp.RegisterClient(tokenClientFakeClient, tokenClientFakeSecret)
	c, err := oidcrefresh.New(oidcrefresh.Config{
		HTTP: &http.Client{Timeout: 5 * time.Second}, ClientID: tokenClientFakeClient, ClientSecret: tokenClientFakeSecret,
		TokenURL: func() (string, bool) { return idp.Issuer() + "/token", true },
	})
	if err != nil {
		tb.Fatal(err)
	}
	return &tokenClientFake{client: c, idp: idp}
}

// tokenClientConformance pins the Dex v2.41.1 shapes the job classifies: a
// refresh rotates and consumes the presented token, an unknown or claimed
// token is 400 invalid_request with Dex's description, a connector refusal is
// 500 invalid_request with no description, the chain's absolute lifetime is
// 400 "Refresh token expired.", a newer login invalidates the earlier chain,
// and a wrong client secret is 401 invalid_client.
func tokenClientConformance(t *testing.T, f *tokenClientFake) {
	ctx := context.Background()
	var c offboard.TokenClient = f.client
	f.idp.AddRefreshChain("rt-conf-1", "sam", "sam@example.com", tokenClientFakeClient)
	r, err := c.Refresh(ctx, "rt-conf-1")
	if err != nil || r.Status != 200 || r.RefreshToken == "" || r.RefreshToken == "rt-conf-1" || r.IDToken == "" {
		t.Fatalf("refresh = %v, %v; want 200 with a rotated token and an ID token", r, err)
	}
	next := r.RefreshToken
	if r, _ := c.Refresh(ctx, "rt-conf-1"); r.Status != 400 || r.ErrorCode != "invalid_request" || r.Description != fakes.DexRefreshInvalidDescription {
		t.Fatalf("reused token = %v %q, want 400 invalid_request claimed", r, r.Description)
	}
	f.idp.SetRefreshFailure("sam", fakes.RefreshUpstreamRefused)
	if r, _ := c.Refresh(ctx, next); r.Status != 500 || r.ErrorCode != "invalid_request" || r.Description != "" {
		t.Fatalf("connector refusal = %v, want 500 invalid_request with no description", r)
	}
	f.idp.SetRefreshFailure("sam", fakes.RefreshExpired)
	if r, _ := c.Refresh(ctx, next); r.Status != 400 || r.Description != fakes.DexRefreshExpiredDescription {
		t.Fatalf("expired = %v, want 400 Refresh token expired.", r)
	}
	f.idp.SetRefreshFailure("sam", fakes.RefreshFailure{})
	f.idp.AddRefreshChain("rt-conf-2", "sam", "sam@example.com", tokenClientFakeClient)
	if r, _ := c.Refresh(ctx, next); r.Status != 400 {
		t.Fatalf("a chain replaced by a login = %v, want 400", r)
	}
	f.idp.RegisterClient(tokenClientFakeClient, "rotated")
	if r, _ := c.Refresh(ctx, "rt-conf-2"); r.Status != 401 || r.ErrorCode != "invalid_client" {
		t.Fatalf("wrong client secret = %v, want 401 invalid_client", r)
	}
}
