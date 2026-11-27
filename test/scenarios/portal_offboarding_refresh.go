package scenarios

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The offboarding refresh job in observe mode (W-P3-OFFB-02): after a portal
// login, the control plane's job refreshes the stored IdP refresh token
// against the issuer as warden-portal on its own schedule (first run one
// minute after start), writes the rotated token back to consent.store with a
// generation bump, and records link_state. An upstream refusal is recorded
// only: the user keeps their portal session. No log line holds a token.

func portalOffboardingOpts() []harness.Option {
	return []harness.Option{harness.WithOffboarding(config.OffboardingModeObserve)}
}

func portalOffboardingRefresh(t *testing.T, h *harness.H) {
	idp := h.Issuer()
	idp.SetLogin(fakes.Valid("dana", "dana@example.com"))
	idp.SetRefreshToken(portalRefreshToken)
	b := h.ConsoleBrowser()
	h.Eventually("the portal has discovered the issuer", func() bool {
		resp, _ := consoleDo(t, b, http.MethodGet, "/portal/callback", nil)
		return resp.StatusCode != http.StatusServiceUnavailable
	})
	if code, body := portalLoginOnce(t, h, b); code != http.StatusFound {
		t.Fatalf("portal callback = %d %q, want 302", code, body)
	}
	uk, err := secrets.UserKey(idp.Issuer(), "dana")
	if err != nil {
		t.Fatal(err)
	}
	name := config.DefaultConsentStoreNamePrefix + "idp/" + uk
	aws := h.UserStoreAWS()

	// 1. The scheduled run rotates the token and bumps the generation.
	h.Eventually("the refresh job rotated dana's token", func() bool {
		h.Clock().Advance(15 * time.Second)
		l := h.IdPLinks()
		return len(l) == 1 && l[0].Generation == 2
	})
	rotated, err := aws.GetSecretValue(name)
	if err != nil || rotated == portalRefreshToken || !idp.LiveRefreshToken(rotated) {
		t.Fatalf("consent.store %s after the refresh: changed=%v live=%v err=%v", name, rotated != portalRefreshToken, idp.LiveRefreshToken(rotated), err)
	}
	if l := h.IdPLinks()[0]; l.RefreshRef != secrets.Ref(rotated).String() || l.LinkState != "active" || l.LastErrorCode != "" {
		t.Fatalf("idp_links after the refresh = %+v", l)
	}

	// 2. An upstream refusal in observe mode is recorded, nothing more.
	idp.SetRefreshFailure("dana", fakes.RefreshUpstreamRefused)
	h.Eventually("the refresh job recorded the refusal", func() bool {
		h.Clock().Advance(15 * time.Second)
		l := h.IdPLinks()
		return len(l) == 1 && l[0].LastErrorCode == "upstream_refused"
	})
	if l := h.IdPLinks()[0]; l.LinkState != "active" || l.Generation != 2 {
		t.Fatalf("idp_links after a refusal = %+v", l)
	}
	if v, _ := aws.GetSecretValue(name); v != rotated {
		t.Fatal("a refusal changed the stored token")
	}
	resp, body := consoleDo(t, b, http.MethodGet, "/portal", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "dana@example.com") {
		t.Fatalf("GET /portal after a refusal in observe mode = %d: the user lost their session", resp.StatusCode)
	}

	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"offboarding_job_run"`) {
		t.Fatal("no offboarding_job_run line")
	}
	if strings.Contains(logs, portalRefreshToken) || strings.Contains(logs, rotated) {
		t.Fatal("the logs hold a refresh token")
	}
}
