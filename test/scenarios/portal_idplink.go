package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The IdP link scenario (W-P3-CSIG-03): a portal login with consent.idpLink on
// writes the refresh token to the CP-only consent.store (a persistent aws
// backend on an in-memory account) at warden-cp/idp/<userKey> and records only
// its Reference in idp_links; a second login bumps the generation; a login
// whose store write fails gets no session and changes nothing; no log line
// holds a token.

const portalRelinkToken = "rt-harness-portal-second-refresh-token"

// portalLoginOnce runs /portal/login, the issuer and /portal/callback and
// returns the callback's status and body.
func portalLoginOnce(t *testing.T, h *harness.H, b *harness.Browser) (int, string) {
	t.Helper()
	resp, _ := consoleDo(t, b, http.MethodGet, "/portal/login", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/portal/login = %d, want 302", resp.StatusCode)
	}
	resp, body := consoleDo(t, b, http.MethodGet, portalIdPLeg(t, h, resp.Header.Get("Location")), nil)
	return resp.StatusCode, body
}

func portalIdPLink(t *testing.T, h *harness.H) {
	idp := h.Issuer()
	idp.SetLogin(fakes.Valid("dana", "dana@example.com"))
	idp.SetRefreshToken(portalRefreshToken)
	b := h.ConsoleBrowser()
	h.Eventually("the portal has discovered the issuer", func() bool {
		resp, _ := consoleDo(t, b, http.MethodGet, "/portal/callback", nil)
		return resp.StatusCode != http.StatusServiceUnavailable
	})
	uk, err := secrets.UserKey(idp.Issuer(), "dana")
	if err != nil {
		t.Fatal(err)
	}
	name := config.DefaultConsentStoreNamePrefix + "idp/" + uk
	aws := h.UserStoreAWS()

	// 1. The login stores the token at warden-cp/idp/<userKey>, and only there.
	if code, body := portalLoginOnce(t, h, b); code != http.StatusFound {
		t.Fatalf("portal callback = %d %q, want 302", code, body)
	}
	if v, err := aws.GetSecretValue(name); err != nil || v != portalRefreshToken {
		t.Fatalf("consent.store %s = %q, %v; want the refresh token", name, v, err)
	}
	all, err := aws.ListSecrets("")
	if err != nil || len(all) != 1 || all[0].Name != name {
		t.Fatalf("consent.store account = %+v, %v; want only %s", all, err, name)
	}
	if under, _ := aws.ListSecrets(secrets.DefaultAWSNamePrefix); len(under) != 0 {
		t.Fatalf("names under the distributed secretStore prefix: %+v", under)
	}
	links := h.IdPLinks()
	if len(links) != 1 || links[0].Sub != "dana" || links[0].UserKey != uk || links[0].SecretKey != "idp/"+uk ||
		links[0].RefreshRef != secrets.Ref(portalRefreshToken).String() || links[0].Generation != 1 || links[0].RelinkDueAt == 0 {
		t.Fatalf("idp_links = %+v", links)
	}
	_, body := consoleDo(t, b, http.MethodGet, "/portal", nil)
	if !strings.Contains(body, `<span id="idp-link-status">linked</span> (generation 1)`) {
		t.Fatalf("/portal does not show the link: %q", body)
	}

	// 2. A second login replaces the token and bumps the generation.
	idp.SetRefreshToken(portalRelinkToken)
	if code, body := portalLoginOnce(t, h, b); code != http.StatusFound {
		t.Fatalf("second portal callback = %d %q", code, body)
	}
	if v, _ := aws.GetSecretValue(name); v != portalRelinkToken {
		t.Fatalf("consent.store after a re-login = %q", v)
	}
	if links = h.IdPLinks(); len(links) != 1 || links[0].Generation != 2 || links[0].RefreshRef != secrets.Ref(portalRelinkToken).String() {
		t.Fatalf("idp_links after a re-login = %+v", links)
	}
	sessions := len(h.PortalSessions())

	// 3. consent.store down: 503, no new session, nothing changed.
	aws.SetDown(errStoreDown{})
	code, body := portalLoginOnce(t, h, b)
	aws.SetDown(nil)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "secret_store_unavailable") {
		t.Fatalf("callback with consent.store down = %d %q, want 503 secret_store_unavailable", code, body)
	}
	if n := len(h.PortalSessions()); n != sessions {
		t.Fatalf("portal_sessions = %d after a failed store write, want %d", n, sessions)
	}
	if after := h.IdPLinks(); len(after) != 1 || after[0] != links[0] {
		t.Fatalf("idp_links changed by a failed store write: %+v", after)
	}

	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"idp_link_stored"`) || !strings.Contains(logs, links[0].RefreshRef) {
		t.Fatal("no idp_link_stored line with the Reference")
	}
	if strings.Contains(logs, portalRefreshToken) || strings.Contains(logs, portalRelinkToken) {
		t.Fatal("the logs hold a refresh token")
	}
}

// errStoreDown is the outage the consent.store account returns.
type errStoreDown struct{}

func (errStoreDown) Error() string { return "secrets: aws unavailable: connection refused" }
