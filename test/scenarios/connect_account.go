package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The connect account scenario (W-P3-BRKR-08): the google provider only
// accepts accounts in example.com whose verified email is the portal user's.
// The fake provider answers with an id_token naming the account. An allowed
// account connects and its id and email land on the grant; another workspace,
// a consumer account and an email that is not the signed-in user's are refused
// with account_not_allowed, nothing is stored and the provider sees exactly one
// revoke per refused token; a refused reconnect over a working grant leaves
// that grant and its token alone and sends no revoke.

func connectAccountOpts() []harness.Option {
	return []harness.Option{harness.WithOAuthProviderFake(), harness.WithOAuthAccountRules([]string{"example.com"}, true)}
}

func connectAccount(t *testing.T, h *harness.H) {
	prov := h.OAuthProvider()
	aws := h.UserStoreAWS()
	account := func(sub, email, hd string) {
		prov.SetAccount(fakes.OAuthAccount{Sub: sub, Email: email, EmailVerified: true, HD: hd})
	}
	deniedLocation := "/portal?connect_denied=google&reason=account_not_allowed"

	// 1. The allowed account connects and is recorded on the grant.
	dana := ccSignIn(t, h, "dana")
	account("g-dana", "dana@example.com", "example.com")
	f1 := ccStart(t, h, dana, "drive.readonly", false)
	if resp, body := ccCallback(t, dana, f1.callback, nil); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/portal?connected=google" {
		t.Fatalf("allowed account = %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	grants := h.OAuthGrants()
	if len(grants) != 1 || grants[0].State != "active" || grants[0].AccountID != "g-dana" || grants[0].AccountLogin != "dana@example.com" {
		t.Fatalf("grants = %+v, want one active grant with the Google account", grants)
	}
	if len(prov.RevokeRequests()) != 0 {
		t.Fatal("an allowed account was revoked")
	}
	stored, err := aws.GetSecretValue(ccKey(f1.userKey))
	if err != nil {
		t.Fatalf("no token for the allowed account: %v", err)
	}

	// 2. Another workspace, and a consumer account with an example.com address.
	erin := ccSignIn(t, h, "erin")
	revokes := 0
	for name, c := range map[string]struct{ sub, email, hd string }{
		"other workspace":  {"g-erin1", "erin@example.com", "gmail.com"},
		"consumer account": {"g-erin2", "erin@example.com", ""},
		"email mismatch":   {"g-erin3", "someone.else@example.com", "example.com"},
	} {
		account(c.sub, c.email, c.hd)
		f := ccStart(t, h, erin, "drive.readonly", false)
		issued := prov.Issued() + 1
		resp, body := ccCallback(t, erin, f.callback, nil)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != deniedLocation {
			t.Fatalf("%s = %d %q %s, want the account_not_allowed redirect", name, resp.StatusCode, resp.Header.Get("Location"), body)
		}
		revokes++
		rv := prov.RevokeRequests()
		if len(rv) != revokes || rv[revokes-1].Token != prov.RefreshToken(issued) {
			t.Fatalf("%s: revoke requests = %+v, want %d, the last for the dropped token", name, rv, revokes)
		}
		if aws.Has(ccKey(f.userKey)) || grantState(h, f.userKey) != "" {
			t.Fatalf("%s stored a token or a grant", name)
		}
	}

	// 3. dana reconnects after her workspace's domain claim changed: refused,
	// but the working grant and its token are untouched and nothing is revoked.
	account("g-dana", "dana@example.com", "moved.example")
	f3 := ccStart(t, h, dana, "drive.readonly", false)
	resp, body := ccCallback(t, dana, f3.callback, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != deniedLocation {
		t.Fatalf("refused reconnect = %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if len(prov.RevokeRequests()) != revokes {
		t.Fatal("a refused reconnect revoked the working grant at the provider")
	}
	if after, err := aws.GetSecretValue(ccKey(f3.userKey)); err != nil || after != stored {
		t.Fatalf("the working token changed: %v", err)
	}
	if g := h.OAuthGrants(); len(g) != 1 || g[0].State != "active" || g[0].GrantID != grants[0].GrantID {
		t.Fatalf("grants after the refused reconnect = %+v", g)
	}

	// 4. No token and no email in the logs.
	logs := h.Logs()
	for i := 1; i <= prov.Issued(); i++ {
		for name, s := range map[string]string{"access token": prov.AccessToken(i), "refresh token": prov.RefreshToken(i)} {
			if strings.Contains(logs, s) {
				t.Errorf("the logs hold the %s of token %d", name, i)
			}
		}
	}
	if strings.Contains(logs, "dana@example.com") || strings.Contains(logs, "g-dana") {
		t.Error("the logs hold the provider account's email or id")
	}
}
