package oauthbroker_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/test/fakes"
)

func googleAccount(sub, email, hd string) fakes.OAuthAccount {
	return fakes.OAuthAccount{Sub: sub, Login: "", Email: email, EmailVerified: true, HD: hd}
}

func withRules(domains []string, emailMatch bool) func([]config.OAuthProviderConfig) {
	return func(c []config.OAuthProviderConfig) {
		for i := range c {
			c[i].AllowedAccountDomains, c[i].RequireEmailMatch = domains, emailMatch
		}
	}
}

// assertAccountDenied checks the shared outcome of a refused account: the
// callback ran to a denial with account_not_allowed, nothing is in consent.store
// or on the grants table, the pending is denied and exactly one revoke reached
// the provider with the token the exchange returned.
func assertAccountDenied(t *testing.T, e *cbEnv, f flow, res oauthbroker.CallbackResult, err error, provider, wantToken string) {
	t.Helper()
	if err != nil || res.Result != oauthbroker.ResultDenied || res.Reason != oauthbroker.ReasonAccountNotAllowed {
		t.Fatalf("callback = %+v, %v; want denied account_not_allowed", res, err)
	}
	e.noKey(t, cbSub, provider)
	if _, gerr := e.grant(t, cbSub, provider); !errors.Is(gerr, oauthbroker.ErrNotFound) {
		t.Fatalf("a denied account left a grant row: %v", gerr)
	}
	if p, _ := e.store.GetPending(context.Background(), f.pendingID); p.Status != oauthbroker.StatusDenied || p.Reason != oauthbroker.ReasonAccountNotAllowed {
		t.Fatalf("pending = %+v, want denied account_not_allowed", p)
	}
	rv := e.prov.RevokeRequests()
	if len(rv) != 1 || rv[0].Token != wantToken {
		t.Fatalf("revoke requests = %+v, want exactly one for the dropped token", rv)
	}
	evs := e.audit.all()
	if last := evs[len(evs)-1]; last.Action != oauthbroker.AuditActionDenied || last.Reason != oauthbroker.ReasonAccountNotAllowed {
		t.Fatalf("audit = %+v", last)
	}
	if strings.Contains(e.logs.String(), wantToken) {
		t.Fatal("the dropped token reached a log line")
	}
}

// TestAccountRules: allowedAccountDomains and requireEmailMatch against a fake
// Google id_token and a fake GitHub /user.
func TestAccountRules(t *testing.T) {
	ctx := context.Background()

	t.Run("google hd allowed records the account", func(t *testing.T) {
		e := newCBEnvWith(t, withRules([]string{"example.com"}, false))
		e.prov.SetAccount(googleAccount("g-sub-1", "alice@example.com", "example.com"))
		f := e.connect(t, cbSub, "google", true, "drive.readonly")
		res, err := e.b.Callback(ctx, f.req)
		if err != nil || res.Result != oauthbroker.ResultGranted {
			t.Fatalf("callback = %+v, %v", res, err)
		}
		g, _ := e.grant(t, cbSub, "google")
		if g.State != oauthbroker.GrantActive || g.Account.ID != "g-sub-1" || g.Account.Login != "alice@example.com" {
			t.Fatalf("grant = %+v, want the Google sub and email recorded", g)
		}
		if len(e.prov.RevokeRequests()) != 0 {
			t.Fatal("an allowed account was revoked")
		}
		evs := e.audit.all()
		if last := evs[len(evs)-1]; last.Action != oauthbroker.AuditActionGranted || last.AccountID != "g-sub-1" {
			t.Fatalf("audit = %+v, want connect.granted with the account id", last)
		}
		if strings.Contains(e.logs.String(), "alice@example.com") {
			t.Fatal("an email reached a log line")
		}
	})

	t.Run("google outside the domain is denied and revoked", func(t *testing.T) {
		for name, hd := range map[string]string{"other workspace": "gmail.com", "consumer account": ""} {
			t.Run(name, func(t *testing.T) {
				e := newCBEnvWith(t, withRules([]string{"example.com"}, false))
				// A consumer account may carry an example.com address with no hd.
				e.prov.SetAccount(googleAccount("g-sub-2", "alice@example.com", hd))
				f := e.connect(t, cbSub, "google", true, "drive.readonly")
				res, err := e.b.Callback(ctx, f.req)
				assertAccountDenied(t, e, f, res, err, "google", e.prov.RefreshToken(1))
			})
		}
	})

	t.Run("requireEmailMatch", func(t *testing.T) {
		cases := []struct {
			name            string
			acct            fakes.OAuthAccount
			sessionEmail    string
			sessionVerified bool
			ok              bool
		}{
			{"same email, any case", googleAccount("s", "Alice@Example.com", "example.com"), "alice@example.COM", true, true},
			{"different email", googleAccount("s", "bob@example.com", "example.com"), "alice@example.com", true, false},
			{"session email not verified", googleAccount("s", "alice@example.com", "example.com"), "alice@example.com", false, false},
			{"provider email not verified", fakes.OAuthAccount{Sub: "s", Email: "alice@example.com", HD: "example.com"}, "alice@example.com", true, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				e := newCBEnvWith(t, withRules(nil, true))
				e.prov.SetAccount(c.acct)
				f := e.connect(t, cbSub, "google", true, "drive.readonly")
				f.req.Email, f.req.EmailVerified = c.sessionEmail, c.sessionVerified
				res, err := e.b.Callback(ctx, f.req)
				if c.ok {
					if err != nil || res.Result != oauthbroker.ResultGranted || len(e.prov.RevokeRequests()) != 0 {
						t.Fatalf("callback = %+v, %v, revokes %v; want granted", res, err, e.prov.RevokeRequests())
					}
					return
				}
				assertAccountDenied(t, e, f, res, err, "google", e.prov.RefreshToken(1))
			})
		}
	})

	t.Run("github records id and login", func(t *testing.T) {
		e := newCBEnv(t)
		e.prov.SetStyle(fakes.OAuthGitHub)
		e.prov.SetAccount(fakes.OAuthAccount{Sub: "9001", Login: "octo-alice", Email: "alice@example.com"})
		f := e.connect(t, cbSub, "github", true, "read:user")
		if res, err := e.b.Callback(ctx, f.req); err != nil || res.Result != oauthbroker.ResultGranted {
			t.Fatalf("callback = %+v, %v", res, err)
		}
		g, _ := e.grant(t, cbSub, "github")
		if g.Account.ID != "9001" || g.Account.Login != "octo-alice" {
			t.Fatalf("grant account = %+v, want the /user id and login", g.Account)
		}
	})

	t.Run("github email outside the domain is denied and revoked", func(t *testing.T) {
		e := newCBEnvWith(t, withRules([]string{"example.com"}, false))
		e.prov.SetStyle(fakes.OAuthGitHub)
		e.prov.SetAccount(fakes.OAuthAccount{Sub: "9002", Login: "mallory", Email: "mallory@gmail.com"})
		f := e.connect(t, cbSub, "github", true, "read:user")
		res, err := e.b.Callback(ctx, f.req)
		assertAccountDenied(t, e, f, res, err, "github", e.prov.AccessToken(1))
	})

	t.Run("github without a public email cannot satisfy a rule", func(t *testing.T) {
		e := newCBEnvWith(t, withRules([]string{"example.com"}, false))
		e.prov.SetStyle(fakes.OAuthGitHub)
		e.prov.SetAccount(fakes.OAuthAccount{Sub: "9003", Login: "private-alice"})
		f := e.connect(t, cbSub, "github", true, "read:user")
		res, err := e.b.Callback(ctx, f.req)
		assertAccountDenied(t, e, f, res, err, "github", e.prov.AccessToken(1))
	})
}

// TestAccountIdentifyFailure: with a rule set a failure to identify denies;
// with none the connect proceeds and records no account.
func TestAccountIdentifyFailure(t *testing.T) {
	ctx := context.Background()
	brokenUserinfo := func(c []config.OAuthProviderConfig) { c[1].UserinfoURL = c[1].TokenURL + "/missing" }

	t.Run("no rule proceeds", func(t *testing.T) {
		e := newCBEnvWith(t, brokenUserinfo)
		e.prov.SetStyle(fakes.OAuthGitHub)
		f := e.connect(t, cbSub, "github", true, "read:user")
		if res, err := e.b.Callback(ctx, f.req); err != nil || res.Result != oauthbroker.ResultGranted {
			t.Fatalf("callback = %+v, %v", res, err)
		}
		if g, _ := e.grant(t, cbSub, "github"); g.State != oauthbroker.GrantActive || g.Account != (oauthbroker.Account{}) {
			t.Fatalf("grant = %+v, want active with no account", g)
		}
		if !strings.Contains(e.logs.String(), "oauth_connect_identify_failed") {
			t.Fatal("the identification failure was not logged")
		}
	})

	t.Run("rule set denies", func(t *testing.T) {
		e := newCBEnvWith(t, func(c []config.OAuthProviderConfig) { brokenUserinfo(c); withRules([]string{"example.com"}, false)(c) })
		e.prov.SetStyle(fakes.OAuthGitHub)
		f := e.connect(t, cbSub, "github", true, "read:user")
		res, err := e.b.Callback(ctx, f.req)
		assertAccountDenied(t, e, f, res, err, "github", e.prov.AccessToken(1))
	})
}

// TestAccountDenyKeepsActiveGrant: a refused reconnect must not end a working
// grant. Revoking at Google (or GitHub) removes the whole grant, so the provider
// revoke is skipped unless the account is known to differ from the stored one.
func TestAccountDenyKeepsActiveGrant(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*cbEnv, oauthbroker.TokenRecord) {
		t.Helper()
		e := newCBEnvWith(t, withRules([]string{"example.com"}, false))
		e.prov.SetAccount(googleAccount("g-same", "alice@example.com", "example.com"))
		f := e.connect(t, cbSub, "google", false, "drive.readonly")
		if res, err := e.b.Callback(ctx, f.req); err != nil || res.Result != oauthbroker.ResultGranted {
			t.Fatalf("first connect = %+v, %v", res, err)
		}
		return e, e.record(t, cbSub, "google")
	}

	t.Run("same account, rule now failing: no provider revoke", func(t *testing.T) {
		e, before := setup(t)
		e.prov.SetAccount(googleAccount("g-same", "alice@example.com", "moved.example"))
		f := e.connect(t, cbSub, "google", true, "drive.readonly")
		res, err := e.b.Callback(ctx, f.req)
		if err != nil || res.Reason != oauthbroker.ReasonAccountNotAllowed {
			t.Fatalf("callback = %+v, %v", res, err)
		}
		if n := len(e.prov.RevokeRequests()); n != 0 {
			t.Fatalf("%d revoke requests; a refused reconnect ended the working grant", n)
		}
		if after := e.record(t, cbSub, "google"); after.GrantID != before.GrantID || after.AccessToken != before.AccessToken {
			t.Fatal("the stored grant changed")
		}
		if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantActive {
			t.Fatalf("grant state = %s, want active", g.State)
		}
	})

	t.Run("another account: its token is revoked, the stored grant stays", func(t *testing.T) {
		e, before := setup(t)
		e.prov.SetAccount(googleAccount("g-other", "bob@gmail.com", ""))
		f := e.connect(t, cbSub, "google", true, "drive.readonly")
		res, err := e.b.Callback(ctx, f.req)
		if err != nil || res.Reason != oauthbroker.ReasonAccountNotAllowed {
			t.Fatalf("callback = %+v, %v", res, err)
		}
		if rv := e.prov.RevokeRequests(); len(rv) != 1 || rv[0].Token != e.prov.RefreshToken(2) {
			t.Fatalf("revoke requests = %+v, want the second token only", rv)
		}
		if after := e.record(t, cbSub, "google"); after.GrantID != before.GrantID {
			t.Fatal("the stored grant changed")
		}
		if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantActive || g.Account.ID != "g-same" {
			t.Fatalf("grant = %+v, want the original active grant", g)
		}
	})
}

// TestAccountScopeExceededRevokes: the scope_exceeded drop revokes the token it
// never stored (no grant to protect).
func TestAccountScopeExceededRevokes(t *testing.T) {
	e := newCBEnv(t)
	f := e.connect(t, cbSub, "google", true, "drive.readonly")
	e.prov.GrantScopes("drive.readonly https://www.googleapis.com/auth/gmail.send")
	if _, err := e.b.Callback(context.Background(), f.req); err == nil {
		t.Fatal("scope outside the cap was accepted")
	}
	e.noKey(t, cbSub, "google")
	if rv := e.prov.RevokeRequests(); len(rv) != 1 || rv[0].Token != e.prov.RefreshToken(1) {
		t.Fatalf("revoke requests = %+v", rv)
	}
}

func idToken(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

// TestAccountIdentifyGoogleToken: iss and aud of the id_token are checked.
func TestAccountIdentifyGoogleToken(t *testing.T) {
	e := newCBEnv(t)
	p, err := e.cfg.Registry.Get("google")
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"iss": "accounts.google.com", "aud": []string{"other", fakes.OAuthDefaultClientID}, "sub": "s1", "email": "a@b.test", "email_verified": "true", "hd": "b.test"}
	id, err := p.Identify(context.Background(), oauthbroker.TokenResponse{IDToken: idToken(good)})
	if err != nil || id.ID != "s1" || !id.EmailVerified || id.HostedDomain != "b.test" {
		t.Fatalf("Identify = %+v, %v", id, err)
	}
	for name, mut := range map[string]func(map[string]any){
		"wrong audience": func(m map[string]any) { m["aud"] = "someone-else" },
		"wrong issuer":   func(m map[string]any) { m["iss"] = "https://evil.test" },
		"no sub":         func(m map[string]any) { delete(m, "sub") },
	} {
		c := map[string]any{}
		for k, v := range good {
			c[k] = v
		}
		mut(c)
		if _, err := p.Identify(context.Background(), oauthbroker.TokenResponse{IDToken: idToken(c)}); !errors.Is(err, oauthbroker.ErrIdentity) {
			t.Errorf("%s: err = %v, want ErrIdentity", name, err)
		}
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c"} {
		if _, err := p.Identify(context.Background(), oauthbroker.TokenResponse{IDToken: bad}); !errors.Is(err, oauthbroker.ErrIdentity) {
			t.Errorf("%q: err = %v, want ErrIdentity", bad, err)
		}
	}
}
