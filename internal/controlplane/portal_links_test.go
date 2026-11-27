package controlplane

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// The HTTP half of the W-P3-CSIG-03 acceptance tests: the real portal
// callback over the real LinkStore, idp_links and a fake consent.store. The
// domain half (generation CAS, value-free row) is in internal/portal.

// TestIdPLinkStored: a completed portal login stores the provider's refresh
// token at idp/<UserKey(iss,sub)> and idp_links.refresh_ref equals
// secrets.Ref(token).String(); the stub page shows the link; logout keeps it;
// the logs hold the Reference, never the token.
func TestIdPLinkStored(t *testing.T) {
	st := fakes.NewMemorySecretStore()
	r := newPortalRig(t, portalRigOpts{userStore: st})
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	r.h = r.srv.Handler()
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")

	uk, err := secrets.UserKey(r.idp.Issuer(), "pat")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := st.Value("idp/" + uk); !ok || v != portalRefreshToken {
		t.Fatalf("consent.store idp/%s = %q, %v", uk, v, ok)
	}
	var ref, sk string
	var gen int
	if err := r.db.SQL().QueryRow(`SELECT refresh_ref, secret_key, generation FROM idp_links WHERE iss = ? AND sub = ?`, r.idp.Issuer(), "pat").Scan(&ref, &sk, &gen); err != nil {
		t.Fatal(err)
	}
	if ref != secrets.Ref(portalRefreshToken).String() || sk != "idp/"+uk || gen != 1 {
		t.Fatalf("idp_links = (%q, %q, %d)", ref, sk, gen)
	}
	rows := rowsByAction(rec, actionIdPLinked)
	if len(rows) != 1 || rows[0].TargetRef != uk || rows[0].Target != targetIdPLink || rows[0].Outcome != adminaudit.OutcomeOK ||
		rows[0].Actor != (adminaudit.Actor{Sub: "pat", Email: "pat@example.com"}) {
		t.Fatalf("user.idp_linked rows = %+v", rows)
	}
	body := r.serve(http.MethodGet, "/portal", c).Body.String()
	if !strings.Contains(body, `<span id="idp-link-status">linked</span> (generation 1)`) || !strings.Contains(body, `id="idp-link-relink-due"`) {
		t.Fatalf("stub page lacks the link: %s", body)
	}
	if strings.Contains(body, portalRefreshToken) || strings.Contains(body, ref) {
		t.Fatal("stub page holds the token or its Reference")
	}
	// A second login increments the generation.
	r.login("")
	if err := r.db.SQL().QueryRow(`SELECT generation FROM idp_links`).Scan(&gen); err != nil || gen != 2 {
		t.Fatalf("generation after a second login = %d, %v", gen, err)
	}
	if l := r.srv.IdPLinks(); l == nil {
		t.Fatal("Server.IdPLinks is nil with the IdP link on")
	}
	logs := r.logs.String()
	if strings.Contains(logs, portalRefreshToken) || !strings.Contains(logs, `"msg":"idp_link_stored"`) || !strings.Contains(logs, ref) {
		t.Fatalf("logs: want idp_link_stored with the Reference and never the token:\n%s", logs)
	}
}

// TestIdPLinkKeyName: with consent.store on the AWS fake and the default
// prefix, a login writes warden-cp/idp/<userKey> and nothing under the
// distributed secretStore prefix.
func TestIdPLinkKeyName(t *testing.T) {
	aws := fakes.NewFakeAWSSecretsClient()
	st := secrets.NewAWSSecretStore(aws, "us-east-1", config.DefaultConsentStoreNamePrefix)
	r := newPortalRig(t, portalRigOpts{userStore: st})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	r.login("")
	uk, _ := secrets.UserKey(r.idp.Issuer(), "pat")
	all, err := aws.ListSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Name != "warden-cp/idp/"+uk {
		t.Fatalf("aws names = %+v, want only warden-cp/idp/%s", all, uk)
	}
	if under, _ := aws.ListSecrets(secrets.DefaultAWSNamePrefix); len(under) != 0 {
		t.Fatalf("names under the distributed prefix: %+v", under)
	}
}

// TestIdPLinkFailClosed: a token response without refresh_token is 502
// offline_access_not_granted, a Put error is 503 secret_store_unavailable,
// and a missing store is 503 too; in every case portal_sessions, idp_links
// and the store are unchanged and the token is not logged.
func TestIdPLinkFailClosed(t *testing.T) {
	t.Run("no refresh token", func(t *testing.T) {
		st := fakes.NewMemorySecretStore()
		r := newPortalRig(t, portalRigOpts{userStore: st})
		r.ready()
		r.idp.SetRefreshToken("")
		res := r.finish(r.start(""))
		if res.Code != http.StatusBadGateway || errBody(t, res) != "offline_access_not_granted" {
			t.Fatalf("callback = %d %s, want 502 offline_access_not_granted", res.Code, res.Body)
		}
		if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 0 || r.count("idp_links") != 0 || st.Puts != 0 {
			t.Fatal("a login without a refresh token wrote something")
		}
	})
	t.Run("put error", func(t *testing.T) {
		st := fakes.NewMemorySecretStore()
		r := newPortalRig(t, portalRigOpts{userStore: st})
		r.ready()
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
		st.SetErrors(nil, errors.New("put failed for "+portalRefreshToken), nil, nil)
		res := r.finish(r.start(""))
		if res.Code != http.StatusServiceUnavailable || errBody(t, res) != portalSecretStoreUnavailable {
			t.Fatalf("callback = %d %s, want 503 secret_store_unavailable", res.Code, res.Body)
		}
		if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 0 || r.count("idp_links") != 0 {
			t.Fatal("a failed Put left a session or a row")
		}
		if all, _ := st.List(t.Context()); len(all) != 0 {
			t.Fatalf("store changed: %+v", all)
		}
		if strings.Contains(r.logs.String(), portalRefreshToken) || !strings.Contains(r.logs.String(), `"reason":"idp_link_secret_put_failed"`) {
			t.Fatalf("logs: want the classified reason and never the token:\n%s", r.logs.String())
		}
		// The store recovers: the next login links and signs in.
		st.SetErrors(nil, nil, nil, nil)
		r.login("")
		if r.count("idp_links") != 1 || r.count("portal_sessions") != 1 {
			t.Fatal("no link and session after the store recovered")
		}
	})
	t.Run("no store", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.srv.portal.links, r.srv.portal.linkStore = nil, nil
		r.ready()
		res := r.finish(r.start(""))
		if res.Code != http.StatusServiceUnavailable || errBody(t, res) != portalSecretStoreUnavailable || r.count("portal_sessions") != 0 {
			t.Fatalf("callback without a link store = %d %s", res.Code, res.Body)
		}
	})
	t.Run("idp link off", func(t *testing.T) {
		st := fakes.NewMemorySecretStore()
		r := newPortalRig(t, portalRigOpts{userStore: st, noIdPLink: true})
		r.ready()
		c := r.login("")
		if r.count("idp_links") != 0 || st.Puts != 0 {
			t.Fatal("the IdP link wrote with idpLink disabled")
		}
		if body := r.serve(http.MethodGet, "/portal", c).Body.String(); !strings.Contains(body, `<span id="idp-link-status">disabled</span>`) {
			t.Fatalf("stub page = %s", body)
		}
	})
}
