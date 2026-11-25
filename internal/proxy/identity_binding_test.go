package proxy

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// These tests cover W-P2-WBND-02: a Warden token is bound to the worker's agent
// and key after its signature verified, against the snapshot current at each
// request. The verifier is a stand-in that returns fixed Warden claims and
// serves a snapshot a test swaps, so the binding is exercised without keys.

type bindVerifier struct {
	claims identity.Claims
	snap   atomic.Pointer[identity.WardenSnapshot]
}

func (b *bindVerifier) Verify(context.Context, string, ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	return b.claims, identity.StatusValid, ""
}

func (b *bindVerifier) Snapshot() *identity.WardenSnapshot { return b.snap.Load() }

func (b *bindVerifier) set(t testing.TB, gen int64, agents map[string]identity.WardenAgent) {
	t.Helper()
	b.setKeys(t, gen, []string{"k1"}, agents)
}

// setKeys installs a snapshot holding one fresh signing key per kid and the
// issuer (default https://cp.example).
func (b *bindVerifier) setKeys(t testing.TB, gen int64, kids []string, agents map[string]identity.WardenAgent, issuer ...string) {
	t.Helper()
	iss := "https://cp.example"
	if len(issuer) > 0 {
		iss = issuer[0]
	}
	var jwks []keys.JWK
	for _, kid := range kids {
		sg, err := signer.GenerateLocal(keys.AlgEdDSA)
		if err != nil {
			t.Fatal(err)
		}
		j, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
		if err != nil {
			t.Fatal(err)
		}
		j.Kid = kid
		jwks = append(jwks, j)
	}
	s, err := identity.NewWardenSnapshot(identity.WardenBundle{Generation: gen, TokenIssuer: iss, JWKS: jwks, Agents: agents})
	if err != nil {
		t.Fatal(err)
	}
	b.snap.Store(s)
}

func jktSet(v ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, x := range v {
		m[x] = struct{}{}
	}
	return m
}

func wardenClaims(act, jkt string) identity.Claims {
	return identity.Claims{
		Sub: "user-1", Email: "u@example.com", SID: "wts_1", Act: act, CnfJKT: jkt, KID: "k1", Issuer: "https://cp.example",
		TokenType: identity.TokenWarden, Expiry: time.Now().Add(time.Hour),
	}
}

func connectBasic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername+":"+tok))
}

// bindProxy is a stage proxy bound to agent-7 (stageProxy's agent) over v.
func bindProxy(t testing.TB, v identity.Verifier) *Proxy {
	t.Helper()
	return stageProxy(t, v, IdentityModeAttribute, nil, nil)
}

func TestIdentityBinding(t *testing.T) {
	const self = "agent-7"
	active := func(k ...string) identity.WardenAgent { return identity.WardenAgent{Active: true, JKT: jktSet(k...)} }

	for _, tc := range []struct {
		name   string
		claims identity.Claims
		agents map[string]identity.WardenAgent
		reason identity.Reason
	}{
		{"agent_mismatch", wardenClaims("agent-A", "T1"), map[string]identity.WardenAgent{self: active("T1"), "agent-A": active("T1")}, identity.ReasonAgentMismatch},
		{"cnf_mismatch", wardenClaims(self, "T9"), map[string]identity.WardenAgent{self: active("T1")}, identity.ReasonCnfMismatch},
		{"agent_disabled", wardenClaims(self, "T1"), map[string]identity.WardenAgent{self: {Active: false, JKT: jktSet("T1")}}, identity.ReasonAgentDisabled},
		{"agent_unregistered", wardenClaims(self, "T1"), map[string]identity.WardenAgent{"other": active("T1")}, identity.ReasonAgentUnregistered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &bindVerifier{claims: tc.claims}
			v.set(t, 1, tc.agents)
			p := bindProxy(t, v)
			ci := p.resolveConnIdentity(1, connectBasic("tok"))
			if ci.Status != identity.StatusInvalid || ci.Reason != tc.reason {
				t.Fatalf("CONNECT identity = %s/%s, want invalid/%s", ci.Status, ci.Reason, tc.reason)
			}
			// The parsed sub and email stay for the block-list check.
			if ci.Claims.Sub != "user-1" || ci.Claims.Email != "u@example.com" {
				t.Errorf("claims lost for the block list: %+v", ci.Claims)
			}
			s := stageScope(ci)
			runIdentity(t, p, s)
			if s.subject != nil {
				t.Errorf("subject = %+v, want nil", s.subject)
			}
			var ev analytics.Event
			s.resolved().stamp(&ev, true)
			if ev.IdentityStatus != "invalid" || ev.IdentityReason != string(tc.reason) || ev.UserSub != "" || ev.UserAct != "" || ev.IdentityTokenType != "" {
				t.Errorf("event = %+v", ev)
			}
		})
	}

	t.Run("match_records_act", func(t *testing.T) {
		v := &bindVerifier{claims: wardenClaims(self, "T1")}
		v.set(t, 1, map[string]identity.WardenAgent{self: active("T1", "T2")})
		p := bindProxy(t, v)
		ci := p.resolveConnIdentity(1, connectBasic("tok"))
		if ci.Status != identity.StatusValid {
			t.Fatalf("identity = %s/%s, want valid", ci.Status, ci.Reason)
		}
		s := stageScope(ci)
		runIdentity(t, p, s)
		if s.subject == nil || s.subject.Sub != "user-1" || s.subject.AgentID != self {
			t.Fatalf("subject = %+v", s.subject)
		}
		var ev analytics.Event
		s.resolved().stamp(&ev, true)
		if ev.IdentityStatus != "valid" || ev.UserSub != "user-1" || ev.UserSID != "wts_1" || ev.UserAct != self || ev.IdentityTokenType != "warden" {
			t.Errorf("event = %+v", ev)
		}
	})

	t.Run("rebound_on_every_request", func(t *testing.T) {
		v := &bindVerifier{claims: wardenClaims(self, "T1")}
		v.set(t, 1, map[string]identity.WardenAgent{self: active("T1")})
		p := bindProxy(t, v)
		ci := p.resolveConnIdentity(1, connectBasic("tok"))
		first := stageScope(ci)
		runIdentity(t, p, first)
		if first.subject == nil {
			t.Fatal("a bound token has no subject")
		}
		// A new bundle removes the key: the same open connection, the next request.
		v.set(t, 2, map[string]identity.WardenAgent{self: active("T2")})
		s := stageScope(ci)
		runIdentity(t, p, s)
		if s.subject != nil || s.idStatus != identity.StatusInvalid || s.idReason != identity.ReasonCnfMismatch {
			t.Errorf("after key removal: subject %+v status %s/%s, want nil invalid/cnf_mismatch", s.subject, s.idStatus, s.idReason)
		}
		// The agent is disabled at the same generation (a replaced snapshot).
		v.set(t, 2, map[string]identity.WardenAgent{self: {Active: false, JKT: jktSet("T1")}})
		s = stageScope(ci)
		runIdentity(t, p, s)
		if s.subject != nil || s.idReason != identity.ReasonAgentDisabled {
			t.Errorf("after disable: subject %+v reason %s, want nil agent_disabled", s.subject, s.idReason)
		}
		// Re-enabled: the token binds again (bindings are never cached).
		v.set(t, 3, map[string]identity.WardenAgent{self: active("T1")})
		s = stageScope(ci)
		runIdentity(t, p, s)
		if s.subject == nil {
			t.Errorf("after re-enable: status %s/%s, want valid", s.idStatus, s.idReason)
		}
	})

	t.Run("idp_token_not_bound", func(t *testing.T) {
		c := wardenClaims("", "")
		c.TokenType = identity.TokenIdP
		v := &bindVerifier{claims: c}
		v.set(t, 1, nil)
		p := bindProxy(t, v)
		if ci := p.resolveConnIdentity(1, connectBasic("tok")); ci.Status != identity.StatusValid {
			t.Errorf("IdP token = %s/%s, want valid (attribute mode)", ci.Status, ci.Reason)
		}
	})

	t.Run("no_snapshot_fails_closed", func(t *testing.T) {
		v := &bindVerifier{claims: wardenClaims(self, "T1")}
		p := bindProxy(t, v)
		if ci := p.resolveConnIdentity(1, connectBasic("tok")); ci.Status != identity.StatusInvalid || ci.Reason != identity.ReasonAgentUnregistered {
			t.Errorf("no snapshot = %s/%s", ci.Status, ci.Reason)
		}
	})
}

func BenchmarkBindingCheck(b *testing.B) {
	v := &bindVerifier{claims: wardenClaims("agent-7", "T1")}
	v.set(b, 1, map[string]identity.WardenAgent{"agent-7": {Active: true, JKT: jktSet("T1")}})
	p := bindProxy(b, v)
	h := p.identity()
	r := idResult{claims: v.claims, status: identity.StatusValid}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if p.rebind(h, r).status != identity.StatusValid {
			b.Fatal("binding failed")
		}
	}
}
