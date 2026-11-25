package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/test/fakes"
)

// W-P2-TOKX-05: the token service end to end, in process and without Docker.
// The real exchange (assertion check, replay store, block list, agent
// registry, session store, signer, issuance records, metrics) sits behind the
// real handler on the fake clock, with the in-process OIDC issuer as the IdP.
// The L2 counterpart with a real Dex token is test/e2e/identity. The refusal
// matrix over the full stack is test/security; this test pins the operator's
// path: exchange, verify against the served JWKS, the records and counters an
// operator reads, revocation, a restart and an IdP outage.

var jwtShaped = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}`)

// restart replaces the control plane server with a new one over the same state
// database and keys, as a process restart does: every in-memory structure (the
// rate limiters, the IdP key cache, the agent snapshot) starts empty, the
// replay and session tables stay.
func (e *limitsEnv) restart(t *testing.T) {
	t.Helper()
	cfg := e.srv.cfg
	srv := New(cfg)
	tc := e.tokenCfg
	ts, err := newTokenService(tc, e.idCfg, cfg.State, e.agents, srv, e.mgr, e.clk, cfg.Logger)
	if err != nil {
		t.Fatal(err)
	}
	srv.EnableTokens(ts.Service, tc.Issuer, ts.Edge)
	e.srv, e.ts, e.h = srv, ts, srv.Handler()
}

// jwks fetches the served key set the way a verifier does.
func (e *limitsEnv) servedJWKS(t *testing.T) []keys.JWK {
	t.Helper()
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, jwksPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS = %d %s", rec.Code, rec.Body.String())
	}
	var set struct {
		Keys []keys.JWK `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	return set.Keys
}

// verified checks raw against the served JWKS with the keys package alone and
// returns its header and claims.
func (e *limitsEnv) verified(t *testing.T, raw string) (keys.Header, identity.WardenClaims) {
	t.Helper()
	h, payload, signingInput, sig, err := keys.ParseCompact(raw)
	if err != nil {
		t.Fatalf("the access token is not a compact JWS: %v", err)
	}
	var jwk *keys.JWK
	for _, k := range e.servedJWKS(t) {
		if k.Kid == h.Kid {
			k := k
			jwk = &k
		}
	}
	if jwk == nil {
		t.Fatalf("kid %q is not in the served JWKS", h.Kid)
	}
	if err := keys.Verify(*jwk, h.Alg, signingInput, sig); err != nil {
		t.Fatalf("the access token does not verify against the served JWKS: %v", err)
	}
	var c identity.WardenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return h, c
}

// exchange posts one exchange for subject through the agent with a fresh
// assertion.
func (e *limitsEnv) exchange(t *testing.T, subject string) *httptest.ResponseRecorder {
	t.Helper()
	return e.post(e.form(subject, e.assertion(t, e.agentID, e.kid)), "198.51.100.9:4000", nil)
}

func requireOAuthError(t *testing.T, name string, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("%s = %d %s, want %d", name, rec.Code, rec.Body.String(), status)
	}
	if got := decodeErr(t, rec).Error; got != code {
		t.Fatalf("%s: error = %q, want %q", name, got, code)
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("%s: a refusal carries a token", name)
	}
}

func (e *limitsEnv) tokenAccess(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	mustStatus(t, "exchange", rec, http.StatusOK)
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil || tr.AccessToken == "" {
		t.Fatalf("exchange body: %v %s", err, rec.Body.String())
	}
	return tr.AccessToken
}

func TestTokenExchangeE2E(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		e := newLimitsEnv(t, nil)
		subject := e.subject("user-1", limitsGroup)
		assertion := e.assertion(t, e.agentID, e.kid)
		rec := e.post(e.form(subject, assertion), "198.51.100.9:4000", nil)
		tok := e.tokenAccess(t, rec)
		h, c := e.verified(t, tok)

		agentPub := e.agent.Public().(ed25519.PublicKey)
		wantJKT, err := keys.Thumbprint(keys.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(agentPub)})
		if err != nil {
			t.Fatal(err)
		}
		subjectExp := e.clk.Now().Add(30 * time.Minute).Unix()
		switch {
		case h.Typ != "wt+jwt" || h.Alg != keys.AlgEdDSA:
			t.Errorf("header = %+v, want typ wt+jwt alg EdDSA", h)
		case c.Iss != testTokenIssuer || c.Aud != "warden-worker":
			t.Errorf("iss/aud = %q %q", c.Iss, c.Aud)
		case c.Sub != "user-1" || c.IdPIss != e.iss.Issuer() || c.Email != "user-1@example.com":
			t.Errorf("subject claims = %+v", c)
		case c.Act.Sub != e.agentID:
			t.Errorf("act.sub = %q, want %q", c.Act.Sub, e.agentID)
		case c.Cnf.JKT != wantJKT:
			t.Errorf("cnf.jkt = %q, want the agent key's RFC 7638 thumbprint %q", c.Cnf.JKT, wantJKT)
		case !strings.HasPrefix(c.SID, tokensvc.SessionPrefix) || c.JTI == "":
			t.Errorf("sid %q jti %q", c.SID, c.JTI)
		case c.Exp-c.Iat > 900 || c.Exp > subjectExp:
			t.Errorf("iat %d exp %d: want exp-iat <= 900 and exp <= the subject's %d", c.Iat, c.Exp, subjectExp)
		}

		// The operator's view: one ok issuance row (hashes, never the
		// credentials), one warden.token.v1 line, and the counter.
		rows := e.events(t)
		if len(rows) != 1 || rows[0]["outcome"] != "issued" || rows[0]["agent"] != e.agentID ||
			rows[0]["sid"] != c.SID || rows[0]["jti"] != c.JTI || rows[0]["kid"] != h.Kid {
			t.Errorf("token_events = %v, want one issued row for the exchange", rows)
		}
		if got := e.ts.Edge.Metrics.IssuedTotal(e.agentID); got != 1 {
			t.Errorf("issued counter = %d, want 1", got)
		}
		if n := len(e.tokenLines(t)); n != 1 {
			t.Errorf("%d token_exchange log lines, want 1", n)
		}
		for name, secret := range map[string]string{"access token": tok, "subject token": subject, "assertion": assertion} {
			if strings.Contains(e.logs.String(), secret) {
				t.Errorf("the control-plane log holds the %s", name)
			}
		}
		if m := jwtShaped.FindString(e.logs.String()); m != "" {
			t.Errorf("the control-plane log holds a JWT-shaped string (%d bytes)", len(m))
		}
	})

	t.Run("denials", func(t *testing.T) {
		e := newLimitsEnv(t, nil)
		ctx := context.Background()
		denied := func() int {
			n := 0
			for _, r := range e.events(t) {
				if r["outcome"] == "denied" {
					n++
				}
			}
			return n
		}

		// Replayed assertion: the second use is refused, and so is a third
		// after the control plane restarts on the same state.
		assertion := e.assertion(t, e.agentID, e.kid)
		e.tokenAccess(t, e.post(e.form(e.subject("user-1", limitsGroup), assertion), "198.51.100.9:4000", nil))
		requireOAuthError(t, "replay", e.post(e.form(e.subject("user-1", limitsGroup), assertion), "198.51.100.9:4000", nil), 401, "invalid_client")
		e.restart(t)
		requireOAuthError(t, "replay after restart", e.post(e.form(e.subject("user-1", limitsGroup), assertion), "198.51.100.9:4000", nil), 401, "invalid_client")
		if got := e.ts.Edge.Metrics.DeniedTotal(tokensvc.ReasonReplay); got != 1 {
			t.Errorf("replay counter after restart = %d, want 1", got)
		}
		// The restarted server still mints for a fresh assertion.
		e.tokenAccess(t, e.exchange(t, e.subject("user-1", limitsGroup)))

		// A verified agent's refusal is one denied row, with no token.
		base := denied()

		if _, err := e.srv.blocks.Add(ctx, BlockEntry{Sub: "blocked-user", Reason: "test"}, "admin"); err != nil {
			t.Fatal(err)
		}
		requireOAuthError(t, "blocked user", e.exchange(t, e.subject("blocked-user", limitsGroup)), 400, "invalid_grant")
		requireOAuthError(t, "user outside allowed_groups", e.exchange(t, e.subject("user-2", "grp-other")), 400, "unauthorized_client")
		expired := e.iss.Mint(fakes.WithAud("warden"), fakes.WithAZP(limitsAZP), fakes.Valid("user-3", "u3@example.com", limitsGroup),
			fakes.WithIAT(e.clk.Now().Add(-2*time.Hour)), fakes.WithExp(e.clk.Now().Add(-time.Hour)))
		requireOAuthError(t, "expired subject", e.exchange(t, expired), 400, "invalid_grant")
		if d := denied() - base; d != 3 {
			t.Errorf("%d new denied rows after the blocked, group and expired refusals, want 3 (one per verified agent's refusal)", d)
		}

		// An assertion for another audience authenticates nothing: 401, no row.
		before := len(e.events(t))
		now := e.clk.Now().Unix()
		wrong, err := keys.SignCompact(ctx, e.agent, keys.Header{Alg: keys.AlgEdDSA, Kid: e.kid, Typ: "JWT"}, map[string]any{
			"iss": e.agentID, "sub": e.agentID, "aud": "https://elsewhere.example.com/oauth2/token", "iat": now, "exp": now + 60, "jti": "wrong-aud-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		requireOAuthError(t, "wrong assertion aud", e.post(e.form(e.subject("user-1", limitsGroup), wrong), "198.51.100.9:4000", nil), 401, "invalid_client")
		if len(e.events(t)) != before {
			t.Errorf("an unauthenticated assertion wrote a token_events row")
		}

		// A disabled agent is refused at once.
		cur, err := e.agents.Get(ctx, e.agentID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.agents.SetStatus(ctx, e.agentID, agentreg.StatusDisabled, cur.Revision, "test"); err != nil {
			t.Fatal(err)
		}
		before = len(e.events(t))
		requireOAuthError(t, "disabled agent", e.exchange(t, e.subject("user-1", limitsGroup)), 401, "invalid_client")
		if len(e.events(t)) != before {
			t.Errorf("a disabled agent's refusal wrote a token_events row")
		}
		if m := jwtShaped.FindString(e.logs.String()); m != "" {
			t.Errorf("the control-plane log holds a JWT-shaped string (%d bytes)", len(m))
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		e := newLimitsEnv(t, nil)
		subject := e.subject("user-1", limitsGroup)
		_, c := e.verified(t, e.tokenAccess(t, e.exchange(t, subject)))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, tokenSessionsListPath+"/"+c.SID+"/revoke", nil)
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("admin revoke = %d %s, want 204", rec.Code, rec.Body.String())
		}
		requireOAuthError(t, "revoked session", e.exchange(t, subject), 400, "invalid_grant")
		if got := e.ts.Edge.Metrics.DeniedTotal(tokensvc.ReasonSessionRevoked); got != 1 {
			t.Errorf("session_revoked counter = %d, want 1", got)
		}
		// A subject token issued after the revoke starts a new session.
		e.clk.Advance(time.Minute)
		_, c2 := e.verified(t, e.tokenAccess(t, e.exchange(t, e.subject("user-1", limitsGroup))))
		if c2.SID == c.SID {
			t.Errorf("a fresh subject token continued the revoked session %s", c.SID)
		}
	})

	t.Run("rate limit", func(t *testing.T) {
		e := newLimitsEnv(t, nil)
		var limited int
		for i := 0; i < 130; i++ {
			rec := e.post(e.form("x", e.assertion(t, e.agentID, "no-such-key")), "203.0.113.5:4000", nil)
			if rec.Code == http.StatusTooManyRequests {
				limited++
				if rec.Header().Get("Retry-After") == "" {
					t.Fatal("429 without Retry-After")
				}
			}
		}
		if limited == 0 {
			t.Fatal("130 requests from one address were never rate limited")
		}
		if got := e.ts.Edge.Metrics.DeniedTotal(tokensvc.ReasonRateLimited); got != int64(limited) {
			t.Errorf("rate_limited counter = %d, want %d", got, limited)
		}
	})

	t.Run("idp down", func(t *testing.T) {
		e := newLimitsEnv(t, nil)
		subject := e.subject("user-1", limitsGroup)
		e.iss.Stop()
		rec := e.exchange(t, subject)
		requireOAuthError(t, "IdP down, cold cache", rec, 503, "temporarily_unavailable")
		if rec.Header().Get("Retry-After") == "" {
			t.Error("503 without Retry-After")
		}
	})
}
