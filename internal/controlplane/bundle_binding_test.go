package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

const bundleTestIssuer = "https://warden.example.com"

func bindingDecodeSegment(t *testing.T, seg string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil || json.Unmarshal(b, v) != nil {
		t.Fatalf("undecodable token segment: %v", err)
	}
}

// TestBundleThumbprintMatchesCnf: the thumbprint the policy wire (and so the
// signed bundle) serves for an agent key is the cnf.jkt of the token minted for
// that key, and the token carries typ wt+jwt and the verified email. The signed
// bundle's reaction to a registry change is TestBundleAgentKeyRemoval.
func TestBundleThumbprintMatchesCnf(t *testing.T) {
	e := newLimitsEnv(t, nil)
	rec := e.post(e.form(e.subject("user-1", limitsGroup), e.assertion(t, e.agentID, e.kid)), "198.51.100.1:1", nil)
	mustStatus(t, "issuance", rec, http.StatusOK)
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tr.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatal("the access token is not a compact JWS")
	}
	var hdr map[string]any
	var claims identity.WardenClaims
	bindingDecodeSegment(t, parts[0], &hdr)
	bindingDecodeSegment(t, parts[1], &claims)
	if hdr["typ"] != "wt+jwt" || claims.Iss != testTokenIssuer {
		t.Fatalf("typ %v iss %q, want wt+jwt and %q", hdr["typ"], claims.Iss, testTokenIssuer)
	}
	if !claims.EmailVerified || claims.Email != "user-1@example.com" {
		t.Errorf("email claims = %q verified=%v", claims.Email, claims.EmailVerified)
	}

	served := func() (map[string][]string, string, string) {
		e.srv.policy.Refresh()
		r := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/policy", nil)
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		e.h.ServeHTTP(r, req)
		if r.Code != http.StatusOK {
			t.Fatalf("GET /policy = %d", r.Code)
		}
		var wire struct {
			Agents []struct {
				ID     string   `json:"id"`
				Status string   `json:"status"`
				JKT    []string `json:"jkt"`
			} `json:"registeredAgents"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &wire); err != nil {
			t.Fatal(err)
		}
		jkt := map[string][]string{}
		status := ""
		for _, a := range wire.Agents {
			jkt[a.ID] = a.JKT
			if a.ID == e.agentID {
				status = a.Status
			}
		}
		return jkt, status, r.Header().Get("ETag")
	}
	// The harness registered the agent through another Store on the shared
	// connection, which the server's own Store cannot see until a write of its
	// own drops its snapshot (in production the Watch tick or Sync does).
	other, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	otherJWK, _ := json.Marshal(map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "b-key",
		"x": base64.RawURLEncoding.EncodeToString(other.Public().(ed25519.PublicKey))})
	if _, err := e.srv.agents.Create(context.Background(), agentreg.Agent{ID: "agent-b", Keys: []agentreg.Key{{KID: "b-key", JWK: otherJWK}}, AllowedGroups: []string{"eng"}}, "test"); err != nil {
		t.Fatal(err)
	}
	jkt, status, _ := served()
	if got := jkt[e.agentID]; len(got) != 1 || got[0] != claims.Cnf.JKT || status != "active" {
		t.Fatalf("served jkt %v (%s), minted cnf.jkt %q: they must be the same thumbprint", got, status, claims.Cnf.JKT)
	}

	a, err := e.srv.agents.Get(context.Background(), e.agentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.agents.SetStatus(context.Background(), e.agentID, agentreg.StatusDisabled, a.Revision, "test"); err != nil {
		t.Fatal(err)
	}
	if _, status, _ := served(); status != "disabled" {
		t.Errorf("after the disable: status %q, want disabled", status)
	}
}

// TestBundleTokenIssuer: the token issuer is signed into every bundle, equals
// the issuer the token service mints with and never the cpID; a change of it
// (also made while the control plane was down, or switching the token service
// on or off) takes a token_issuer row so a seq never covers two issuers; an
// unchanged issuer across a restart is a plain refresh.
func TestBundleTokenIssuer(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	db := openPolicyState(t)
	fk := newFakeBundleKeys(t)
	clk := clocktest.NewFake(btStart)

	h1 := newBundleHarnessIssuer(t, BundlesOffer, path, db, fk, clk, nil, bundleTestIssuer)
	v1 := h1.verify(t, h1.bundleResp(t).body, bundle.State{})
	if v1.Bundle.TokenIssuer != bundleTestIssuer || v1.Bundle.TokenIssuer == v1.Bundle.CPID {
		t.Fatalf("signed tokenIssuer = %q (cpID %q), want %q", v1.Bundle.TokenIssuer, v1.Bundle.CPID, bundleTestIssuer)
	}
	if rows := h1.publishRows(t); rows[len(rows)-1].Reason != publishReasonTokenIssuer {
		t.Errorf("first row reason = %q, want %q (the issuer is new to this publish log)", rows[len(rows)-1].Reason, publishReasonTokenIssuer)
	}
	if h1.degraded() {
		t.Error("publisher degraded after the first signing")
	}

	// Same issuer, restarted: a refresh of the same content.
	clk.Advance(time.Minute)
	h2 := newBundleHarnessIssuer(t, BundlesOffer, path, db, fk, clk, nil, bundleTestIssuer)
	v2 := h2.verify(t, h2.bundleResp(t).body, btState(v1))
	if v2.Seq != v1.Seq || v2.ContentSHA256 != v1.ContentSHA256 || !v2.Refresh {
		t.Errorf("restart with the same issuer: seq %d -> %d refresh=%v, want a refresh", v1.Seq, v2.Seq, v2.Refresh)
	}

	// A different issuer while down: a new seq, a token_issuer row, a new hash.
	clk.Advance(time.Minute)
	h3 := newBundleHarnessIssuer(t, BundlesOffer, path, db, fk, clk, nil, "https://other.example.com")
	v3 := h3.verify(t, h3.bundleResp(t).body, btState(v2))
	if v3.Seq <= v2.Seq || v3.Bundle.TokenIssuer != "https://other.example.com" || v3.ContentSHA256 == v2.ContentSHA256 {
		t.Errorf("issuer change: seq %d -> %d issuer %q", v2.Seq, v3.Seq, v3.Bundle.TokenIssuer)
	}
	if rows := h3.publishRows(t); rows[len(rows)-1].Reason != publishReasonTokenIssuer {
		t.Errorf("newest row = %q, want token_issuer", rows[len(rows)-1].Reason)
	}
	if h3.degraded() {
		t.Error("publisher degraded after an issuer change")
	}

	// The token service switched off: no tokenIssuer, and again a new seq.
	clk.Advance(time.Minute)
	h4 := newBundleHarnessIssuer(t, BundlesOffer, path, db, fk, clk, nil, "")
	v4 := h4.verify(t, h4.bundleResp(t).body, btState(v3))
	if v4.Seq <= v3.Seq || v4.Bundle.TokenIssuer != "" || strings.Contains(string(h4.bundleResp(t).body), "tokenIssuer") {
		t.Errorf("token service off: seq %d -> %d issuer %q", v3.Seq, v4.Seq, v4.Bundle.TokenIssuer)
	}

	// The token service switched on while the publisher runs (EnableTokens
	// after start): the issuer is signed at once, with a row of its own.
	h4.s.EnableTokens(&fakeExchanger{}, bundleTestIssuer, TokenEdge{})
	v5 := h4.verify(t, h4.bundleResp(t).body, btState(v4))
	if v5.Seq <= v4.Seq || v5.Bundle.TokenIssuer != bundleTestIssuer {
		t.Errorf("EnableTokens: seq %d -> %d issuer %q", v4.Seq, v5.Seq, v5.Bundle.TokenIssuer)
	}
}

// TestBundleTokenIssuerUpgrade: a state database written before the issuer was
// tracked (no stored issuer hash) and a token service that is now on gets one
// row and a new seq, not a refusal to sign.
func TestBundleTokenIssuerUpgrade(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	db := openPolicyState(t)
	fk := newFakeBundleKeys(t)
	clk := clocktest.NewFake(btStart)
	h1 := newBundleHarnessIssuer(t, BundlesOffer, path, db, fk, clk, nil, "")
	v1 := h1.verify(t, h1.bundleResp(t).body, bundle.State{})
	if _, err := db.SQL().Exec(`DELETE FROM bundle_state WHERE name = ?`, stateIssuerSHA); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	h2 := newBundleHarnessIssuer(t, BundlesOffer, path, db, fk, clk, nil, bundleTestIssuer)
	v2 := h2.verify(t, h2.bundleResp(t).body, btState(v1))
	if v2.Seq <= v1.Seq || v2.Bundle.TokenIssuer != bundleTestIssuer || h2.degraded() {
		t.Errorf("upgrade: seq %d -> %d issuer %q degraded=%v", v1.Seq, v2.Seq, v2.Bundle.TokenIssuer, h2.degraded())
	}
}

// TestIdentityIssuerCollisionRefusedAtRuntime: while the token service is on, a
// settings write that sets identity.issuer to the token issuer is refused in
// file mode and in versioned mode (no version created), naming both keys; with
// the service off, or a different issuer, the write goes through.
func TestIdentityIssuerCollisionRefusedAtRuntime(t *testing.T) {
	colliding := config.SettingsWire{Identity: testIdentity()}
	colliding.Identity.Issuer = bundleTestIssuer
	colliding.Identity.InternalIssuerURL = ""
	ok := config.SettingsWire{Identity: testIdentity()}

	check := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "identity.issuer") || !strings.Contains(err.Error(), "tokenService.issuer") {
			t.Fatalf("err = %v, want a refusal naming identity.issuer and tokenService.issuer", err)
		}
		var ip *dashboard.InvalidPolicyError
		if !errors.As(err, &ip) {
			t.Errorf("err type %T, want a dashboard.InvalidPolicyError (a 4xx, not a 500)", err)
		}
	}

	t.Run("file mode", func(t *testing.T) {
		srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
		if err := srv.writeSettings(colliding); err != nil {
			t.Fatalf("token service off: %v", err)
		}
		srv.cfg.TokenIssuer = bundleTestIssuer
		check(t, srv.writeSettings(colliding))
		if err := srv.writeSettings(ok); err != nil {
			t.Fatalf("a different issuer: %v", err)
		}
	})
	t.Run("versioned mode", func(t *testing.T) {
		srv, _ := newPublishServer(t, writePolicyFile(t, "api.openai.com"), config.ConsoleConfig{})
		srv.cfg.TokenIssuer = bundleTestIssuer
		before := mustHead(t, srv.versions)
		check(t, srv.writeSettings(colliding))
		if after := mustHead(t, srv.versions); after != before {
			t.Errorf("head moved %d -> %d on a refused write", before, after)
		}
		if err := srv.writeSettings(ok); err != nil {
			t.Fatalf("a different issuer: %v", err)
		}
	})
}

// TestBundleAgentKeyRemoval: removing one key of an enabled agent moves the
// signed bundle (a new seq, an agent_registry row, a new ETag a held long poll
// wakes on) and the removed thumbprint is gone from the signed registeredAgents.
func TestBundleAgentKeyRemoval(t *testing.T) {
	h := newBundleHarnessIssuer(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil, bundleTestIssuer)
	mkKey := func(kid string) agentreg.Key {
		s, err := signer.GenerateLocal(keys.AlgEdDSA)
		if err != nil {
			t.Fatal(err)
		}
		jwk, _ := json.Marshal(map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": kid,
			"x": base64.RawURLEncoding.EncodeToString(s.Public().(ed25519.PublicKey))})
		return agentreg.Key{KID: kid, JWK: jwk}
	}
	ctx := context.Background()
	created, err := h.s.agents.Create(ctx, agentreg.Agent{ID: "agent-a", Keys: []agentreg.Key{mkKey("k1"), mkKey("k2")}, AllowedGroups: []string{"eng"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	h.ps.Refresh()
	signedJKT := func() (bundle.Verified, []string) {
		r := h.bundleResp(t)
		v := h.verify(t, r.body, bundle.State{})
		var wire struct {
			Agents []struct {
				ID  string   `json:"id"`
				JKT []string `json:"jkt"`
			} `json:"registeredAgents"`
		}
		if err := json.Unmarshal(v.Bundle.Policy, &wire); err != nil {
			t.Fatal(err)
		}
		for _, a := range wire.Agents {
			if a.ID == "agent-a" {
				return v, a.JKT
			}
		}
		t.Fatal("agent-a is not in the signed bundle")
		return v, nil
	}
	before, both := signedJKT()
	if len(both) != 2 {
		t.Fatalf("signed jkt = %v, want both keys", both)
	}
	etag := h.bundleResp(t).hdr.Get("ETag")
	removed := agentreg.Thumbprints(agentreg.Agent{Keys: created.Keys[1:]})[0]

	held := make(chan btResp, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/policy?wait=30s", nil)
		req.Header.Set("Accept", BundleMediaType)
		req.Header.Set("If-None-Match", etag)
		rec := httptest.NewRecorder()
		h.ps.ServePolicy(rec, req)
		held <- btResp{rec.Code, rec.Header(), rec.Body.Bytes()}
	}()
	created.Keys = created.Keys[:1]
	if _, err := h.s.agents.Update(ctx, created, "test"); err != nil {
		t.Fatal(err)
	}
	h.ps.Refresh()
	select {
	case r := <-held:
		if r.code != http.StatusOK {
			t.Fatalf("long poll = %d", r.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the key removal did not wake the long poll")
	}
	after, left := signedJKT()
	if after.Seq <= before.Seq || len(left) != 1 || left[0] == removed {
		t.Errorf("seq %d -> %d, signed jkt %v, removed %s: the removed key must be gone and the seq must move", before.Seq, after.Seq, left, removed)
	}
	if rows := h.publishRows(t); rows[len(rows)-1].Reason != agentRegistryOverlayName {
		t.Errorf("newest row = %q, want %q", rows[len(rows)-1].Reason, agentRegistryOverlayName)
	}
}
