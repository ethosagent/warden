package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
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
// that key; the token carries typ wt+jwt and the verified email; and a registry
// change moves the served ETag, which wakes the long poll.
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
	jkt, status, etag := served()
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
	if _, status, next := served(); status != "disabled" || next == etag {
		t.Errorf("after the disable: status %q, ETag unchanged=%v; the served policy must move", status, next == etag)
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
