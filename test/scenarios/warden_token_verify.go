package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/test/harness"
)

// Warden token verification on the worker (W-P2-WBND-01). A pinned worker takes
// the token keys and issuer only from the signed bundle it verified, so a token
// the control plane minted verifies, while a token signed with a key that is not
// in the bundle, a token with the wrong issuer and a token with a good kid and a
// forged signature are all refused (invalid, never a subject). A worker on the
// legacy wire has no verified bundle and so no keys: the same valid token is
// unverified. The IdP's own tokens keep working next to Warden tokens.
//
// Attribute mode never blocks, so every request is allowed and what is checked
// is the identity recorded on the event and the verify counter. Tokens are
// never printed.

func wardenTokenVerifyOpts() []harness.Option {
	return tokenServiceOpts(harness.WithBundles(controlplane.BundlesOffer), harness.WithBundlePins())
}

// wardenTokenLegacyOpts is the same stack with workers that do not pin bundle
// keys, so they stay on the unsigned wire.
func wardenTokenLegacyOpts() []harness.Option {
	return tokenServiceOpts(harness.WithBundles(controlplane.BundlesOffer))
}

// wardenProber sends GETs through the worker carrying a token as
// Proxy-Authorization on CONNECT and returns the event each one recorded.
type wardenProber struct {
	t *testing.T
	h *harness.H
	n int
}

// probe sends one GET and returns its event.
func (p *wardenProber) probe(tok string) analytics.Event {
	p.t.Helper()
	p.n++
	path := fmt.Sprintf("/probe-%d", p.n)
	req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
	if err != nil {
		p.t.Fatal(err)
	}
	resp, err := p.h.AgentWithProxyToken(tok).Do(req)
	if err != nil {
		p.t.Fatalf("probe %d: %v", p.n, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.t.Fatalf("probe %d: status %d, want the upstream's 200 (attribute mode never blocks)", p.n, resp.StatusCode)
	}
	return only(p.t, p.h.Events(), "https://"+identityHost+path)
}

// resign signs the claims of the Warden token raw with sg under a header made of
// kid, keeping typ wt+jwt. The claims are edited by mod first.
func resign(t *testing.T, raw string, sg keys.Signer, kid string, mod func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(claims)
	}
	tok, err := keys.SignCompact(context.Background(), sg, keys.Header{Alg: keys.AlgEdDSA, Kid: kid, Typ: identity.WardenTokenTyp}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// verifySeries returns warden.identity.verify.total{result,reason,token_type}.
func verifySeries(h *harness.H, result, reason, tokenType string) float64 {
	var total float64
	for k, v := range h.Metrics() {
		if !strings.HasPrefix(k, verifyMetric+"{") {
			continue
		}
		labels := map[string]string{}
		for _, kv := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(k, verifyMetric+"{"), "}"), ",") {
			name, val, _ := strings.Cut(kv, "=")
			labels[name] = val
		}
		if labels["result"] == result && labels["reason"] == reason && labels["token_type"] == tokenType {
			total += v
		}
	}
	return total
}

func requireRefusedEvent(t *testing.T, name string, e analytics.Event, status, reason string) {
	t.Helper()
	if e.IdentityStatus != status || e.IdentityReason != reason {
		t.Errorf("%s: identity %s/%s, want %s/%s", name, e.IdentityStatus, e.IdentityReason, status, reason)
	}
	if e.UserSub != "" || e.UserEmail != "" || len(e.UserGroups) != 0 {
		t.Errorf("%s: a refused token attributed a user (sub %q email %q groups %v)", name, e.UserSub, e.UserEmail, e.UserGroups)
	}
}

// wardenTokenVerify: pinned worker, CP token service. A valid token is accepted
// once the worker holds the bundle that carries the key; a token signed by a key
// outside the bundle, a token with a forged signature under a real kid and a
// token with the wrong issuer are refused; the IdP's own token still works.
func wardenTokenVerify(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	agent := h.RegisterTokenAgent("bound-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	idpTok := tokenUser(h, "user-1", "eng")
	resp := decodeToken(t, exchangeForm(h, agent.Form(idpTok, nil)))
	good := resp.AccessToken
	hdr, claims := verifyWardenToken(t, h, good)
	realKID, _ := hdr["kid"].(string)
	if claims.Iss != harness.TokenServiceIssuer {
		t.Fatalf("minted iss %q, want %q", claims.Iss, harness.TokenServiceIssuer)
	}
	p := &wardenProber{t: t, h: h}

	// The worker applies the bundle that carries the key on its long poll; until
	// it does the token is unknown_kid (the keys are the bundle's, nothing else).
	var e analytics.Event
	h.Eventually("the worker verifies a Warden token against the bundle's keys", func() bool {
		e = p.probe(good)
		return e.IdentityStatus == "valid"
	})
	if e.UserSub != "user-1" || e.UserEmail != "user-1@example.com" || strings.Join(e.UserGroups, ",") != "eng" {
		t.Errorf("valid Warden token attributed sub %q email %q groups %v, want user-1 / user-1@example.com / [eng]", e.UserSub, e.UserEmail, e.UserGroups)
	}

	// Probes made while the worker caught up were counted too: measure from here.
	base := map[string]float64{}
	for _, r := range []string{"unknown_kid", "bad_signature", "wrong_iss"} {
		base[r] = verifySeries(h, "invalid", r, "warden")
	}

	// A key that is in no bundle: the CP's own claims, an attacker's signature.
	attacker, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	unknown := resign(t, good, attacker, attacker.KID(), nil)
	requireRefusedEvent(t, "key not in the bundle", p.probe(unknown), "invalid", "unknown_kid")

	// The attacker claims a kid the bundle does hold: the signature is wrong.
	forged := resign(t, good, attacker, realKID, nil)
	requireRefusedEvent(t, "forged signature under a real kid", p.probe(forged), "invalid", "bad_signature")

	// The control plane's real key signs a token for another issuer.
	cpKey, err := h.KeyManager().KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	wrongIss := resign(t, good, cpKey, cpKey.KID(), func(c map[string]any) { c["iss"] = "https://other-issuer.example.test" })
	requireRefusedEvent(t, "wrong issuer", p.probe(wrongIss), "invalid", "wrong_iss")

	// The IdP's own token keeps verifying next to Warden tokens (acceptDexTokens
	// resolves true: identity.issuer is set).
	if e := p.probe(idpTok); e.IdentityStatus != "valid" || e.UserSub != "user-1" {
		t.Errorf("IdP token: identity %s sub %q, want valid user-1", e.IdentityStatus, e.UserSub)
	}

	if h.MetricsAvailable() {
		for _, c := range []struct {
			result, reason, tt string
			want               float64
		}{
			{"invalid", "unknown_kid", "warden", 1},
			{"invalid", "bad_signature", "warden", 1},
			{"invalid", "wrong_iss", "warden", 1},
		} {
			if got := verifySeries(h, c.result, c.reason, c.tt) - base[c.reason]; got != c.want {
				t.Errorf("%s{result=%s,reason=%s,token_type=%s} = %v, want %v", verifyMetric, c.result, c.reason, c.tt, got, c.want)
			}
		}
		if got := verifySeries(h, "valid", "none", "warden"); got < 1 {
			t.Errorf("no valid warden series")
		}
		if got := verifySeries(h, "valid", "none", "idp"); got != 1 {
			t.Errorf("valid idp series = %v, want 1", got)
		}
	}
	requireNoCredentialsInLogs(t, h, good, unknown, forged, wrongIss, idpTok)
}

// wardenTokenLegacyWire: a worker with no pinned bundle keys has no verified
// bundle, so it installs no token keys: the very token the control plane minted
// is unverified (jwks_unavailable), not valid.
func wardenTokenLegacyWire(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	agent := h.RegisterTokenAgent("bound-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	good := decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil))).AccessToken
	p := &wardenProber{t: t, h: h}
	requireRefusedEvent(t, "legacy-wire worker", p.probe(good), "unverified", "jwks_unavailable")
	if h.MetricsAvailable() {
		if got := verifySeries(h, "unverified", "jwks_unavailable", "warden"); got != 1 {
			t.Errorf("%s{unverified,jwks_unavailable,warden} = %v, want 1", verifyMetric, got)
		}
	}
	requireNoCredentialsInLogs(t, h, good)
}
