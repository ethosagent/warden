//go:build e2e

package identity

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness/compose"
)

// TestTokenExchangeDex (W-P2-TOKX-05): alice's real Dex ID token, with a
// registered agent's private_key_jwt assertion, exchanges at the stack's control
// plane (tokenService enabled in configs/config.e2e-identity-cp.yaml) for a
// Warden token that verifies against the served JWKS and carries alice's real
// groups, warden-admins among them. The in-process counterpart with the
// refusals, the restart and the IdP outage is TestTokenExchangeE2E in
// internal/controlplane. Nothing here prints a token: failures report statuses
// and OAuth error codes only.
func TestTokenExchangeDex(t *testing.T) {
	requireStack(t)

	const (
		tokenIssuer   = "https://localhost:7070"
		tokenEndpoint = "/oauth2/token"
		grantType     = "urn:ietf:params:oauth:grant-type:token-exchange"
		assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		idTokenType   = "urn:ietf:params:oauth:token-type:id_token"
	)
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	agentID := "e2e-token-agent-" + hex.EncodeToString(suffix)
	key := fakes.NewAgentKey(t, "e2e-key-1")

	// An admin registers the agent with the public key, as an operator does.
	admin := loginAs(t, "alice")
	body, err := json.Marshal(map[string]any{
		"id": agentID, "displayName": agentID, "keys": []json.RawMessage{key.JWK()},
		"allowedGroups": []string{"warden-admins"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, resp := admin.mustDo(t, http.MethodPost, "/dashboard/api/agents", body, true); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("register agent: status %d (%d bytes)", code, len(resp))
	}

	pool, err := compose.CAPool()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	idToken := dexToken(t, "alice")

	type reply struct {
		status int
		body   []byte
	}
	post := func() reply {
		form := url.Values{
			"grant_type": {grantType}, "subject_token": {idToken}, "subject_token_type": {idTokenType},
			"client_assertion_type": {assertionType},
			"client_assertion":      {key.ClientAssertion(agentID, tokenIssuer+tokenEndpoint, time.Now())},
		}
		req, err := http.NewRequest(http.MethodPost, compose.CPBase+tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", tokenEndpoint, redactURLError(err))
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		return reply{resp.StatusCode, b}
	}

	// A new control plane has not published its first token key long enough for
	// verifiers to hold it and answers 503 signer_unavailable until it has;
	// any other answer ends the wait.
	var r reply
	if err := compose.PollUntil(3*time.Minute, func() (bool, string) {
		r = post()
		var e struct {
			Desc string `json:"error_description"`
		}
		_ = json.Unmarshal(r.body, &e)
		return !(r.status == http.StatusServiceUnavailable && e.Desc == "signer_unavailable"), "status " + http.StatusText(r.status) + " " + e.Desc
	}); err != nil {
		t.Fatalf("the token key was never published: %v", err)
	}
	if r.status != http.StatusOK {
		var e struct{ Error, ErrorDescription string }
		_ = json.Unmarshal(r.body, &e)
		t.Fatalf("exchange of alice's Dex token = %d %s %s, want 200", r.status, e.Error, e.ErrorDescription)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(r.body, &tr); err != nil || tr.AccessToken == "" {
		t.Fatalf("the exchange reply has no access token (%v)", err)
	}

	// Verify against the served JWKS with the keys package alone.
	h, payload, signingInput, sig, err := keys.ParseCompact(tr.AccessToken)
	if err != nil {
		t.Fatalf("the access token is not a compact JWS: %v", err)
	}
	jr, err := client.Get(compose.CPBase + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", redactURLError(err))
	}
	defer jr.Body.Close()
	var set struct {
		Keys []keys.JWK `json:"keys"`
	}
	if jr.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(jr.Body, 1<<20)).Decode(&set) != nil {
		t.Fatalf("GET jwks = %d", jr.StatusCode)
	}
	var served *keys.JWK
	for i := range set.Keys {
		if set.Keys[i].Kid == h.Kid {
			served = &set.Keys[i]
		}
	}
	if served == nil {
		t.Fatalf("the token's kid %q is not in the served JWKS", h.Kid)
	}
	if err := keys.Verify(*served, h.Alg, signingInput, sig); err != nil {
		t.Fatalf("the access token does not verify against the served JWKS: %v", err)
	}
	var c identity.WardenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	hasGroup := false
	for _, g := range c.Groups {
		hasGroup = hasGroup || g == "warden-admins"
	}
	switch {
	case h.Typ != "wt+jwt":
		t.Errorf("typ = %q, want wt+jwt", h.Typ)
	case c.Iss != tokenIssuer || c.Aud != "warden-worker":
		t.Errorf("iss/aud = %q %q", c.Iss, c.Aud)
	case c.IdPIss != dexURL || c.Sub == "":
		t.Errorf("idp_iss = %q sub set = %v", c.IdPIss, c.Sub != "")
	case !hasGroup:
		t.Errorf("groups = %v, want warden-admins among them", c.Groups)
	case c.Act.Sub != agentID || c.Cnf.JKT != key.Thumbprint():
		t.Errorf("binding: act.sub = %q, cnf.jkt matches the agent key = %v", c.Act.Sub, c.Cnf.JKT == key.Thumbprint())
	case c.Exp-c.Iat > 900:
		t.Errorf("exp-iat = %d, want <= 900", c.Exp-c.Iat)
	}

	// No token reaches the captured test output or the control plane's log.
	logs, err := compose.LogsOf(compose.SvcCP)
	if err != nil {
		t.Fatalf("control-plane logs: %v", err)
	}
	for name, secret := range map[string]string{"access token": tr.AccessToken, "Dex ID token": idToken} {
		if strings.Contains(logs, secret) {
			t.Errorf("the control-plane log holds the %s", name)
		}
	}
	if strings.Contains(logs, "eyJ") {
		t.Errorf("the control-plane log holds a JWT-shaped string (eyJ)")
	}
}
