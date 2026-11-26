package scenarios

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The token endpoint gate (W-P2-TOKX-03): with tokenService.enabled an agent
// exchanges a user's ID token and its own private_key_jwt assertion at
// POST /oauth2/token for a short-lived Warden token that verifies against the
// control plane's JWKS; every refusal is an RFC 6749 error with a closed reason
// and no token; the endpoint is absent (404) unless the block enables it.

func tokenServiceOpts(extra ...harness.Option) []harness.Option {
	return append([]harness.Option{harness.WithIdentity("attribute"), harness.WithTokenService(), harness.WithControlPlaneAdminToken()}, extra...)
}

func tokenServiceDisabledOpts() []harness.Option { return []harness.Option{harness.WithKeys()} }

// tokenUser mints the user's ID token: sub, verified email and groups, valid
// for 30 minutes so the token service's own 15-minute ttl is what caps the
// issued token.
func tokenUser(h *harness.H, sub string, groups ...string) string {
	return h.MintUserToken(fakes.Valid(sub, sub+"@example.com", groups...),
		fakes.WithIAT(h.Clock().Now()), fakes.WithExp(h.Clock().Now().Add(30*time.Minute)))
}

// publishWindow is longer than the control plane's mint window after a key is
// published (one policy long-poll plus worker skew).
const publishWindow = 2*time.Minute + time.Second

// waitTokenKeyPublished moves the harness clock past the window in which a
// freshly created token key may not mint yet.
func waitTokenKeyPublished(h *harness.H) { h.Clock().Advance(publishWindow) }

// exchangeForm posts form to the token endpoint.
func exchangeForm(h *harness.H, form url.Values) harness.RawResponse {
	return h.CP().Exchange(form.Encode(), nil)
}

// requireNoStore checks the headers every reply of the endpoint carries.
func requireNoStore(t *testing.T, r harness.RawResponse) {
	t.Helper()
	if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Errorf("token endpoint headers = %v, want no-store, no-cache, application/json", r.Header)
	}
}

// requireRefusal checks a reply is the RFC 6749 error code with description
// desc, carries the headers and holds no token.
func requireRefusal(t *testing.T, name string, r harness.RawResponse, status int, code, desc string) {
	t.Helper()
	if r.Status != status {
		t.Errorf("%s: status = %d, want %d (%s)", name, r.Status, status, r.Body)
		return
	}
	gotCode, gotDesc := harness.TokenOAuthError(t, r)
	if gotCode != code || gotDesc != desc {
		t.Errorf("%s: error = %s/%s, want %s/%s", name, gotCode, gotDesc, code, desc)
	}
	requireNoStore(t, r)
	if strings.Contains(r.Body, "access_token") {
		t.Errorf("%s: a refusal carries a token: %s", name, r.Body)
	}
	if status == http.StatusServiceUnavailable && r.Header.Get("Retry-After") == "" {
		t.Errorf("%s: a 503 carries no Retry-After", name)
	}
}

// tokenResponse is a successful exchange.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

func decodeToken(t *testing.T, r harness.RawResponse) tokenResponse {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("exchange = %d %s, want 200", r.Status, r.Body)
	}
	requireNoStore(t, r)
	var tr tokenResponse
	if err := json.Unmarshal([]byte(r.Body), &tr); err != nil {
		t.Fatalf("exchange body: %v", err)
	}
	return tr
}

// verifyWardenToken checks raw's EdDSA signature against the JWKS the control
// plane serves, with no help from the control plane's own code, and returns
// the header and claims.
func verifyWardenToken(t *testing.T, h *harness.H, raw string) (map[string]any, identity.WardenClaims) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("the access token is not a compact JWS")
	}
	var hdr map[string]any
	dec := func(s string, v any) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || json.Unmarshal(b, v) != nil {
			t.Fatalf("undecodable token segment: %v", err)
		}
	}
	dec(parts[0], &hdr)
	jwks := h.CP().DoWorker(http.MethodGet, "/.well-known/jwks.json", "", "", "")
	var set struct {
		Keys []struct{ Kid, Kty, Crv, X string } `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks.Body), &set); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var pub ed25519.PublicKey
	for _, k := range set.Keys {
		if k.Kid == hdr["kid"] && k.Kty == "OKP" && k.Crv == "Ed25519" {
			x, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil || len(x) != ed25519.PublicKeySize {
				t.Fatalf("JWKS key %s: bad x", k.Kid)
			}
			pub = x
		}
	}
	if pub == nil {
		t.Fatalf("kid %v is not in the served JWKS", hdr["kid"])
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatalf("the access token does not verify against the served JWKS")
	}
	var c identity.WardenClaims
	dec(parts[1], &c)
	return hdr, c
}

// requireNoCredentialsInLogs checks none of the secrets reached the control
// plane's log.
func requireNoCredentialsInLogs(t *testing.T, h *harness.H, secrets ...string) {
	t.Helper()
	logs := h.Logs()
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("the control-plane log holds a credential (%d bytes of it)", len(s))
		}
	}
}

// tokenExchangeIssuesToken: a user in an allowed group and a registered agent
// exchange for a typ wt+jwt token that verifies against the served JWKS and
// carries the specified claims, capped at the user's own expiry; the
// discovery document names the endpoint; no credential reaches the log.
func tokenExchangeIssuesToken(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read", "write"})
	// The first key was created a moment ago: until verifiers can hold it the
	// endpoint refuses to mint, then it does.
	requireRefusal(t, "first key not yet published", exchangeForm(h, agent.Form(tokenUser(h, "user-0", "eng"), nil)), 503, "temporarily_unavailable", "signer_unavailable")
	waitTokenKeyPublished(h)
	user := tokenUser(h, "user-42", "eng", "ops")
	form := agent.Form(user, url.Values{"scope": {"write read"}})
	assertion := form.Get("client_assertion")
	res := exchangeForm(h, form)
	tr := decodeToken(t, res)
	if tr.TokenType != "Bearer" || tr.IssuedTokenType != "urn:ietf:params:oauth:token-type:jwt" || tr.Scope != "read write" || tr.ExpiresIn != 900 {
		t.Fatalf("response = %+v, want a Bearer jwt token of 900s with scope \"read write\"", tr)
	}
	hdr, c := verifyWardenToken(t, h, tr.AccessToken)
	if hdr["typ"] != "wt+jwt" || hdr["alg"] != "EdDSA" {
		t.Errorf("header = %v, want typ wt+jwt alg EdDSA", hdr)
	}
	idpIss := h.Issuer().Issuer()
	switch {
	case c.Ver != 1 || c.Iss != harness.TokenServiceIssuer || c.Aud != "warden-worker":
		t.Errorf("ver/iss/aud = %d %s %s", c.Ver, c.Iss, c.Aud)
	case c.Sub != "user-42" || c.IdPIss != idpIss || c.Email != "user-42@example.com" || !c.EmailVerified:
		t.Errorf("subject claims = %+v", c)
	case strings.Join(c.Groups, ",") != "eng,ops":
		t.Errorf("groups = %v", c.Groups)
	case c.Act.Sub != "harness-agent" || c.Cnf.JKT == "":
		t.Errorf("binding = act %+v cnf %+v", c.Act, c.Cnf)
	case !strings.HasPrefix(c.SID, tokensvc.SessionPrefix) || c.JTI == "":
		t.Errorf("sid %q jti %q", c.SID, c.JTI)
	case c.Exp-c.Iat != 900 || c.Nbf != c.Iat || c.Scope != "read write":
		t.Errorf("times/scope = iat %d nbf %d exp %d scope %q", c.Iat, c.Nbf, c.Exp, c.Scope)
	}

	// A second exchange by the same user through the same agent continues the
	// session.
	again := decodeToken(t, exchangeForm(h, agent.Form(user, nil)))
	_, c2 := verifyWardenToken(t, h, again.AccessToken)
	if c2.SID != c.SID || c2.JTI == c.JTI {
		t.Errorf("second exchange sid %s jti %s, want sid %s and a fresh jti", c2.SID, c2.JTI, c.SID)
	}
	// With no scope requested the agent's whole allowed scope is issued.
	if again.Scope != "read write" {
		t.Errorf("default scope = %q, want the agent's allowed scopes", again.Scope)
	}

	// The token never outlives the user's own proof.
	short := h.MintUserToken(fakes.Valid("user-43", "u43@example.com", "eng"))
	capped := decodeToken(t, exchangeForm(h, agent.Form(short, nil)))
	if capped.ExpiresIn != 300 {
		t.Errorf("expires_in for a 5-minute ID token = %d, want 300", capped.ExpiresIn)
	}

	meta := h.CP().TokenRequest(http.MethodGet, "/.well-known/oauth-authorization-server", "", nil)
	var doc map[string]any
	if meta.Status != http.StatusOK || json.Unmarshal([]byte(meta.Body), &doc) != nil ||
		doc["token_endpoint"] != harness.TokenServiceIssuer+"/oauth2/token" || doc["issuer"] != harness.TokenServiceIssuer ||
		!strings.Contains(meta.Body, "private_key_jwt") {
		t.Errorf("discovery = %d %s", meta.Status, meta.Body)
	}
	requireNoCredentialsInLogs(t, h, user, assertion, tr.AccessToken, again.AccessToken)
}

// tokenExchangeRefusals: every way a request can be wrong is an RFC 6749 error
// with a closed reason and no token; the four causes of a failed client
// authentication are indistinguishable.
func tokenExchangeRefusals(t *testing.T, h *harness.H) {
	waitTokenKeyPublished(h)
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read", "write"})
	other := h.RegisterTokenAgent("second-agent", []string{"eng"}, []string{"read"})
	user := tokenUser(h, "user-1", "eng")
	const invalidClient = "client_authentication_failed"

	// Client authentication: replay, unknown agent, wrong audience, expired
	// assertion, no signature algorithm, unknown key id, disabled agent.
	form := agent.Form(user, nil)
	if res := exchangeForm(h, form); res.Status != http.StatusOK {
		t.Fatalf("first use of the assertion = %d %s", res.Status, res.Body)
	}
	replay := exchangeForm(h, form)
	requireRefusal(t, "replayed assertion", replay, 401, "invalid_client", invalidClient)
	now := h.Clock().Now().Unix()
	ghost := exchangeForm(h, agent.Form(user, nil, harness.AssertionClaim("iss", "ghost-agent"), harness.AssertionClaim("sub", "ghost-agent")))
	requireRefusal(t, "unknown agent", ghost, 401, "invalid_client", invalidClient)
	for name, f := range map[string]url.Values{
		"wrong audience":    agent.Form(user, nil, harness.AssertionClaim("aud", "https://evil.example.com/oauth2/token")),
		"expired assertion": agent.Form(user, nil, harness.AssertionClaim("iat", now-600), harness.AssertionClaim("exp", now-540)),
		"alg none":          agent.Form(user, nil, harness.AssertionHeader("alg", "none")),
		"alg HS256":         agent.Form(user, nil, harness.AssertionHeader("alg", "HS256")),
		"unknown kid":       agent.Form(user, nil, harness.AssertionHeader("kid", "no-such-key")),
		"embedded jwk":      agent.Form(user, nil, harness.AssertionHeader("jwk", map[string]string{"kty": "OKP"})),
		"someone else's id": agent.Form(user, url.Values{"client_id": {"second-agent"}}),
	} {
		requireRefusal(t, name, exchangeForm(h, f), 401, "invalid_client", invalidClient)
	}
	h.DisableTokenAgent("second-agent")
	h.Eventually("the registry watch sees the disabled agent", func() bool {
		h.Clock().Advance(3 * time.Second)
		return exchangeForm(h, other.Form(user, nil)).Status == http.StatusUnauthorized
	})
	disabled := exchangeForm(h, other.Form(user, nil))
	requireRefusal(t, "disabled agent", disabled, 401, "invalid_client", invalidClient)
	if disabled.Body != replay.Body || disabled.Body != ghost.Body {
		t.Errorf("client authentication failures differ: replay %s, unknown %s, disabled %s", replay.Body, ghost.Body, disabled.Body)
	}

	// The subject token.
	requireRefusal(t, "expired subject", exchangeForm(h, agent.Form(h.MintUserToken(fakes.Expired()), nil)), 400, "invalid_grant", "subject_expired")
	requireRefusal(t, "wrong azp", exchangeForm(h, agent.Form(h.MintUserToken(fakes.WrongAZP()), nil)), 400, "invalid_grant", "subject_invalid")
	requireRefusal(t, "wrong audience", exchangeForm(h, agent.Form(h.MintUserToken(fakes.WrongAudience()), nil)), 400, "invalid_grant", "subject_invalid")
	requireRefusal(t, "not a token", exchangeForm(h, agent.Form("not-a-jwt", nil)), 400, "invalid_grant", "subject_invalid")
	// The token endpoint's own output is no subject token.
	issued := decodeToken(t, exchangeForm(h, agent.Form(user, nil)))
	requireRefusal(t, "warden token as subject", exchangeForm(h, agent.Form(issued.AccessToken, nil)), 400, "invalid_grant", "subject_invalid")

	// Authorization.
	requireRefusal(t, "user outside the agent's groups", exchangeForm(h, agent.Form(tokenUser(h, "user-2", "sales"), nil)), 400, "unauthorized_client", "group_not_allowed")
	requireRefusal(t, "scope not allowed", exchangeForm(h, agent.Form(user, url.Values{"scope": {"read admin"}})), 400, "invalid_scope", "scope_not_allowed")
	requireRefusal(t, "malformed scope", exchangeForm(h, agent.Form(user, url.Values{"scope": {"READ"}})), 400, "invalid_scope", "scope_not_allowed")
	requireRefusal(t, "other audience", exchangeForm(h, agent.Form(user, url.Values{"audience": {"somewhere-else"}})), 400, "invalid_target", "invalid_target")
	requireRefusal(t, "other requested token type", exchangeForm(h, agent.Form(user, url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:saml2"}})), 400, "invalid_request", "unsupported_token_type")
	requireRefusal(t, "other subject token type", exchangeForm(h, agent.Form(user, url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}})), 400, "invalid_request", "unsupported_token_type")
	h.BlockUser("user-blocked", "")
	h.Eventually("the block list refuses the user", func() bool {
		h.Clock().Advance(time.Second)
		return exchangeForm(h, agent.Form(tokenUser(h, "user-blocked", "eng"), nil)).Status == http.StatusBadRequest
	})
	requireRefusal(t, "blocked user", exchangeForm(h, agent.Form(tokenUser(h, "user-blocked", "eng"), nil)), 400, "invalid_grant", "user_blocked")

	// The request's shape.
	valid := func() url.Values { return agent.Form(user, nil) }
	with := func(k, v string) string { f := valid(); f.Set(k, v); return f.Encode() }
	post := func(name, body string, hdr http.Header, status int, code, desc string) {
		t.Helper()
		requireRefusal(t, name, h.CP().Exchange(body, hdr), status, code, desc)
	}
	post("password grant", with("grant_type", "password"), nil, 400, "unsupported_grant_type", "unsupported_grant_type")
	post("json content type", valid().Encode(), http.Header{"Content-Type": {"application/json"}}, 400, "invalid_request", "unsupported_content_type")
	post("duplicate subject token", valid().Encode()+"&subject_token=second", nil, 400, "invalid_request", "duplicate_parameter")
	post("actor token", with("actor_token", "x"), nil, 400, "invalid_request", "unsupported_parameter")
	post("resource", with("resource", "https://x.example.com"), nil, 400, "invalid_request", "unsupported_parameter")
	post("authorization header", valid().Encode(), http.Header{"Authorization": {"Bearer " + h.CP().Token()}}, 400, "invalid_request", "authorization_header_not_allowed")
	post("worker token as client auth", valid().Encode(), http.Header{"Authorization": {"Bearer wwt_0123456789abcdef"}}, 400, "invalid_request", "authorization_header_not_allowed")
	post("33 KiB body", with("subject_token", strings.Repeat("a", 33<<10)), nil, 400, "invalid_request", "body_too_large")
	noAssertion := valid()
	noAssertion.Del("client_assertion")
	noAssertion.Del("client_assertion_type")
	post("a session cookie and no assertion", noAssertion.Encode(), http.Header{"Cookie": {"warden_session=0123456789abcdef"}}, 401, "invalid_client", invalidClient)
	requireRefusal(t, "query string", h.CP().TokenRequest(http.MethodPost, "/oauth2/token?client_id=x", valid().Encode(), nil), 400, "invalid_request", "query_parameters_not_allowed")
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		r := h.CP().TokenRequest(m, "/oauth2/token", "", nil)
		if r.Status != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "POST" {
			t.Errorf("%s /oauth2/token = %d Allow %q, want 405 Allow: POST", m, r.Status, r.Header.Get("Allow"))
		}
		requireNoStore(t, r)
	}
	requireNoCredentialsInLogs(t, h, user, issued.AccessToken)
}

// tokenServiceDisabledByDefault: without the tokenService block the endpoint
// and its discovery document are 404 while the rest of the control plane
// (policy, JWKS) is untouched.
func tokenServiceDisabledByDefault(t *testing.T, h *harness.H) {
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/oauth2/token"}, {http.MethodGet, "/oauth2/token"}, {http.MethodGet, "/.well-known/oauth-authorization-server"},
	} {
		if r := h.CP().TokenRequest(c.method, c.path, "grant_type=x", nil); r.Status != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 with the token service disabled", c.method, c.path, r.Status)
		}
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("/policy = %d, want 200", status)
	}
	if res := jwksBody(h); res.Status != http.StatusOK {
		t.Errorf("JWKS = %d, want 200", res.Status)
	}
}

// tokenExchangeSignerUnavailable: with the private-key store down at startup
// the endpoint answers 503 temporarily_unavailable/signer_unavailable with
// Retry-After and mints nothing, and exchanges work again once the store
// returns.
func tokenExchangeSignerUnavailable(t *testing.T, h *harness.H) {
	waitTokenKeyPublished(h)
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	user := tokenUser(h, "user-1", "eng")
	decodeToken(t, exchangeForm(h, agent.Form(user, nil)))

	h.CP().Stop()
	h.KeyStore().SetDown(errors.New("secret backend unreachable"))
	h.CP().Start()
	requireRefusal(t, "no signing key", exchangeForm(h, agent.Form(user, nil)), 503, "temporarily_unavailable", "signer_unavailable")
	if r := h.CP().DoWorker(http.MethodGet, "/readyz", "", "", ""); r.Status != http.StatusServiceUnavailable {
		t.Errorf("/readyz with no signing key = %d, want 503", r.Status)
	}

	h.KeyStore().SetDown(nil)
	h.Eventually("the key manager reloads the signing key", func() bool {
		h.Clock().Advance(time.Minute)
		return exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil)).Status == http.StatusOK
	})
}

// tokenExchangeIdPUnavailable: with the IdP unreachable and no cached keys a
// valid-looking ID token cannot be verified, so the endpoint answers 503
// temporarily_unavailable/idp_unavailable with Retry-After (the harness retries
// rather than sending the user to sign in again).
func tokenExchangeIdPUnavailable(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	requireRefusal(t, "IdP down", exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil)), 503, "temporarily_unavailable", "idp_unavailable")
}

// tokenExchangeIdPOutageDuringRotation: the control plane has cached the
// IdP's JWKS, then the IdP rotates its signing key and becomes unreachable. A
// subject token signed with the new kid cannot be checked, so the endpoint
// answers 503 temporarily_unavailable/idp_unavailable with Retry-After (a
// client is expected to retry) rather than 400 subject_invalid (which forces a re-login),
// both on the failing refetch and inside the 30 s refetch floor after it. A
// token under the cached kid keeps working, and once the IdP is back the new
// kid verifies.
func tokenExchangeIdPOutageDuringRotation(t *testing.T, h *harness.H) {
	waitTokenKeyPublished(h)
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil))) // caches the JWKS

	rotated := h.MintUserToken(fakes.Valid("user-2", "user-2@example.com", "eng"), fakes.RotateKey(),
		fakes.WithIAT(h.Clock().Now()), fakes.WithExp(h.Clock().Now().Add(30*time.Minute)))
	h.Issuer().Stop()
	h.Clock().Advance(31 * time.Second) // past the refetch floor of the first fetch
	requireRefusal(t, "new kid, IdP down (failed refetch)", exchangeForm(h, agent.Form(rotated, nil)), 503, "temporarily_unavailable", "idp_unavailable")
	h.Clock().Advance(5 * time.Second) // inside the floor after the failed refetch
	requireRefusal(t, "new kid, IdP down (inside the floor)", exchangeForm(h, agent.Form(rotated, nil)), 503, "temporarily_unavailable", "idp_unavailable")
	decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-3", "eng"), nil))) // cached kid still verifies

	h.Issuer().Start()
	h.Eventually("the new kid verifies once the IdP is back", func() bool {
		h.Clock().Advance(31 * time.Second)
		return exchangeForm(h, agent.Form(rotated, nil)).Status == http.StatusOK
	})
}
