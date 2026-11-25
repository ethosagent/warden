package harness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// The token endpoint gate (W-P2-TOKX-03): the control plane boots with
// tokenService.enabled over a state dir, the signing keys (WithKeys) and the
// identity block of the OIDC issuer fake (WithIdentity). A scenario registers
// an agent with a key pair the harness holds, signs client assertions with it
// and exchanges a user token minted by the issuer fake at POST /oauth2/token,
// the way a harness agent does. The control plane runs on the harness's fake
// clock, so the assertion times and the issued token's exp are exact.

// TokenServiceIssuer is tokenService.issuer in the harness config: a loopback
// http origin, the one plain-http form the config accepts. The assertion
// audience is this value plus /oauth2/token.
const TokenServiceIssuer = "http://localhost"

// TokenEndpointPath is the token endpoint's path.
const TokenEndpointPath = "/oauth2/token"

const (
	grantTypeExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	assertionTypeJWT    = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	subjectTypeIDToken  = "urn:ietf:params:oauth:token-type:id_token"
	tokenAssertionKeyID = "-key-1"
)

// WithTokenService boots the control plane with tokenService.enabled: true and
// an https-style (loopback) issuer, over the state dir WithKeys provides. It
// implies WithKeys and needs WithIdentity (the verifier of the user's ID
// token is the served identity block's). In-process only.
func WithTokenService() Option {
	return func(h *H) {
		h.wantKeys = true
		h.wantTokenSvc = true
	}
}

// tokenLimits are the tokenService.rateLimit and eventRetention overrides of a
// scenario. The harness default is a limit no scenario reaches by accident, so
// the many exchanges of a scenario from one loopback address and one test user
// do not trip the production defaults; a scenario about the limits sets its own.
type tokenLimits struct {
	perIP, perAgent, perUser string
	eventRetention           string
	trustLoopbackProxy       bool
}

const harnessTokenRate = "100000/minute"

// WithTokenRateLimit sets tokenService.rateLimit.perIP, perAgent and perUser
// (each "N/second|minute|hour"; "" keeps the harness default).
func WithTokenRateLimit(perIP, perAgent, perUser string) Option {
	return func(h *H) {
		h.tokenLimits.perIP, h.tokenLimits.perAgent, h.tokenLimits.perUser = perIP, perAgent, perUser
	}
}

// WithTokenEventRetention sets tokenService.eventRetention (at least 24h).
func WithTokenEventRetention(d string) Option {
	return func(h *H) { h.tokenLimits.eventRetention = d }
}

// WithTokenTrustedLoopbackProxy sets console.trustedProxies to the loopback
// host, so a scenario can stand in for a reverse proxy by sending
// X-Forwarded-For: the token endpoint then keys its per-IP limit on the
// forwarded client address instead of 127.0.0.1.
func WithTokenTrustedLoopbackProxy() Option {
	return func(h *H) { h.tokenLimits.trustLoopbackProxy = true }
}

// tokenServiceYAML renders the tokenService block of the control plane's
// config file (empty without the option).
func (h *H) tokenServiceYAML() string {
	if !h.wantTokenSvc {
		return ""
	}
	if h.identityMode == "" {
		h.tb.Fatal("harness: WithTokenService needs WithIdentity (the user's ID token is verified against the served identity block)")
	}
	pick := func(v string) string {
		if v == "" {
			return harnessTokenRate
		}
		return v
	}
	out := "\ntokenService:\n  enabled: true\n  issuer: " + TokenServiceIssuer + "\n" +
		"  rateLimit:\n    perIP: " + pick(h.tokenLimits.perIP) + "\n    perAgent: " + pick(h.tokenLimits.perAgent) +
		"\n    perUser: " + pick(h.tokenLimits.perUser) + "\n"
	if h.tokenLimits.eventRetention != "" {
		out += "  eventRetention: " + h.tokenLimits.eventRetention + "\n"
	}
	return out
}

// TokenAgent is an agent registered with the control plane's registry, with
// the private key the harness signs its assertions with.
type TokenAgent struct {
	// ID is the agent id (the assertion's iss and sub).
	ID string
	// KID is the registry key id the assertion header names.
	KID string

	h    *H
	priv *signer.LocalSigner
}

// RegisterTokenAgent registers an agent with a fresh Ed25519 key, the given
// allowed groups and allowed scopes, straight on the control plane's state
// database the way the offline CLI does, and returns once the control plane
// sees it. Needs WithTokenService.
func (h *H) RegisterTokenAgent(id string, groups, scopes []string) *TokenAgent {
	h.tb.Helper()
	priv, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		h.tb.Fatalf("harness: generate an agent key: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		h.tb.Fatal("harness: the agent key is not Ed25519")
	}
	kid := id + tokenAssertionKeyID
	jwk, err := json.Marshal(map[string]string{
		"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub),
	})
	if err != nil {
		h.tb.Fatalf("harness: encode an agent key: %v", err)
	}
	store, closeDB := h.agentStore()
	defer closeDB()
	_, err = store.Create(context.Background(), agentreg.Agent{
		ID: id, DisplayName: id, Keys: []agentreg.Key{{KID: kid, JWK: jwk}},
		AllowedGroups: groups, AllowedScopes: scopes,
	}, "harness")
	if err != nil {
		h.tb.Fatalf("harness: register agent %s: %v", id, err)
	}
	h.awaitRegisteredAgent(id)
	return &TokenAgent{ID: id, KID: kid, h: h, priv: priv}
}

// awaitRegisteredAgent waits until GET /policy lists agent id. The control
// plane reads the registry from a snapshot that a write on another connection
// only drops at the next policy reload (Store.Sync, a real-time tick) or
// registry watch tick; the token endpoint reads the same Store, so once the
// wire lists the agent an exchange sees it too. It does not advance the fake
// clock, so the token key publish window a scenario may be testing is
// untouched.
func (h *H) awaitRegisteredAgent(id string) {
	h.tb.Helper()
	h.Eventually("the control plane sees registered agent "+id, func() bool {
		r, err := h.CP().Send(http.MethodGet, "/policy", nil, nil)
		if err != nil || r.Status != http.StatusOK {
			return false
		}
		var p struct {
			RegisteredAgents []struct {
				ID string `json:"id"`
			} `json:"registeredAgents"`
		}
		if json.Unmarshal(r.Body, &p) != nil {
			return false
		}
		for _, a := range p.RegisteredAgents {
			if a.ID == id {
				return true
			}
		}
		return false
	})
}

// RegisterTokenAgentKey registers agent id with the public JWK of a key the
// scenario holds (the kid is the JWK's own), the way an operator registers the
// key `warden identity enroll` printed. It returns once the control plane sees
// the agent. Needs WithTokenService.
func (h *H) RegisterTokenAgentKey(id string, jwk keys.JWK, groups, scopes []string) {
	h.tb.Helper()
	raw, err := json.Marshal(jwk)
	if err != nil {
		h.tb.Fatalf("harness: encode an agent key: %v", err)
	}
	store, closeDB := h.agentStore()
	defer closeDB()
	_, err = store.Create(context.Background(), agentreg.Agent{
		ID: id, DisplayName: id, Keys: []agentreg.Key{{KID: jwk.Kid, JWK: raw}},
		AllowedGroups: groups, AllowedScopes: scopes,
	}, "harness")
	if err != nil {
		h.tb.Fatalf("harness: register agent %s: %v", id, err)
	}
	h.awaitRegisteredAgent(id)
}

// TokenEndpointURL is the URL a client reaches POST /oauth2/token at. The
// assertion audience is TokenServiceIssuer + TokenEndpointPath, which is not
// this URL: the harness issuer is a loopback origin.
func (c *CPClient) TokenEndpointURL() string { return "https://" + c.addr + TokenEndpointPath }

// TokenAudience is the audience a client assertion names in the harness.
func TokenAudience() string { return TokenServiceIssuer + TokenEndpointPath }

// HTTPClient is the client the harness reaches the control plane with: it
// trusts the control plane's CA.
func (c *CPClient) HTTPClient() *http.Client { return c.cl }

// DisableTokenAgent switches agent id off in the registry. The control plane
// notices on its next registry watch tick, so a scenario advances the clock
// until the refusal shows.
func (h *H) DisableTokenAgent(id string) {
	h.tb.Helper()
	store, closeDB := h.agentStore()
	defer closeDB()
	a, err := store.Get(context.Background(), id)
	if err != nil {
		h.tb.Fatalf("harness: read agent %s: %v", id, err)
	}
	if _, err := store.SetStatus(context.Background(), id, agentreg.StatusDisabled, a.Revision, "harness"); err != nil {
		h.tb.Fatalf("harness: disable agent %s: %v", id, err)
	}
}

// RotateTokenAgentKey replaces agent id's only key with a fresh one (the agent
// stays enabled), straight on the state database like the offline CLI. The
// control plane notices on its next registry watch tick, so a scenario advances
// the clock until the change shows. The old key can no longer authenticate.
func (h *H) RotateTokenAgentKey(id string) {
	h.tb.Helper()
	priv, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		h.tb.Fatalf("harness: generate an agent key: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		h.tb.Fatal("harness: the agent key is not Ed25519")
	}
	kid := id + "-key-2"
	jwk, err := json.Marshal(map[string]string{
		"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub),
	})
	if err != nil {
		h.tb.Fatalf("harness: encode an agent key: %v", err)
	}
	store, closeDB := h.agentStore()
	defer closeDB()
	a, err := store.Get(context.Background(), id)
	if err != nil {
		h.tb.Fatalf("harness: read agent %s: %v", id, err)
	}
	a.Keys = []agentreg.Key{{KID: kid, JWK: jwk}}
	if _, err := store.Update(context.Background(), a, "harness"); err != nil {
		h.tb.Fatalf("harness: rotate the key of agent %s: %v", id, err)
	}
}

// agentStore opens the control plane's agent registry on its state database.
func (h *H) agentStore() (*agentregsqlite.Store, func()) {
	h.tb.Helper()
	if !h.wantTokenSvc {
		h.tb.Fatal("harness: the token agent helpers need the WithTokenService option")
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(h.root, "cp-state", "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	return agentregsqlite.New(db), func() { _ = db.Close() }
}

// assertionSpec is one assertion under construction.
type assertionSpec struct {
	claims map[string]any
	header map[string]any
}

// AssertionOption adjusts a client assertion before it is signed.
type AssertionOption func(*assertionSpec)

// AssertionClaim sets (or, with a nil value, removes) one claim.
func AssertionClaim(name string, v any) AssertionOption {
	return func(s *assertionSpec) {
		if v == nil {
			delete(s.claims, name)
			return
		}
		s.claims[name] = v
	}
}

// AssertionHeader sets one header member.
func AssertionHeader(name string, v any) AssertionOption {
	return func(s *assertionSpec) { s.header[name] = v }
}

// Assertion signs a client assertion (RFC 7523) for the token endpoint: iss
// and sub are the agent id, aud the endpoint URL, iat now (the harness
// clock), exp a minute later, and a fresh jti. opts then adjust it.
func (a *TokenAgent) Assertion(opts ...AssertionOption) string {
	a.h.tb.Helper()
	now := a.h.fake.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		a.h.tb.Fatalf("harness: assertion jti: %v", err)
	}
	s := &assertionSpec{
		claims: map[string]any{
			"iss": a.ID, "sub": a.ID, "aud": TokenServiceIssuer + TokenEndpointPath,
			"iat": now.Unix(), "exp": now.Unix() + 60, "jti": hex.EncodeToString(jti),
		},
		header: map[string]any{"alg": "EdDSA", "kid": a.KID, "typ": "JWT"},
	}
	for _, o := range opts {
		o(s)
	}
	hb, err := json.Marshal(s.header)
	if err != nil {
		a.h.tb.Fatalf("harness: encode the assertion header: %v", err)
	}
	cb, err := json.Marshal(s.claims)
	if err != nil {
		a.h.tb.Fatalf("harness: encode the assertion claims: %v", err)
	}
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig, err := a.priv.Sign(context.Background(), []byte(in))
	if err != nil {
		a.h.tb.Fatalf("harness: sign the assertion: %v", err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Form is a complete token exchange request body for subjectToken: the grant,
// the subject token (an ID token), a fresh assertion and the extra parameters.
func (a *TokenAgent) Form(subjectToken string, extra url.Values, opts ...AssertionOption) url.Values {
	a.h.tb.Helper()
	f := url.Values{
		"grant_type":            {grantTypeExchange},
		"subject_token":         {subjectToken},
		"subject_token_type":    {subjectTypeIDToken},
		"client_assertion_type": {assertionTypeJWT},
		"client_assertion":      {a.Assertion(opts...)},
	}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// Exchange POSTs body to /oauth2/token with Content-Type
// application/x-www-form-urlencoded and no credential but what hdr adds
// (hdr's values override: an empty value removes the header). It returns the
// reply as is.
func (c *CPClient) Exchange(body string, hdr http.Header) RawResponse {
	c.h.tb.Helper()
	return c.tokenRequest(http.MethodPost, TokenEndpointPath, body, hdr)
}

// TokenRequest is Exchange for any method and path (a wrong method, a query
// string, the discovery document).
func (c *CPClient) TokenRequest(method, path, body string, hdr http.Header) RawResponse {
	c.h.tb.Helper()
	return c.tokenRequest(method, path, body, hdr)
}

func (c *CPClient) tokenRequest(method, path, body string, hdr http.Header) RawResponse {
	c.h.tb.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+c.addr+path, rd)
	if err != nil {
		c.h.tb.Fatalf("harness: build the token request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, vs := range hdr {
		req.Header.Del(k)
		for _, v := range vs {
			if v != "" {
				req.Header.Add(k, v)
			}
		}
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		c.h.tb.Fatalf("harness: %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		c.h.tb.Fatalf("harness: read the %s reply: %v", path, err)
	}
	return RawResponse{Status: resp.StatusCode, Header: resp.Header, Body: string(b)}
}

// TokenOAuthError decodes an RFC 6749 error body.
func TokenOAuthError(tb interface{ Fatalf(string, ...any) }, r RawResponse) (code, description string) {
	var e struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(r.Body), &e); err != nil {
		tb.Fatalf("harness: the reply %d is not an OAuth error: %v", r.Status, err)
	}
	return e.Error, e.Desc
}

// TokenEventRow is one row of the control plane's token_events table.
type TokenEventRow struct {
	ID      int64
	TS      int64
	Outcome string
	Reason  string
	AgentID string
	SubHMAC string
	SID     string
	JTI     string
	KID     string
	Exp     int64
	Scope   string
}

// TokenEvents reads token_events (oldest first) from the control plane's state
// database, read-only: what was stored, independent of the API.
func (h *H) TokenEvents() []TokenEventRow {
	h.tb.Helper()
	db := h.openStateReadOnly()
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT id, ts, outcome, reason, agent_id, sub_hmac, sid, jti, kid, exp, scope FROM token_events ORDER BY id`)
	if err != nil {
		h.tb.Fatalf("harness: read token_events: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []TokenEventRow
	for rows.Next() {
		var r TokenEventRow
		if err := rows.Scan(&r.ID, &r.TS, &r.Outcome, &r.Reason, &r.AgentID, &r.SubHMAC, &r.SID, &r.JTI, &r.KID, &r.Exp, &r.Scope); err != nil {
			h.tb.Fatalf("harness: scan a token_events row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read token_events: %v", err)
	}
	return out
}

// TokenReplayRows counts the rows of token_assertion_jti, the replay table.
func (h *H) TokenReplayRows() int {
	h.tb.Helper()
	db := h.openStateReadOnly()
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM token_assertion_jti`).Scan(&n); err != nil {
		h.tb.Fatalf("harness: count token_assertion_jti: %v", err)
	}
	return n
}

func (h *H) openStateReadOnly() *cpstate.DB {
	h.tb.Helper()
	if !h.wantTokenSvc {
		h.tb.Fatal("harness: the token table helpers need the WithTokenService option")
	}
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(h.root, "cp-state", "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	return db
}
