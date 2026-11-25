package security

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
)

// The route boundaries of W-P2-SECT-06: each credential works on the control
// plane routes meant for it and on no other. A worker certificate and a wwt_
// token open the worker routes and no human route; a wak_ API key opens only the
// admin routes its scopes name and is never a worker or an agent credential; a
// console session cookie authenticates a human and nobody else. Each refusal is
// proved to have reached the check that makes it: the case pins the CP's log
// line, and for a write that no certificate, token, key, agent or secret
// changed and what the audit trail holds.

const (
	routeCanaryKey   = "route-canary-key"
	routeCanaryValue = "route-canary-value-5b1e9c"
)

// The credentials of a case.
const (
	credCert   = "cert"   // a valid worker certificate in the TLS handshake
	credWWT    = "wwt_"   // a valid worker token as the bearer
	credWAK    = "wak_"   // a valid API key as the bearer
	credCookie = "cookie" // the admin's console session cookie, no CSRF header
)

// routeFixtures are the credentials of one stack, each valid.
type routeFixtures struct {
	leaf         Leaf
	victim       Leaf
	wwt, wak     string
	wakID        string
	cookie       string
	enrollmentID string
	agent        *Agent
	agentKey     *fakes.AgentKey
}

func newRouteFixtures(tb testing.TB, s *Stack) *routeFixtures {
	tb.Helper()
	adm := s.AdminSession(tb)
	fx := &routeFixtures{leaf: s.NewLeaf(tb, "sec-route"), victim: s.NewLeaf(tb, "sec-route-victim"), cookie: adm.CookieValue(tb)}
	var wt struct {
		Token string `json:"token"`
	}
	r := adm.Do(tb, http.MethodPost, "/dashboard/api/worker-tokens", map[string]any{"name": "sec-route-wwt", "proxyID": "sec-route-wwt"})
	if r.Status != http.StatusCreated || json.Unmarshal([]byte(r.Body), &wt) != nil || wt.Token == "" {
		tb.Fatalf("security: create a worker token: %d", r.Status)
	}
	fx.wwt = wt.Token
	s.Track("worker token", fx.wwt)

	var ak struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	r = adm.Do(tb, http.MethodPost, "/dashboard/api/api-keys", map[string]any{"name": "sec-route-key", "scopes": []string{"policy:read"}})
	if r.Status != http.StatusCreated || json.Unmarshal([]byte(r.Body), &ak) != nil || ak.Key == "" {
		tb.Fatalf("security: create an API key: %d", r.Status)
	}
	fx.wak, fx.wakID = ak.Key, ak.ID
	s.Track("api key", fx.wak)

	// A live enrollment token the revoke attack aims at, and a secret the
	// delete and read attacks aim at.
	s.TrackToken(adm.CreateEnrollmentTokenWith(tb, map[string]any{"name": "sec-route-target", "workerId": "sec-route-target"}))
	fx.enrollmentID = s.EnrollRowByName(tb, "sec-route-target").ID
	if r := adm.Do(tb, http.MethodPost, "/central/secrets", map[string]string{"key": routeCanaryKey, "value": routeCanaryValue}); r.Status != http.StatusNoContent {
		tb.Fatalf("security: plant a secret: %d %s", r.Status, r.Body)
	}
	s.Track("secret value", routeCanaryValue)

	fx.agentKey = fakes.NewAgentKey(tb, "attacker-key-1")
	fx.agent = s.RegisterAgent(tb, "agent-a", fakes.NewAgentKey(tb, "agent-a-key-1"), "eng")
	return fx
}

// client is the HTTP client of a credential and the headers it adds.
func (fx *routeFixtures) client(tb testing.TB, s *Stack, cred string) (*http.Client, http.Header) {
	tb.Helper()
	h := http.Header{}
	switch cred {
	case credCert:
		cert := fx.leaf.TLS()
		return s.CPClient(tb, &cert), h
	case credWWT:
		h.Set("Authorization", "Bearer "+fx.wwt)
	case credWAK:
		h.Set("Authorization", "Bearer "+fx.wak)
	case credCookie:
		h.Set("Cookie", consoleSessionCookie+"="+fx.cookie)
	}
	return s.CPClient(tb, nil), h
}

// send sends one request with the credential cred.
func (fx *routeFixtures) send(tb testing.TB, s *Stack, cred, method, path string, hdr http.Header, body []byte) Reply {
	tb.Helper()
	cl, h := fx.client(tb, s, cred)
	for k, v := range hdr {
		h[k] = v
	}
	return s.Send(tb, cl, method, path, h, body)
}

// awaitKeys waits until the API key index is current again. The index goes
// stale by the shared fake clock when a case moves it; its own loop refreshes
// it on the next tick, so a key request must not race that.
func (fx *routeFixtures) awaitKeys(tb testing.TB, s *Stack) {
	tb.Helper()
	s.Eventually("the API key index to be fresh", func() bool {
		return fx.send(tb, s, credWAK, http.MethodGet, "/dashboard/api/api-keys/self", nil, nil).Status == http.StatusOK
	})
}

// resources is what an attack on the admin API could create, revoke or delete:
// the certificates, enrollment tokens and audit rows, and the number of worker
// tokens, enrollment tokens, agents, API keys and secrets the console lists.
type resources struct {
	State
	lens map[string]int
}

var resourceLists = []string{
	"/dashboard/api/worker-tokens", "/dashboard/api/worker-enrollments", "/dashboard/api/agents", "/dashboard/api/api-keys", "/central/secrets",
}

func (s *Stack) resources(tb testing.TB) resources {
	tb.Helper()
	adm := s.AdminSession(tb)
	out := resources{State: s.State(tb), lens: map[string]int{}}
	for _, p := range resourceLists {
		r := adm.Do(tb, http.MethodGet, p, nil)
		if r.Status != http.StatusOK {
			tb.Fatalf("security: GET %s as the admin = %d", p, r.Status)
		}
		out.lens[p] = listLen(tb, r.Body)
	}
	return out
}

// listLen is the length of a JSON array, or of the first array member of an object.
func listLen(tb testing.TB, body string) int {
	tb.Helper()
	var arr []json.RawMessage
	if json.Unmarshal([]byte(body), &arr) == nil {
		return len(arr)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		tb.Fatalf("security: a console list is neither an array nor an object: %s", tail(body, 80))
	}
	for _, v := range obj {
		if json.Unmarshal(v, &arr) == nil {
			return len(arr)
		}
	}
	return 0
}

// humanRoute is a route only a console session may use. action is the audit
// action of a write ("" for a read), need what a policy:read key is told it
// lacks, and body what a bypass would act on.
type humanRoute struct {
	method, path, action, need string
	body                       func() any
}

func humanRoutes(fx *routeFixtures) []humanRoute {
	return []humanRoute{
		{http.MethodGet, "/central/secrets", "", `"error":"insufficient_scope","need":"none"`, nil},
		{http.MethodPost, "/central/secrets", "secrets.write", `"error":"insufficient_scope","need":"none"`, func() any { return map[string]string{"key": "attacker-key", "value": "attacker-value-7c3d"} }},
		{http.MethodGet, "/central/secrets/" + routeCanaryKey, "", `"error":"insufficient_scope","need":"none"`, nil},
		{http.MethodPut, "/central/secrets", "", `"error":"insufficient_scope","need":"none"`, func() any { return map[string]string{"key": routeCanaryKey, "value": "attacker-value-7c3d"} }},
		{http.MethodPatch, "/central/secrets", "", `"error":"insufficient_scope","need":"none"`, func() any { return map[string]string{"key": routeCanaryKey, "value": "attacker-value-7c3d"} }},
		{http.MethodDelete, "/central/secrets/" + routeCanaryKey, "secrets.delete", `"error":"insufficient_scope","need":"none"`, nil},
		{http.MethodGet, "/dashboard/api/worker-enrollments", "", `"error":"insufficient_scope","need":"workers:admin"`, nil},
		{http.MethodPost, "/dashboard/api/worker-enrollments", "worker_enroll_token.create", `"error":"insufficient_scope","need":"none"`, func() any { return map[string]string{"name": "attacker", "workerId": "attacker"} }},
		{http.MethodDelete, "/dashboard/api/worker-enrollments/" + fx.enrollmentID, "worker_enroll_token.revoke", `"error":"insufficient_scope","need":"workers:admin"`, nil},
		{http.MethodGet, "/dashboard/api/worker-tokens", "", `"error":"insufficient_scope","need":"none"`, nil},
		{http.MethodPost, "/dashboard/api/worker-tokens", "worker_token.create", `"error":"insufficient_scope","need":"none"`, func() any { return map[string]string{"name": "attacker", "proxyID": "attacker"} }},
		{http.MethodGet, "/dashboard/api/agents", "", `"error":"insufficient_scope","need":"agents:read"`, nil},
		{http.MethodPost, "/dashboard/api/agents", "agent.create", `"error":"insufficient_scope","need":"agents:write"`, func() any {
			return map[string]any{"id": "attacker-agent", "displayName": "x", "keys": []json.RawMessage{fx.agentKey.JWK()}}
		}},
		{http.MethodPost, "/dashboard/api/workers/sec-route-victim/revoke", "worker.revoked", `"error":"insufficient_scope","need":"workers:admin"`, func() any { return map[string]any{} }},
		{http.MethodGet, "/dashboard/api/api-keys", "", `"error":"insufficient_scope","need":"none"`, nil},
		{http.MethodPost, "/dashboard/api/api-keys", "api_key.create", `"error":"session_required"`, func() any { return map[string]any{"name": "attacker", "scopes": []string{"policy:read"}} }},
		{http.MethodGet, "/dashboard/api/unlisted", "", `"error":"forbidden"`, nil},
	}
}

func jsonBody(tb testing.TB, f func() any) []byte {
	tb.Helper()
	if f == nil {
		return nil
	}
	b, err := json.Marshal(f())
	if err != nil {
		tb.Fatalf("security: encode a request body: %v", err)
	}
	return b
}

// humanCase is the attack of credential cred on a human route.
func humanCase(fx *routeFixtures, cred string, r humanRoute) Case {
	c := Case{
		Name: cred + " " + r.method + " " + strings.ReplaceAll(strings.ReplaceAll(r.path, fx.enrollmentID, "{id}"), "/", "."),
		Path: PathCPRoute,
	}
	if cred == credWAK {
		// A valid key reaches the authorization check and is refused there.
		c.WantStatus = http.StatusForbidden
		c.WantBody = r.need
	} else {
		// No principal: the request reaches the same check and is refused as
		// unauthenticated, never redirected and never answered with data.
		c.WantStatus = http.StatusUnauthorized
		c.WantBody = `"error":"unauthenticated"`
	}
	wantAudit := 0
	if cred == credWAK && r.action != "" {
		wantAudit = 1
	}
	logSub := `"sub":""`
	if cred == credWAK {
		logSub = `"sub":"apikey:` + fx.wakID + `"`
	}
	c.WantLog = logSub + `,"method":"` + r.method + `","path":"` + r.path + `"}`
	c.Attack = func(t testing.TB, s *Stack) Observed {
		if cred == credWAK {
			// A key's rate bucket refills with the shared fake clock only.
			s.Clock.Advance(time.Second)
			fx.awaitKeys(t, s)
		}
		before, mark := s.resources(t), s.AuditMark(t)
		keyDenied := s.Server().APIKeyAuthCounts()[controlplane.APIKeyOutcomeInsufficientScope]
		rep := fx.send(t, s, cred, r.method, r.path, http.Header{"Content-Type": {"application/json"}}, jsonBody(t, r.body))
		after := s.resources(t)

		// No certificate, token, key, agent or secret was created, revoked or
		// deleted, and only the denied key write is on the audit trail.
		if after.Audit-before.Audit != wantAudit {
			t.Errorf("audit rows moved by %d, want %d", after.Audit-before.Audit, wantAudit)
		}
		after.Audit, before.Audit = 0, 0
		if after.State != before.State {
			t.Errorf("CP state moved by the attack: %+v -> %+v", before.State, after.State)
		}
		for p, n := range before.lens {
			if after.lens[p] != n {
				t.Errorf("%s lists %d entries after the attack, want %d", p, after.lens[p], n)
			}
		}
		if wantAudit == 1 {
			for _, row := range s.ExpectAudit(t, mark, "denied", r.action) {
				if row.HTTPStatus != http.StatusForbidden {
					t.Errorf("audit row %s has status %d, want 403", r.action, row.HTTPStatus)
				}
			}
		} else {
			s.ExpectAudit(t, mark, "")
		}
		if cred == credWAK {
			// A route the table does not list is refused as forbidden before
			// any scope is weighed, so only the listed routes count a scope refusal.
			want := int64(1)
			if strings.Contains(r.need, "forbidden") {
				want = 0
			}
			if d := s.Server().APIKeyAuthCounts()[controlplane.APIKeyOutcomeInsufficientScope] - keyDenied; d != want {
				t.Errorf("warden_cp_apikey_auth_total{outcome=insufficient_scope} rose by %d, want %d", d, want)
			}
		}
		for _, secret := range []string{routeCanaryKey, routeCanaryValue} {
			if strings.Contains(rep.Body, secret) {
				t.Errorf("the refusal carries the secret store's data (%s)", secret)
			}
		}
		return SeenReply(rep)
	}
	return c
}

// workerRoute is a route workers call.
type workerRoute struct {
	method, path string
	bundle       bool
}

var boundaryWorkerRoutes = []workerRoute{
	{http.MethodGet, "/policy", true},
	{http.MethodPost, "/control/heartbeat", false},
	{http.MethodPost, "/central/ingest", false},
	{http.MethodPost, "/control/renew", false},
}

// workerCase is the attack of a credential that is not a worker's on a worker
// route; reason is the CP's rejection reason.
func workerCase(fx *routeFixtures, cred string, r workerRoute, reason string) Case {
	return Case{
		Name: cred + " " + r.method + " " + strings.ReplaceAll(r.path, "/", "."),
		Path: PathCPRoute,
		Attack: func(t testing.TB, s *Stack) Observed {
			fresh(s)
			if cred == credWAK {
				fx.awaitKeys(t, s)
			}
			h := http.Header{"Content-Type": {"application/json"}}
			if r.bundle {
				h.Set("Accept", controlplane.BundleMediaType)
			}
			before := s.State(t)
			rep := fx.send(t, s, cred, r.method, r.path, h, []byte(`{}`))
			expectDelta(t, before, s.State(t), State{})
			return SeenReply(rep)
		},
		WantStatus: http.StatusUnauthorized,
		WantBody:   unauthorizedBody,
		WantHeader: map[string]string{"Www-Authenticate": "Bearer"},
		WantLog:    `"reason":"` + reason + `"`,
	}
}

// tokenCase is the attack of a credential that is not an agent's on
// POST /oauth2/token. A bearer is refused outright, even next to a complete,
// valid exchange form; a cookie or certificate is no client authentication.
func tokenCase(fx *routeFixtures, cred string) Case {
	c := Case{Name: cred + " POST.oauth2.token", Path: PathCPRoute}
	bearer := cred == credWWT || cred == credWAK
	if bearer {
		c.WantStatus, c.WantBody, c.WantLog = http.StatusBadRequest, `"error_description":"authorization_header_not_allowed"`, `"reason":"authorization_header_not_allowed"`
	} else {
		c.WantStatus, c.WantBody, c.WantLog = http.StatusUnauthorized, `"error":"invalid_client"`, `"reason":"client_authentication_failed"`
	}
	c.Attack = func(t testing.TB, s *Stack) Observed {
		fresh(s)
		form := s.ExchangeForm(fx.agent, s.UserToken("route-user", []string{"eng"}), nil)
		if !bearer {
			form.Del("client_assertion")
			form.Del("client_assertion_type")
		}
		issuedBefore := issuedTokens(s.TokenEvents(t))
		rep := fx.send(t, s, cred, http.MethodPost, tokenPath, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
		if n := issuedTokens(s.TokenEvents(t)); n != issuedBefore {
			t.Errorf("token_events holds %d issued rows after the attack, want %d", n, issuedBefore)
		}
		if strings.Contains(rep.Body, "access_token") {
			t.Error("the refusal carries an access token")
		}
		return SeenReply(rep)
	}
	return c
}

// tokenFormCase is the attack of a wwt_ token or wak_ key smuggled into the
// form of POST /oauth2/token as the client secret or the client assertion, with
// no Authorization header at all: it authenticates no agent.
func tokenFormCase(fx *routeFixtures, cred, field string) Case {
	return Case{
		Name:       cred + " POST.oauth2.token form " + field,
		Path:       PathCPRoute,
		WantStatus: http.StatusUnauthorized,
		WantBody:   `"error":"invalid_client"`,
		WantLog:    `"reason":"client_authentication_failed"`,
		Attack: func(t testing.TB, s *Stack) Observed {
			fresh(s)
			form := s.ExchangeForm(fx.agent, s.UserToken("route-user", []string{"eng"}), nil)
			form.Del("client_assertion")
			form.Del("client_assertion_type")
			secret := fx.wwt
			if cred == credWAK {
				secret = fx.wak
			}
			form.Set(field, secret)
			issuedBefore := issuedTokens(s.TokenEvents(t))
			rep := s.PostToken(t, form)
			if n := issuedTokens(s.TokenEvents(t)); n != issuedBefore {
				t.Errorf("token_events holds %d issued rows after the attack, want %d", n, issuedBefore)
			}
			if strings.Contains(rep.Body, "access_token") {
				t.Error("the refusal carries an access token")
			}
			return SeenReply(rep)
		},
	}
}

func issuedTokens(rows []TokenEvent) int {
	n := 0
	for _, r := range rows {
		if r.Outcome == "issued" {
			n++
		}
	}
	return n
}

// routeCases are the attacks of the four credentials on the routes of the
// others. wwtReason and cookieReason are what the CP logs for a wwt_ token and
// a console cookie on a worker route in the stack's worker auth mode.
func routeCases(fx *routeFixtures, wwtReason, cookieReason string, humanToo bool) []Case {
	var out []Case
	// Human routes: a worker certificate and a wwt_ token are no principal, a
	// valid API key is one whose scopes do not reach them.
	for _, cred := range []string{credCert, credWWT, credWAK} {
		for _, r := range humanRoutes(fx) {
			if humanToo {
				out = append(out, humanCase(fx, cred, r))
			}
		}
	}
	// Worker routes: an API key and a console cookie are not worker
	// credentials. (A wwt_ token and a certificate are, so the wwt_ token is
	// refused only where a certificate is the only way in.)
	for _, r := range boundaryWorkerRoutes {
		reason := func(r workerRoute, want string) string {
			if r.path == "/control/renew" {
				return "cert_required"
			}
			return want
		}
		out = append(out, workerCase(fx, credWAK, r, reason(r, "api_key_bearer")))
		out = append(out, workerCase(fx, credCookie, r, reason(r, cookieReason)))
		if r.path == "/control/renew" || wwtReason != "" {
			out = append(out, workerCase(fx, credWWT, r, reason(r, wwtReason)))
		}
	}
	// The token endpoint is the agents' route.
	for _, cred := range []string{credWWT, credWAK, credCookie, credCert} {
		out = append(out, tokenCase(fx, cred))
	}
	for _, cred := range []string{credWWT, credWAK} {
		for _, field := range []string{"client_secret", "client_assertion"} {
			out = append(out, tokenFormCase(fx, cred, field))
		}
	}
	return out
}

// routeControls are the positive controls of the category: every credential
// does what it is for, so the refusals above are the routes' and not the stack's.
func routeControls(t *testing.T, s *Stack, fx *routeFixtures, wwtWorks bool) {
	t.Helper()
	bundle := http.Header{"Accept": {controlplane.BundleMediaType}}
	expect := func(cred, method, path string, hdr http.Header, want int) Reply {
		t.Helper()
		r := fx.send(t, s, cred, method, path, hdr, []byte(`{}`))
		if r.Status != want {
			t.Fatalf("%s %s %s = %d, want %d: %s", cred, method, path, r.Status, want, tail(r.Body, 120))
		}
		return r
	}
	expect(credCert, http.MethodGet, "/policy", bundle, http.StatusOK)
	expect(credCert, http.MethodPost, "/control/heartbeat", nil, http.StatusNoContent)
	expect(credCert, http.MethodPost, "/central/ingest", nil, http.StatusNoContent)
	if wwtWorks {
		expect(credWWT, http.MethodGet, "/policy", bundle, http.StatusOK)
		expect(credWWT, http.MethodPost, "/control/heartbeat", nil, http.StatusNoContent)
		expect(credWWT, http.MethodPost, "/central/ingest", nil, http.StatusNoContent)
	}
	fx.awaitKeys(t, s)
	expect(credWAK, http.MethodGet, "/dashboard/api/policy", nil, http.StatusOK)
	r := expect(credCookie, http.MethodGet, "/central/secrets", nil, http.StatusOK)
	if !strings.Contains(r.Body, routeCanaryKey) {
		t.Fatalf("GET /central/secrets as the admin does not list the planted secret: %s", tail(r.Body, 120))
	}
	expect(credCookie, http.MethodGet, "/dashboard/api/worker-tokens", nil, http.StatusOK)
	// The token endpoint serves an agent: the same form, without a bearer.
	if rep, tok := s.Exchange(t, fx.agent, s.UserToken("route-user", []string{"eng"}), nil); tok == "" {
		t.Fatalf("POST /oauth2/token with a valid exchange = %d %s, want a token", rep.Status, rep.Body)
	}
}

// TestRouteBoundary runs the four credentials against the routes of the others
// on the stack where a wwt_ token and a certificate both open the worker routes
// (--require-worker-tokens), which is the only mode a wwt_ token has a route of
// its own to be refused everywhere else.
func TestRouteBoundary(t *testing.T) {
	s := StartStack(t, StackOptions{WorkerTokens: true, APIKeys: true, EchoSecretStore: true})
	fx := newRouteFixtures(t, s)
	s.PositiveControl(t, "cp-route", func(t *testing.T) { routeControls(t, s, fx, true) })
	Run(t, s, "cp-route", routeCases(fx, "", "worker_token_required", true))
}

// TestRouteBoundary_StrictCerts is the worker-route half for the shipped
// strict-certs mode, where a wwt_ token is refused on the worker routes too
// (the human routes do not depend on the worker auth mode).
func TestRouteBoundary_StrictCerts(t *testing.T) {
	s := StartStack(t, StackOptions{APIKeys: true, EchoSecretStore: true})
	fx := newRouteFixtures(t, s)
	s.PositiveControl(t, "cp-route", func(t *testing.T) { routeControls(t, s, fx, false) })
	Run(t, s, "cp-route", routeCases(fx, "worker_cert_required", "worker_cert_required", false))
}
