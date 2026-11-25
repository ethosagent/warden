package security

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The actors of a case: the admin who registers agents and mints enrollment
// tokens through the console API, the agent that exchanges a user's token at
// the token endpoint, and the client that sends traffic through a worker.

const (
	consoleSessionCookie = "__Host-warden_console"
	tokenPath            = "/oauth2/token"
	agentsPath           = "/dashboard/api/agents"
	enrollmentsPath      = "/dashboard/api/worker-enrollments"

	grantTypeExchange  = "urn:ietf:params:oauth:grant-type:token-exchange"
	assertionTypeJWT   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	subjectTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
)

// TokenAudience is the audience a client assertion names: tokenService.issuer
// plus the token path.
const TokenAudience = TokenIssuer + tokenPath

// Session is a signed-in console user: a browser with a cookie jar and the
// session's CSRF token.
type Session struct {
	s    *Stack
	cl   *http.Client
	csrf string
}

// AdminSession signs an admin in through the console OIDC login against the
// issuer fake and returns the session. It is cached: one admin per stack.
func (s *Stack) AdminSession(tb testing.TB) *Session {
	tb.Helper()
	s.mu.Lock()
	cached := s.admin
	s.mu.Unlock()
	if cached != nil {
		return cached
	}
	sess := s.Login(tb, fakes.Valid("admin-1", "admin-1@example.com", ConsoleAdminGroup))
	s.mu.Lock()
	s.admin = sess
	s.mu.Unlock()
	return sess
}

// Login signs a console user in with the issuer's login claims set to login
// (fakes.Valid(sub, email, groups...)): a new browser, a new session.
func (s *Stack) Login(tb testing.TB, login fakes.MintOption) *Session {
	tb.Helper()
	cb, cl := s.loginAttempt(tb, login)
	var sc *http.Cookie
	for _, c := range cb.Cookies() {
		if c.Name == consoleSessionCookie {
			sc = c
		}
	}
	_ = cb.Body.Close()
	if cb.StatusCode != http.StatusFound || sc == nil {
		tb.Fatalf("security: /auth/callback = %d with a session cookie %t, want 302 and a cookie", cb.StatusCode, sc != nil)
	}
	s.tracker.add("console session", sc.Value)
	return &Session{s: s, cl: cl, csrf: controlplane.CSRFToken(sc.Value)}
}

// LoginAttempt is a console login whose callback may be refused: it returns
// the callback reply (status, headers, body) as the browser saw it. The
// issuer mints the ID token with login, so a wrong nonce or audience is an
// option away.
func (s *Stack) LoginAttempt(tb testing.TB, login ...fakes.MintOption) Reply {
	tb.Helper()
	cb, _ := s.loginAttempt(tb, login...)
	body, _ := io.ReadAll(io.LimitReader(cb.Body, 64<<10))
	_ = cb.Body.Close()
	for _, c := range cb.Cookies() {
		if c.Name == consoleSessionCookie {
			s.tracker.add("console session", c.Value)
		}
	}
	return Reply{Status: cb.StatusCode, Header: cb.Header, Body: string(body)}
}

// loginAttempt drives the OIDC login up to the callback and returns the
// callback's response (its body unread) and the browser client.
func (s *Stack) loginAttempt(tb testing.TB, login ...fakes.MintOption) (*http.Response, *http.Client) {
	tb.Helper()
	s.Issuer.SetLogin(login...)
	jar, err := cookiejar.New(nil)
	if err != nil {
		tb.Fatalf("security: cookie jar: %v", err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.CPCA.Pool(), MinVersion: tls.VersionTLS12}}
	tb.Cleanup(tr.CloseIdleConnections)
	cl := harness.NewLoopbackClient(tr, harness.ClientOptions{Jar: jar, Timeout: 30 * time.Second})
	getRaw := func(target string) *http.Response {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			tb.Fatalf("security: build request: %v", err)
		}
		resp, err := cl.Do(req)
		if err != nil {
			tb.Fatalf("security: GET %s: %v", urlPath(target), err)
		}
		return resp
	}
	get := func(target string) *http.Response {
		resp := getRaw(target)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	// The CP discovers the issuer lazily; the callback answers 503 until it has.
	s.Eventually("the control plane to discover the OIDC issuer", func() bool {
		return get(s.CP.URL+"/auth/callback").StatusCode != http.StatusServiceUnavailable
	})
	resp := get(s.CP.URL + "/auth/login?next=/dashboard/")
	if resp.StatusCode != http.StatusFound {
		tb.Fatalf("security: /auth/login = %d, want 302", resp.StatusCode)
	}
	idp := get(resp.Header.Get("Location"))
	if idp.StatusCode != http.StatusFound {
		tb.Fatalf("security: the issuer's authorize endpoint = %d, want 302", idp.StatusCode)
	}
	return getRaw(idp.Header.Get("Location")), cl
}

// Reply is an HTTP reply a helper read in full.
type Reply struct {
	Status int
	Header http.Header
	Body   string
}

// Do sends one console API request with the session cookie and the CSRF
// header. A non-nil body is sent as JSON.
func (c *Session) Do(tb testing.TB, method, path string, body any) Reply {
	tb.Helper()
	return c.DoWith(tb, method, path, body, nil)
}

// DoWith is Do with extra request headers (If-Match on an agent write).
func (c *Session) DoWith(tb testing.TB, method, path string, body any, hdr http.Header) Reply {
	tb.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			tb.Fatalf("security: encode the %s request: %v", path, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.s.CP.URL+path, rd)
	if err != nil {
		tb.Fatalf("security: build %s %s: %v", method, path, err)
	}
	req.Header.Set(controlplane.CSRFHeader, c.csrf)
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		tb.Fatalf("security: %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		tb.Fatalf("security: read %s %s: %v", method, path, err)
	}
	return Reply{Status: resp.StatusCode, Header: resp.Header, Body: string(out)}
}

// CreateEnrollmentToken mints a single-use wet_ enrollment token bound to
// workerID through POST /dashboard/api/worker-enrollments. The token is
// registered with the leak invariant before it is returned.
func (c *Session) CreateEnrollmentToken(tb testing.TB, workerID string) string {
	tb.Helper()
	return c.CreateEnrollmentTokenWith(tb, map[string]any{"name": "sec-" + workerID, "workerId": workerID})
}

// CreateEnrollmentTokenWith is CreateEnrollmentToken with an explicit request
// body (a prefix pool token, a short lifetime, several uses).
func (c *Session) CreateEnrollmentTokenWith(tb testing.TB, req map[string]any) string {
	tb.Helper()
	r := c.Do(tb, http.MethodPost, enrollmentsPath, req)
	var out struct {
		Token string `json:"token"`
	}
	if r.Status != http.StatusCreated || json.Unmarshal([]byte(r.Body), &out) != nil || !strings.HasPrefix(out.Token, "wet_") {
		tb.Fatalf("security: POST %s = %d (no wet_ token in the 201 body)", enrollmentsPath, r.Status)
	}
	c.s.tracker.add("enrollment token", out.Token)
	return out.Token
}

// Agent is a registered agent with the key it signs assertions with.
type Agent struct {
	ID  string
	Key *fakes.AgentKey
}

// RegisterAgent registers agent id with key and the allowed groups through
// POST /dashboard/api/agents, as an admin does, and returns it.
func (s *Stack) RegisterAgent(tb testing.TB, id string, key *fakes.AgentKey, groups ...string) *Agent {
	tb.Helper()
	r := s.AdminSession(tb).Do(tb, http.MethodPost, agentsPath, map[string]any{
		"id": id, "displayName": id, "keys": []json.RawMessage{key.JWK()}, "allowedGroups": groups,
	})
	if r.Status != http.StatusCreated {
		tb.Fatalf("security: POST %s for agent %s = %d %s", agentsPath, id, r.Status, r.Body)
	}
	a := &Agent{ID: id, Key: key}
	// Registering an agent publishes a new bundle; wait until the worker
	// enforces its mode again, probing without a request upstream.
	for _, w := range s.Workers {
		if w.AgentID == id {
			w := w
			mode := s.opts.IdentityMode
			if m := s.opts.AgentModes[id]; m != "" {
				mode = m
			}
			if mode != "challenge" && mode != "require" {
				// Only challenge and require refuse a credential-less CONNECT: in
				// attribute mode the worker is enforcing once it has counted a
				// verification.
				s.Eventually(w.Name+" to verify tokens in identity mode "+mode+" for registered agent "+id, func() bool {
					status := s.probeConnectWith(w, "Basic "+base64.StdEncoding.EncodeToString([]byte("session:not-a-jwt")))
					v, ok := s.TryMetric(w, "warden_identity_verify_total", map[string]string{"result": "invalid"})
					return status == http.StatusOK && ok && v > 0
				})
				continue
			}
			s.Eventually(w.Name+" to enforce identity mode "+mode+" for registered agent "+id, func() bool {
				return s.probeConnect(w) == http.StatusProxyAuthRequired
			})
		}
	}
	s.mu.Lock()
	if s.agents == nil {
		s.agents = map[string]*Agent{}
	}
	s.agents[id] = a
	s.mu.Unlock()
	return a
}

// UserToken mints an OIDC ID token the workers' and the token endpoint's
// identity block accept (audience warden, azp agent-harness), for sub with the
// given groups. opts then override anything (fakes.WithAlg, WithExp, ...).
func (s *Stack) UserToken(sub string, groups []string, opts ...fakes.MintOption) string {
	s.tb.Helper()
	all := []fakes.MintOption{
		fakes.Valid(sub, sub+"@example.com", groups...), fakes.WithAud(IdentityAudience), fakes.WithAZP(IdentityAZP),
	}
	tok := s.Issuer.Mint(append(all, opts...)...)
	s.tracker.add("user token", tok)
	return tok
}

// ExchangeForm is the form body of a token exchange for agent a over
// subjectToken, with a fresh assertion; extra values and assertion options
// then adjust it.
func (s *Stack) ExchangeForm(a *Agent, subjectToken string, extra url.Values, opts ...fakes.AssertionOption) url.Values {
	s.tb.Helper()
	assertion := a.Key.ClientAssertion(a.ID, TokenAudience, s.Clock.Now(), opts...)
	s.tracker.add("client assertion", assertion)
	f := url.Values{
		"grant_type":            {grantTypeExchange},
		"subject_token":         {subjectToken},
		"subject_token_type":    {subjectTypeIDToken},
		"client_assertion_type": {assertionTypeJWT},
		"client_assertion":      {assertion},
	}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// PostToken POSTs form to /oauth2/token exactly as given, with no credential
// besides the form.
func (s *Stack) PostToken(tb testing.TB, form url.Values) Reply {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.CP.URL+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("security: build the token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.CP.HTTP.Do(req)
	if err != nil {
		tb.Fatalf("security: POST %s: %v", tokenPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		tb.Fatalf("security: read the token reply: %v", err)
	}
	return Reply{Status: resp.StatusCode, Header: resp.Header, Body: string(out)}
}

// Exchange trades subjectToken for a Warden token as agent a. A fresh control
// plane has not published its first token signing key yet and answers 503
// temporarily_unavailable; Exchange advances the shared clock until it has
// (a condition, never a fixed advance) and returns the first answer that is
// not that 503. The access token, when issued, is registered with the leak
// invariant. It returns the reply and the access token ("" on refusal).
func (s *Stack) Exchange(tb testing.TB, a *Agent, subjectToken string, extra url.Values, opts ...fakes.AssertionOption) (Reply, string) {
	tb.Helper()
	var r Reply
	s.EventuallyAdvance("the token endpoint to stop answering 503 temporarily_unavailable", 10*time.Second, func() bool {
		r = s.PostToken(tb, s.ExchangeForm(a, subjectToken, extra, opts...))
		return r.Status != http.StatusServiceUnavailable
	})
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if r.Status == http.StatusOK && json.Unmarshal([]byte(r.Body), &out) == nil && out.AccessToken != "" {
		s.tracker.add("warden token", out.AccessToken)
		return r, out.AccessToken
	}
	return r, ""
}

// MintWardenToken is Exchange that requires success: the Warden token of user
// sub (in groups) for agent a.
func (s *Stack) MintWardenToken(tb testing.TB, a *Agent, sub string, groups ...string) string {
	tb.Helper()
	r, tok := s.Exchange(tb, a, s.UserToken(sub, groups), nil)
	if tok == "" {
		tb.Fatalf("security: the exchange for agent %s was refused: %d %s", a.ID, r.Status, r.Body)
	}
	return tok
}

// Transport is how traffic reaches the worker.
type Transport string

// The three transports every category of case runs over.
const (
	// TransportConnect is CONNECT with the token on Proxy-Authorization, then
	// a plain GET through the tunnel.
	TransportConnect Transport = "connect"
	// TransportTerminated is the same tunnel with the request also carrying
	// the token as X-Warden-Identity: the header the worker reads where it
	// terminates TLS.
	TransportTerminated Transport = "terminated"
	// TransportMCP is CONNECT, then a JSON-RPC POST the MCP gateway inspects.
	TransportMCP Transport = "mcp"
)

// Transports lists them for a case that runs over all three.
var Transports = []Transport{TransportConnect, TransportTerminated, TransportMCP}

// Request is one agent request through a worker. Token fills the credential
// the way the transport normally carries it; ConnectToken and HeaderToken
// override that per header for a case that attacks one of them (a conflict, a
// header-only token).
type Request struct {
	Transport Transport
	// Token is the credential: Proxy-Authorization on CONNECT, and for the
	// terminated transport X-Warden-Identity as well.
	Token string
	// ConnectToken and HeaderToken, when non-nil, replace the value Token
	// would have put in that header ("" sends the header empty, nil follows
	// Token).
	ConnectToken, HeaderToken *string
	// ProxyAuthorization, when set, is sent verbatim instead of the Basic
	// credential built from the token (a malformed scheme).
	ProxyAuthorization string
	// Host defaults to UpstreamHost.
	Host string
}

// Response is what the agent saw. Status is the status of the last reply the
// agent got: the CONNECT reply when the tunnel was refused, else the request's.
type Response struct {
	Status int
	Header http.Header
	Body   string
	// ConnectStatus, ConnectHeader and ConnectBody are the CONNECT reply.
	ConnectStatus int
	ConnectHeader http.Header
	ConnectBody   string
}

// Via is a Request over transport t carrying token.
func Via(t Transport, token string) Request { return Request{Transport: t, Token: token} }

// Do sends r through worker w and returns what the agent saw. The client is a
// raw CONNECT dialer, so a refusal keeps its status, headers and body instead
// of becoming a transport error. The request carries the swapped-secret
// placeholder, so an allowed request shows the swapped value at the upstream.
func (s *Stack) Do(tb testing.TB, w *Worker, r Request) Response {
	tb.Helper()
	host := r.Host
	if host == "" {
		host = UpstreamHost
	}
	conn, err := net.DialTimeout("tcp", w.ProxyAddr, 10*time.Second)
	if err != nil {
		tb.Fatalf("security: dial %s: %v", w.Name, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		tb.Fatalf("security: set a deadline: %v", err)
	}

	connectTok := r.Token
	if r.ConnectToken != nil {
		connectTok = *r.ConnectToken
	}
	var preamble strings.Builder
	preamble.WriteString("CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n")
	switch {
	case r.ProxyAuthorization != "":
		preamble.WriteString("Proxy-Authorization: " + r.ProxyAuthorization + "\r\n")
	case connectTok != "":
		preamble.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+connectTok)) + "\r\n")
	}
	preamble.WriteString("\r\n")
	if _, err := io.WriteString(conn, preamble.String()); err != nil {
		tb.Fatalf("security: write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	cresp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		tb.Fatalf("security: read the CONNECT reply: %v", err)
	}
	// A 2xx reply to CONNECT has no body, but net/http's reader does not know
	// that without the transport's special case and would read to EOF: only
	// a refusal's body is read.
	var cbody []byte
	if cresp.StatusCode != http.StatusOK {
		cbody, _ = io.ReadAll(io.LimitReader(cresp.Body, 64<<10))
		_ = cresp.Body.Close()
	}
	out := Response{
		Status: cresp.StatusCode, Header: cresp.Header, Body: string(cbody),
		ConnectStatus: cresp.StatusCode, ConnectHeader: cresp.Header, ConnectBody: string(cbody),
	}
	if cresp.StatusCode != http.StatusOK {
		return out
	}
	if br.Buffered() != 0 {
		tb.Fatalf("security: the proxy sent %d bytes after the CONNECT reply before the TLS handshake", br.Buffered())
	}

	pool := s.ProxyCA.Pool()
	if s.opts.NoCA {
		pool = s.UpstreamCA.Pool() // a raw tunnel: the client speaks TLS to the upstream itself
	}
	tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		tb.Fatalf("security: the worker's MITM handshake for %s failed: %v", host, err)
	}
	method, path, body := http.MethodGet, "/", []byte(nil)
	if r.Transport == TransportMCP {
		method, path = http.MethodPost, "/mcp"
		body = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		tb.Fatalf("security: build the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+SwappedPlaceholder)
	req.Header.Set("Connection", "close")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if hdr := headerToken(r); hdr != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+hdr)
	}
	if err := req.Write(tc); err != nil {
		tb.Fatalf("security: write the request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		tb.Fatalf("security: read the response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rbody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out.Status, out.Header, out.Body = resp.StatusCode, resp.Header, string(rbody)
	return out
}

// headerToken is the X-Warden-Identity value of r ("" = no header).
func headerToken(r Request) string {
	if r.HeaderToken != nil {
		return *r.HeaderToken
	}
	if r.Transport == TransportTerminated {
		return r.Token
	}
	return ""
}

// Str is a *string literal helper for Request.ConnectToken and HeaderToken.
func Str(v string) *string { return &v }

func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	return u.Path
}

// Credential loads the worker's enrolled client certificate and key from its
// state dir, as a tls.Certificate a case can present to the control plane. The
// key PEM is registered with the leak invariant.
func (s *Stack) Credential(tb testing.TB, w *Worker) tls.Certificate {
	tb.Helper()
	dir := filepath.Join(w.StateDir, "cert")
	certPEM, err := os.ReadFile(filepath.Join(dir, "worker-cert.pem"))
	if err != nil {
		tb.Fatalf("security: read %s certificate: %v", w.Name, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "worker-key.pem"))
	if err != nil {
		tb.Fatalf("security: read %s key: %v", w.Name, err)
	}
	s.tracker.add("key PEM", string(keyPEM))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		tb.Fatalf("security: load %s credential: %v", w.Name, err)
	}
	return cert
}

// CPClient is an HTTP client for the control plane that trusts its CA and
// presents cert in the handshake (nil: no client certificate).
func (s *Stack) CPClient(tb testing.TB, cert *tls.Certificate) *http.Client {
	tb.Helper()
	cfg := &tls.Config{RootCAs: s.CPCA.Pool(), MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	tr := &http.Transport{TLSClientConfig: cfg}
	tb.Cleanup(tr.CloseIdleConnections)
	return harness.NewLoopbackClient(tr, harness.ClientOptions{Timeout: 30 * time.Second})
}

// Send sends one request to the control plane through cl with the given
// headers and body and returns the reply in full.
func (s *Stack) Send(tb testing.TB, cl *http.Client, method, path string, hdr http.Header, body []byte) Reply {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, s.CP.URL+path, bytes.NewReader(body))
	if err != nil {
		tb.Fatalf("security: build %s %s: %v", method, path, err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := cl.Do(req)
	if err != nil {
		tb.Fatalf("security: %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		tb.Fatalf("security: read %s %s: %v", method, path, err)
	}
	return Reply{Status: resp.StatusCode, Header: resp.Header, Body: string(out)}
}

// FetchBundle GETs /policy as the worker w would: its certificate, and the
// bundle media type in Accept.
func (s *Stack) FetchBundle(tb testing.TB, w *Worker) Reply {
	tb.Helper()
	cert := s.Credential(tb, w)
	return s.Send(tb, s.CPClient(tb, &cert), http.MethodGet, "/policy", http.Header{"Accept": {controlplane.BundleMediaType}}, nil)
}

// exchangeAs posts a token exchange for agentID with a fresh signature by the
// registered key of that agent held in the stack. It exists for cases that only
// vary the subject token.
func (s *Stack) exchangeAs(tb testing.TB, agentID, subjectToken string) Reply {
	tb.Helper()
	a := s.agents[agentID]
	if a == nil {
		tb.Fatalf("security: agent %q is not registered through RegisterAgent", agentID)
	}
	r, _ := s.Exchange(tb, a, subjectToken, nil)
	return r
}

// UpstreamClient is an HTTP client that trusts the upstream CA, for a test that
// talks to the upstream directly (it should never be used by an attack case).
func (s *Stack) UpstreamClient(tb testing.TB) *http.Client {
	tb.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.UpstreamCA.Pool(), ServerName: UpstreamHost, MinVersion: tls.VersionTLS12}}
	tb.Cleanup(tr.CloseIdleConnections)
	return harness.NewLoopbackClient(tr, harness.ClientOptions{Timeout: 10 * time.Second, FollowRedirects: true})
}

// Agent returns the agent registered through RegisterAgent.
func (s *Stack) Agent(id string) *Agent {
	s.tb.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[id]
	if a == nil {
		s.tb.Fatalf("security: agent %q is not registered through RegisterAgent", id)
	}
	return a
}
