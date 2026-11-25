package controlplane

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/tokensvc"
	tokensvcsqlite "github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
	"github.com/ethosagent/warden/test/fakes"
)

// limitsEnv is the real token service (limits, recorder, metrics) behind the
// real handler on a fake clock, with an in-process IdP and one registered agent.
type limitsEnv struct {
	*keysEnv
	iss     *fakes.OIDCIssuer
	ts      *tokenService
	h       http.Handler
	logs    *syncBuf
	agent   *signer.LocalSigner
	agentID string
	kid     string
	// agents, tokenCfg and idCfg let a test rebuild the service over the same
	// state (a restart).
	agents   *agentregsqlite.Store
	tokenCfg config.TokenServiceConfig
	idCfg    config.IdentitySettings
}

const (
	limitsGroup = "grp-canary-eng"
	limitsAZP   = "agent-harness"
)

func newLimitsEnv(t *testing.T, tune func(*config.TokenServiceConfig), proxies ...string) *limitsEnv {
	t.Helper()
	e := &limitsEnv{keysEnv: newKeysEnv(t, keysEnvOpts{tokens: true}), logs: &syncBuf{}, agentID: "agent-a", kid: "a-key"}
	e.iss = fakes.NewOIDCIssuer(t)
	logger := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	db := e.srv.cfg.State
	agents := agentregsqlite.New(db, agentregsqlite.WithClock(e.clk))
	tc := config.DefaultTokenService()
	tc.Enabled, tc.Issuer = true, testTokenIssuer
	if tune != nil {
		tune(&tc)
	}
	id := config.IdentitySettings{Issuer: e.iss.Issuer(), InternalIssuerURL: e.iss.Issuer(), Audience: "warden", AllowedAZP: []string{limitsAZP}}
	ts, err := newTokenService(tc, id, db, agents, e.srv, e.mgr, e.clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	e.ts, e.agents, e.tokenCfg, e.idCfg = ts, agents, tc, id
	e.srv.cfg.Logger = logger
	e.srv.cfg.Console.TrustedProxies = proxies
	e.srv.EnableTokens(ts.Service, tc.Issuer, ts.Edge)

	e.agent, err = signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := json.Marshal(map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": e.kid,
		"x": base64.RawURLEncoding.EncodeToString(e.agent.Public().(ed25519.PublicKey))})
	if _, err := agents.Create(context.Background(), agentreg.Agent{
		ID: e.agentID, Keys: []agentreg.Key{{KID: e.kid, JWK: jwk}}, AllowedGroups: []string{limitsGroup}, AllowedScopes: []string{"read"},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(tokenKeyPublishWindow + time.Second)
	e.h = e.srv.Handler()
	// No JWT-shaped string (every JWS starts with eyJ) reaches a log or the
	// admin audit trail, in any test on this environment.
	t.Cleanup(func() {
		sinks := map[string]string{"token service log": e.logs.String(), "key manager log": e.klog.String()}
		for i, in := range e.rec.inputs() {
			b, _ := json.Marshal(in)
			sinks["admin audit row "+strconv.Itoa(i)] = string(b)
		}
		for name, text := range sinks {
			if strings.Contains(text, "eyJ") {
				t.Errorf("the %s holds a JWT-shaped string (eyJ)", name)
			}
		}
	})
	return e
}

// subject mints an ID token for sub in groups, valid for 30 minutes of the
// fake clock.
func (e *limitsEnv) subject(sub string, groups ...string) string {
	return e.iss.Mint(fakes.WithAud("warden"), fakes.WithAZP(limitsAZP), fakes.Valid(sub, sub+"@example.com", groups...),
		fakes.WithIAT(e.clk.Now()), fakes.WithExp(e.clk.Now().Add(30*time.Minute)))
}

// assertion signs a client assertion for iss; kid overrides the header kid.
func (e *limitsEnv) assertion(t *testing.T, iss, kid string) string {
	t.Helper()
	now := e.clk.Now().Unix()
	jti := make([]byte, 8)
	_, _ = rand.Read(jti)
	a, err := keys.SignCompact(context.Background(), e.agent, keys.Header{Alg: keys.AlgEdDSA, Kid: kid, Typ: "JWT"}, map[string]any{
		"iss": iss, "sub": iss, "aud": testTokenIssuer + "/oauth2/token", "iat": now, "exp": now + 60, "jti": hex.EncodeToString(jti),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *limitsEnv) form(subject, assertion string) url.Values {
	return url.Values{
		"grant_type": {grantTypeTokenExchange}, "subject_token": {subject}, "subject_token_type": {tokensvc.TokenTypeIDToken},
		"client_assertion_type": {clientAssertionJWT}, "client_assertion": {assertion},
	}
}

// post sends form from the peer address remote (host:port) with extra headers.
func (e *limitsEnv) post(form url.Values, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, tokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *limitsEnv) events(t *testing.T) []map[string]string {
	t.Helper()
	rows, err := e.srv.cfg.State.SQL().Query(`SELECT outcome, reason, agent_id, sub_hmac, sid, jti, kid, scope FROM token_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]string
	for rows.Next() {
		var o, r, a, s, sid, jti, kid, sc string
		if err := rows.Scan(&o, &r, &a, &s, &sid, &jti, &kid, &sc); err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]string{"outcome": o, "reason": r, "agent": a, "sub": s, "sid": sid, "jti": jti, "kid": kid, "scope": sc})
	}
	return out
}

func (e *limitsEnv) tokenLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(e.logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil && m["msg"] == "token_exchange" {
			out = append(out, m)
		}
	}
	return out
}

func (e *limitsEnv) warnLines(t *testing.T, reason string) int {
	t.Helper()
	var n int
	for _, ln := range strings.Split(e.logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil && m["msg"] == "token_exchange_unauthenticated" && m["reason"] == reason {
			n++
		}
	}
	return n
}

func mustStatus(t *testing.T, what string, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s = %d %s, want %d", what, rec.Code, rec.Body.String(), want)
	}
}

// TestTokenRateLimitForgedAgentNoDoS: 200 forged assertions that claim a real
// agent from one address are answered 401 until the per-IP limit (120/minute)
// and 429 after it, and the agent's own budget is never touched, so a genuine
// request from another address still succeeds.
func TestTokenRateLimitForgedAgentNoDoS(t *testing.T) {
	e := newLimitsEnv(t, nil)
	var unauth, throttled int
	for i := 0; i < 200; i++ {
		rec := e.post(e.form("x", e.assertion(t, e.agentID, "no-such-key")), "203.0.113.5:4000", nil)
		switch rec.Code {
		case http.StatusUnauthorized:
			unauth++
		case http.StatusTooManyRequests:
			throttled++
			if rec.Header().Get("Retry-After") == "" || decodeErr(t, rec).Error != "rate_limited" {
				t.Fatalf("429 without Retry-After or the rate_limited body: %v %s", rec.Header(), rec.Body.String())
			}
		default:
			t.Fatalf("forged request %d = %d", i, rec.Code)
		}
	}
	if unauth != 120 || throttled != 80 {
		t.Fatalf("forged flood: %d unauthorized, %d throttled; want 120 and 80", unauth, throttled)
	}
	rec := e.post(e.form(e.subject("user-1", limitsGroup), e.assertion(t, e.agentID, e.kid)), "198.51.100.9:4000", nil)
	mustStatus(t, "genuine request from another address", rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "access_token") {
		t.Fatal("no token for the genuine request")
	}
	if got := e.ts.Edge.Metrics.DeniedTotal(tokensvc.ReasonRateLimited); got != 80 {
		t.Errorf("rate_limited counter = %d, want 80", got)
	}
}

// TestTokenRateLimitKeyedSafely: X-Forwarded-For counts only from a trusted
// proxy, and then only the nearest hop the proxy chain vouches for; IPv6
// clients share a /64 budget.
func TestTokenRateLimitKeyedSafely(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	mk := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, tokenPath, nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	for _, c := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"direct peer", mk("203.0.113.5:1"), "203.0.113.5"},
		{"untrusted peer's XFF is ignored", mk("203.0.113.5:1", "1.2.3.4"), "203.0.113.5"},
		{"trusted proxy, one hop", mk("10.1.1.1:1", "198.51.100.7"), "198.51.100.7"},
		{"a client-supplied left hop is ignored", mk("10.1.1.1:1", "9.9.9.9, 198.51.100.7"), "198.51.100.7"},
		{"trusted hops are skipped", mk("10.1.1.1:1", "198.51.100.7, 10.2.2.2"), "198.51.100.7"},
		{"split headers", mk("10.1.1.1:1", "9.9.9.9", "198.51.100.7"), "198.51.100.7"},
		{"all hops trusted", mk("10.1.1.1:1", "10.3.3.3"), "10.1.1.1"},
		{"garbage hop stops the walk", mk("10.1.1.1:1", "198.51.100.7, not-an-ip"), "10.1.1.1"},
		{"no header from a trusted proxy", mk("10.1.1.1:1"), "10.1.1.1"},
		{"ipv4-mapped", mk("[::ffff:203.0.113.5]:1"), "203.0.113.5"},
		{"ipv6 /64", mk("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:1"), "2001:db8:1:2::/64"},
		{"same /64, other host bits", mk("[2001:db8:1:2:1:2:3:4]:1"), "2001:db8:1:2::/64"},
		{"not an ip", mk("pipe"), "-"},
	} {
		if got := tokenClientKey(c.req, trusted); got != c.want {
			t.Errorf("%s: key = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestTokenEventsRecorded: one issuance and one group_not_allowed denial each
// write one row and one warden.token.v1 line and no admin audit row; 100 bad
// signatures write no row, raise the bad_signature counter by 100 and log one
// warning per minute.
func TestTokenEventsRecorded(t *testing.T) {
	e := newLimitsEnv(t, nil)
	auditBefore := len(e.rec.inputs()) // key creation is audited at startup
	mustStatus(t, "issuance", e.post(e.form(e.subject("user-1", limitsGroup), e.assertion(t, e.agentID, e.kid)), "198.51.100.1:1", nil), http.StatusOK)
	mustStatus(t, "denial", e.post(e.form(e.subject("user-2", "other-group"), e.assertion(t, e.agentID, e.kid)), "198.51.100.1:1", nil), http.StatusBadRequest)

	for i := 0; i < 100; i++ {
		a := e.assertion(t, e.agentID, e.kid)
		mid := len(a) - 20
		flip := "A"
		if a[mid:mid+1] == "A" {
			flip = "B"
		}
		mustStatus(t, "bad signature", e.post(e.form("x", a[:mid]+flip+a[mid+1:]), "203.0.113.5:1", nil), http.StatusUnauthorized)
	}
	rows := e.events(t)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2: %v", len(rows), rows)
	}
	if rows[0]["outcome"] != "issued" || rows[0]["reason"] != "" || rows[0]["agent"] != "agent-a" || len(rows[0]["sub"]) != 64 || rows[0]["scope"] != "read" ||
		rows[1]["outcome"] != "denied" || rows[1]["reason"] != "group_not_allowed" || rows[1]["sid"] != "" {
		t.Errorf("rows = %v", rows)
	}
	lines := e.tokenLines(t)
	if len(lines) != 2 || lines[0]["schema"] != "warden.token.v1" || lines[0]["outcome"] != "issued" || lines[1]["reason"] != "group_not_allowed" ||
		lines[0]["sid"] != rows[0]["sid"] || lines[0]["jti"] != rows[0]["jti"] || lines[0]["kid"] != rows[0]["kid"] || lines[0]["sub"] != rows[0]["sub"] {
		t.Errorf("lines = %v", lines)
	}
	if got := e.ts.Edge.Metrics.DeniedTotal(tokensvc.ReasonBadSignature); got != 100 {
		t.Errorf("bad_signature = %d, want 100", got)
	}
	if got := e.ts.Edge.Metrics.IssuedTotal("agent-a"); got != 1 {
		t.Errorf("issued{agent-a} = %d, want 1", got)
	}
	if n := len(e.rec.inputs()); n != auditBefore {
		t.Errorf("admin audit grew from %d to %d rows: machine events stay out of the chain", auditBefore, n)
	}
	if n := e.warnLines(t, "bad_signature"); n != 1 {
		t.Errorf("%d warnings for 100 bad signatures from one address, want 1", n)
	}
	e.clk.Advance(61 * time.Second)
	mustStatus(t, "bad signature a minute later", e.post(e.form("x", e.assertion(t, e.agentID, "no-such-key")), "203.0.113.5:1", nil), http.StatusUnauthorized)
	e.post(e.form("x", func() string { a := e.assertion(t, e.agentID, e.kid); return a[:len(a)-30] + "AAAA" + a[len(a)-26:] }()), "203.0.113.5:1", nil)
	if n := e.warnLines(t, "bad_signature") + e.warnLines(t, "unknown_kid"); n < 2 {
		t.Errorf("%d warnings after the minute passed, want a new one", n)
	}
}

// TestTokenEventsNoLeak: the subject token, the client assertion, the issued
// token, an Authorization header and the group names appear in no row, log
// line or metric label, on success and on every kind of refusal.
func TestTokenEventsNoLeak(t *testing.T) {
	e := newLimitsEnv(t, nil)
	subject := e.subject("user-canary-sub", limitsGroup)
	assertion := e.assertion(t, e.agentID, e.kid)
	rec := e.post(e.form(subject, assertion), "198.51.100.1:1", nil)
	mustStatus(t, "issuance", rec, http.StatusOK)
	var issued struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil || issued.AccessToken == "" {
		t.Fatalf("issuance body: %v", err)
	}
	// Refusals that carry the secrets: a replay, a bearer on the endpoint, an
	// unknown agent, a forged assertion, a denial after authentication.
	e.post(e.form(subject, assertion), "198.51.100.1:1", nil)
	e.post(e.form(subject, e.assertion(t, e.agentID, e.kid)), "198.51.100.1:1", map[string]string{"Authorization": "Bearer canary-bearer-secret"})
	forgedAssertion := e.assertion(t, "ghost-canary-agent", e.kid)
	e.post(e.form(subject, forgedAssertion), "198.51.100.2:1", nil)
	e.post(e.form(e.subject("user-2", "elsewhere"), e.assertion(t, e.agentID, e.kid)), "198.51.100.1:1", nil)

	var stored strings.Builder
	for _, q := range []string{
		`SELECT outcome||reason||agent_id||sub_hmac||sid||jti||kid||scope FROM token_events`,
		`SELECT hex(salt) FROM token_event_salt`,
	} {
		rows, err := e.srv.cfg.State.SQL().Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			stored.WriteString(s)
		}
		_ = rows.Close()
	}
	m := e.ts.Edge.Metrics
	var labels strings.Builder
	for r := range m.DeniedSnapshot() {
		labels.WriteString(string(r) + "\n")
	}
	for a := range m.IssuedSnapshot() {
		labels.WriteString(a + "\n")
	}
	// The id an unauthenticated caller claims is logged as claimed_agent (the
	// #84 design) but is never a row or a label.
	for _, where := range []string{stored.String(), labels.String()} {
		if strings.Contains(where, "ghost-canary-agent") {
			t.Error("a claimed agent id reached a row or a label")
		}
	}
	for name, where := range map[string]string{"rows": stored.String(), "log": e.logs.String(), "labels": labels.String()} {
		for what, canary := range map[string]string{
			"subject token": subject, "client assertion": assertion, "issued token": issued.AccessToken,
			"forged assertion": forgedAssertion, "authorization header": "canary-bearer-secret",
			"group name": limitsGroup, "raw subject": "user-canary-sub",
		} {
			if strings.Contains(where, canary) {
				t.Errorf("the %s hold the %s", name, what)
			}
		}
	}
}

// TestTokenHandlerRateLimitedMapping: a rate_limited error of the service is a
// 429 with a whole-second Retry-After rounded up (RFC 6585).
func TestTokenHandlerRateLimitedMapping(t *testing.T) {
	fake := &fakeExchanger{err: &tokensvc.Error{Code: tokensvc.CodeRateLimited, Reason: tokensvc.ReasonRateLimited, AgentID: "agent-a", RetryAfter: 1500 * time.Millisecond, Verified: true}}
	e := newTokenEnv(t, fake)
	rec := e.postForm(validForm())
	mustStatus(t, "rate limited exchange", rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") != "2" || decodeErr(t, rec).Error != "rate_limited" {
		t.Errorf("headers %v body %s", rec.Header(), rec.Body.String())
	}
	requireTokenHeaders(t, rec)
	for d, want := range map[time.Duration]int{0: 1, time.Millisecond: 1, time.Second: 1, time.Second + 1: 2, 12 * time.Second: 12} {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%s) = %d, want %d", d, got, want)
		}
	}
}

// blockingExchanger holds every Exchange until released.
type blockingExchanger struct {
	in      chan struct{}
	release chan struct{}
}

func (b *blockingExchanger) Exchange(context.Context, tokensvc.ExchangeRequest) (*tokensvc.Issued, error) {
	b.in <- struct{}{}
	<-b.release
	return okIssued(), nil
}

// TestTokenInFlightCap: past maxInFlight concurrent requests the next one is a
// 429 with Retry-After before its body is read; a slot frees when a request
// ends.
func TestTokenInFlightCap(t *testing.T) {
	b := &blockingExchanger{in: make(chan struct{}, 4), release: make(chan struct{})}
	logger, _ := testLogger()
	cfg := detectionEditorConfig(t)
	cfg.Logger = logger
	cfg.Tokens, cfg.TokenIssuer = b, testTokenIssuer
	cfg.TokenEdge = TokenEdge{MaxInFlight: 2, Metrics: tokensvc.NewMetrics()}
	srv := New(cfg)
	t.Cleanup(func() {
		if srv.integrationsStore != nil {
			_ = srv.integrationsStore.Close()
		}
	})
	h := srv.Handler()
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, tokenPath, strings.NewReader(validForm().Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	var wg sync.WaitGroup
	done := make([]*httptest.ResponseRecorder, 2)
	for i := range done {
		wg.Add(1)
		go func() { defer wg.Done(); done[i] = send() }()
	}
	<-b.in
	<-b.in
	over := send()
	mustStatus(t, "request over the cap", over, http.StatusTooManyRequests)
	if over.Header().Get("Retry-After") != "1" || decodeErr(t, over).Error != "rate_limited" {
		t.Errorf("headers %v body %s", over.Header(), over.Body.String())
	}
	if got := cfg.TokenEdge.Metrics.DeniedTotal(tokensvc.ReasonRateLimited); got != 1 {
		t.Errorf("rate_limited counter = %d, want 1", got)
	}
	close(b.release)
	wg.Wait()
	for _, rec := range done {
		mustStatus(t, "request under the cap", rec, http.StatusOK)
	}
	b.in = make(chan struct{}, 4)
	mustStatus(t, "request after the slots freed", send(), http.StatusOK)
}

// TestTokenStalledBodyHoldsNoSlotPastTheDeadline: the read deadline is set
// before the in-flight slot is taken, so a client that trickles its body holds
// a slot for tokenReadTimeout at most.
func TestTokenStalledBodyHoldsNoSlotPastTheDeadline(t *testing.T) {
	old := tokenReadTimeout
	tokenReadTimeout = time.Second
	t.Cleanup(func() { tokenReadTimeout = old })
	fake := &fakeExchanger{issued: okIssued()}
	logger, _ := testLogger()
	cfg := detectionEditorConfig(t)
	cfg.Logger = logger
	cfg.Tokens, cfg.TokenIssuer = fake, testTokenIssuer
	cfg.TokenEdge = TokenEdge{MaxInFlight: 1}
	srv := New(cfg)
	t.Cleanup(func() {
		if srv.integrationsStore != nil {
			_ = srv.integrationsStore.Close()
		}
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	stalled, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stalled.Close() }()
	_, _ = stalled.Write([]byte("POST /oauth2/token HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\ngrant_type="))

	post := func() int {
		resp, err := http.Post(ts.URL+tokenPath, "application/x-www-form-urlencoded", strings.NewReader(validForm().Encode()))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// While the stalled body holds the only slot, others are turned away.
	deadline := time.Now().Add(5 * time.Second)
	for post() != http.StatusTooManyRequests {
		if time.Now().After(deadline) {
			t.Fatal("the stalled request never held the slot")
		}
	}
	// It is cut at the deadline and the slot frees.
	_ = stalled.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(stalled), nil)
	if err != nil {
		t.Fatalf("no response to the stalled body: %v", err)
	}
	_ = resp.Body.Close()
	for post() != http.StatusOK {
		if time.Now().After(deadline.Add(5 * time.Second)) {
			t.Fatal("the slot was never released")
		}
	}
}

// TestTokenRateParsersAgree: config cannot import policy, so
// config.validateTokenServiceRate repeats policy.ParseRateLimit's grammar; this
// pins one table of cases through both. A value the config accepts must parse
// with the policy parser (the control plane parses the config's own, trimmed,
// value), and one it refuses must not.
func TestTokenRateParsersAgree(t *testing.T) {
	cases := []string{
		"1/second", "120/minute", "3600/hour", "+5/minute", "0007/second", "300/minute",
		"0/minute", "-1/minute", "x/minute", "5/day", "5/Minute", "5/minutes", "5", "/minute", "5/", "5/minute/x",
		"5 /minute", "1.5/minute", "5//minute", "５/minute", "5/\u0000minute", "0x10/minute", "1_0/minute", "99999999999999999999/minute",
	}
	for _, in := range cases {
		path := writeConfigFile(t, fmt.Sprintf("tokenService:\n  rateLimit:\n    perAgent: %q\n", in))
		tc, cerr := config.LoadTokenService(path)
		rl, perr := policy.ParseRateLimit(in)
		if (cerr == nil) != (perr == nil) {
			t.Errorf("%q: config says %v, policy says %v", in, cerr, perr)
			continue
		}
		if cerr == nil {
			if got, err := policy.ParseRateLimit(tc.RateLimit.PerAgent); err != nil || got != rl {
				t.Errorf("%q: the control plane would parse %q to %+v, %v; want %+v", in, tc.RateLimit.PerAgent, got, err, rl)
			}
		}
	}
	// Surrounding blanks are the one deliberate difference: config trims what
	// the operator typed and hands the control plane the trimmed value.
	tc, err := config.LoadTokenService(writeConfigFile(t, "tokenService:\n  rateLimit:\n    perAgent: \" 5/minute \"\n"))
	if err != nil || tc.RateLimit.PerAgent != "5/minute" {
		t.Errorf("padded value: %q, %v; want it trimmed", tc.RateLimit.PerAgent, err)
	}
	for _, d := range []string{config.DefaultTokenServiceRatePerIP, config.DefaultTokenServiceRatePerAgent, config.DefaultTokenServiceRatePerUser} {
		if _, err := policy.ParseRateLimit(d); err != nil {
			t.Errorf("default %q does not parse: %v", d, err)
		}
	}
}

// TestSubjectLifetimeBound: the revoked-session retention is the identity max
// token TTL plus the clock skew, with the verifier's defaults when unset.
func TestSubjectLifetimeBound(t *testing.T) {
	if got := subjectLifetimeBound(config.IdentitySettings{}); got != identity.DefaultMaxTokenTTL+identity.DefaultClockSkew {
		t.Errorf("defaults: %s", got)
	}
	if got := subjectLifetimeBound(config.IdentitySettings{MaxTokenTTLSeconds: 7200, ClockSkewSeconds: 300}); got != 2*time.Hour+5*time.Minute {
		t.Errorf("configured: %s", got)
	}
}

// TestTokenRetentionPurge: Purge keeps a revoked session row until no subject
// token issued before the revoke can still verify, drops idle sessions, spent
// assertion records and old events, and runs on the control plane's clock from
// the retention loop.
func TestTokenRetentionPurge(t *testing.T) {
	ctx := context.Background()
	e := newKeysEnv(t, keysEnvOpts{tokens: true})
	db := e.srv.cfg.State
	sessions, replay, events := tokensvcsqlite.NewSessions(db), tokensvcsqlite.New(db), tokensvcsqlite.NewEvents(db, nil)
	logger, _ := testLogger()
	subjectMax := subjectLifetimeBound(config.IdentitySettings{})
	r := &TokenRetention{
		Sessions: sessions, Replay: replay, Events: events,
		SessionIdle: 12 * time.Hour, SubjectMax: subjectMax, EventRetention: 24 * time.Hour, Logger: logger,
	}
	t0 := e.clk.Now()
	pol := tokensvc.SessionPolicy{Idle: 12 * time.Hour, Absolute: 168 * time.Hour}
	touch := func(sub string) string {
		sid, err := sessions.Touch(ctx, tokensvc.SessionKey{IdPIss: "https://idp", Sub: sub, AgentID: "a"}, t0, t0, pol, "wts_"+sub)
		if err != nil {
			t.Fatal(err)
		}
		return sid
	}
	revokedSID, idleSID := touch("revoked"), touch("idle")
	if _, err := sessions.Revoke(ctx, revokedSID, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.Consume(ctx, "a", "hash", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := events.Record(ctx, tokensvc.Event{TS: t0, Outcome: tokensvc.OutcomeDenied, Reason: tokensvc.ReasonReplay, AgentID: "a"}); err != nil {
		t.Fatal(err)
	}
	count := func(table string) int {
		var n int
		if err := db.SQL().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Just inside the subject lifetime: the revoked row stays, so a subject
	// token issued before the revoke is still refused. The replay record is
	// spent; the live session is within its idle time and stays.
	r.Purge(ctx, t0.Add(subjectMax-time.Second))
	if count("token_sessions") != 2 || count("token_assertion_jti") != 0 || count("token_events") != 1 {
		t.Fatalf("inside the subject lifetime: sessions %d jti %d events %d, want 2 0 1", count("token_sessions"), count("token_assertion_jti"), count("token_events"))
	}
	if _, err := sessions.Touch(ctx, tokensvc.SessionKey{IdPIss: "https://idp", Sub: "revoked", AgentID: "a"}, t0.Add(-time.Minute), t0.Add(subjectMax-time.Second), pol, "wts_new"); err != tokensvc.ErrSessionRevoked {
		t.Fatalf("a subject token from before the revoke: %v, want ErrSessionRevoked", err)
	}
	// Past it the revoke row is no longer needed; the idle session still is.
	r.Purge(ctx, t0.Add(subjectMax+time.Second))
	if count("token_sessions") != 1 {
		t.Errorf("sessions after the subject lifetime = %d, want only the live one", count("token_sessions"))
	}
	// Past the idle time and the event retention everything else goes.
	r.Purge(ctx, t0.Add(25*time.Hour))
	if count("token_sessions") != 0 || count("token_events") != 0 {
		t.Errorf("sessions %d events %d after the retention, want 0 0", count("token_sessions"), count("token_events"))
	}
	_ = idleSID

	// The loop: once at start and then on the control plane's clock.
	if _, err := replay.Consume(ctx, "a", "hash2", e.clk.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.TokenEdge.Retention = r
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.srv.runTokenRetention(loopCtx)
	// Driven by condition: which timer is the loop's is not observable.
	waitFor(t, func() bool { e.clk.Advance(tokenRetentionInterval); return count("token_assertion_jti") == 0 })
}

// TestTokenStateMigrationsRegisterEvents: the events migration is known to the
// downgrade guard always and applied only with tokenService.enabled.
func TestTokenStateMigrationsRegisterEvents(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), stateMigrationsFor(config.KeysConfig{}, config.ConsoleConfig{}, config.TokenServiceConfig{Enabled: enabled}))
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('token_events','token_event_salt')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if want := map[bool]int{false: 0, true: 2}[enabled]; n != want {
			t.Errorf("enabled=%v: %d event tables, want %d", enabled, n, want)
		}
	}
}
