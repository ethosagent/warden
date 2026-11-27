package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
)

// These tests cover W-P3-PUL-09: the per-user rate limits held by
// policy.Evaluator are charged on every request, h2 stream and WebSocket
// upgrade by userLimitStage, once per raw tunnel at CONNECT, and only peeked
// at a TLS-terminated CONNECT. The verifier is fakes.Verifier (tok-alice and
// tok-bob are valid members of group eng; tok-bad is invalid).

const rateLimitedWant = `{"error":"user_rate_limited"}`

// limitEdit replaces the env's policy with idHost allowed plus the given
// per-user limit rules, and installs j as the judge when non-nil.
func limitEdit(pol config.Policy, j Judge, extra ...func(*Config)) func(*Config) {
	return func(c *Config) {
		if pol.Allowlist == nil {
			pol.Allowlist = []config.AllowlistEntry{{Domain: idHost, Port: 443}}
		}
		c.Policy = policy.NewEvaluator(pol)
		if j != nil {
			c.Judge = j
		}
		for _, f := range extra {
			f(c)
		}
	}
}

func engRule(rate string) config.UserLimit {
	return config.UserLimit{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: rate}
}

// assertRateLimited asserts a user_rate_limited 429 with an integer
// Retry-After of at least 1 and at most max seconds.
func assertRateLimited(t *testing.T, resp *http.Response, maxRetry int) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body %q)", resp.StatusCode, body)
	}
	if string(body) != rateLimitedWant || !json.Valid(body) {
		t.Errorf("body = %q, want %q", body, rateLimitedWant)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	ra := resp.Header.Get("Retry-After")
	n, err := strconv.Atoi(ra)
	if err != nil || n < 1 || n > maxRetry {
		t.Errorf("Retry-After = %q, want an integer in [1, %d]", ra, maxRetry)
	}
}

func limitDenies(st *syncStore) []analytics.Event {
	var out []analytics.Event
	for _, ev := range st.snapshot() {
		if ev.Decision == "deny" {
			out = append(out, ev)
		}
	}
	return out
}

// assertNoIdentityInMetrics fails if any recorded metric call carries a user's
// sub or email.
func assertNoIdentityInMetrics(t *testing.T, m *fakeMetrics, values ...string) {
	t.Helper()
	got := m.describe()
	for _, v := range values {
		if strings.Contains(got, v) {
			t.Errorf("metric calls carry %q:\n%s", v, got)
		}
	}
}

// Two users on one keep-alive tunnel, each with a per-request identity: only
// the user over the limit is refused, with 429 + Retry-After, and the refused
// request reaches neither the judge nor the upstream.
func TestUserLimit_RequestStage(t *testing.T) {
	j := &fakeJudge{verdict: Verdict{Decision: "allow"}}
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("2/hour")}}, j))
	c := e.h1("")
	alice, bob := "X-Warden-Identity: Bearer tok-alice\r\n", "X-Warden-Identity: Bearer tok-bob\r\n"
	for i, h := range []string{alice, alice, bob, bob} {
		if st := c.get(h); st != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, st)
		}
	}
	assertRateLimited(t, c.getResp(alice), 3600)
	if n := e.be.requests(); n != 4 {
		t.Errorf("upstream saw %d requests, want 4", n)
	}
	j.mu.Lock()
	calls := j.calls
	j.mu.Unlock()
	if calls != 0 {
		t.Errorf("judge calls = %d, want 0", calls)
	}
	// The refusal ends the h1 session (Connection: close).
	_ = c.tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.br.ReadByte(); err == nil {
		t.Error("connection still open after a user_rate_limited deny")
	}
	// Bob's budget is his own: his third request is refused on a new tunnel.
	assertRateLimited(t, e.h1("").getResp(bob), 3600)

	evs := waitEvents(t, e.store, 6)
	denies := limitDenies(e.store)
	if len(denies) != 2 {
		t.Fatalf("denies = %+v, want 2", denies)
	}
	d := denies[0]
	if d.Reason != string(denyreason.UserRateLimited) || d.UserSub != "alice" || d.LimitRule != "eng" ||
		d.AgentID != "agent" || d.Protocol != "https" || d.Domain != idHost {
		t.Errorf("deny event = %+v", d)
	}
	allows := 0
	for _, ev := range evs {
		if ev.Decision == "allow" {
			allows++
			if ev.LimitRule != "eng" {
				t.Errorf("allow event limit_rule = %q, want eng", ev.LimitRule)
			}
		}
	}
	if allows != 4 {
		t.Errorf("allow events = %d, want 4", allows)
	}
	if n := e.m.userLimitDenied("rate"); n != 2 {
		t.Errorf("user_limit.denied{kind=rate} = %d, want 2", n)
	}
	if n := e.m.blockedCount(string(denyreason.UserRateLimited)); n != 2 {
		t.Errorf("blocked{user_rate_limited} = %d, want 2", n)
	}
	assertNoIdentityInMetrics(t, e.m, "alice", "bob", "@example.test")
	if logs := e.logs.String(); !strings.Contains(logs, "limit_rule=eng") {
		t.Errorf("decision log has no limit_rule:\n%s", logs)
	}
}

// An h2 stream over the limit gets 429 on that stream; the connection's other
// streams (another user) go on.
func TestUserLimit_H2Stream(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("2/hour")}}, nil))
	cc := e.h2("")
	alice := map[string]string{"X-Warden-Identity": "Bearer tok-alice"}
	for i := 0; i < 2; i++ {
		if st := h2Get(t, cc, alice); st != http.StatusOK {
			t.Fatalf("stream %d status = %d", i, st)
		}
	}
	req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
	req.Header.Set("X-Warden-Identity", "Bearer tok-alice")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	assertRateLimited(t, resp, 3600)
	if st := h2Get(t, cc, map[string]string{"X-Warden-Identity": "Bearer tok-bob"}); st != http.StatusOK {
		t.Errorf("bob's stream on the same connection = %d, want 200", st)
	}
	if n := e.be.requests(); n != 3 {
		t.Errorf("upstream saw %d requests, want 3", n)
	}
	waitEvents(t, e.store, 4)
	if d := limitDenies(e.store); len(d) != 1 || d[0].Protocol != "http2" || d[0].LimitRule != "eng" || d[0].UserSub != "alice" {
		t.Errorf("denies = %+v", d)
	}
}

// A WebSocket upgrade is charged once per upgrade, never per frame.
func TestUserLimit_WebSocketUpgrade(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("1/hour")}}, nil))
	_, _, caCert, caKey := generateTestCA(t)
	b := &wsBackend{}
	ln := startWSBackend(t, caCert, caKey, b)
	inner := dialBackend(ln)
	var wsDials atomic.Int64
	e.p.dialTLS = func(n, a string, c *tls.Config) (*tls.Conn, error) {
		wsDials.Add(1)
		return inner(n, a, c)
	}
	upgrade := func() *http.Response {
		conn, br, status := e.connect("")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status = %q", status)
		}
		tc := e.tlsOver(conn, br, "http/1.1")
		_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"X-Warden-Identity: Bearer tok-alice\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := upgrade(); resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("first upgrade status = %d, want 101", resp.StatusCode)
	}
	assertRateLimited(t, upgrade(), 3600)
	if n := wsDials.Load(); n != 1 {
		t.Errorf("upstream dials = %d, want 1", n)
	}
}

// A raw tunnel (no CA) shows no requests: it is charged once at CONNECT,
// before the 200 and any dial, however many bytes it then carries.
func TestUserLimit_RawTunnelChargedOncePerConnect(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("2/hour")}}, nil, noCA))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	e.setRaw(func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) })
	auth := "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"
	for i := 0; i < 2; i++ {
		conn, br, status := e.connect(auth)
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT %d status = %q, want 200", i, status)
		}
		// Many writes through one tunnel cost nothing more.
		for k := 0; k < 3; k++ {
			_, _ = io.WriteString(conn, "ping")
			buf := make([]byte, 4)
			if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("echo = %q, %v", buf, err)
			}
		}
	}
	dialsBefore := e.dials.Load()
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+idHost+":443 HTTP/1.1\r\nHost: "+idHost+":443\r\n"+auth+"\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRateLimited(t, resp, 3600)
	if !resp.Close {
		t.Error("CONNECT refusal is not Connection: close")
	}
	if n := e.dials.Load(); n != dialsBefore {
		t.Errorf("dials after the refusal = %d, want %d", n, dialsBefore)
	}
	waitEvents(t, e.store, 3)
	var allows int
	for _, ev := range e.store.snapshot() {
		if ev.Decision == "allow" && ev.Protocol == "tcp" {
			allows++
			if ev.LimitRule != "eng" {
				t.Errorf("tunnel allow limit_rule = %q", ev.LimitRule)
			}
		}
	}
	if allows != 2 {
		t.Errorf("tunnel allow events = %d, want 2", allows)
	}
	if d := limitDenies(e.store); len(d) != 1 || d[0].Protocol != "tcp" || d[0].LimitRule != "eng" || d[0].UserSub != "alice" {
		t.Errorf("denies = %+v", d)
	}
}

// A TLS-terminated CONNECT only peeks: opening tunnels costs nothing, and a
// user whose bucket is exhausted is refused at CONNECT, before the 200.
func TestUserLimit_ConnectPeek(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("2/hour")}}, nil))
	auth := "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"
	var cs []*idH1
	for i := 0; i < 3; i++ {
		cs = append(cs, e.h1(auth))
	}
	for i, c := range cs[:2] {
		if st := c.get(""); st != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (CONNECTs must not be charged)", i, st)
		}
	}
	if resp := cs[2].getResp(""); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third request status = %d, want 429", resp.StatusCode)
	}
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+idHost+":443 HTTP/1.1\r\nHost: "+idHost+":443\r\n"+auth+"\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRateLimited(t, resp, 3600)
	// Another user still connects.
	if _, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-bob") + "\r\n"); !strings.Contains(status, "200") {
		t.Errorf("bob CONNECT = %q, want 200", status)
	}
}

// No token, or a token that does not verify, puts the request in the
// anonymous bucket keyed by the worker's agent, never in a user's bucket; and
// a token-less CONNECT is never refused on the anonymous bucket.
func TestUserLimit_AnonymousBucket(t *testing.T) {
	anon := config.UserLimit{RateLimit: "2/hour"}
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{
		UserLimits:     []config.UserLimit{engRule("5/hour"), {Name: "mallory", Match: config.UserLimitMatch{Users: []string{"mallory"}}, RateLimit: "100/hour"}},
		AnonymousLimit: &anon,
	}, nil))
	c := e.h1("")
	if st := c.get(""); st != http.StatusOK {
		t.Fatalf("first anonymous request = %d, want 200", st)
	}
	// tok-bad carries sub mallory unverified: it is charged to the anonymous
	// bucket, never to mallory's.
	if st := c.get("X-Warden-Identity: Bearer tok-bad\r\n"); st != http.StatusOK {
		t.Fatalf("unverified-token request = %d, want 200", st)
	}
	assertRateLimited(t, c.getResp(""), 3600)
	// A token-less CONNECT is not refused on the anonymous bucket: its requests
	// may carry other users' identities, each charged on its own.
	c2 := e.h1("")
	assertRateLimited(t, c2.getResp(""), 3600)
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-bob\r\n"); st != http.StatusOK {
		t.Errorf("bob on a token-less CONNECT = %d, want 200", st)
	}
	if st := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n").get(""); st != http.StatusOK {
		t.Errorf("alice = %d, want 200 (her own rule)", st)
	}
	evs := waitEvents(t, e.store, 6)
	for _, ev := range evs {
		if ev.Decision == "allow" && ev.UserSub == "" && ev.LimitRule != config.UserLimitNameAnonymous {
			t.Errorf("anonymous allow = %+v", ev)
		}
	}
	denies := limitDenies(e.store)
	if len(denies) != 2 {
		t.Fatalf("denies = %+v", denies)
	}
	for _, d := range denies {
		if d.LimitRule != config.UserLimitNameAnonymous || d.UserSub != "" || d.Reason != string(denyreason.UserRateLimited) || d.AgentID != "agent" {
			t.Errorf("anonymous deny = %+v", d)
		}
	}
	// One anonymous bucket (agent-keyed), alice's and bob's; none for mallory.
	if n := e.p.cfg.Policy.(*policy.Evaluator).UserLimitBuckets(); n != 3 {
		t.Errorf("buckets = %d, want 3", n)
	}
}

// A truncated group list that may hide the applicable rule fails closed with
// 403 identity_groups_truncated and no Retry-After (waiting does not help).
func TestUserLimit_GroupsTruncated(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{
		UserLimits:       []config.UserLimit{{Name: "ops", Match: config.UserLimitMatch{Groups: []string{"ops"}}, RateLimit: "1/hour"}},
		DefaultUserLimit: &config.UserLimit{RateLimit: "100/hour"},
	}, nil))
	c := idClaims("trunc", e.clk.now().Add(time.Hour))
	c.GroupsTruncated = true
	e.v.Set("tok-trunc", c, identity.StatusValid, "")
	resp := e.h1("").getResp("X-Warden-Identity: Bearer tok-trunc\r\n")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(body) != `{"error":"identity_groups_truncated"}` {
		t.Fatalf("status = %d body = %q, want 403 identity_groups_truncated", resp.StatusCode, body)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		t.Errorf("Retry-After = %q, want none", ra)
	}
	if n := e.be.requests(); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
	waitEvents(t, e.store, 1)
	if d := limitDenies(e.store); len(d) != 1 || d[0].Reason != string(denyreason.IdentityGroupsTruncated) || d[0].LimitRule != "ops" {
		t.Errorf("denies = %+v", d)
	}
	if n := e.m.userLimitDenied("rate"); n != 0 {
		t.Errorf("rate denials = %d, want 0", n)
	}
}

// Limits are charged only on a request that will be forwarded (a policy Allow,
// or a NoMatch the judge allowed). A NoMatch the judge denies ends denied, so
// it is never charged and its judge deny is never overwritten by a limit; the
// budget is intact for the next allowed request.
func TestUserLimit_OnlyAfterPolicyAllow(t *testing.T) {
	j := &fakeJudge{verdict: Verdict{Decision: "deny", Reason: "no"}}
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{
		Allowlist:  []config.AllowlistEntry{{Domain: "other.test", Port: 443}},
		UserLimits: []config.UserLimit{engRule("1/hour")},
	}, j))
	alice := "X-Warden-Identity: Bearer tok-alice\r\n"
	for i := 0; i < 3; i++ {
		resp := e.h1("").getResp(alice)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("judge-denied request %d = %d, want 403", i, resp.StatusCode)
		}
	}
	for _, d := range waitEvents(t, e.store, 3) {
		if d.Reason != string(denyreason.Judge) {
			t.Errorf("deny reason = %q, want judge (a limit never overwrites it)", d.Reason)
		}
		if d.LimitRule != "" {
			t.Errorf("judge deny carries limit_rule %q: a peek is not a charge", d.LimitRule)
		}
	}
	if n := e.p.cfg.Policy.(*policy.Evaluator).UserLimitBuckets(); n != 0 {
		t.Errorf("buckets = %d, want 0: a judge-denied request is never charged", n)
	}
	j.mu.Lock()
	j.verdict = Verdict{Decision: "allow"}
	j.mu.Unlock()
	if st := e.h1("").get(alice); st != http.StatusOK {
		t.Errorf("first judge-allowed request = %d, want 200", st)
	}
}

// A NoMatch request the judge allows is forwarded, so it is charged: after the
// judge, before the upstream. Once the bucket is exhausted the request is
// refused by the pre-judge peek, so an over-limit user costs no judge call.
func TestUserLimit_JudgeAllowedCharged(t *testing.T) {
	j := &fakeJudge{verdict: Verdict{Decision: "allow"}}
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{
		Allowlist:  []config.AllowlistEntry{{Domain: "other.test", Port: 443}},
		UserLimits: []config.UserLimit{engRule("2/hour")},
	}, j))
	c := e.h1("")
	alice := "X-Warden-Identity: Bearer tok-alice\r\n"
	for i := 0; i < 2; i++ {
		if st := c.get(alice); st != http.StatusOK {
			t.Fatalf("judge-allowed request %d = %d, want 200", i, st)
		}
	}
	assertRateLimited(t, c.getResp(alice), 3600)
	j.mu.Lock()
	calls := j.calls
	j.mu.Unlock()
	if calls != 2 {
		t.Errorf("judge calls = %d, want 2 (the over-limit request is refused before the judge)", calls)
	}
	if n := e.be.requests(); n != 2 {
		t.Errorf("upstream saw %d requests, want 2", n)
	}
	for _, ev := range waitEvents(t, e.store, 3) {
		if ev.LimitRule != "eng" {
			t.Errorf("%s event limit_rule = %q, want eng", ev.Decision, ev.LimitRule)
		}
	}
	if d := limitDenies(e.store); len(d) != 1 || d[0].Reason != string(denyreason.UserRateLimited) || d[0].UserSub != "alice" {
		t.Errorf("denies = %+v", d)
	}
}

// With no user limits configured nothing changes: no limit_rule on events and
// no user-limit metric.
func TestUserLimit_NoLimitsUnchanged(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	c := e.h1("")
	for i := 0; i < 5; i++ {
		if st := c.get("X-Warden-Identity: Bearer tok-alice\r\n"); st != http.StatusOK {
			t.Fatalf("request %d = %d", i, st)
		}
	}
	for _, ev := range waitEvents(t, e.store, 5) {
		if ev.LimitRule != "" {
			t.Errorf("event carries limit_rule %q", ev.LimitRule)
		}
	}
	if strings.Contains(e.m.describe(), "UserLimit") {
		t.Errorf("user-limit metric recorded with no limits:\n%s", e.m.describe())
	}
	if strings.Contains(e.logs.String(), "limit_rule") {
		t.Error("decision log carries limit_rule with no limits")
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]int{
		0:                       1,
		-time.Second:            1,
		time.Nanosecond:         1,
		time.Second:             1,
		time.Second + 1:         2,
		59*time.Second + 999999: 60,
		time.Hour:               3600,
	} {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", d, got, want)
		}
	}
}

// bucketsOf is the env evaluator's open per-user bucket count.
func bucketsOf(e *idEnv) int { return e.p.cfg.Policy.(*policy.Evaluator).UserLimitBuckets() }

// The authoritative charge is made just before the request is sent: a request
// refused by DLP after the pre-judge peek consumes no budget and its deny
// carries no limit_rule.
func TestUserLimit_DLPDeniedNotCharged(t *testing.T) {
	dlp := NewDLPScanner(config.DLPConfig{
		Mode:  config.DLPModeEnforce,
		Rules: []config.DLPRule{{Class: "pii.*", Action: config.DLPActionBlock}},
	}, false, false)
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("1/hour")}}, nil,
		func(c *Config) { c.DLP = dlp }))
	post := func() int {
		c := e.h1("")
		body := "contact: alice@example.com please"
		_, _ = io.WriteString(c.tc, "POST /x HTTP/1.1\r\nHost: "+idHost+"\r\nX-Warden-Identity: Bearer tok-alice\r\n"+
			"Content-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
		resp, err := http.ReadResponse(c.br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 2; i++ {
		if st := post(); st != http.StatusForbidden {
			t.Fatalf("DLP-blocked request %d = %d, want 403", i, st)
		}
	}
	if n := bucketsOf(e); n != 0 {
		t.Errorf("buckets = %d, want 0: a DLP-denied request is never charged", n)
	}
	for _, ev := range waitEvents(t, e.store, 2) {
		if ev.LimitRule != "" {
			t.Errorf("DLP deny carries limit_rule %q", ev.LimitRule)
		}
	}
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-alice\r\n"); st != http.StatusOK {
		t.Errorf("first clean request = %d, want 200 (budget intact)", st)
	}
}

// A request whose upstream dial the SSRF dialer refuses is never charged.
func TestUserLimit_SSRFDeniedNotCharged(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("1/hour")}}, nil))
	inner := e.p.dialTLS
	var refuse atomic.Bool
	refuse.Store(true)
	e.p.dialTLS = func(n, a string, c *tls.Config) (*tls.Conn, error) {
		if refuse.Load() {
			return nil, &SSRFError{Reason: SSRFReasonBlocked, AddrClass: "private"}
		}
		return inner(n, a, c)
	}
	for i := 0; i < 2; i++ {
		if st := e.h1("").get("X-Warden-Identity: Bearer tok-alice\r\n"); st != http.StatusBadGateway {
			t.Fatalf("SSRF-refused request %d = %d, want 502", i, st)
		}
	}
	if n := bucketsOf(e); n != 0 {
		t.Errorf("buckets = %d, want 0: an SSRF-refused request is never charged", n)
	}
	refuse.Store(false)
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-alice\r\n"); st != http.StatusOK {
		t.Errorf("first dialable request = %d, want 200 (budget intact)", st)
	}
}

// A raw tunnel whose dial fails is never charged; one that is dialed is.
func TestUserLimit_RefusedTunnelNotCharged(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("1/hour")}}, nil, noCA))
	auth := "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"
	// No raw upstream: every dial fails after the 200.
	for i := 0; i < 2; i++ {
		conn, br, status := e.connect(auth)
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT %d = %q, want 200", i, status)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = br.ReadByte() // the tunnel closes when the dial fails
	}
	if n := bucketsOf(e); n != 0 {
		t.Errorf("buckets = %d, want 0: a tunnel that never dialed is never charged", n)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	e.setRaw(func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) })
	conn, br, status := e.connect(auth)
	if !strings.Contains(status, "200") {
		t.Fatalf("dialable CONNECT = %q, want 200", status)
	}
	_, _ = io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if n := bucketsOf(e); n != 1 {
		t.Errorf("buckets = %d, want 1 after one dialed tunnel", n)
	}
}

// TestUserLimit_H2SSRFRefusedIsCharged pins a known gap: the h2 transport
// dials the upstream inside RoundTrip, after the charge, so an h2 stream the
// SSRF dialer refuses has already consumed budget (on HTTP/1.1 it has not, see
// TestUserLimit_SSRFDeniedNotCharged). The stream still gets 502 with the
// ssrf_* deny. Follow-up: own the h2 upstream connection
// (http2.Transport.NewClientConn + ClientConn.ReserveNewRequest) so the dial
// happens before the charge; this test then flips to "not charged".
func TestUserLimit_H2SSRFRefusedIsCharged(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeAttribute, limitEdit(config.Policy{UserLimits: []config.UserLimit{engRule("5/hour")}}, nil))
	e.p.dialTLS = func(string, string, *tls.Config) (*tls.Conn, error) {
		return nil, &SSRFError{Reason: SSRFReasonBlocked, AddrClass: "private"}
	}
	cc := e.h2("")
	if st := h2Get(t, cc, map[string]string{"X-Warden-Identity": "Bearer tok-alice"}); st != http.StatusBadGateway {
		t.Fatalf("SSRF-refused h2 stream = %d, want 502", st)
	}
	if n := bucketsOf(e); n != 1 {
		t.Errorf("buckets = %d, want 1: the h2 stream is charged before the transport dials (known gap)", n)
	}
	evs := waitEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].Decision != "deny" || !strings.HasPrefix(evs[0].Reason, "ssrf_") || evs[0].Protocol != "http2" {
		t.Errorf("events = %+v, want one ssrf_* deny on http2", evs)
	}
}
