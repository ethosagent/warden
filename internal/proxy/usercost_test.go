package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/policy"
)

// These tests cover W-P3-PUL-04: the worker's per-user daily spend ledger
// caps estimated cost per verified user (and per agent for anonymous
// traffic) under a rule with dailyCostUSD, on destinations the cost estimator
// tracks only. tok-alice and tok-bob are valid members of group eng.

const (
	costHost = "api.openai.com" // tracked by cost.NewEstimator (openai prices)
	// costBody is 1600 bytes: 400 output tokens at openai's $0.015 per 1K is
	// $0.006 per request (a GET has no request body).
	costBodyBytes = 1600
)

var costPerRequest = cost.NewEstimator().Estimate(costHost, 0, costBodyBytes).TotalCost

// costEnv is an identity env whose proxy prices costHost and enforces the
// ledger, over a backend that streams a chunked (unknown-length) response.
type costEnv struct {
	*idEnv
	ledger *cost.Ledger
	clk    *idClock
	reqs   atomic.Int64
	// handler, when set, replaces the default chunked body.
	handler http.HandlerFunc
}

// costEngRule is the eng rule capped at capUSD a day, on every domain.
func costEngRule(capUSD float64) config.UserLimit {
	return config.UserLimit{Name: "eng-llm", Match: config.UserLimitMatch{Groups: []string{"eng"}}, DailyCostUSD: capUSD}
}

var costNoon = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func newCostEnv(t *testing.T, pol config.Policy, extra ...func(*Config)) *costEnv {
	t.Helper()
	ce := &costEnv{clk: &idClock{t: costNoon}}
	ce.ledger = cost.NewLedger(ce.clk.now)
	if pol.Allowlist == nil {
		pol.Allowlist = []config.AllowlistEntry{{Domain: idHost, Port: 443}, {Domain: costHost, Port: 443}}
	}
	edit := func(c *Config) {
		c.Policy = policy.NewEvaluator(pol)
		c.Cost = cost.NewEstimator()
		c.UserCost = ce.ledger
		for _, f := range extra {
			f(c)
		}
	}
	ce.idEnv = newIDEnvCfg(t, IdentityModeAttribute, edit)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		ce.reqs.Add(1)
		if ce.handler != nil {
			ce.handler(w, r)
			return
		}
		f := w.(http.Flusher)
		_, _ = io.WriteString(w, strings.Repeat("a", costBodyBytes/2))
		f.Flush() // chunked: the length is known only from the relayed bytes
		_, _ = io.WriteString(w, strings.Repeat("b", costBodyBytes/2))
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	ce.p.dialTLS = func(_, a string, c *tls.Config) (*tls.Conn, error) {
		ce.dials.Add(1)
		if strings.HasPrefix(a, idHost+":") {
			return tls.Dial("tcp", strings.TrimPrefix(ce.be.srv.URL, "https://"), &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
		}
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}
	return ce
}

// costH1 is an HTTP/1.1 keep-alive session to host over a CONNECT tunnel.
type costH1 struct {
	t    *testing.T
	host string
	tc   *tls.Conn
	br   *bufio.Reader
}

func (e *costEnv) h1To(host, connectExtra string) *costH1 {
	e.t.Helper()
	conn, br, status, err := e.dialConnectTo(host, connectExtra)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	if !strings.Contains(status, "200") {
		e.t.Fatalf("CONNECT %s status = %q, want 200", host, status)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	tc := tls.Client(&bufferedTLSConn{Reader: br, Conn: conn}, &tls.Config{ServerName: host, RootCAs: pool, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		e.t.Fatalf("TLS to %s: %v", host, err)
	}
	return &costH1{t: e.t, host: host, tc: tc, br: bufio.NewReader(tc)}
}

// get sends GET /v1/x with extra header lines; the body is read and closed.
func (c *costH1) get(extra string) (*http.Response, string) {
	c.t.Helper()
	_, _ = io.WriteString(c.tc, "GET /v1/x HTTP/1.1\r\nHost: "+c.host+"\r\n"+extra+"\r\n")
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

const (
	aliceHdr = "X-Warden-Identity: Bearer tok-alice\r\n"
	bobHdr   = "X-Warden-Identity: Bearer tok-bob\r\n"
)

// assertCostLimited asserts 403 user_cost_limited with Retry-After to the
// next UTC midnight of the ledger clock.
func assertCostLimited(t *testing.T, e *costEnv, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusForbidden || body != `{"error":"user_cost_limited"}` {
		t.Fatalf("status %d body %q, want 403 user_cost_limited", resp.StatusCode, body)
	}
	now := e.clk.now()
	want := int(math.Ceil(cost.NextUTCMidnight(now).Sub(now).Seconds()))
	if got, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || got != want {
		t.Errorf("Retry-After = %q, want %d (seconds to the next UTC midnight)", resp.Header.Get("Retry-After"), want)
	}
}

func (e *costEnv) spent(sub string) float64 {
	v, _ := e.ledger.Spent(cost.UserKey(sub, "agent", "eng-llm"))
	return v
}

// waitSpent waits until sub's ledger spend under eng-llm is want: the ledger
// is charged after the response was relayed, so the client can read it first.
func (e *costEnv) waitSpent(sub string, want float64) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := e.spent(sub)
		if math.Abs(got-want) <= 1e-12 {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("%s spent %v, want %v", sub, got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// With dailyCostUSD 0.01 and requests estimated at $0.006 (a chunked
// response, priced from the relayed bytes), alice's third request is refused
// with 403 user_cost_limited and Retry-After to UTC midnight, while bob is
// allowed and alice still reaches an untracked allowed domain.
func TestUserCostCap(t *testing.T) {
	if math.Abs(costPerRequest-0.006) > 1e-12 {
		t.Fatalf("fixture prices a request at %v, want 0.006", costPerRequest)
	}
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(0.01)}})
	c := e.h1To(costHost, "")
	for i := 0; i < 2; i++ {
		if resp, body := c.get(aliceHdr); resp.StatusCode != http.StatusOK || len(body) != costBodyBytes {
			t.Fatalf("alice request %d = %d (%d bytes), want 200", i, resp.StatusCode, len(body))
		}
		// The ledger holds the exact estimate of the relayed bytes.
		e.waitSpent("alice", float64(i+1)*costPerRequest)
	}
	resp, body := c.get(aliceHdr)
	assertCostLimited(t, e, resp, body)
	if n := e.reqs.Load(); n != 2 {
		t.Errorf("upstream saw %d requests, want 2 (the refusal never reaches it)", n)
	}
	if got := e.spent("alice"); math.Abs(got-2*costPerRequest) > 1e-12 {
		t.Errorf("the refusal was charged: alice spent %v", got)
	}

	// bob has his own budget.
	if resp, _ := e.h1To(costHost, "").get(bobHdr); resp.StatusCode != http.StatusOK {
		t.Errorf("bob = %d, want 200", resp.StatusCode)
	}
	// An untracked destination is never refused for cost.
	if st := e.h1("").get(aliceHdr); st != http.StatusOK {
		t.Errorf("alice to untracked %s = %d, want 200", idHost, st)
	}

	evs := waitEvents(t, e.store, 5)
	denies := limitDenies(e.store)
	if len(denies) != 1 {
		t.Fatalf("denies = %+v, want 1", denies)
	}
	d := denies[0]
	if d.Reason != string(denyreason.UserCostLimited) || d.UserSub != "alice" || d.UserEmail != "alice@example.test" ||
		d.LimitRule != "eng-llm" || d.Domain != costHost || d.AgentID != "agent" {
		t.Errorf("deny event = %+v", d)
	}
	for _, ev := range evs {
		if ev.Decision != "allow" {
			continue
		}
		switch ev.Domain {
		case costHost:
			if ev.LimitRule != "eng-llm" || math.Abs(ev.CostUSD-costPerRequest) > 1e-12 {
				t.Errorf("tracked allow event: limit_rule %q cost %v", ev.LimitRule, ev.CostUSD)
			}
		case idHost:
			if ev.CostUSD != 0 {
				t.Errorf("untracked allow priced at %v", ev.CostUSD)
			}
		}
	}
	if n := e.m.userLimitDenied("cost"); n != 1 {
		t.Errorf("user_limit.denied{kind=cost} = %d, want 1", n)
	}
	if n := e.m.blockedCount(string(denyreason.UserCostLimited)); n != 1 {
		t.Errorf("blocked{user_cost_limited} = %d, want 1", n)
	}
	assertNoIdentityInMetrics(t, e.m, "alice", "bob", "@example.test")
	if logs := e.logs.String(); strings.Contains(logs, "0.012") || strings.Contains(logs, "0.006") {
		t.Errorf("a log line carries a user's spend:\n%s", logs)
	}
}

// A costBlockedUsers entry for today refuses alice with no local spend; the
// same entry dated yesterday is ignored.
func TestUserCostCap_WireBlock(t *testing.T) {
	e := newCostEnv(t, config.Policy{
		UserLimits: []config.UserLimit{costEngRule(5)},
		CostBlockedUsers: []config.CostBlockedUser{
			{Sub: "alice", Rule: "eng-llm", Day: "2026-11-27"},
			{Sub: "bob", Rule: "eng-llm", Day: "2026-11-26"},
		},
	})
	resp, body := e.h1To(costHost, "").get(aliceHdr)
	assertCostLimited(t, e, resp, body)
	if e.spent("alice") != 0 {
		t.Error("alice had local spend")
	}
	if resp, _ := e.h1To(costHost, "").get(bobHdr); resp.StatusCode != http.StatusOK {
		t.Errorf("bob (entry dated yesterday) = %d, want 200", resp.StatusCode)
	}
	// The block is per rule: a cost entry never refuses an untracked host.
	if st := e.h1("").get(aliceHdr); st != http.StatusOK {
		t.Errorf("alice to untracked = %d, want 200", st)
	}
	// A TLS-terminated CONNECT with alice's verified identity is refused
	// before the 200, like an exhausted rate bucket.
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+costHost+":443 HTTP/1.1\r\nHost: "+costHost+":443\r\nProxy-Authorization: "+basicAuth("tok-alice")+"\r\n\r\n")
	cresp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	cbody, _ := io.ReadAll(cresp.Body)
	assertCostLimited(t, e, cresp, string(cbody))
}

// Past 00:00 UTC (the fake clock) alice's spend and her wire block lapse.
func TestUserCostCap_UTCMidnight(t *testing.T) {
	e := newCostEnv(t, config.Policy{
		UserLimits:       []config.UserLimit{costEngRule(0.006)},
		CostBlockedUsers: []config.CostBlockedUser{{Sub: "bob", Rule: "eng-llm", Day: "2026-11-27"}},
	})
	c := e.h1To(costHost, "")
	if resp, _ := c.get(aliceHdr); resp.StatusCode != http.StatusOK {
		t.Fatalf("first = %d", resp.StatusCode)
	}
	resp, body := c.get(aliceHdr)
	assertCostLimited(t, e, resp, body)
	resp, body = e.h1To(costHost, "").get(bobHdr)
	assertCostLimited(t, e, resp, body)

	e.clk.advance(12*time.Hour + time.Second) // 00:00:01 UTC on the 28th
	if resp, _ := e.h1To(costHost, "").get(aliceHdr); resp.StatusCode != http.StatusOK {
		t.Errorf("alice after UTC midnight = %d, want 200", resp.StatusCode)
	}
	if resp, _ := e.h1To(costHost, "").get(bobHdr); resp.StatusCode != http.StatusOK {
		t.Errorf("bob after UTC midnight (yesterday's wire entry) = %d, want 200", resp.StatusCode)
	}
}

// A raw tunnel (no CA) to a tracked destination for a subject under a
// cost-capped rule cannot be measured: it is refused at CONNECT, before the
// 200 and any dial, with user_cost_unmeasurable. A tunnel to an untracked
// destination is not.
func TestUserCostCap_RawTunnelUnmeasurable(t *testing.T) {
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(5)}}, noCA)
	e.setRaw(func() (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = b.Close() })
		return a, nil
	})
	auth := "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+costHost+":443 HTTP/1.1\r\nHost: "+costHost+":443\r\n"+auth+"\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || string(body) != `{"error":"user_cost_unmeasurable"}` {
		t.Fatalf("CONNECT = %d %q, want 403 user_cost_unmeasurable", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") != "" {
		t.Errorf("unmeasurable refusal has Retry-After %q", resp.Header.Get("Retry-After"))
	}
	if n := e.dials.Load(); n != 0 {
		t.Errorf("dials = %d, want 0", n)
	}
	if _, _, status := e.connect(auth); !strings.Contains(status, "200") {
		t.Errorf("raw tunnel to untracked %s = %q, want 200", idHost, status)
	}
	waitEvents(t, e.store, 2)
	if d := limitDenies(e.store); len(d) != 1 || d[0].Reason != string(denyreason.UserCostUnmeasurable) ||
		d[0].LimitRule != "eng-llm" || d[0].UserSub != "alice" || d[0].Protocol != "tcp" {
		t.Errorf("denies = %+v", d)
	}
	if n := e.m.userLimitDenied("unmeasurable"); n != 1 {
		t.Errorf("user_limit.denied{kind=unmeasurable} = %d, want 1", n)
	}
}

// A WebSocket upgrade to a tracked destination under a cost-capped rule is
// refused before it reaches the upstream.
func TestUserCostCap_WebSocketUnmeasurable(t *testing.T) {
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(5)}})
	c := e.h1To(costHost, "")
	resp, body := c.get("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" + aliceHdr)
	if resp.StatusCode != http.StatusForbidden || body != `{"error":"user_cost_unmeasurable"}` {
		t.Fatalf("upgrade = %d %q, want 403 user_cost_unmeasurable", resp.StatusCode, body)
	}
	if n := e.reqs.Load(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

// A request under a rule with no cost cap, or with no ledger configured, is
// never checked or charged; the anonymous rule's ledger is keyed per agent.
func TestUserCostCap_AnonymousAndUncapped(t *testing.T) {
	e := newCostEnv(t, config.Policy{
		UserLimits:     []config.UserLimit{{Name: "eng-llm", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "100/hour"}},
		AnonymousLimit: &config.UserLimit{DailyCostUSD: 0.006},
	})
	c := e.h1To(costHost, "")
	for i := 0; i < 3; i++ {
		if resp, _ := c.get(aliceHdr); resp.StatusCode != http.StatusOK {
			t.Fatalf("alice (uncapped rule) %d = %d", i, resp.StatusCode)
		}
	}
	if e.ledger.Keys() != 0 {
		t.Errorf("an uncapped rule was charged: %d keys", e.ledger.Keys())
	}
	// No token: the anonymous rule, keyed on the worker's agent.
	if resp, _ := c.get(""); resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous first = %d", resp.StatusCode)
	}
	waitFor(t, "anonymous spend charged on the agent", func() bool {
		got, _ := e.ledger.Spent(cost.UserKey("", "agent", config.UserLimitNameAnonymous))
		return math.Abs(got-costPerRequest) <= 1e-12
	})
	resp, body := e.h1To(costHost, "").get("")
	assertCostLimited(t, e, resp, body)
	// An invalid token is anonymous too, never a user's ledger.
	resp, body = e.h1To(costHost, "").get("X-Warden-Identity: Bearer tok-bad\r\n")
	assertCostLimited(t, e, resp, body)
}

// A deny that cuts the response after the upstream answered (the echo guard
// on a streamed response) still charges the relayed bytes: a capped user
// cannot get a free stream by having it cut.
func TestUserCostCap_EchoCutCharged(t *testing.T) {
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(5)}}, func(c *Config) {
		c.PlaceholderScopes = map[string][]string{scopedPlaceholder: {costHost}}
	})
	e.handler = func(w http.ResponseWriter, _ *http.Request) {
		f := w.(http.Flusher)
		_, _ = io.WriteString(w, strings.Repeat("a", costBodyBytes-len("real-value")))
		f.Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "real-value")
		f.Flush()
	}
	c := e.h1To(costHost, "")
	_, _ = io.WriteString(c.tc, "GET /v1/x HTTP/1.1\r\nHost: "+costHost+"\r\nAuthorization: Bearer "+scopedPlaceholder+"\r\n"+aliceHdr+"\r\n")
	if resp, err := http.ReadResponse(c.br, nil); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	d := e.waitDeny(t, denyreason.SecretEcho, 1)
	if d[0].LimitRule != "eng-llm" {
		t.Errorf("echo deny limit_rule = %q", d[0].LimitRule)
	}
	e.waitSpent("alice", costPerRequest)
	// The deny event carries the charge, so a reseed and the rollup count it.
	if math.Abs(d[0].CostUSD-costPerRequest) > 1e-12 || d[0].Provider != "openai" {
		t.Errorf("echo deny cost = %v by %q, want %v by openai", d[0].CostUSD, d[0].Provider, costPerRequest)
	}
}

// A buffered response the response scanner blocks (enforce) was still
// answered by the upstream: the capped user is charged its exact estimate, and
// the deny event carries it.
func TestUserCostCap_ScannerBlockCharged(t *testing.T) {
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(5)}}, func(c *Config) {
		c.ResponseScan = NewResponseScanner("enforce", 1<<20, false, false)
	})
	e.handler = func(w http.ResponseWriter, _ *http.Request) {
		body := leakBody + strings.Repeat(" ", costBodyBytes-len(leakBody))
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}
	resp, _ := e.h1To(costHost, "").get(aliceHdr)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (scanner block)", resp.StatusCode)
	}
	e.waitSpent("alice", costPerRequest)
	var deny []analytics.Event
	waitFor(t, "the scanner deny", func() bool {
		deny = limitDenies(e.store)
		return len(deny) == 1
	})
	if math.Abs(deny[0].CostUSD-costPerRequest) > 1e-12 || deny[0].Provider != "openai" || deny[0].LimitRule != "eng-llm" {
		t.Errorf("scanner deny = %+v, want cost %v by openai under eng-llm", deny[0], costPerRequest)
	}
}

// With no ledger configured a dailyCostUSD rule is never checked.
func TestUserCostCap_NoLedgerUnchanged(t *testing.T) {
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(0.000001)}}, func(c *Config) { c.UserCost = nil })
	c := e.h1To(costHost, "")
	for i := 0; i < 3; i++ {
		if resp, _ := c.get(aliceHdr); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, resp.StatusCode)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUserLimitResponse_Cost(t *testing.T) {
	st, body, retry := userLimitResponse(policy.RequestVerdict{Reason: denyreason.UserCostLimited, RetryAfter: 90*time.Second + time.Millisecond})
	if st != http.StatusForbidden || body != `{"error":"user_cost_limited"}` || retry != 91 {
		t.Errorf("cost = %d %q %d", st, body, retry)
	}
	st, body, retry = userLimitResponse(policy.RequestVerdict{Reason: denyreason.UserCostUnmeasurable})
	if st != http.StatusForbidden || body != `{"error":"user_cost_unmeasurable"}` || retry != 0 {
		t.Errorf("unmeasurable = %d %q %d", st, body, retry)
	}
}

// The estimator tracks every spelling of a provider host that the policy
// normalizes to it: a cost cap cannot be dodged with a trailing dot or case.
func TestEstimatorNormalizesLikePolicy(t *testing.T) {
	est := cost.NewEstimator()
	for _, h := range []string{"api.openai.com", "api.openai.com.", "API.OPENAI.COM.", "Api.OpenAI.Com..", "api.anthropic.com."} {
		n := policy.NormalizeHost(h)
		_, want := est.Tracks(n)
		if _, got := est.Tracks(h); got != want || !want {
			t.Errorf("Tracks(%q) = %v, Tracks(NormalizeHost) = %v; want both true", h, got, want)
		}
		if est.Estimate(h, 4000, 0) == nil {
			t.Errorf("Estimate(%q) = nil", h)
		}
	}
}

// A raw tunnel to a provider host spelled with a trailing dot or in upper
// case is still unmeasurable under a cost cap.
func TestUserCostCap_RawTunnelHostSpellings(t *testing.T) {
	for _, host := range []string{"api.openai.com.", "API.OPENAI.COM."} {
		t.Run(host, func(t *testing.T) {
			e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(5)}}, noCA)
			conn, err := net.Dial("tcp", e.p.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(conn, "CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\nProxy-Authorization: "+basicAuth("tok-alice")+"\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusForbidden || string(body) != `{"error":"user_cost_unmeasurable"}` {
				t.Fatalf("CONNECT %s = %d %q, want 403 user_cost_unmeasurable", host, resp.StatusCode, body)
			}
			if n := e.dials.Load(); n != 0 {
				t.Errorf("dials = %d, want 0", n)
			}
		})
	}
}

// A terminated tunnel to such a spelling is priced and capped like the plain
// host.
func TestUserCostCap_TerminatedHostSpellings(t *testing.T) {
	for _, host := range []string{"api.openai.com.", "API.OPENAI.COM."} {
		t.Run(host, func(t *testing.T) {
			e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(0.01)}})
			c := e.h1To(host, "")
			for i := 1; i <= 2; i++ {
				if resp, _ := c.get(aliceHdr); resp.StatusCode != http.StatusOK {
					t.Fatalf("request %d = %d, want 200", i, resp.StatusCode)
				}
				e.waitSpent("alice", float64(i)*costPerRequest)
			}
			resp, body := c.get(aliceHdr)
			assertCostLimited(t, e, resp, body)
		})
	}
}

// fullLedger is a cost ledger with no room: every key reads untracked.
type fullLedger struct{ now time.Time }

func (fullLedger) Add(cost.LedgerKey, float64)          {}
func (fullLedger) Spent(cost.LedgerKey) (float64, bool) { return 0, false }
func (l fullLedger) Now() time.Time                     { return l.now }

// A full ledger fails closed: a new user under a cost cap is refused with
// user_cost_limited, and the worker warns once.
func TestUserCostCap_LedgerFullFailsClosed(t *testing.T) {
	e := newCostEnv(t, config.Policy{UserLimits: []config.UserLimit{costEngRule(5)}}, func(c *Config) {
		c.UserCost = fullLedger{now: costNoon}
	})
	for i := 0; i < 2; i++ {
		resp, body := e.h1To(costHost, "").get(aliceHdr)
		assertCostLimited(t, e, resp, body)
	}
	if n := strings.Count(e.logs.String(), "per-user cost ledger is full"); n != 1 {
		t.Errorf("ledger-full WARN logged %d times, want 1", n)
	}
}

// reloadJudge allows every request and, on its first call, hot-reloads the
// evaluator: the reload lands between the userLimitStage peek and the charge.
type reloadJudge struct {
	ev   *policy.Evaluator
	next config.Policy
	done atomic.Bool
}

func (j *reloadJudge) Evaluate(_, _, _, _, _ string, _ bool) Verdict {
	if !j.done.Swap(true) {
		j.ev.Replace(j.next)
	}
	return Verdict{Decision: "allow"}
}

// A reload between the peek and the charge that puts the request under a
// newly cost-capped rule is enforced on that same request.
func TestUserCostCap_ReloadBetweenPeekAndCharge(t *testing.T) {
	allow := []config.AllowlistEntry{{Domain: idHost, Port: 443}} // costHost goes to the judge
	before := config.Policy{Allowlist: allow, UserLimits: []config.UserLimit{
		{Name: "old", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "100/hour"},
	}}
	after := config.Policy{Allowlist: allow,
		UserLimits:       []config.UserLimit{costEngRule(5)},
		CostBlockedUsers: []config.CostBlockedUser{{Sub: "alice", Rule: "eng-llm", Day: "2026-11-27"}},
	}
	j := &reloadJudge{next: after}
	e := newCostEnv(t, before, func(c *Config) {
		c.Judge = j
		j.ev = c.Policy.(*policy.Evaluator)
	})
	resp, body := e.h1To(costHost, "").get(aliceHdr)
	assertCostLimited(t, e, resp, body)
	if !j.done.Load() {
		t.Fatal("the judge never ran: the reload did not land between peek and charge")
	}
	if n := e.reqs.Load(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	d := limitDenies(e.store)
	if len(d) != 1 || d[0].LimitRule != "eng-llm" || d[0].Reason != string(denyreason.UserCostLimited) {
		t.Errorf("denies = %+v, want one user_cost_limited under eng-llm", d)
	}
}

// An MCP SSE response the gateway blocks mid-stream (enforce, a poisoned
// event after a benign one that reached the agent) charges the capped user the
// exact estimate of what was read, and the gateway deny event carries it.
func TestUserCostCap_SSEGatewayDenyCharged(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	benign := sseEvent(`{"jsonrpc":"2.0","id":"0","result":{}}`)
	body := benign + sseEvent(mcpPoisonedList)
	rb := &mcpBackend{respStatus: 200, respCT: "text/event-stream", respBody: body, chunked: true}
	backendLn := startMCPBackend(t, caCert, caKey, rb)
	p, ss := startTestProxyWithMCP(t, []string{costHost}, caCertPEM, caKeyPEM, enforceMCPConfig(), nil)
	ledger := cost.NewLedger(func() time.Time { return costNoon })
	p.cfg.Cost = cost.NewEstimator()
	p.cfg.UserCost = ledger
	ev := p.cfg.Policy.(*policy.Evaluator)
	pol := ev.CurrentPolicy()
	pol.AnonymousLimit = &config.UserLimit{DailyCostUSD: 5}
	ev.Replace(pol)
	p.dialTLS = dialBackend(backendLn)

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), costHost, caCertPEM)
	req, _ := http.NewRequest("POST", "https://"+costHost+"/mcp", strings.NewReader(mcpToolsList))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(mcpToolsList))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	want := cost.NewEstimator().Estimate(costHost, int64(len(mcpToolsList)), int64(len(body))).TotalCost
	var deny *analytics.Event
	waitFor(t, "the gateway deny", func() bool {
		deny = findEvent(ss.snapshot(), "mcp", "deny")
		return deny != nil
	})
	if deny.Reason != "mcp_poisoning" || deny.LimitRule != config.UserLimitNameAnonymous {
		t.Fatalf("deny = %+v, want mcp_poisoning under the anonymous rule", deny)
	}
	if math.Abs(deny.CostUSD-want) > 1e-12 || deny.Provider != "openai" {
		t.Errorf("gateway deny cost = %v by %q, want exactly %v by openai", deny.CostUSD, deny.Provider, want)
	}
	if got, _ := ledger.Spent(cost.UserKey("", p.cfg.AgentID, config.UserLimitNameAnonymous)); math.Abs(got-want) > 1e-12 {
		t.Errorf("ledger = %v, want %v", got, want)
	}
}
