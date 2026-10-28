package scenarios

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/policyeval"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The group-policy scenarios (W-P1-GPOL-09, feature identity-policy). A
// {domain, groups} allow entry and a group-gated MCP tool are served by the
// control plane (so the fail-closed wire projection and the worker's merge are
// in the path), decided per request with the verified subject, and asserted
// through Warden's own outputs only: the audit events, the metrics, the fake
// upstream's recorded requests and the counting judge fake. Every deny asserts
// the judge got no call and the upstream nothing; every allow asserts the
// upstream never saw Proxy-Authorization or X-Warden-Identity. Tokens are never
// printed: failure messages name the case, not the value.

// groupsOpts boots identity on (attribute mode) and the inline judge against a
// counting fake, so "never sent to the judge" is observable.
func groupsOpts() []harness.Option {
	return append(identityOpts(), harness.WithFakeJudge())
}

// groupsTokens mints the three subjects the scenarios
// share. eng is the group the scoped entry names.
func groupsTokens(h *harness.H) (eng, sales, expired string) {
	eng = h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	sales = h.MintUserToken(fakes.Valid("sam", "sam@example.com", "sales"))
	expired = h.MintUserToken(fakes.Valid("erin", "erin@example.com", "eng"), fakes.Expired())
	return eng, sales, expired
}

// groupsServe saves the scoped policy through the control plane and waits for
// the workers to enforce it: scopedHost for group eng, plainHost for everyone.
func groupsServe(t *testing.T, h *harness.H, scopedGroups ...string) {
	t.Helper()
	if r := savePolicy(t, h, map[string]any{"domain": scopedHost, "groups": scopedGroups}, map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("scoped save = %d %s, want 200", r.Status, r.Body)
	}
	h.Eventually("workers enforce the save", func() bool {
		return connectStatus(t, h, plainHost+":443") == http.StatusOK
	})
}

// groupsNoLeak fails when any request an upstream received carried a header
// that must stay on the agent side of the proxy.
func groupsNoLeak(t *testing.T, ups ...*harness.Upstream) {
	t.Helper()
	for _, u := range ups {
		for i, r := range u.Requests() {
			for _, hdr := range []string{"Proxy-Authorization", "X-Warden-Identity"} {
				if v := r.Header.Get(hdr); v != "" {
					t.Errorf("upstream request %d carried %s", i, hdr)
				}
			}
		}
	}
}

// groupsJudgeIdle asserts the judge was never consulted: the endpoint received
// no call and warden.judge.decisions.total has no allow or deny.
func groupsJudgeIdle(t *testing.T, h *harness.H) {
	t.Helper()
	if n := h.Judge().Calls(); n != 0 {
		t.Errorf("judge fake received %d calls, want 0", n)
	}
	if h.MetricsAvailable() {
		for _, outcome := range []string{"allow", "deny"} {
			k := harness.MetricKey("warden.judge.decisions.total", map[string]string{"outcome": outcome})
			if got := h.Metrics()[k]; got != 0 {
				t.Errorf("%s = %v, want 0: a scoped decision is never the judge's", k, got)
			}
		}
	}
}

// groupsDenyEvents counts deny events on host with reason, with the identity
// status the event must carry ("" = any).
func groupsDenyEvents(h *harness.H, host, reason, status string) int {
	n := 0
	for _, e := range h.Events() {
		if e.Decision == "deny" && e.Domain == host && e.Reason == reason && (status == "" || e.IdentityStatus == status) {
			n++
		}
	}
	return n
}

// groupsAllowEvents counts allow events on host for a valid subject email.
func groupsAllowEvents(h *harness.H, host, email string) int {
	n := 0
	for _, e := range h.Events() {
		if e.Decision == "allow" && e.Domain == host && e.IdentityStatus == "valid" && e.UserEmail == email {
			n++
		}
	}
	return n
}

// groupsGet sends one GET to host through cl and returns the status and the
// response protocol major, or the transport error (usable off the test
// goroutine).
func groupsGet(cl *http.Client, host, token string) (status, proto int, err error) {
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/x", nil)
	if err != nil {
		return 0, 0, err
	}
	if token != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.ProtoMajor, nil
}

// groupsTunnel is one CONNECT tunnel the scenario drives by hand, so several
// requests ride the same keep-alive connection.
type groupsTunnel struct {
	conn net.Conn
	br   *bufio.Reader
	host string
}

// groupsConnect opens a CONNECT tunnel to host:443 (proxyAuth is the raw
// Proxy-Authorization value, "" for none) and returns it with the status of
// the CONNECT reply. With a 200 the caller owns the connection.
func groupsConnect(t *testing.T, h *harness.H, host, proxyAuth string) (*groupsTunnel, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n", host, host)
	if proxyAuth != "" {
		req += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		t.Fatalf("send CONNECT %s: %v", host, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read the CONNECT %s reply: %v", host, err)
	}
	_ = resp.Body.Close()
	return &groupsTunnel{conn: conn, br: br, host: host}, resp.StatusCode
}

// startTLS runs the client handshake over the tunnel with cfg and swaps the
// reader to the TLS stream.
func (tn *groupsTunnel) startTLS(t *testing.T, cfg *tls.Config) {
	t.Helper()
	cfg.ServerName = tn.host
	tc := tls.Client(tn.conn, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake over the tunnel to %s: %v", tn.host, err)
	}
	tn.conn = tc
	tn.br = bufio.NewReader(tc)
}

// get sends one GET on the tunnel (X-Warden-Identity when token is set) and
// returns the status. A transport error is returned as 0 with the error, which
// is how a scenario sees a tunnel the worker closed.
func (tn *groupsTunnel) get(token string) (int, error) {
	req := "GET /x HTTP/1.1\r\nHost: " + tn.host + "\r\n"
	if token != "" {
		req += "X-Warden-Identity: Bearer " + token + "\r\n"
	}
	if _, err := io.WriteString(tn.conn, req+"\r\n"); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(tn.br, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// groupsMemberAllowed: a valid eng token opens the scoped host whether it is
// presented on CONNECT (Proxy-Authorization) or on the request
// (X-Warden-Identity). The upstream sees both requests, neither header, and the
// events name the verified user. The judge is never consulted.
func groupsMemberAllowed(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	eng, _, _ := groupsTokens(h)
	groupsServe(t, h, "eng")

	if got := getStatus(t, h.AgentWithProxyToken(eng), scopedHost, ""); got != http.StatusOK {
		t.Fatalf("member via Proxy-Authorization = %d, want 200", got)
	}
	if got := getStatus(t, h.Agent(), scopedHost, eng); got != http.StatusOK {
		t.Fatalf("member via X-Warden-Identity = %d, want 200", got)
	}

	h.Eventually("both requests are audited as the verified user", func() bool {
		return groupsAllowEvents(h, scopedHost, "alice@example.com") >= 2
	})
	if n := len(up.Requests()); n != 2 {
		t.Errorf("upstream saw %d requests, want 2", n)
	}
	groupsNoLeak(t, up)
	groupsJudgeIdle(t, h)
}

// groupsNonMemberDenied: a valid token of the wrong group is denied outright
// (group_not_allowed, 403), on the request and on CONNECT, and the upstream
// and the judge see nothing.
func groupsNonMemberDenied(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	_, sales, _ := groupsTokens(h)
	groupsServe(t, h, "eng")

	if got := getStatus(t, h.Agent(), scopedHost, sales); got != http.StatusForbidden {
		t.Fatalf("non-member via X-Warden-Identity = %d, want 403", got)
	}
	if got := h.ConnectStatusWithAuth(scopedHost+":443", "Bearer "+sales); got != http.StatusForbidden {
		t.Fatalf("non-member CONNECT = %d, want 403", got)
	}

	h.Eventually("both refusals are audited as group_not_allowed", func() bool {
		return groupsDenyEvents(h, scopedHost, "group_not_allowed", "valid") == 2
	})
	if n := len(up.Requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	groupsJudgeIdle(t, h)
	if h.MetricsAvailable() {
		// Only the request-level decision is counted; the CONNECT refusal is an
		// audit event alone.
		k := harness.MetricKey("warden.policy.scoped.total", map[string]string{"result": "not_member"})
		if got := h.Metrics()[k]; got != 1 {
			t.Errorf("%s = %v, want 1", k, got)
		}
	}
}

// groupsAnonymousDenied: with no token the CONNECT is admitted (the decision
// is deferred to the request) and each request is refused identity_required,
// on HTTP/1.1 and on h2. Nothing reaches the upstream or the judge.
func groupsAnonymousDenied(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	groupsServe(t, h, "eng")

	if got := getStatus(t, h.Agent(), scopedHost, ""); got != http.StatusForbidden {
		t.Fatalf("anonymous h1 = %d, want 403", got)
	}
	if got := getStatus(t, h.AgentH2(), scopedHost, ""); got != http.StatusForbidden {
		t.Fatalf("anonymous h2 = %d, want 403", got)
	}

	h.Eventually("both refusals are audited as identity_required", func() bool {
		return groupsDenyEvents(h, scopedHost, "identity_required", "") == 2
	})
	if n := len(up.Requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	groupsJudgeIdle(t, h)
	if h.MetricsAvailable() {
		k := harness.MetricKey("warden.policy.scoped.total", map[string]string{"result": "no_identity"})
		if got := h.Metrics()[k]; got != 2 {
			t.Errorf("%s = %v, want 2", k, got)
		}
	}
}

// groupsExpiredDenied: a token past its expiry never opens a scoped host, on
// the request or on CONNECT. The refusal is identity_required and the event
// records identity status expired.
func groupsExpiredDenied(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	_, _, expired := groupsTokens(h)
	groupsServe(t, h, "eng")

	if got := getStatus(t, h.Agent(), scopedHost, expired); got != http.StatusForbidden {
		t.Fatalf("expired via X-Warden-Identity = %d, want 403", got)
	}
	if got := getStatus(t, h.AgentWithProxyToken(expired), scopedHost, ""); got != http.StatusForbidden {
		t.Fatalf("expired via Proxy-Authorization = %d, want 403", got)
	}

	h.Eventually("both refusals are identity_required with status expired", func() bool {
		return groupsDenyEvents(h, scopedHost, "identity_required", "expired") == 2
	})
	if n := len(up.Requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	groupsJudgeIdle(t, h)
}

// groupsKeepaliveMixedUsers: one keep-alive tunnel carries requests from
// different users and each is decided by its own token. eng is forwarded
// twice on the same connection (so the tunnel really is reused), then sales on
// that connection is refused group_not_allowed and the worker ends the session.
func groupsKeepaliveMixedUsers(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	eng, sales, _ := groupsTokens(h)
	groupsServe(t, h, "eng")

	tn, st := groupsConnect(t, h, scopedHost, "")
	if st != http.StatusOK {
		t.Fatalf("anonymous CONNECT = %d, want 200 (the decision is per request)", st)
	}
	tn.startTLS(t, h.AgentTLSConfig())
	for i := 0; i < 2; i++ {
		if got, err := tn.get(eng); err != nil || got != http.StatusOK {
			t.Fatalf("eng request %d on the shared tunnel = %d, %v, want 200", i+1, got, err)
		}
	}
	if got, err := tn.get(sales); err != nil || got != http.StatusForbidden {
		t.Fatalf("sales request on the same tunnel = %d, %v, want 403", got, err)
	}

	h.Eventually("the sales request is audited as group_not_allowed", func() bool {
		return groupsDenyEvents(h, scopedHost, "group_not_allowed", "valid") == 1
	})
	if n := groupsAllowEvents(h, scopedHost, "alice@example.com"); n != 2 {
		t.Errorf("allow events for the eng user = %d, want 2", n)
	}
	if n := len(up.Requests()); n != 2 {
		t.Errorf("upstream saw %d requests, want 2 (eng only)", n)
	}
	groupsNoLeak(t, up)
	groupsJudgeIdle(t, h)
}

// groupsH2PerStream: on one h2 connection every stream is decided by its own
// token, so a refused stream does not poison its neighbours: eng, sales and
// anonymous streams get 200, 403, 403 and a later eng stream on the same
// connection is still served, also when the streams run concurrently.
func groupsH2PerStream(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	eng, sales, _ := groupsTokens(h)
	groupsServe(t, h, "eng")

	cl := h.AgentH2()
	for _, c := range []struct {
		who   string
		token string
		want  int
	}{{"eng", eng, 200}, {"sales", sales, 403}, {"anonymous", "", 403}, {"eng again", eng, 200}} {
		got, proto, err := groupsGet(cl, scopedHost, c.token)
		if err != nil || got != c.want || proto != 2 {
			t.Fatalf("%s stream = %d (h%d), %v, want %d on h2", c.who, got, proto, err, c.want)
		}
	}
	// Concurrent streams on the same connection, mixed users.
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		token, want := eng, 200
		if i%2 == 1 {
			token, want = sales, 403
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, proto, err := groupsGet(cl, scopedHost, token)
			if err != nil || got != want || proto != 2 {
				t.Errorf("concurrent stream = %d (h%d), %v, want %d on h2", got, proto, err, want)
			}
		}()
	}
	wg.Wait()

	h.Eventually("every refused stream is audited with its reason", func() bool {
		return groupsDenyEvents(h, scopedHost, "group_not_allowed", "valid") == 4 &&
			groupsDenyEvents(h, scopedHost, "identity_required", "") == 1
	})
	if n := len(up.Requests()); n != 5 {
		t.Errorf("upstream saw %d requests, want 5 (the eng streams)", n)
	}
	groupsNoLeak(t, up)
	groupsJudgeIdle(t, h)
}

// groupsNoCAConditional: a worker with no TLS-termination CA cannot decide per
// request, so a scoped destination needs a verified member at CONNECT itself:
// no token, an expired token and a non-member are refused (identity_required /
// group_not_allowed) before any tunnel opens; a member gets an opaque tunnel to
// the real upstream; an unscoped destination is tunneled as before.
func groupsNoCAConditional(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	eng, sales, expired := groupsTokens(h)
	groupsServe(t, h, "eng")

	for _, c := range []struct {
		who  string
		auth string
	}{{"anonymous", ""}, {"expired", "Bearer " + expired}, {"non-member", "Bearer " + sales}} {
		if got := h.ConnectStatusWithAuth(scopedHost+":443", c.auth); got != http.StatusForbidden {
			t.Fatalf("%s CONNECT = %d, want 403", c.who, got)
		}
	}
	h.Eventually("the CONNECT refusals are audited with their reasons", func() bool {
		return groupsDenyEvents(h, scopedHost, "identity_required", "") == 2 &&
			groupsDenyEvents(h, scopedHost, "group_not_allowed", "valid") == 1
	})
	if n := len(up.Requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0 before the member", n)
	}
	groupsJudgeIdle(t, h)

	// A member gets an opaque tunnel, valid only until the token expires.
	tn, st := groupsConnect(t, h, scopedHost, "Bearer "+eng)
	if st != http.StatusOK {
		t.Fatalf("member CONNECT = %d, want 200", st)
	}
	// The tunnel is a raw TCP pipe to the upstream; the harness's raw dial
	// reaches the fake's plain-HTTP twin, so speak plain HTTP through it.
	if got, err := tn.get(""); err != nil || got != http.StatusOK {
		t.Fatalf("member request through the opaque tunnel = %d, %v, want 200", got, err)
	}
	if n := len(up.Requests()); n != 1 {
		t.Errorf("upstream saw %d requests, want 1 (the member)", n)
	}
	groupsNoLeak(t, up)

	// An unscoped destination is tunneled with no identity, as before.
	if got := h.ConnectStatusWithAuth(plainHost+":443", ""); got != http.StatusOK {
		t.Errorf("unscoped CONNECT = %d, want 200", got)
	}
	groupsJudgeIdle(t, h)
}

// groupsRawBytesConditional: a CONNECT to a scoped host with no token (a
// Conditional admission) is accepted only because a TLS ClientHello would
// still be decided per request; when the first bytes are not TLS the worker
// cannot decide anything, so it denies identity_required and closes the
// connection. The upstream sees nothing, with or without a member token.
func groupsRawBytesConditional(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	eng, _, _ := groupsTokens(h)
	groupsServe(t, h, "eng")

	for _, c := range []struct {
		who  string
		auth string
	}{{"anonymous", ""}, {"member", "Bearer " + eng}} {
		tn, st := groupsConnect(t, h, scopedHost, c.auth)
		if st != http.StatusOK {
			t.Fatalf("%s CONNECT = %d, want 200", c.who, st)
		}
		if _, err := io.WriteString(tn.conn, "SSH-2.0-not-tls\r\nGET / HTTP/1.1\r\n\r\n"); err != nil {
			t.Fatalf("%s: write the non-TLS bytes: %v", c.who, err)
		}
		// The worker closes the connection without forwarding a byte.
		_ = tn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(tn.br)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("%s: the worker left the connection open", c.who)
		}
		if len(b) != 0 {
			t.Fatalf("%s: connection yielded %d bytes, want a close with no data", c.who, len(b))
		}
	}
	h.Eventually("both tunnels are denied identity_required", func() bool {
		return groupsDenyEvents(h, scopedHost, "identity_required", "") == 2
	})
	if n := len(up.Requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	groupsJudgeIdle(t, h)
}

// groupsTruncated: the verifier keeps at most identity.MaxGroups (64) groups
// of a token. A member present in the kept part is allowed; a user who is not
// in the kept part may still be a member of the dropped part, so the worker
// refuses with identity_groups_truncated rather than the plain non-member
// reason, and records the truncation on the event.
func groupsTruncated(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	// Kept groups are the sorted first 64: token A keeps g00..g63 (g01 is in),
	// token B (g10..g90) keeps g10..g73 (g01 is out).
	names := func(from, to int) []string {
		var g []string
		for i := from; i <= to; i++ {
			g = append(g, fmt.Sprintf("g%02d", i))
		}
		return g
	}
	member := h.MintUserToken(fakes.Valid("tina", "tina@example.com", names(0, 69)...))
	partial := h.MintUserToken(fakes.Valid("tom", "tom@example.com", names(10, 90)...))
	groupsServe(t, h, "g01")

	if got := getStatus(t, h.Agent(), scopedHost, member); got != http.StatusOK {
		t.Fatalf("member in a partial list = %d, want 200", got)
	}
	if got := getStatus(t, h.Agent(), scopedHost, partial); got != http.StatusForbidden {
		t.Fatalf("non-member of a partial list = %d, want 403", got)
	}

	h.Eventually("the refusal is identity_groups_truncated and flagged", func() bool {
		for _, e := range h.Events() {
			if e.Decision == "deny" && e.Domain == scopedHost && e.Reason == "identity_groups_truncated" && e.UserGroupsTruncated {
				return true
			}
		}
		return false
	})
	if n := groupsDenyEvents(h, scopedHost, "group_not_allowed", ""); n != 0 {
		t.Errorf("group_not_allowed denies = %d, want 0: a truncated list is never a plain non-member", n)
	}
	if n := groupsAllowEvents(h, scopedHost, "tina@example.com"); n != 1 {
		t.Errorf("allow events for the member = %d, want 1", n)
	}
	if n := len(up.Requests()); n != 1 {
		t.Errorf("upstream saw %d requests, want 1 (the member)", n)
	}
	groupsNoLeak(t, up)
	groupsJudgeIdle(t, h)
}

// mcpGatedBody is a tools/call for tool.
func mcpGatedBody(tool string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
}

// groupsPostMCP POSTs one tools/call to the fake MCP server.
func groupsPostMCP(cl *http.Client, host, tool, token string) (int, error) {
	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/mcp", strings.NewReader(mcpGatedBody(tool)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// groupsMCPYAML is the MCP block the control plane serves after the scenario
// edits its config: enforce mode, the "pay" tool gated to finance. It is an
// out-of-process edit of the served file (a worker applies settings on change),
// so the scoped condition rides the real projection and the worker's merge.
const groupsMCPYAML = `
mcp:
  enabled: true
  mode: enforce
  tools:
    allow: [pay, lookup]
    constraints:
      pay:
        allowWhen:
          groups: [finance]
`

// groupsMCPOpts serves the scoped allow entry from boot; the scenario adds the
// gated tool with groupsServeMCP.
func groupsMCPOpts() []harness.Option {
	return append(groupsOpts(), harness.WithScopedAllow(scopedHost, "eng"))
}

// groupsServeMCP edits the control plane's served config to add the gated tool.
func groupsServeMCP(h *harness.H) {
	h.EditControlPlaneConfig(func(cur string) string { return cur + groupsMCPYAML })
}

// groupsMCPToolGated: a tool whose allowWhen names the finance group, served by
// the control plane in enforce mode, is forwarded for a finance member and
// denied mcp_tool_condition for an eng member, an anonymous caller and an
// expired token. An ungated tool is unaffected, a denied call never reaches the
// MCP upstream and the judge is never consulted.
func groupsMCPToolGated(t *testing.T, h *harness.H) {
	up := h.FakeMCP()
	host := h.Host("mcp")
	fin := h.MintUserToken(fakes.Valid("fran", "fran@example.com", "finance"))
	eng := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	expired := h.MintUserToken(fakes.Valid("erin", "erin@example.com", "finance"), fakes.Expired())

	groupsServeMCP(h)
	// An unlisted tool is denied only once the worker enforces the settings.
	h.Eventually("the worker enforces the MCP settings", func() bool {
		got, err := groupsPostMCP(h.Agent(), host, "unlisted", fin)
		return err == nil && got == http.StatusForbidden
	})
	before := len(up.Requests())

	allowed, denied := 0, 0
	for _, tc := range []struct {
		name string
		cl   func() *http.Client
	}{{"h1", h.Agent}, {"h2", h.AgentH2}} {
		for _, c := range []struct {
			who, tool, token string
			want             int
		}{
			{"finance", "pay", fin, http.StatusOK},
			{"eng", "pay", eng, http.StatusForbidden},
			{"anonymous", "pay", "", http.StatusForbidden},
			{"expired", "pay", expired, http.StatusForbidden},
			{"eng ungated", "lookup", eng, http.StatusOK},
		} {
			got, err := groupsPostMCP(tc.cl(), host, c.tool, c.token)
			if err != nil || got != c.want {
				t.Errorf("%s %s: status = %d, %v, want %d", tc.name, c.who, got, err, c.want)
			}
			if c.want == http.StatusOK {
				allowed++
			} else {
				denied++
			}
		}
	}
	h.Eventually("an mcp_tool_condition deny per denied call", func() bool {
		n := 0
		for _, e := range h.Events() {
			if e.Decision == "deny" && e.Reason == "mcp_tool_condition" {
				n++
			}
		}
		return n == denied
	})
	reqs := up.Requests()[before:]
	if len(reqs) != allowed {
		t.Errorf("MCP upstream saw %d calls, want %d (denied calls must not reach it)", len(reqs), allowed)
	}
	for i, rq := range reqs {
		if rq.Header.Get("X-Warden-Identity") != "" || rq.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("MCP upstream request %d carried an identity header", i)
		}
	}
	groupsJudgeIdle(t, h)
}

// The frozen pre-GPOL decoder. It is the shape a worker built before group
// policy decodes the control plane's /policy body with: lenient JSON, so a
// "groups"/"users" field on an allow entry, or on an MCP tool condition, is
// silently dropped. Do not add fields to it: it exists to prove the served
// wire alone keeps such a worker from reading a scoped rule as a global one.
type frozenAllow struct {
	Domain string `json:"domain"`
	Port   int    `json:"port"`
}

type frozenCondition struct {
	AgentID    string
	TimeWindow string
}

type frozenConstraint struct {
	AllowWhen *frozenCondition
}

type frozenWire struct {
	Allowlist []frozenAllow `json:"allowlist"`
	Settings  *struct {
		MCP *struct {
			Tools *struct {
				Allow       []string                    `json:"allow"`
				Constraints map[string]frozenConstraint `json:"constraints"`
			} `json:"tools"`
		} `json:"mcp"`
	} `json:"settings"`
}

// groupsOldWorkerDenies: the control plane's real /policy body, loaded through
// the frozen pre-change decoder, denies the scoped host (it matches no rule)
// and the gated tool (its condition names an agent id nobody has), while the
// unscoped host and ungated tool still work. This is the fail-closed wire
// proven end to end: remove the projection and the old worker allows both.
func groupsOldWorkerDenies(t *testing.T, h *harness.H) {
	groupsServeMCP(h)
	var w frozenWire
	h.Eventually("the control plane serves the MCP settings", func() bool {
		status, body, err := h.CP().Do(http.MethodGet, "/policy", h.CP().Token(), nil)
		if err != nil || status != http.StatusOK {
			return false
		}
		w = frozenWire{}
		if err := json.Unmarshal([]byte(body), &w); err != nil {
			t.Fatalf("frozen decoder: %v", err)
		}
		return w.Settings != nil && w.Settings.MCP != nil && w.Settings.MCP.Tools != nil
	})

	// The old worker's evaluator, fed what it decoded.
	pol := config.Policy{}
	for _, a := range w.Allowlist {
		pol.Allowlist = append(pol.Allowlist, config.AllowlistEntry{Domain: a.Domain, Port: a.Port})
	}
	ev := policy.NewEvaluator(pol)
	decide := func(host string) policy.Decision {
		return ev.EvaluateFor(policy.RequestContext{Domain: host, Port: 443, Scheme: policy.SchemeHTTPS}).Decision
	}
	if got := decide(scopedHost); got == policy.Allow || got == policy.Conditional {
		t.Errorf("old worker decision for the scoped host = %v, want a deny (no matching rule)", got)
	}
	if got := decide("api.example.com"); got != policy.Allow {
		t.Errorf("old worker decision for an unscoped host = %v, want Allow", got)
	}

	// The old worker's MCP gateway, fed what it decoded.
	cons := map[string]config.MCPToolConstraints{}
	for tool, c := range w.Settings.MCP.Tools.Constraints {
		if c.AllowWhen != nil {
			cons[tool] = config.MCPToolConstraints{AllowWhen: &config.MCPToolCondition{AgentID: c.AllowWhen.AgentID, TimeWindow: c.AllowWhen.TimeWindow}}
		}
	}
	gw := gateway.New(config.MCPConfig{
		Enabled: true,
		Mode:    "enforce",
		Tools:   config.MCPToolsConfig{Allow: w.Settings.MCP.Tools.Allow, Constraints: cons},
	}, scan.NewScanner(), nil, gateway.WithAgentID("agent-1"))
	t.Cleanup(func() { _ = gw.Close() })
	call := func(tool string) gateway.Action {
		hdr := http.Header{"Content-Type": []string{"application/json"}}
		return gw.OnRequest("old-worker", http.MethodPost, "https://"+h.Host("mcp")+"/mcp", hdr, []byte(mcpGatedBody(tool)), gateway.RequestMeta{}).Action
	}
	if got := call("pay"); got != gateway.Deny {
		t.Errorf("old worker action for the gated tool = %v, want Deny", got)
	}
	if got := call("lookup"); got != gateway.Pass {
		t.Errorf("old worker action for the ungated tool = %v, want Pass", got)
	}
}

// groupsPolicyEvalAffectedUsers: real traffic from three verified users (two in
// eng, one in sales) and one anonymous request is recorded, then replayed
// against a candidate that drops eng from the scoped rule. The replay lists
// exactly the two eng users it would cut off, by email and sorted, never the
// sales user, and carries no token or group.
func groupsPolicyEvalAffectedUsers(t *testing.T, h *harness.H) {
	h.Upstream(scopedHost)
	h.Upstream(plainHost)
	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	bob := h.MintUserToken(fakes.Valid("bob", "bob@example.com", "eng"))
	sam := h.MintUserToken(fakes.Valid("sam", "sam@example.com", "sales"))
	groupsServe(t, h, "eng", "sales")

	for _, tok := range []string{alice, bob, sam} {
		if got := getStatus(t, h.Agent(), scopedHost, tok); got != http.StatusOK {
			t.Fatalf("scoped request = %d, want 200", got)
		}
	}
	if got := getStatus(t, h.Agent(), plainHost, ""); got != http.StatusOK {
		t.Fatalf("anonymous plain request = %d, want 200", got)
	}
	h.Eventually("the identities are recorded", func() bool {
		n := 0
		for _, e := range h.Events() {
			if e.Domain == scopedHost && e.IdentityStatus == "valid" && e.Decision == "allow" {
				n++
			}
		}
		return n == 3
	})

	candidate := config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: scopedHost, Groups: []string{"sales"}},
		{Domain: plainHost},
	}}
	var recorded []analytics.Event
	for _, e := range h.Events() {
		if e.Method == http.MethodGet {
			recorded = append(recorded, e)
		}
	}
	res := policyeval.Evaluate(recorded, candidate)
	var users []string
	for _, d := range res.NewDenies {
		users = append(users, d.AffectedUsers...)
	}
	if got := strings.Join(users, ","); got != "alice@example.com,bob@example.com" {
		t.Errorf("affected users = %q, want alice@example.com,bob@example.com (eng only)", got)
	}
	if got := fmt.Sprintf("%+v", res); strings.Contains(got, "sam@example.com") || strings.Contains(got, alice) || strings.Contains(got, "eng") {
		t.Errorf("replay result names the sales user or carries a token or group list: %s", got)
	}
}
