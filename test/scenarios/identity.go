package scenarios

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The identity attribution scenarios (W-P1-VRFY-05, feature p1-verify-token):
// a real worker and control plane, the in-process OIDC issuer fake as the IdP,
// the harness's fake upstream as the recorder. They prove, through Warden's own
// outputs only, that a user token presented as Proxy-Authorization on CONNECT or
// as X-Warden-Identity on terminated HTTP/1.1 and HTTP/2 is verified and
// recorded on the event, the signed receipt and the decision log; that every
// outcome is allowed (attribute mode never blocks); that neither header ever
// reaches an upstream; and that no token string appears in any output.
//
// Tokens are never printed: failure messages name the case, not the value.

const (
	identityHost = "api.example.com"
	// identityDenyHost is not on the allowlist, so a CONNECT to it is a policy
	// deny the identity must still be attributed on.
	identityDenyHost = "sneaky.example.test"
)

// identityOpts boots attribute mode: the worker verifies against the issuer fake.
func identityOpts() []harness.Option {
	return []harness.Option{harness.WithIdentity(config.IdentityModeAttribute)}
}

// --- tokens ---

// idToken is one credential a scenario presents, with what Warden must record.
type idToken struct {
	name   string
	tok    string // "" = no token at all
	status string
	reason string
	// sub/email/groups are expected only for status valid; every other status
	// must leave the user fields empty.
	sub, email string
	groups     []string
}

// idCases are the five single-token outcomes, each with its own subject so an
// event can be matched back to its case.
func idCases(h *harness.H) []idToken {
	return []idToken{
		{name: "valid", tok: h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng", "ops")),
			status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng", "ops"}},
		{name: "expired", tok: h.MintUserToken(fakes.Valid("erin", "erin@example.com"), fakes.Expired()),
			status: "expired"},
		{name: "wrong_aud", tok: h.MintUserToken(fakes.Valid("walt", "walt@example.com"), fakes.WrongAudience()),
			status: "invalid", reason: "wrong_aud"},
		{name: "wrong_azp", tok: h.MintUserToken(fakes.Valid("zed", "zed@example.com"), fakes.WrongAZP()),
			status: "invalid", reason: "wrong_azp"},
		{name: "none", status: "none"},
	}
}

// --- the transports ---

// idTransport is one way to present a token to a terminated HTTP request.
type idTransport struct {
	name string
	h2   bool
	// viaConnect presents the token as Proxy-Authorization on CONNECT;
	// otherwise as X-Warden-Identity on the request.
	viaConnect bool
}

var idTransports = []idTransport{
	{name: "connect_h1", viaConnect: true},
	{name: "connect_h2", h2: true, viaConnect: true},
	{name: "header_h1"},
	{name: "header_h2", h2: true},
}

// get sends one GET for path through the worker carrying c's token and returns
// the response status. It fails the test when the request does not ride the
// protocol the transport names.
func (tr idTransport) get(t *testing.T, h *harness.H, c idToken, path string) int {
	t.Helper()
	var cl *http.Client
	switch {
	case tr.viaConnect && c.tok != "" && tr.h2:
		cl = h.AgentH2WithProxyToken(c.tok)
	case tr.viaConnect && c.tok != "":
		cl = h.AgentWithProxyToken(c.tok)
	case tr.h2:
		cl = h.AgentH2()
	default:
		cl = h.Agent()
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.viaConnect && c.tok != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+c.tok)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("%s/%s: GET: %v", tr.name, c.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if tr.h2 != (resp.ProtoMajor == 2) {
		t.Fatalf("%s/%s: response protocol %s, want h2=%v", tr.name, c.name, resp.Proto, tr.h2)
	}
	return resp.StatusCode
}

// identityMatrix is the case table for one transport: valid, expired, wrong
// audience, wrong azp and no token, each answered by the upstream's 200, each
// recorded with the expected status on the event, the signed receipt and the
// decision log, and counted once in warden.identity.verify.total.
func identityMatrix(tr idTransport) func(*testing.T, *harness.H) {
	return func(t *testing.T, h *harness.H) {
		up := h.Upstream(identityHost)
		cases := idCases(h)
		for _, c := range cases {
			if got := tr.get(t, h, c, "/"+c.name); got != http.StatusOK {
				t.Fatalf("%s/%s: status %d, want the upstream's 200 (attribute mode never blocks)", tr.name, c.name, got)
			}
		}

		evs := h.Events()
		if len(evs) != len(cases) {
			t.Fatalf("%s: %d events, want %d (one per request)", tr.name, len(evs), len(cases))
		}
		receipts := h.Receipts()
		for _, c := range cases {
			url := "https://" + identityHost + "/" + c.name
			assertIdentityEvent(t, tr.name+"/"+c.name, only(t, evs, url), c, "allow")
			assertIdentityEvent(t, tr.name+"/"+c.name+" receipt", only(t, receipts, url), c, "allow")
			assertDecisionLog(t, h, url, c)
		}

		assertVerifyCounts(t, h, map[[2]string]float64{
			{"valid", "none"}:        1,
			{"expired", "none"}:      1,
			{"invalid", "wrong_aud"}: 1,
			{"invalid", "wrong_azp"}: 1,
			{"none", "none"}:         1,
		})
		assertUpstreamClean(t, up, len(cases))
		assertNoTokenLeak(t, h, cases, up)
	}
}

// --- oracles ---

// only returns the single event whose URL is url.
func only(t *testing.T, evs []analytics.Event, url string) analytics.Event {
	t.Helper()
	var hit []analytics.Event
	for _, e := range evs {
		if e.URL == url {
			hit = append(hit, e)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%d events for %s, want exactly 1", len(hit), url)
	}
	return hit[0]
}

// eventStatus is the identity_status an event stores for c. A caller with no
// token (status none) is stored unstamped, so an unattributed event stays
// byte-identical to one written before identity existed (W-P1-VRFY-09); the
// "none" outcome is visible in warden.identity.verify.total instead.
func eventStatus(c idToken) string {
	if c.status == "none" {
		return ""
	}
	return c.status
}

// assertIdentityEvent checks one event (or the event a receipt signed) against
// what the case must record. Only status valid carries user fields.
func assertIdentityEvent(t *testing.T, what string, e analytics.Event, c idToken, decision string) {
	t.Helper()
	if e.Decision != decision {
		t.Errorf("%s: decision %q, want %q", what, e.Decision, decision)
	}
	if want := eventStatus(c); e.IdentityStatus != want {
		t.Errorf("%s: identity_status %q, want %q", what, e.IdentityStatus, want)
	}
	if e.IdentityReason != c.reason {
		t.Errorf("%s: identity_reason %q, want %q", what, e.IdentityReason, c.reason)
	}
	if e.UserSub != c.sub || e.UserEmail != c.email || strings.Join(e.UserGroups, ",") != strings.Join(c.groups, ",") {
		t.Errorf("%s: user fields (sub %q, email %q, groups %v), want (%q, %q, %v): only a valid token attributes a user",
			what, e.UserSub, e.UserEmail, e.UserGroups, c.sub, c.email, c.groups)
	}
	if e.UserSID != "" {
		t.Errorf("%s: user_sid %q, want empty", what, e.UserSID)
	}
}

// decisionLogRecords returns the structured "egress decision" records matching
// match, parsed from the worker's JSON log.
func decisionLogRecords(t *testing.T, h *harness.H, match func(map[string]any) bool) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(h.Logs(), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec["msg"] == "egress decision" && match(rec) {
			out = append(out, rec)
		}
	}
	return out
}

// assertDecisionLog checks the decision log line of the request for url: it
// names the identity status (and reason), the user's sub only for valid, and
// never the email or group list (those are debug-level).
func assertDecisionLog(t *testing.T, h *harness.H, url string, c idToken) {
	t.Helper()
	recs := decisionLogRecords(t, h, func(r map[string]any) bool { return r["url"] == url })
	if len(recs) != 1 {
		t.Fatalf("%s: %d decision log lines for %s, want 1", c.name, len(recs), url)
	}
	assertDecisionRecord(t, recs[0], c)
}

func assertDecisionRecord(t *testing.T, rec map[string]any, c idToken) {
	t.Helper()
	// A caller with no token logs no identity attributes at all.
	wantStatus := eventStatus(c)
	if got, _ := rec["identity_status"].(string); got != wantStatus {
		t.Errorf("%s: log identity_status %q, want %q", c.name, got, wantStatus)
	}
	if got, _ := rec["identity_reason"].(string); got != c.reason {
		t.Errorf("%s: log identity_reason %q, want %q", c.name, got, c.reason)
	}
	if got, _ := rec["user_sub"].(string); got != c.sub {
		t.Errorf("%s: log user_sub %q, want %q", c.name, got, c.sub)
	}
	if _, ok := rec["user_email"]; ok {
		t.Errorf("%s: the info-level decision log carries user_email", c.name)
	}
	if _, ok := rec["user_groups"]; ok {
		t.Errorf("%s: the info-level decision log carries user_groups", c.name)
	}
}

// verifyMetric is the counter every outcome increments.
const verifyMetric = "warden.identity.verify.total"

// verifyCounts reads warden.identity.verify.total as {result, reason} -> count.
func verifyCounts(h *harness.H) map[[2]string]float64 {
	out := map[[2]string]float64{}
	for k, v := range h.Metrics() {
		if !strings.HasPrefix(k, verifyMetric+"{") {
			continue
		}
		labels := map[string]string{}
		for _, kv := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(k, verifyMetric+"{"), "}"), ",") {
			name, val, _ := strings.Cut(kv, "=")
			labels[name] = val
		}
		out[[2]string{labels["result"], labels["reason"]}] = v
	}
	return out
}

// assertVerifyCounts compares the whole verify counter to want: every series
// that should exist exists with that count and none else does. Skipped
// explicitly on a target that exports no metrics.
func assertVerifyCounts(t *testing.T, h *harness.H, want map[[2]string]float64) {
	t.Helper()
	if !h.MetricsAvailable() {
		t.Log("this target exports no metrics; skipping the warden.identity.verify.total assertion")
		return
	}
	got := verifyCounts(h)
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s{result=%s,reason=%s} = %v, want %v", verifyMetric, k[0], k[1], got[k], w)
		}
	}
	for k, g := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected %s{result=%s,reason=%s} = %v", verifyMetric, k[0], k[1], g)
		}
	}
}

// assertUpstreamClean fails when the upstream saw other than n requests or any
// request carrying either identity header. The strip is unconditional: it holds
// in every mode, including off.
func assertUpstreamClean(t *testing.T, up *harness.Upstream, n int) {
	t.Helper()
	if got := len(up.Requests()); got != n {
		t.Errorf("upstream saw %d requests, want %d", got, n)
	}
	assertNoIdentityHeaders(t, up)
}

// assertNoIdentityHeaders is assertUpstreamClean for a scenario whose request
// count is not fixed (it polls until a reload lands).
func assertNoIdentityHeaders(t *testing.T, up *harness.Upstream) {
	t.Helper()
	for _, r := range up.Requests() {
		for _, name := range []string{"Proxy-Authorization", "X-Warden-Identity"} {
			if v := r.Header.Values(name); len(v) > 0 {
				t.Errorf("upstream request %s carries %s", r.Path, name)
			}
		}
	}
}

// leakNeedles are the strings that must appear nowhere: each token, its payload
// and signature segments, and the Basic credential the proxy-URL form encodes.
func leakNeedles(tokens []string) []string {
	var out []string
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		out = append(out, tok, base64.StdEncoding.EncodeToString([]byte("session:"+tok)))
		if parts := strings.Split(tok, "."); len(parts) == 3 {
			out = append(out, parts[1], parts[2])
		}
	}
	return out
}

// assertNoTokenLeak fails when any token (or a piece of one) appears in the
// logs, the events, the signed receipts, the metrics or anything an upstream
// recorded. The failure names the surface, never the token.
func assertNoTokenLeak(t *testing.T, h *harness.H, cases []idToken, ups ...*harness.Upstream) {
	t.Helper()
	toks := make([]string, 0, len(cases))
	for _, c := range cases {
		toks = append(toks, c.tok)
	}
	assertNoLeakOf(t, h, toks, ups...)
}

func assertNoLeakOf(t *testing.T, h *harness.H, tokens []string, ups ...*harness.Upstream) {
	t.Helper()
	needles := leakNeedles(tokens)
	surfaces := map[string]string{"logs": h.Logs()}
	evJSON, _ := json.Marshal(h.Events())
	surfaces["events"] = string(evJSON)
	rcJSON, _ := json.Marshal(h.Receipts())
	surfaces["receipts"] = string(rcJSON)
	if h.MetricsAvailable() {
		var keys []string
		for k := range h.Metrics() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		surfaces["metrics"] = strings.Join(keys, "\n")
	}
	for i, up := range ups {
		reqJSON, _ := json.Marshal(up.Requests())
		surfaces[fmt.Sprintf("upstream %d requests", i+1)] = string(reqJSON)
	}
	for name, body := range surfaces {
		for _, n := range needles {
			if strings.Contains(body, n) {
				t.Errorf("a token (or part of one) appears in the %s", name)
				break
			}
		}
	}
}

// --- raw CONNECT helpers ---

// basicAuth is the Proxy-Authorization value the proxy-URL form produces.
func basicAuth(user, tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+tok))
}

// dialConnect opens a CONNECT to hostPort presenting auth verbatim ("" sends no
// header) and returns the connection past the reply, the reply's status and a
// reader positioned after it.
func dialConnect(t *testing.T, h *harness.H, hostPort, auth string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostPort, hostPort)
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	if _, err := fmt.Fprint(conn, req+"\r\n"); err != nil {
		t.Fatalf("send CONNECT %s: %v", hostPort, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read the CONNECT %s reply: %v", hostPort, err)
	}
	_ = resp.Body.Close()
	return conn, br, resp.StatusCode
}

// --- scenarios ---

// identityRawTunnel: a tunnel Warden does not terminate (the first bytes are
// not a TLS hello) carries no per-request header, so only the CONNECT identity
// attributes it. The tunnel event is the one decision recorded, stamped with the
// CONNECT result.
func identityRawTunnel(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	cases := idCases(h)
	for _, c := range cases {
		auth := ""
		if c.tok != "" {
			auth = basicAuth("session", c.tok)
		}
		conn, br, status := dialConnect(t, h, identityHost+":443", auth)
		if status != http.StatusOK {
			t.Fatalf("%s: CONNECT = %d, want 200", c.name, status)
		}
		// Not a TLS hello: the worker pipes it as an opaque tunnel.
		_, _ = fmt.Fprint(conn, "plain bytes, not TLS\r\n\r\n")
		_, _ = io.Copy(io.Discard, br)
		_ = conn.Close()
	}

	evs := h.Events()
	if len(evs) != len(cases) {
		t.Fatalf("%d tunnel events, want %d", len(evs), len(cases))
	}
	for _, c := range cases {
		e := bySubOrStatus(t, evs, c)
		assertIdentityEvent(t, "tunnel/"+c.name, e, c, "allow")
		if e.Protocol != "tcp" {
			t.Errorf("tunnel/%s: protocol %q, want tcp (an opaque tunnel)", c.name, e.Protocol)
		}
	}
	for _, c := range cases {
		recs := decisionLogRecords(t, h, func(r map[string]any) bool {
			return r["protocol"] == "tcp" && r["identity_status"] == statusOrAbsent(c) &&
				r["identity_reason"] == reasonOrAbsent(c) && r["user_sub"] == subOrAbsent(c)
		})
		if len(recs) != 1 {
			t.Errorf("tunnel/%s: %d matching decision log lines, want 1", c.name, len(recs))
			continue
		}
		assertDecisionRecord(t, recs[0], c)
	}
	assertVerifyCounts(t, h, map[[2]string]float64{
		{"valid", "none"}:        1,
		{"expired", "none"}:      1,
		{"invalid", "wrong_aud"}: 1,
		{"invalid", "wrong_azp"}: 1,
	})
	assertUpstreamClean(t, up, 0)
	assertNoTokenLeak(t, h, cases, up)
}

// bySubOrStatus finds the one event of a case that has no URL to key on: by its
// sub when valid, else by status and reason.
func bySubOrStatus(t *testing.T, evs []analytics.Event, c idToken) analytics.Event {
	t.Helper()
	var hit []analytics.Event
	for _, e := range evs {
		switch {
		case c.sub != "" && e.UserSub == c.sub:
			hit = append(hit, e)
		case c.sub == "" && e.IdentityStatus == eventStatus(c) && e.IdentityReason == c.reason:
			hit = append(hit, e)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%d events for case %s, want exactly 1", len(hit), c.name)
	}
	return hit[0]
}

func statusOrAbsent(c idToken) any {
	if c.status == "none" {
		return nil
	}
	return c.status
}

func reasonOrAbsent(c idToken) any {
	if c.reason == "" {
		return nil
	}
	return c.reason
}

func subOrAbsent(c idToken) any {
	if c.sub == "" {
		return nil
	}
	return c.sub
}

// identityConflict: a valid CONNECT identity plus a valid header with a
// DIFFERENT sub is a conflict (no user, no subject, still allowed); the same sub
// stays valid; a header that is not one well-formed Bearer value is invalid
// (malformed) even next to the live CONNECT identity.
func identityConflict(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	bob := h.MintUserToken(fakes.Valid("bob", "bob@example.com"))

	do := func(path, header string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			req.Header.Set("X-Warden-Identity", header)
		}
		resp, err := h.AgentWithProxyToken(alice).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, want 200 (attribute mode never blocks, not even on a conflict)", path, resp.StatusCode)
		}
	}
	do("/same_sub", "Bearer "+alice)
	do("/conflict", "Bearer "+bob)
	do("/connect_only", "")
	do("/malformed_header", "Basic not-a-bearer-value")

	valid := idToken{name: "valid", status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng"}}
	conflict := idToken{name: "conflict", status: "conflict"}
	malformed := idToken{name: "malformed", status: "invalid", reason: "malformed"}
	evs := h.Events()
	receipts := h.Receipts()
	for path, c := range map[string]idToken{"/same_sub": valid, "/connect_only": valid, "/conflict": conflict, "/malformed_header": malformed} {
		url := "https://" + identityHost + path
		assertIdentityEvent(t, path, only(t, evs, url), c, "allow")
		assertIdentityEvent(t, path+" receipt", only(t, receipts, url), c, "allow")
		assertDecisionLog(t, h, url, c)
	}
	assertVerifyCounts(t, h, map[[2]string]float64{
		// 4 CONNECTs (one per client) + the same-sub header + bob's header.
		{"valid", "none"}:        6,
		{"conflict", "none"}:     1,
		{"invalid", "malformed"}: 1,
	})
	assertUpstreamClean(t, up, 4)
	assertNoLeakOf(t, h, []string{alice, bob}, up)
}

// identityDenyAttributed: the CONNECT credential forms a client library will not produce
// (Bearer, a wrong username, garbage, duplicate lines), on a CONNECT the policy
// denies. The deny event, the metric and the decision log all carry the identity
// result, and the deny is still the policy's 403: identity never turns a deny
// into an allow or the reverse.
func identityDenyAttributed(t *testing.T, h *harness.H) {
	mint := func(sub string, opts ...fakes.MintOption) string {
		return h.MintUserToken(append([]fakes.MintOption{fakes.Valid(sub, sub+"@example.com", "eng")}, opts...)...)
	}
	bearerTok, basicTok := mint("bob"), mint("carol")
	expiredTok := mint("erin", fakes.Expired())
	audTok := mint("walt", fakes.WrongAudience())
	userTok := mint("mallory")
	dupTok := mint("dave")

	type row struct {
		auth string
		want idToken
	}
	rows := []row{
		{"Bearer " + bearerTok, idToken{name: "bearer", status: "valid", sub: "bob", email: "bob@example.com", groups: []string{"eng"}}},
		{basicAuth("session", basicTok), idToken{name: "basic", status: "valid", sub: "carol", email: "carol@example.com", groups: []string{"eng"}}},
		{basicAuth("session", expiredTok), idToken{name: "expired", status: "expired"}},
		{basicAuth("session", audTok), idToken{name: "wrong_aud", status: "invalid", reason: "wrong_aud"}},
		{basicAuth("someone-else", userTok), idToken{name: "wrong_username", status: "invalid", reason: "malformed"}},
		{"Basic !!!not-base64", idToken{name: "garbage", status: "invalid", reason: "malformed"}},
		// Two Proxy-Authorization lines are one malformed credential, never verified.
		{"Bearer " + dupTok + "\r\nProxy-Authorization: Bearer " + dupTok, idToken{name: "duplicate", status: "invalid", reason: "malformed"}},
		{"", idToken{name: "none", status: "none"}},
	}
	var tokens []string
	for _, r := range rows {
		if got := h.ConnectStatusWithAuth(identityDenyHost+":443", r.auth); got != http.StatusForbidden {
			t.Fatalf("%s: CONNECT = %d, want the policy's 403", r.want.name, got)
		}
	}
	tokens = append(tokens, bearerTok, basicTok, expiredTok, audTok, userTok, dupTok)

	evs := h.Events()
	if len(evs) != len(rows) {
		t.Fatalf("%d deny events, want %d", len(evs), len(rows))
	}
	// Valid rows match by sub; the rest by (status, reason), where the three
	// malformed rows are indistinguishable, so compare them as a group.
	got := map[string]int{}
	for _, e := range evs {
		if e.Domain != identityDenyHost {
			t.Errorf("event for %q, want the denied host", e.Domain)
		}
		got[e.Decision+"|"+e.IdentityStatus+"|"+e.IdentityReason+"|"+e.UserSub]++
	}
	want := map[string]int{}
	for _, r := range rows {
		want["deny|"+eventStatus(r.want)+"|"+r.want.reason+"|"+r.want.sub]++
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("deny events by decision|status|reason|sub = %v, want %v", got, want)
	}
	for _, r := range rows {
		if r.want.sub != "" {
			assertIdentityEvent(t, "deny/"+r.want.name, bySubOrStatus(t, evs, r.want), r.want, "deny")
		}
	}
	// The deny's decision log line names the user and status, at warn.
	for _, r := range rows {
		if r.want.sub == "" {
			continue
		}
		recs := decisionLogRecords(t, h, func(rec map[string]any) bool { return rec["user_sub"] == r.want.sub })
		if len(recs) != 1 {
			t.Errorf("deny/%s: %d decision log lines for the user, want 1", r.want.name, len(recs))
			continue
		}
		if recs[0]["level"] != "WARN" || recs[0]["decision"] != "deny" {
			t.Errorf("deny/%s: log line %v/%v, want a WARN deny", r.want.name, recs[0]["level"], recs[0]["decision"])
		}
		assertDecisionRecord(t, recs[0], r.want)
	}
	assertVerifyCounts(t, h, map[[2]string]float64{
		{"valid", "none"}:        2,
		{"expired", "none"}:      1,
		{"invalid", "wrong_aud"}: 1,
		{"invalid", "malformed"}: 3,
	})
	assertNoLeakOf(t, h, tokens)
}

// identityOff: with the default mode off a token is only noted. Nothing is
// verified (no metric series, the issuer is never contacted), no user is
// recorded, the status is off, and the headers are still stripped.
func identityOff(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	tok := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	for _, x := range idTransports {
		if got := x.get(t, h, idToken{name: "off", tok: tok}, "/"+x.name); got != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", x.name, got)
		}
	}
	if got := (idTransports[2]).get(t, h, idToken{name: "none"}, "/no_token"); got != http.StatusOK {
		t.Fatalf("no token: status %d, want 200", got)
	}

	evs := h.Events()
	off := idToken{name: "off", status: "off"}
	for _, x := range idTransports {
		url := "https://" + identityHost + "/" + x.name
		assertIdentityEvent(t, x.name, only(t, evs, url), off, "allow")
		assertIdentityEvent(t, x.name+" receipt", only(t, h.Receipts(), url), off, "allow")
		assertDecisionLog(t, h, url, off)
	}
	assertIdentityEvent(t, "no_token", only(t, evs, "https://"+identityHost+"/no_token"), idToken{name: "none", status: "none"}, "allow")

	assertVerifyCounts(t, h, map[[2]string]float64{})
	if n := h.Issuer().JWKSRequests() + h.Issuer().DiscoveryRequests(); n != 0 {
		t.Errorf("the issuer served %d requests in mode off, want 0: nothing is verified", n)
	}
	assertUpstreamClean(t, up, 5)
	assertNoLeakOf(t, h, []string{tok}, up)
}

// identityIssuerDown: the issuer is unreachable and the worker's key cache is
// cold, so a presented token cannot be checked. The request still succeeds
// (identity is never a gate in attribute mode), the status is unverified with
// reason jwks_unavailable, and no user is recorded. Once the issuer is back the
// same token verifies.
func identityIssuerDown(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	iss := h.Issuer()
	if iss.JWKSRequests() != 0 {
		t.Fatal("the worker fetched keys at boot; the cache is not cold")
	}
	iss.Stop()
	tok := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	down := idToken{name: "unverified", status: "unverified", reason: "jwks_unavailable"}
	for _, tr := range []idTransport{idTransports[0], idTransports[2]} {
		down.tok = tok
		if got := tr.get(t, h, down, "/down_"+tr.name); got != http.StatusOK {
			t.Fatalf("%s: status %d with the issuer down, want 200", tr.name, got)
		}
	}
	for _, name := range []string{"down_connect_h1", "down_header_h1"} {
		url := "https://" + identityHost + "/" + name
		assertIdentityEvent(t, name, only(t, h.Events(), url), down, "allow")
		assertIdentityEvent(t, name+" receipt", only(t, h.Receipts(), url), down, "allow")
		assertDecisionLog(t, h, url, down)
	}
	assertVerifyCounts(t, h, map[[2]string]float64{{"unverified", "jwks_unavailable"}: 2})

	// The key cache retries a failed fetch at most once per 30s of real time, so
	// a restarted issuer is picked up by a rebuilt verifier (any verifier input
	// moving rebuilds it) rather than by waiting; the rebuild fetches at once.
	iss.Start()
	if err := editIdentity(t, h, func(s *config.IdentitySettings) { s.ClockSkewSeconds = 30 }); err != nil {
		t.Fatalf("change the clock skew: %v", err)
	}
	valid := idToken{name: "valid", tok: tok, status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng"}}
	n := 0
	h.Eventually("the rebuilt verifier to fetch keys from the restored issuer", func() bool {
		n++
		path := fmt.Sprintf("/recovered_%d", n)
		if got := idTransports[2].get(t, h, valid, path); got != http.StatusOK {
			t.Fatalf("recovery request: status %d, want 200", got)
		}
		return only(t, h.Events(), "https://"+identityHost+path).IdentityStatus == "valid"
	})
	assertNoIdentityHeaders(t, up)
	assertNoLeakOf(t, h, []string{tok}, up)
}

// identityWebSocket: the upgrade handshake is a terminated HTTP request, so it
// attributes through either door. The 101 completes, the handshake event
// carries the identity, and neither header reaches the upstream.
func identityWebSocket(t *testing.T, h *harness.H) {
	up := h.FakeWS()
	cases := idCases(h)
	type door struct {
		name       string
		viaConnect bool
	}
	doors := []door{{"connect", true}, {"header", false}}
	for _, d := range doors {
		for _, c := range cases {
			auth, hdr := "", ""
			if c.tok != "" && d.viaConnect {
				auth = basicAuth("session", c.tok)
			}
			if c.tok != "" && !d.viaConnect {
				hdr = "X-Warden-Identity: Bearer " + c.tok + "\r\n"
			}
			conn, _, status := dialConnect(t, h, "ws.example.com:443", auth)
			if status != http.StatusOK {
				t.Fatalf("ws/%s/%s: CONNECT = %d, want 200", d.name, c.name, status)
			}
			cfg := h.AgentTLSConfig()
			cfg.ServerName = "ws.example.com"
			tc := tls.Client(conn, cfg)
			if err := tc.Handshake(); err != nil {
				t.Fatalf("ws/%s/%s: TLS handshake with the worker: %v", d.name, c.name, err)
			}
			fmt.Fprintf(tc, "GET /ws?case=%s-%s HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://ws.example.com\r\n%s\r\n",
				d.name, c.name, hdr)
			resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
			if err != nil {
				t.Fatalf("ws/%s/%s: read the upgrade reply: %v", d.name, c.name, err)
			}
			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("ws/%s/%s: upgrade = %d, want 101 (attribute mode never blocks)", d.name, c.name, resp.StatusCode)
			}
			_ = tc.Close()
		}
	}

	// A WebSocket's event is written when its stream ends, which the worker sees
	// a moment after the client closes; wait for all of them.
	want := len(doors) * len(cases)
	h.Eventually("every handshake event to be recorded", func() bool { return len(h.Events()) == want })
	evs := h.Events()
	receipts := h.Receipts()
	for _, d := range doors {
		for _, c := range cases {
			url := fmt.Sprintf("https://ws.example.com/ws?case=%s-%s", d.name, c.name)
			assertIdentityEvent(t, "ws/"+d.name+"/"+c.name, only(t, evs, url), c, "allow")
			assertIdentityEvent(t, "ws/"+d.name+"/"+c.name+" receipt", only(t, receipts, url), c, "allow")
			assertDecisionLog(t, h, url, c)
		}
	}
	assertVerifyCounts(t, h, map[[2]string]float64{
		{"valid", "none"}:        2,
		{"expired", "none"}:      2,
		{"invalid", "wrong_aud"}: 2,
		{"invalid", "wrong_azp"}: 2,
		{"none", "none"}:         2, // the header door counts the empty one per request
	})
	assertUpstreamClean(t, up, len(doors)*len(cases))
	assertNoTokenLeak(t, h, cases, up)
}

// identityTransparent: with no CONNECT there is no Proxy-Authorization to read,
// so only X-Warden-Identity on terminated traffic attributes. A request with no
// header records none, even when it carries a Proxy-Authorization with a valid
// token (which is not consulted, and is stripped like everywhere else).
func identityTransparent(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	cases := idCases(h)
	send := func(path string, c idToken, proxyAuth string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.tok != "" {
			req.Header.Set("X-Warden-Identity", "Bearer "+c.tok)
		}
		if proxyAuth != "" {
			req.Header.Set("Proxy-Authorization", proxyAuth)
		}
		resp, err := h.TransparentAgent().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", path, resp.StatusCode)
		}
	}
	for _, c := range cases {
		send("/"+c.name, c, "")
	}
	// Proxy-Authorization with a valid token, no X-Warden-Identity: not consulted.
	send("/proxy_auth_only", idToken{name: "none"}, basicAuth("session", cases[0].tok))

	evs := h.Events()
	receipts := h.Receipts()
	for _, c := range cases {
		url := "https://" + identityHost + "/" + c.name
		assertIdentityEvent(t, "transparent/"+c.name, only(t, evs, url), c, "allow")
		assertIdentityEvent(t, "transparent/"+c.name+" receipt", only(t, receipts, url), c, "allow")
		assertDecisionLog(t, h, url, c)
	}
	none := idToken{name: "none", status: "none"}
	assertIdentityEvent(t, "transparent/proxy_auth_only", only(t, evs, "https://"+identityHost+"/proxy_auth_only"), none, "allow")
	assertVerifyCounts(t, h, map[[2]string]float64{
		{"valid", "none"}:        1,
		{"expired", "none"}:      1,
		{"invalid", "wrong_aud"}: 1,
		{"invalid", "wrong_azp"}: 1,
		{"none", "none"}:         2, // the no-header case and the Proxy-Authorization-only case
	})
	assertUpstreamClean(t, up, len(cases)+1)
	assertNoTokenLeak(t, h, cases, up)
}

// editIdentity read-modify-writes the control plane's settings document: edit
// changes the identity block, the rest is posted back as read. The error is the
// control plane's refusal, if any; the workers pick an accepted change up live.
func editIdentity(t *testing.T, h *harness.H, edit func(*config.IdentitySettings)) error {
	t.Helper()
	var cur struct {
		Settings *config.SettingsWire `json:"settings"`
	}
	if err := h.CP().GetJSON("/dashboard/api/settings", &cur); err != nil {
		t.Fatalf("read the distributed settings: %v", err)
	}
	if cur.Settings == nil || cur.Settings.Identity == nil {
		t.Fatal("the control plane distributes no identity block")
	}
	edit(cur.Settings.Identity)
	return h.CP().PostJSON("/dashboard/api/settings", cur.Settings, nil)
}

// identityHotReload: identity settings are distributed by the control plane and
// applied live. Without a restart: mode off stops attributing (and verifying),
// attribute resumes it, a changed audience rebuilds the verifier so a token for
// the old audience is rejected, and a settings document the control plane
// refuses leaves the running config untouched. Proven through events and
// metrics only; the proxy has no identity getter.
func identityHotReload(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	tok := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	newAud := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"), fakes.WithAud("warden-v2"))
	valid := idToken{name: "valid", tok: tok, status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng"}}

	probe := func(path string) analytics.Event {
		t.Helper()
		if got := idTransports[2].get(t, h, valid, path); got != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", path, got)
		}
		return only(t, h.Events(), "https://"+identityHost+path)
	}
	// settle probes until the worker reports the wanted status. Each probe is its
	// own path, so a stale (pre-reload) answer never satisfies the wait.
	n := 0
	settle := func(desc, status, reason string) {
		t.Helper()
		h.Eventually(desc, func() bool {
			n++
			e := probe(fmt.Sprintf("/probe_%d", n))
			return e.IdentityStatus == status && e.IdentityReason == reason
		})
	}
	apply := func(edit func(*config.IdentitySettings)) error {
		t.Helper()
		return editIdentity(t, h, edit)
	}

	// Boot state: attribute.
	if e := probe("/boot"); e.IdentityStatus != "valid" || e.UserSub != "alice" {
		t.Fatalf("boot: identity_status %q user_sub %q, want valid/alice", e.IdentityStatus, e.UserSub)
	}

	// attribute -> off: attribution stops and nothing is verified any more.
	if err := apply(func(s *config.IdentitySettings) { s.DefaultMode = config.IdentityModeOff }); err != nil {
		t.Fatalf("switch to off: %v", err)
	}
	settle("the worker to apply mode off", "off", "")
	before := verifyCounts(h)
	for i := 0; i < 3; i++ {
		if e := probe(fmt.Sprintf("/off_%d", i)); e.IdentityStatus != "off" || e.UserSub != "" {
			t.Fatalf("mode off: identity_status %q user_sub %q, want off with no user", e.IdentityStatus, e.UserSub)
		}
	}
	if h.MetricsAvailable() {
		if after := verifyCounts(h); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Errorf("verify counters moved in mode off: %v -> %v", before, after)
		}
	}

	// off -> attribute: attribution resumes.
	if err := apply(func(s *config.IdentitySettings) { s.DefaultMode = config.IdentityModeAttribute }); err != nil {
		t.Fatalf("switch back to attribute: %v", err)
	}
	settle("the worker to re-enable attribute mode", "valid", "")

	// A new audience rebuilds the verifier: the old token is now for the wrong one.
	if err := apply(func(s *config.IdentitySettings) { s.Audience = "warden-v2" }); err != nil {
		t.Fatalf("change the audience: %v", err)
	}
	settle("the worker to rebuild the verifier for the new audience", "invalid", "wrong_aud")
	v2 := idToken{name: "v2", tok: newAud, status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng"}}
	if got := idTransports[2].get(t, h, v2, "/v2"); got != http.StatusOK {
		t.Fatalf("v2: status %d, want 200", got)
	}
	if e := only(t, h.Events(), "https://"+identityHost+"/v2"); e.IdentityStatus != "valid" || e.UserSub != "alice" {
		t.Errorf("a token for the new audience: identity_status %q user_sub %q, want valid/alice", e.IdentityStatus, e.UserSub)
	}

	// A refused document (attribute mode with no issuer) changes nothing live.
	if err := apply(func(s *config.IdentitySettings) { s.Issuer = "" }); err == nil {
		t.Error("the control plane accepted an identity block with attribute mode and no issuer")
	}
	if e := probe("/after_refused"); e.IdentityStatus != "invalid" || e.IdentityReason != "wrong_aud" {
		t.Errorf("after a refused edit: identity_status %q reason %q, want the previous config (invalid/wrong_aud)", e.IdentityStatus, e.IdentityReason)
	}

	if h.MetricsAvailable() && verifyCounts(h)[[2]string{"valid", "none"}] == 0 {
		t.Error("no valid verification was ever counted")
	}
	assertNoIdentityHeaders(t, up)
	assertNoLeakOf(t, h, []string{tok, newAud}, up)
}
