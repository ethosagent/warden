package scenarios

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/harness"
)

// The canary matrix: HTTP/1.1, HTTP/2, gRPC and WebSocket, each on an allowed
// destination (the secret is swapped in for the upstream and must reach nobody
// else) and a denied one (the secret must not reach the destination at all).
// Every row ends by sweeping the agent, logs, events, metrics and every
// upstream for the planted value.
//
// Rows that a documented, still-open issue breaks carry knownIssue: the row
// ASSERTS the violation still happens and fails with "appears fixed: remove
// knownIssue" the day it does not (see expectKnown). A row is never skipped.
//
//	#388  HTTP/2 does not run the request stages: the placeholder in an h2 (and
//	      gRPC) request BODY reaches the upstream unswapped. Headers are swapped.
//	#389  no echo guard: an upstream that reflects its request headers returns
//	      the real secret to the agent.

// canaryValue is the planted secret of the matrix; canaryHost is where it may be
// swapped in. Each row boots its own harness, so rows cannot contaminate each
// other's sweep.
var canaryValue = harness.Canary()

type canaryRow struct {
	proto      string   // http1, h2, grpc, ws
	deny       bool     // false: allowed destination; true: denied destination
	echo       bool     // the allowed upstream reflects its request headers (#389)
	knownIssue []string // open issues this row is expected to still hit
}

// canaryHost is the upstream the row talks to.
func (r canaryRow) host() string {
	switch {
	case r.deny:
		return "evil.example.com" // registered upstream, never allowlisted
	case r.proto == "grpc":
		return "grpc.example.com"
	case r.proto == "ws":
		return "ws.example.com"
	default:
		return "api.example.com"
	}
}

func (r canaryRow) name() string {
	path := "allow"
	if r.deny {
		path = "deny"
	}
	if r.echo {
		path += "_echo"
	}
	return "canary_" + r.proto + "_" + path
}

// canaryRows is the matrix. Echo rows add the reflecting-upstream variant for
// the two plain-HTTP protocols.
var canaryRows = []canaryRow{
	{proto: "http1"},
	{proto: "http1", deny: true},
	{proto: "http1", echo: true, knownIssue: []string{"#389"}},
	{proto: "h2", knownIssue: []string{"#388"}},
	{proto: "h2", deny: true},
	{proto: "h2", echo: true, knownIssue: []string{"#388", "#389"}},
	{proto: "grpc", knownIssue: []string{"#388"}},
	{proto: "grpc", deny: true},
	{proto: "ws"},
	{proto: "ws", deny: true},
}

// canaryScenarios turns the matrix into catalog entries. Only the rows that use
// no in-process-only lever are L2 (EchoHeaders is a harness fault on the fake).
func canaryScenarios() []Scenario {
	out := make([]Scenario, 0, len(canaryRows))
	for _, row := range canaryRows {
		out = append(out, Scenario{
			Name: row.name(),
			L2:   !row.echo,
			Opts: []harness.Option{harness.WithSecret("canary", canaryValue, row.allowedHost())},
			Run:  row.run,
		})
	}
	return out
}

// allowedHost is the one host the secret is scoped to: the row's own host on an
// allow path, and the protocol's allowed host on a deny path (so a swap
// delivered to the DENIED host would be out of scope and flagged).
func (r canaryRow) allowedHost() string {
	return canaryRow{proto: r.proto}.host()
}

func (r canaryRow) run(t *testing.T, h *harness.H) {
	up := h.Upstream(r.host())
	switch r.proto {
	case "grpc":
		if !r.deny {
			h.FakeGRPC()
		}
	case "ws":
		if !r.deny {
			h.FakeWS()
		}
	}
	if r.echo {
		up.EchoHeaders(true)
	}

	ph := h.Placeholder("canary")
	var bodySwapped bool // allow path: did the body placeholder reach the upstream swapped?
	switch r.proto {
	case "http1":
		bodySwapped = r.doHTTP(t, h, h.Agent(), up, ph)
	case "h2":
		bodySwapped = r.doHTTP(t, h, h.AgentH2(), up, ph)
	case "grpc":
		bodySwapped = r.doGRPC(t, h, up, ph)
	case "ws":
		r.doWS(t, h, up, ph)
		bodySwapped = true // no body on this path: nothing for #388 to break
	}

	if r.deny {
		if got := len(up.Requests()); got != 0 {
			t.Fatalf("the denied upstream %s saw %d request(s), want 0", r.host(), got)
		}
	} else if r.proto == "h2" || r.proto == "grpc" {
		expectKnown(t, knownFor(r.knownIssue, "#388"), bodySwapped,
			r.name()+": the request-body placeholder must be swapped on the HTTP/2 path")
	}

	r.assertLeaks(t, h)
}

// knownLeaks maps each open issue a row can hit to the oracle line it produces
// (one hit per surface): #388 delivers the placeholder unswapped to the upstream,
// #389 returns the real value in the agent's response.
var knownLeaks = map[string]string{
	"#388": "appeared unswapped placeholder in upstream",
	"#389": "in agent response",
}

// assertLeaks ends a row. A row with no knownIssue is the plain oracle. A row
// with one asserts the leak set is EXACTLY the known one — each known issue
// produces exactly one hit on its own surface and nothing else leaked — so a
// new, second leak still fails the row, and a fixed issue fails "appears fixed".
func (r canaryRow) assertLeaks(t *testing.T, h *harness.H) {
	t.Helper()
	if len(r.knownIssue) == 0 {
		h.AssertCanaryNeverLeaked()
		return
	}
	rest := h.CanaryLeaks()
	for issue, marker := range knownLeaks {
		var matched, others []string
		for _, l := range rest {
			if strings.Contains(l, marker) {
				matched = append(matched, l)
			} else {
				others = append(others, l)
			}
		}
		rest = others
		if !slices.Contains(r.knownIssue, issue) {
			if len(matched) > 0 {
				t.Fatalf("%s: unexpected leak (not a known issue of this row):\n  - %s", r.name(), strings.Join(matched, "\n  - "))
			}
			continue
		}
		if len(matched) > 1 {
			t.Fatalf("%s: %s should leak exactly once, got %d:\n  - %s", r.name(), issue, len(matched), strings.Join(matched, "\n  - "))
		}
		expectKnown(t, issue, len(matched) == 0, r.name()+": "+issue+" leak ("+marker+")")
	}
	if len(rest) > 0 {
		t.Fatalf("%s: CANARY LEAKED beyond the known issues:\n  - %s", r.name(), strings.Join(rest, "\n  - "))
	}
}

// knownFor narrows a row's knownIssue to the check it applies to.
func knownFor(rowIssues []string, check string) string {
	if slices.Contains(rowIssues, check) {
		return check
	}
	return ""
}

// doHTTP sends one POST (placeholder in a header and in the body) through cl.
// On the allow path it asserts the header swap and returns whether the body was
// swapped too; on the deny path it asserts the agent was refused.
func (r canaryRow) doHTTP(t *testing.T, h *harness.H, cl *http.Client, up *harness.Upstream, ph string) (bodySwapped bool) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+r.host()+"/v1/canary", strings.NewReader("key="+ph))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", ph)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := cl.Do(req)
	if r.deny {
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s: the request to a denied destination succeeded", r.name())
		}
		return false
	}
	if err != nil {
		t.Fatalf("%s: %v", r.name(), err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d, want 200", r.name(), resp.StatusCode)
	}
	got := lastRequest(t, up)
	if v := got.Header.Get("X-Api-Key"); v != canaryValue {
		t.Errorf("%s: upstream header X-Api-Key = %q, want the real value (swap in a header)", r.name(), v)
	}
	return string(got.Body) == "key="+canaryValue
}

// doGRPC sends one framed unary call through the h2 agent with the placeholder
// in the authorization metadata and in the message.
func (r canaryRow) doGRPC(t *testing.T, h *harness.H, up *harness.Upstream, ph string) (bodySwapped bool) {
	t.Helper()
	msg := []byte("token=" + ph)
	frame := make([]byte, 5+len(msg))
	frame[1], frame[2], frame[3], frame[4] = byte(len(msg)>>24), byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg))
	copy(frame[5:], msg)

	req, err := http.NewRequest(http.MethodPost, "https://"+r.host()+"/pkg.Svc/Method", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Authorization", "Bearer "+ph)
	resp, err := h.AgentH2().Do(req)
	if r.deny {
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s: the call to a denied destination succeeded", r.name())
		}
		return false
	}
	if err != nil {
		t.Fatalf("%s: %v", r.name(), err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d, want 200", r.name(), resp.StatusCode)
	}
	got := lastRequest(t, up)
	if v := got.Header.Get("Authorization"); v != "Bearer "+canaryValue {
		t.Errorf("%s: upstream authorization metadata = %q, want the real value", r.name(), v)
	}
	return bytes.Contains(got.Body, []byte("token="+canaryValue))
}

// doWS opens a WebSocket through the worker's tunnel with the placeholder in a
// handshake header. The handshake is the whole path under test: on this
// configuration (MCP gateway off) the worker completes the upgrade but does not
// pump frames (#408), so no frame is sent and these rows cover the handshake
// only until that is fixed. Allowed: the upstream sees the real value in
// the handshake and the 101 the agent reads carries it nowhere. Denied: the
// tunnel itself is refused.
func (r canaryRow) doWS(t *testing.T, h *harness.H, up *harness.Upstream, ph string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	hostPort := r.host() + ":443"
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
	connectResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("%s: read the CONNECT reply: %v", r.name(), err)
	}
	_ = connectResp.Body.Close()
	if r.deny {
		if connectResp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: CONNECT to a denied destination = %d, want 403", r.name(), connectResp.StatusCode)
		}
		return
	}
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("%s: CONNECT = %d, want 200", r.name(), connectResp.StatusCode)
	}

	cfg := h.AgentTLSConfig()
	cfg.ServerName = r.host()
	tlsConn := tls.Client(conn, cfg)
	defer func() { _ = tlsConn.Close() }()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("%s: TLS handshake with the worker: %v", r.name(), err)
	}
	fmt.Fprintf(tlsConn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://%s\r\nX-Api-Key: %s\r\n\r\n",
		r.host(), r.host(), ph)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("%s: read the upgrade reply: %v", r.name(), err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("%s: upgrade = %d, want 101", r.name(), resp.StatusCode)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			if strings.Contains(v, canaryValue) {
				t.Errorf("%s: the 101 reply header %s carries the real secret to the agent", r.name(), k)
			}
		}
	}
	if v := lastRequest(t, up).Header.Get("X-Api-Key"); v != canaryValue {
		t.Errorf("%s: upstream handshake header X-Api-Key = %q, want the real value", r.name(), v)
	}
}
