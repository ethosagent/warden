package worker_test

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/test/harness"
)

// noLeakCheck opts these harness tests out of the goroutine-leak check: this
// package's other tests run workers in the same process and leave proxy
// connection goroutines behind, which the harness's process-wide check cannot
// tell apart from its own. The hermetic leak check runs on the scenario
// packages.
var noLeakCheck = harness.NoLeakCheck()

// decodeStream parses the decision lines and checks the invariants every
// stream must hold: warden.decision.v1 schema, one line per stored analytics
// row, and consecutive seq values starting at 1.
func decodeStream(t *testing.T, h *harness.H) []auditlog.Record {
	t.Helper()
	rows := h.Events()
	lines := h.DecisionLines()
	if len(lines) != len(rows) {
		t.Fatalf("decision lines = %d, analytics rows = %d; want one line per row", len(lines), len(rows))
	}
	recs := make([]auditlog.Record, 0, len(lines))
	for i, ln := range lines {
		var r auditlog.Record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		if r.Schema != auditlog.SchemaDecisionV1 {
			t.Errorf("line %d schema = %q", i, r.Schema)
		}
		if r.Seq != uint64(i+1) {
			t.Errorf("line %d seq = %d, want %d", i, r.Seq, i+1)
		}
		recs = append(recs, r)
	}
	return recs
}

func reasons(recs []auditlog.Record) map[string]int {
	out := map[string]int{}
	for _, r := range recs {
		out[r.Decision+":"+r.Reason]++
	}
	return out
}

// wsUpgrade CONNECTs to host:443 through the worker, terminates TLS against the
// worker's CA and performs a WebSocket handshake; it returns the upgrade status.
func wsUpgrade(t *testing.T, h *harness.H, host string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	cr, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read the CONNECT reply: %v", err)
	}
	_ = cr.Body.Close()
	if cr.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d, want 200", cr.StatusCode)
	}
	cfg := h.AgentTLSConfig()
	cfg.ServerName = host
	tc := tls.Client(conn, cfg)
	defer func() { _ = tc.Close() }()
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake with the worker: %v", err)
	}
	fmt.Fprintf(tc, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://%s\r\n\r\n", host, host)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read the upgrade reply: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func agentGet(t *testing.T, h *harness.H, url string) int {
	t.Helper()
	resp, err := h.Agent().Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestDecisionStream_AllowDenyAndWebSocket drives an allowed HTTPS request, a
// policy deny and a WebSocket upgrade through a worker with audit.jsonLog on
// (file output): every stored analytics row has exactly one line, with
// consecutive seq from 1, the schema, and the compliance tags the tagging
// decorator set.
func TestDecisionStream_AllowDenyAndWebSocket(t *testing.T) {
	h := harness.New(t, harness.Local(), noLeakCheck, harness.WithAuditLogs())
	h.Upstream("api.example.com")
	h.FakeWS()

	if got := agentGet(t, h, "https://api.example.com/v1/models"); got != http.StatusOK {
		t.Fatalf("allowed GET = %d", got)
	}
	if got := h.ConnectStatus("evil.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT to a non-allowlisted host = %d, want 403", got)
	}
	if got := wsUpgrade(t, h, "ws.example.com"); got != http.StatusSwitchingProtocols {
		t.Fatalf("WebSocket upgrade = %d, want 101", got)
	}

	// The WebSocket tunnel records its event when the connection winds down,
	// after the client has gone; wait for all three rows before reading.
	h.Eventually("three analytics rows", func() bool { return len(h.Events()) >= 3 })
	recs := decodeStream(t, h)
	got := reasons(recs)
	if got["allow:"] < 1 || got["deny:policy_no_match"] != 1 {
		t.Errorf("decisions = %v, want an allow and one deny:policy_no_match", got)
	}
	rows := h.Events()
	byDomain := map[string][]string{}
	for _, e := range rows {
		byDomain[e.Domain+"/"+e.Decision] = e.Compliance
	}
	for _, r := range recs {
		want := byDomain[r.Domain+"/"+r.Decision]
		if strings.Join(r.Compliance, ",") != strings.Join(want, ",") {
			t.Errorf("%s/%s compliance = %v, want the row's %v", r.Domain, r.Decision, r.Compliance, want)
		}
	}
	for _, r := range recs {
		if r.BootID == "" || r.ProxyID == "" || r.ProxyIDSource == "" || r.AgentID == "" {
			t.Errorf("line misses Meta: %+v", r)
		}
	}
}

// TestDecisionStream_NoTLSDeny: with the judge on, an unlisted destination is
// admitted at CONNECT and a tunnel that carries no TLS fails closed with the
// no_tls reason; that deny is on the stream like any other.
func TestDecisionStream_NoTLSDeny(t *testing.T) {
	h := harness.New(t, harness.Local(), noLeakCheck, harness.WithAuditLogs(), harness.WithUnreachableJudge())

	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(conn, "CONNECT unlisted.example.com:443 HTTP/1.1\r\nHost: unlisted.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read the CONNECT reply: %v", err)
	}
	_ = resp.Body.Close()
	fmt.Fprint(conn, "plain bytes, no clienthello")
	_, _ = io.ReadAll(br)

	recs := decodeStream(t, h)
	if got := reasons(recs); got["deny:no_tls"] != 1 {
		t.Errorf("decisions = %v, want one deny:no_tls", got)
	}
}

// TestDecisionStream_SwappedQueryNeverLeaks: a placeholder in the query is
// swapped for the real value on the wire to the upstream, yet the SQLite row,
// the signed receipt, the operational log and the JSON line never hold it.
func TestDecisionStream_SwappedQueryNeverLeaks(t *testing.T) {
	real := harness.Canary()
	h := harness.New(t, harness.Local(), noLeakCheck, harness.WithAuditLogs(),
		harness.WithSecret("openai", real, "api.example.com"))
	u := h.Upstream("api.example.com")
	ph := h.Placeholder("openai")

	if got := agentGet(t, h, "https://api.example.com/v1/models?api_key="+ph); got != http.StatusOK {
		t.Fatalf("GET = %d", got)
	}
	reqs := u.Requests()
	if len(reqs) == 0 || !strings.Contains(reqs[len(reqs)-1].Query, real) {
		t.Fatalf("the upstream did not receive the real value in the query: %+v", reqs)
	}

	recs := decodeStream(t, h)
	if len(recs) != 1 {
		t.Fatalf("lines = %d, want 1", len(recs))
	}
	surfaces := map[string]string{
		"JSON line":  strings.Join(h.DecisionLines(), "\n"),
		"receipt":    strings.Join(h.ReceiptLines(), "\n"),
		"op log":     h.Logs(),
		"SQLite row": fmt.Sprintf("%+v", h.Events()),
	}
	for name, s := range surfaces {
		if s == "" {
			t.Errorf("%s is empty: the check would pass vacuously", name)
		}
		if strings.Contains(s, real) {
			t.Errorf("the real secret value reached the %s", name)
		}
	}
	h.AssertCanaryNeverLeaked()
}
