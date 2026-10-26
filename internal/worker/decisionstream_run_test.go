package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/internal/config"
)

// TestDecisionStream_StdoutSeparation: with audit.jsonLog.output stdout, the
// worker's stdout carries only warden.decision.v1 lines and the operational
// log (including the one-time notice that it moved) goes to the error writer.
func TestDecisionStream_StdoutSeparation(t *testing.T) {
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: info
  format: json
audit:
  jsonLog:
    enabled: true
    output: stdout
`
	var stdout, stderr syncBuffer
	p := runParams(t, writeConfig(t, cfg))
	p.ErrOut = &stderr
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ProxyListener = ln
	ready := make(chan string, 1)
	p.OnReady = func(proxyAddr, _ string) { ready <- proxyAddr }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, &stdout, p) }()

	var proxyAddr string
	select {
	case proxyAddr = <-ready:
	case err := <-errc:
		t.Fatalf("Run exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("worker never became ready")
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the CONNECT reply: %v", err)
	}
	_ = resp.Body.Close()
	_ = conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT = %d, want 403", resp.StatusCode)
	}

	// Shutdown drains the async writer into the tee and then the sink.
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("stdout lines = %d (%q), want exactly the one decision line", len(lines), stdout.String())
	}
	var rec auditlog.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil || rec.Schema != auditlog.SchemaDecisionV1 || rec.Decision != "deny" {
		t.Fatalf("stdout line = %q (%v), want a warden.decision.v1 deny", lines[0], err)
	}
	logged := stderr.String()
	for _, want := range []string{"effective listener config", "operational logs moved to stderr", "audit JSON decision stream enabled"} {
		if !strings.Contains(logged, want) {
			t.Errorf("stderr misses %q:\n%s", want, logged)
		}
	}
	if strings.Contains(stdout.String(), "effective listener config") {
		t.Error("an operational log line reached stdout")
	}
}

// TestDecisionStream_BadPathFailsStartup: a file path that cannot be opened
// fails startup with an error naming audit.jsonLog.path.
func TestDecisionStream_BadPathFailsStartup(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`
policy:
  allowlist:
    - domain: api.openai.com
audit:
  jsonLog:
    enabled: true
    output: file
    path: %q
`, filepath.Join(blocker, "sub", "decisions.jsonl"))
	err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg)))
	if err == nil || !strings.Contains(err.Error(), "audit.jsonLog.path") {
		t.Fatalf("Run error = %v, want one naming audit.jsonLog.path", err)
	}
}

// TestAnalyticsChain_ComplianceAndSink: the sink is a tee on the async writer,
// below the tagging layer, so the line carries the compliance tags the tagging
// decorator set, and rebuilding the tagging layer around the stable signing
// store (what the managed apply loop does on a compliance toggle) never touches
// the sink: seq continues and nothing is lost or duplicated.
func TestAnalyticsChain_ComplianceAndSink(t *testing.T) {
	base, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })

	var out syncBuffer
	sink, err := auditlog.New(config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputStdout},
		auditlog.Meta{ProxyID: "p", ProxyIDSource: "config", AgentID: "a", BootID: "b"}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), auditlog.WithWriter(&out))
	if err != nil {
		t.Fatal(err)
	}
	async := analytics.NewAsyncWriter(base, analytics.WithFlushInterval(time.Hour), analytics.WithOnBatch(sink.Observe))
	mapper := audit.NewMapper()
	deny := analytics.Event{Domain: "api.openai.com", Protocol: "https", Decision: "deny", Reason: "policy_denylist"}

	tagged := audit.NewTaggingStore(async, mapper)
	if err := tagged.StoreEvent(deny); err != nil {
		t.Fatal(err)
	}
	// Toggle off: the apply loop swaps in the bare signing/async store.
	if err := async.StoreEvent(deny); err != nil {
		t.Fatal(err)
	}
	// Toggle back on: a NEW tagging layer around the same stable inner store.
	if err := audit.NewTaggingStore(async, mapper).StoreEvent(deny); err != nil {
		t.Fatal(err)
	}
	if err := async.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	var recs []auditlog.Record
	for _, ln := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		var r auditlog.Record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("bad line %q: %v", ln, err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 3 {
		t.Fatalf("lines = %d, want 3 (one per stored event across both toggles)", len(recs))
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Errorf("line %d seq = %d, want %d", i, r.Seq, i+1)
		}
	}
	if len(recs[0].Compliance) == 0 || len(recs[2].Compliance) == 0 {
		t.Error("lines written under the tagging layer carry no compliance tags")
	}
	if len(recs[1].Compliance) != 0 {
		t.Errorf("a line written with tagging off carries tags: %v", recs[1].Compliance)
	}
	if rows, _ := base.GetEvents(analytics.EventFilter{}); len(rows) != 3 {
		t.Errorf("stored rows = %d, want 3", len(rows))
	}
}

// TestNewAuditMeta: ProxyID comes from central.proxyID (env-expanded) when set,
// else the hostname, and the boot id is 16 random bytes in hex.
func TestNewAuditMeta(t *testing.T) {
	t.Setenv("WARDEN_TEST_PROXY_ID", "edge-7")
	m := newAuditMeta(config.Policy{Central: config.CentralConfig{ProxyID: "${WARDEN_TEST_PROXY_ID}"}}, "agent-1")
	if m.ProxyID != "edge-7" || m.ProxyIDSource != "config" || m.AgentID != "agent-1" {
		t.Errorf("config meta = %+v", m)
	}
	host, _ := os.Hostname()
	h := newAuditMeta(config.Policy{}, "agent-1")
	if h.ProxyID != host || h.ProxyIDSource != "hostname" {
		t.Errorf("hostname meta = %+v, want %q", h, host)
	}
	if len(h.BootID) != 32 || h.BootID == newAuditMeta(config.Policy{}, "").BootID {
		t.Errorf("boot id %q is not 16 fresh random bytes in hex", h.BootID)
	}
}
