//go:build vector

package auditlog

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// writeStream writes lines through a real file Sink: one decision line and one
// admin line, each to its own file under dir.
func writeStream(t *testing.T, dir string) {
	t.Helper()
	meta := Meta{ProxyID: "worker-1", ProxyIDSource: "config", AgentID: "agent-1", BootID: "0123456789abcdef"}
	dec, err := New(config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputFile, Path: filepath.Join(dir, "decision.jsonl"),
		MaxSizeMB: 1, MaxBackups: 1, FileMode: 0o600, Query: config.JSONLogQueryDrop}, meta, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec.Observe([]analytics.Event{{Timestamp: time.Unix(1700000000, 0), Domain: "api.example.com", Protocol: "https",
		Decision: "deny", Reason: "policy_no_match", URL: "https://api.example.com/v1/x", Method: "GET"}})
	closeSink(t, dec)

	adm, err := New(config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputFile, Path: filepath.Join(dir, "admin.jsonl"),
		MaxSizeMB: 1, MaxBackups: 1, FileMode: 0o600, Query: config.JSONLogQueryDrop}, Meta{ProxyID: "cp-1", BootID: "fedcba9876543210"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	adm.WriteAdmin(AdminRecord{TS: FormatTS(time.Unix(1700000001, 0)), Actor: AdminActor{Role: "admin"}, AuthMethod: "oidc",
		Action: "policy.write", Target: "policy", TargetRef: "/policy", Outcome: "ok", EntryHash: "aa", PrevHash: "bb", KeyID: "k1"})
	closeSink(t, adm)
}

// TestSIEMVectorRoutes runs the shipped docs/siem/vector.yaml once over a
// decision line and an admin line written by the real sink, and checks each
// record reaches its own route. It needs the vector binary and runs with
// `go test -tags vector`; the validate step is part of it.
func TestSIEMVectorRoutes(t *testing.T) {
	bin, err := exec.LookPath("vector")
	if err != nil {
		t.Fatalf("the vector tag needs the vector binary on PATH: %v", err)
	}
	in := t.TempDir()
	writeStream(t, in)
	cfg, err := filepath.Abs(siemVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"WARDEN_AUDIT_GLOB="+filepath.Join(in, "*.jsonl"),
		"WARDEN_VECTOR_DATA_DIR="+t.TempDir())

	val := exec.Command(bin, "validate", "--no-environment", cfg)
	val.Env = env
	if out, err := val.CombinedOutput(); err != nil {
		t.Fatalf("vector validate --no-environment: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--config", cfg, "--quiet")
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()

	streams := map[string]string{} // schema -> siem_stream
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for len(streams) < 2 && sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		schema, _ := ev["schema"].(string)
		stream, _ := ev["siem_stream"].(string)
		streams[schema] = stream
	}
	if got := streams[SchemaDecisionV1]; got != "decision" {
		t.Errorf("decision line routed to %q, want decision (seen %v)", got, streams)
	}
	if got := streams[SchemaAdminV1]; got != "admin" {
		t.Errorf("admin line routed to %q, want admin (seen %v)", got, streams)
	}
}
