package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
)

// jsonSinkEnv is an oidc control plane whose real admin audit store emits
// through newAdminAuditEmitter: the slog line into opLog and, when a sink is
// built, a warden.admin.v1 line into out.
type jsonSinkEnv struct {
	*auditEnv
	store  *adminaudit.Store
	sink   *auditlog.Sink
	out    *syncBuffer // the JSON stream (stdout output)
	opLog  *syncBuffer // the operational log
	policy string
	em     adminaudit.Emitter
}

type jsonSinkOpts struct {
	disabled bool      // no sink: the CP behaves as before
	writer   *failingW // replaces the stream's writer
}

type failingW struct{}

func (failingW) Write([]byte) (int, error) { return 0, errors.New("disk on fire") }

func newJSONSinkEnv(t *testing.T, o jsonSinkOpts) *jsonSinkEnv {
	t.Helper()
	db := openAuditDB(t)
	e := &jsonSinkEnv{out: &syncBuffer{}, opLog: &syncBuffer{}}
	opLogger := slog.New(slog.NewJSONHandler(e.opLog, nil))
	if !o.disabled {
		var err error
		cfg := config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputStdout}
		w := auditlog.WithWriter(e.out)
		if o.writer != nil {
			w = auditlog.WithWriter(*o.writer)
		}
		e.sink, err = newAuditSink(cfg, opLogger, w)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.sink.Close(context.Background()) })
	}
	e.em = newAdminAuditEmitter(opLogger, e.sink)
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	store, err := openAdminAudit(context.Background(), opLogger, db, t.TempDir(), Params{}, clk, e.em)
	if err != nil {
		t.Fatal(err)
	}
	e.store = store
	e.auditEnv = newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken, db: db, store: store})
	e.policy = e.srv.cfg.PolicyPath
	return e
}

// lines closes the sink (draining its queue) and returns the admin lines.
func (e *jsonSinkEnv) lines(t *testing.T) []auditlog.AdminRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.sink.Close(ctx); err != nil {
		t.Fatalf("sink Close: %v", err)
	}
	var out []auditlog.AdminRecord
	for _, ln := range strings.Split(strings.TrimRight(e.out.String(), "\n"), "\n") {
		if ln == "" {
			continue
		}
		var r auditlog.AdminRecord
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("not a JSON admin line: %v: %q", err, ln)
		}
		out = append(out, r)
	}
	return out
}

func (e *jsonSinkEnv) storedHead(t *testing.T) adminaudit.ListItem {
	t.Helper()
	items, err := e.store.List(context.Background(), adminaudit.Filter{}, 1, 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("List = %v, %v", items, err)
	}
	return items[0]
}

func TestAdminAuditJSONSink(t *testing.T) {
	e := newJSONSinkEnv(t, jsonSinkOpts{})
	admin := e.session(t, groupAdmin)
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("policy save = %d %s", rec.Code, rec.Body)
	}
	stored := e.storedHead(t)
	lines := e.lines(t)
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want exactly 1: %q", len(lines), e.out.String())
	}
	l := lines[0]
	if l.Schema != "warden.admin.v1" || l.Outcome != "ok" || l.Actor.Sub == "" || l.Action != "policy.write" {
		t.Errorf("line = %+v", l)
	}
	if l.BeforeHash == "" || l.BeforeHash == l.AfterHash {
		t.Errorf("before_hash %q after_hash %q, want both set and different", l.BeforeHash, l.AfterHash)
	}
	if l.ChainSeq != stored.Seq || l.EntryHash != hex.EncodeToString(stored.EntryHash) ||
		l.PrevHash != hex.EncodeToString(stored.PrevHash) || l.KeyID != stored.KeyID {
		t.Errorf("chain fields %d %s %s %s differ from the stored row %d %x %x %s",
			l.ChainSeq, l.EntryHash, l.PrevHash, l.KeyID, stored.Seq, stored.EntryHash, stored.PrevHash, stored.KeyID)
	}
	if l.BeforeHash != stored.BeforeHash || l.AfterHash != stored.AfterHash || l.RequestID != stored.RequestID ||
		l.Target != stored.Target || l.TargetRef != stored.TargetRef || l.AuthMethod != stored.AuthMethod || l.Actor.Role != stored.ActorRole {
		t.Errorf("line %+v does not carry the stored row %+v", l, stored.Entry)
	}
	if want := auditlog.FormatTS(time.Unix(0, stored.TSUnixNano)); l.TS != want {
		t.Errorf("ts = %q, want the stored row's %q", l.TS, want)
	}
	if l.CPID == "" || l.BootID == "" || l.Seq != 1 {
		t.Errorf("stream fields = %+v", l)
	}
	// The operational admin_audit line is unchanged by the sink.
	if n := len(jsonLines(t, e.opLog.String(), "admin_audit")); n != 1 {
		t.Errorf("operational admin_audit lines = %d, want 1", n)
	}
}

func TestAdminAuditJSONSink_Denied(t *testing.T) {
	e := newJSONSinkEnv(t, jsonSinkOpts{})
	before, err := os.ReadFile(e.policy)
	if err != nil {
		t.Fatal(err)
	}
	viewer := e.session(t, groupViewer)
	if rec := e.send(viewer, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer policy save = %d, want 403", rec.Code)
	}
	after, _ := os.ReadFile(e.policy)
	if string(before) != string(after) {
		t.Error("a denied save changed the policy")
	}
	lines := e.lines(t)
	if len(lines) != 1 || lines[0].Outcome != "denied" || lines[0].Actor.Role != "viewer" || lines[0].Action != "policy.write" {
		t.Fatalf("lines = %+v, want one denied policy.write line", lines)
	}
}

func TestAdminAuditJSONSink_Checkpoint(t *testing.T) {
	e := newJSONSinkEnv(t, jsonSinkOpts{})
	at := time.Date(2026, 10, 28, 9, 30, 0, 7, time.UTC)
	hash := []byte{0xde, 0xad, 0xbe, 0xef}
	e.em.Checkpoint(adminaudit.Checkpoint{HeadSeq: 41, HeadHash: hash, KeyID: "k-head", At: at})
	lines := e.lines(t)
	if len(lines) != 1 {
		t.Fatalf("lines = %d: %q", len(lines), e.out.String())
	}
	l := lines[0]
	if l.Schema != "warden.admin.v1" || l.Action != auditlog.ActionCheckpoint || l.ChainSeq != 41 ||
		l.EntryHash != "deadbeef" || l.KeyID != "k-head" || l.PrevHash != "" || l.Outcome != "ok" ||
		l.TS != auditlog.FormatTS(at) || l.Actor.Sub != "" {
		t.Errorf("checkpoint line = %+v", l)
	}
	if n := len(jsonLines(t, e.opLog.String(), "admin_audit.checkpoint")); n != 1 {
		t.Errorf("slog checkpoint lines = %d, want 1 (the anchor stays)", n)
	}
}

func TestAdminAuditJSONSink_Disabled(t *testing.T) {
	e := newJSONSinkEnv(t, jsonSinkOpts{disabled: true})
	admin := e.session(t, groupAdmin)
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("policy save = %d", rec.Code)
	}
	if n := len(jsonLines(t, e.opLog.String(), "admin_audit")); n != 1 {
		t.Errorf("operational admin_audit lines = %d, want 1", n)
	}
	if e.out.String() != "" {
		t.Errorf("a stream was written with the sink disabled: %q", e.out.String())
	}
}

// With audit.jsonLog absent or disabled, Run builds no sink and creates no file.
func TestAdminAuditJSONSink_DisabledCreatesNoFile(t *testing.T) {
	for _, block := range []string{"", "audit:\n  jsonLog:\n    enabled: false\n    output: file\n    path: AUDITPATH\n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "sub", "admin.jsonl")
		cfgPath := writeAuditPolicy(t, "true")
		body := readFile(t, cfgPath) + strings.ReplaceAll(block, "AUDITPATH", path)
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		logs := runCPWhile(t, Params{ConfigPath: cfgPath, StateDir: t.TempDir()}, func() {})
		if _, err := os.Stat(filepath.Dir(path)); err == nil {
			t.Errorf("block %q: the audit directory was created", block)
		}
		if len(jsonLines(t, logs, "admin_audit.checkpoint")) == 0 {
			t.Errorf("block %q: slog checkpoint missing:\n%s", block, logs)
		}
	}
}

func TestAdminAuditJSONSink_WriterFailure(t *testing.T) {
	e := newJSONSinkEnv(t, jsonSinkOpts{writer: &failingW{}})
	admin := e.session(t, groupAdmin)
	for i := 0; i < 3; i++ {
		if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
			t.Fatalf("policy save %d with a failing writer = %d, want 200", i, rec.Code)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = e.sink.Close(ctx)
	res, err := e.store.VerifyAll(context.Background(), adminaudit.VerifyOptions{})
	if err != nil || !res.OK {
		t.Fatalf("chain after writer failure: %+v, %v", res, err)
	}
	if n := len(jsonLines(t, e.opLog.String(), "admin_audit")); n != 3 {
		t.Errorf("operational admin_audit lines = %d, want 3", n)
	}
	if strings.Contains(e.opLog.String(), "disk on fire") {
		t.Error("the WARN carries the writer's error text")
	}
	if !strings.Contains(e.opLog.String(), "write failed") {
		t.Errorf("no rate-limited WARN for the failing writer:\n%s", e.opLog.String())
	}
}

func TestAdminAuditJSONSink_NoBodyLeak(t *testing.T) {
	const canary = "tok-canary-0123456789"
	e := newJSONSinkEnv(t, jsonSinkOpts{})
	admin := e.session(t, groupAdmin)
	body := `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[],"token":"` + canary + `"}`
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/policy", body, "Authorization", "Bearer "+canary); rec.Code == http.StatusInternalServerError {
		t.Fatalf("policy save = %d", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/secretstore", `{"key":"K","value":"`+canary+`"}`); rec.Code == http.StatusInternalServerError {
		t.Fatalf("secretstore save = %d", rec.Code)
	}
	lines := e.lines(t)
	if len(lines) == 0 {
		t.Fatal("no admin lines written")
	}
	if strings.Contains(e.out.String(), canary) || strings.Contains(strings.ToLower(e.out.String()), "authorization") {
		t.Errorf("the request token reached the stream:\n%s", e.out.String())
	}
}

func writeJSONLogPolicy(t *testing.T, adminAudit, jsonLog string) string {
	t.Helper()
	path := writeAuditPolicy(t, adminAudit)
	if err := os.WriteFile(path, []byte(readFile(t, path)+jsonLog), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Run with a file output writes the startup and shutdown checkpoints as
// warden.admin.v1 lines and keeps them out of the operational log's stream.
func TestAdminAuditJSONSink_RunFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "admin.jsonl")
	cfg := writeJSONLogPolicy(t, "true", "audit:\n  jsonLog:\n    enabled: true\n    output: file\n    path: "+path+"\n")
	logs := runCPWhile(t, Params{ConfigPath: cfg, StateDir: t.TempDir()}, func() {})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("audit file: %v", err)
	}
	var seqs []uint64
	for _, ln := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		var r auditlog.AdminRecord
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line %q: %v", ln, err)
		}
		if r.Schema != "warden.admin.v1" || r.Action != auditlog.ActionCheckpoint || r.ChainSeq != 1 || len(r.EntryHash) != 64 {
			t.Errorf("line = %+v, want a genesis-head checkpoint", r)
		}
		seqs = append(seqs, r.Seq)
	}
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 2 {
		t.Errorf("seqs = %v, want startup and shutdown checkpoints 1, 2", seqs)
	}
	if strings.Contains(string(raw), `"msg"`) {
		t.Error("operational log lines reached the audit file")
	}
	if len(jsonLines(t, logs, "admin_audit.checkpoint")) != 2 {
		t.Errorf("slog checkpoints must stay:\n%s", logs)
	}
}

// With stdout as the output the operational log moves to ErrOut and stdout
// holds only admin lines.
func TestAdminAuditJSONSink_StdoutMovesOperationalLog(t *testing.T) {
	cfg := writeJSONLogPolicy(t, "true", "audit:\n  jsonLog:\n    enabled: true\n    output: stdout\n")
	var stderr syncBuffer
	var stdout syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, &stdout, Params{
			ConfigPath: cfg, StateDir: t.TempDir(), ListenAddr: "127.0.0.1:0", AnalyticsProvider: "memory",
			ErrOut: &stderr, OnReady: func(a string) { ready <- a },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("Run: %v\n%s", err, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		var r auditlog.AdminRecord
		if err := json.Unmarshal([]byte(ln), &r); err != nil || r.Schema != "warden.admin.v1" {
			t.Errorf("stdout line %q is not an admin line (%v)", ln, err)
		}
	}
	if !strings.Contains(stderr.String(), "control plane listening") || !strings.Contains(stderr.String(), "operational logs moved to stderr") {
		t.Errorf("operational log missing from stderr:\n%s", stderr.String())
	}
}

func TestAdminAuditJSONSink_EnabledWithoutAdminAuditWarns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.jsonl")
	cfg := writeJSONLogPolicy(t, "false", "audit:\n  jsonLog:\n    enabled: true\n    output: file\n    path: "+path+"\n")
	logs := runCPWhile(t, Params{ConfigPath: cfg, StateDir: t.TempDir()}, func() {})
	if !strings.Contains(logs, "no admin lines will be written") {
		t.Errorf("no warning that the stream has nothing to write:\n%s", logs)
	}
}

func TestAdminAuditJSONSink_BadPathFailsStartup(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeJSONLogPolicy(t, "true", "audit:\n  jsonLog:\n    enabled: true\n    output: file\n    path: "+filepath.Join(blocker, "x", "a.jsonl")+"\n")
	err := bootErr(t, Params{ConfigPath: cfg, StateDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "audit.jsonLog") {
		t.Fatalf("boot error = %v, want an audit.jsonLog error", err)
	}
}

func TestCPAuditMetricsDropWarnIsRateLimited(t *testing.T) {
	var buf syncBuffer
	m := &cpAuditMetrics{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	for i := 0; i < 5; i++ {
		m.RecordAuditLogDropped(1)
	}
	m.RecordAuditLogLine("x")
	m.RecordAuditLogWriteError("write")
	if n := strings.Count(buf.String(), "dropped"); n != 1 {
		t.Errorf("drop WARNs = %d, want 1", n)
	}
}
