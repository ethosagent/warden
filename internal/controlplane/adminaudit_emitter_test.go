package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

// loopProbe records the checkpoint loop's lifecycle through the
// checkpointLoopHooks seam, so the tests need no goroutine-stack inspection or
// timing.
type loopProbe struct {
	started chan struct{} // closed on the first start
	once    sync.Once
	starts  atomic.Int32
	exits   atomic.Int32
}

func newLoopProbe() *loopProbe { return &loopProbe{started: make(chan struct{})} }

func (p *loopProbe) hooks() checkpointLoopHooks {
	return checkpointLoopHooks{
		started: func() { p.starts.Add(1); p.once.Do(func() { close(p.started) }) },
		exited:  func() { p.exits.Add(1) },
	}
}

// jsonLines decodes the JSON log lines whose msg is msg.
func jsonLines(t *testing.T, logs, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(logs, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) == nil && rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// runCPWhile boots Run with p, calls during once it is serving, then shuts it
// down and returns everything it logged.
func runCPWhile(t *testing.T, p Params, during func()) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	p.OnReady = func(a string) { ready <- a }
	p.ListenAddr = "127.0.0.1:0"
	p.AnalyticsProvider = "memory"
	var out syncBuffer
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, &out, p) }()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	during()
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
	return out.String()
}

func TestCheckpointLifecycle(t *testing.T) {
	t.Run("disabled starts no loop and logs nothing", func(t *testing.T) {
		probe := newLoopProbe()
		logs := runCPWhile(t, Params{ConfigPath: writeAuditPolicy(t, "false"), StateDir: t.TempDir(), checkpointHooks: probe.hooks()}, func() {})
		if n := probe.starts.Load(); n != 0 {
			t.Errorf("checkpoint goroutine started %d times with admin audit disabled", n)
		}
		if strings.Contains(logs, "admin_audit") || strings.Contains(logs, adminaudit.SchemaV1) {
			t.Errorf("admin audit disabled but the CP logged admin_audit lines:\n%s", logs)
		}
	})

	t.Run("enabled runs until cancel with startup and shutdown checkpoints", func(t *testing.T) {
		stateDir := t.TempDir()
		clk := clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
		probe := newLoopProbe()
		logs := runCPWhile(t, Params{
			ConfigPath: writeAuditPolicy(t, "true"), StateDir: stateDir, Clock: clk,
			checkpointHooks: probe.hooks(),
		}, func() {
			select {
			case <-probe.started:
			case <-time.After(10 * time.Second):
				t.Error("no checkpoint goroutine with admin audit enabled")
			}
		})
		// Run returns only after the loop has stopped.
		if probe.starts.Load() != 1 || probe.exits.Load() != 1 {
			t.Fatalf("checkpoint goroutine starts=%d exits=%d after Run returned, want 1 and 1",
				probe.starts.Load(), probe.exits.Load())
		}
		lines := jsonLines(t, logs, "admin_audit.checkpoint")
		if len(lines) != 2 {
			t.Fatalf("got %d checkpoint lines, want startup + shutdown:\n%s", len(lines), logs)
		}
		started := jsonLines(t, logs, "admin audit enabled")
		if len(started) != 1 {
			t.Fatalf("no `admin audit enabled` line:\n%s", logs)
		}
		for _, l := range lines {
			if l["schema"] != adminaudit.SchemaV1 || l["head_seq"] != float64(1) || l["key_id"] != started[0]["key_id"] {
				t.Errorf("checkpoint line = %v, want schema %s, head seq 1 (genesis), key_id %v",
					l, adminaudit.SchemaV1, started[0]["key_id"])
			}
			if h, _ := l["head_entry_hash"].(string); len(h) != 64 {
				t.Errorf("head_entry_hash = %q, want 64 hex characters", h)
			}
		}
		if auditRows(t, stateDir) != 1 {
			t.Error("checkpoints must not write rows")
		}
	})
}

// TestEmitterNoSecretLeak drives a request carrying the canary as its bearer
// token and body through a handler that records an admin audit entry with the
// store openAdminAudit builds with the slog Emitter, as Run does. The
// handler records only safe, derived fields, as the AAUD-02 middleware's
// Annotate does; the emitted line must hold neither the canary nor a body or
// authorization field.
func TestEmitterNoSecretLeak(t *testing.T) {
	const canary = "s3cr3t-canary-123"
	stateDir := t.TempDir()
	state, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	var logs syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	clk := clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	store, err := openAdminAudit(context.Background(), logger, state, stateDir, Params{}, clk, adminaudit.NewSlogEmitter(logger))
	if err != nil {
		t.Fatal(err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		if _, err := store.Record(r.Context(), adminaudit.Input{
			Actor:      adminaudit.Actor{Sub: "alice", Email: "alice@example.com"},
			ActorRole:  "admin",
			AuthMethod: adminaudit.AuthMethodBearer,
			Action:     "secretstore.put",
			Target:     "secretstore",
			TargetRef:  r.URL.Path,
			Details:    map[string]string{"name": "db-password"},
			Outcome:    adminaudit.OutcomeOK,
			HTTPStatus: http.StatusNoContent,
			RequestID:  r.Header.Get("X-Request-Id"),
		}); err != nil {
			t.Errorf("Record: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/dashboard/api/secretstore/db-password",
		strings.NewReader(`{"value":"`+canary+`"}`))
	req.Header.Set("Authorization", "Bearer "+canary)
	req.Header.Set("X-Request-Id", "req-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	out := logs.String()
	if strings.Contains(out, canary) {
		t.Fatal("the canary appears in the emitted log lines")
	}
	lines := jsonLines(t, out, "admin_audit")
	if len(lines) != 1 {
		t.Fatalf("got %d admin_audit lines, want 1:\n%s", len(lines), out)
	}
	l := lines[0]
	for _, k := range []string{"body", "authorization", "Authorization", "headers"} {
		if _, ok := l[k]; ok {
			t.Errorf("emitted line has a %q field", k)
		}
	}
	if l["actor_sub"] != "alice" || l["target_ref"] != "/dashboard/api/secretstore/db-password" || l["request_id"] != "req-1" {
		t.Errorf("emitted line = %v, want the recorded actor, target_ref and request_id", l)
	}
}
