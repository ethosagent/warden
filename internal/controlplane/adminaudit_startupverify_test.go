package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

// seedAuditRows appends n admin entries to the chain in stateDir with the
// key the CP created, then runs tamper (if any) on the raw database.
func seedAuditRows(t *testing.T, stateDir string, n int, tamper string) {
	t.Helper()
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s, err := adminaudit.Open(ctx, db, adminaudit.OpenOptions{KeyFile: adminaudit.DefaultKeyPath(stateDir)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := s.Record(ctx, adminaudit.Input{
			Actor: adminaudit.Actor{Sub: "alice"}, ActorRole: "admin", AuthMethod: adminaudit.AuthMethodOIDC,
			Action: "policy.update", Target: "policy", TargetRef: "policy@" + string(rune('a'+i%26)),
			Outcome: adminaudit.OutcomeOK, HTTPStatus: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if tamper != "" {
		if _, err := db.SQL().Exec(tamper); err != nil {
			t.Fatal(err)
		}
	}
}

const verifyFailedMsg = "admin audit chain verification failed"

// logLine returns the first JSON log line whose msg is msg.
func logLine(logs, msg string) map[string]any {
	for _, l := range strings.Split(logs, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
			return m
		}
	}
	return nil
}

func verifyFailedAlerts(t *testing.T, stateDir string) []integration.Alert {
	t.Helper()
	st, err := integration.NewStore(filepath.Join(stateDir, "warden-alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	all, err := st.ListAlerts(100)
	if err != nil {
		t.Fatal(err)
	}
	var out []integration.Alert
	for _, a := range all {
		if strings.HasPrefix(a.DedupKey, adminAuditVerifyFailedRule+":") {
			out = append(out, a)
		}
	}
	return out
}

// TestStartupVerifyTamperedStillServes: a CP started on a chain with a
// tampered row among the newest 1000 logs the failure at ERROR, publishes an
// admin_audit_verify_failed Finding naming the seq, and still serves
// GET /policy with 200. An intact chain publishes nothing.
func TestStartupVerifyTamperedStillServes(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeAuditPolicy(t, "true")
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	seedAuditRows(t, stateDir, 30, "")

	_, logs := runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	if got := verifyFailedAlerts(t, stateDir); len(got) != 0 {
		t.Fatalf("intact chain raised %d verify alerts: %+v", len(got), got)
	}
	if logLine(logs, verifyFailedMsg) != nil {
		t.Fatalf("intact chain logged a verify failure:\n%s", logs)
	}

	seedAuditRows(t, stateDir, 0, "UPDATE admin_audit SET target_ref = 'policy@forged' WHERE seq = 17")
	policy, logs := runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	if !strings.Contains(string(policy), "api.openai.com") {
		t.Fatalf("GET /policy after a failed verify = %q, want the served policy", policy)
	}
	line := logLine(logs, verifyFailedMsg)
	if line == nil || line["level"] != "ERROR" || line["first_bad_seq"] != float64(17) || line["reason"] != adminaudit.ReasonEntryHash {
		t.Errorf("startup log line = %v, want an ERROR naming seq 17 and entry_hash; logs:\n%s", line, logs)
	}
	got := verifyFailedAlerts(t, stateDir)
	if len(got) != 1 {
		t.Fatalf("verify alerts = %+v, want exactly one", got)
	}
	a := got[0]
	if a.Severity != integration.SevCritical || !strings.Contains(a.Summary, "17") || !strings.Contains(string(a.Evidence), "first_bad_seq=17") {
		t.Errorf("alert = %+v, want a critical alert naming seq 17", a)
	}
}

// TestStartupVerifyOutsideWindow: a tampered row older than the newest 1000
// is not part of the bounded startup check (the offline CLI covers it).
func TestStartupVerifyOutsideWindow(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeAuditPolicy(t, "true")
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	seedAuditRows(t, stateDir, startupVerifyRows+5, "UPDATE admin_audit SET target_ref = 'policy@forged' WHERE seq = 3")
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	if got := verifyFailedAlerts(t, stateDir); len(got) != 0 {
		t.Errorf("a tamper outside the startup window raised alerts: %+v", got)
	}
}

// TestStartupVerifyNilSafe: no store, no pipeline and a store whose database
// is gone never panic; an unreadable chain is logged, not fatal.
func TestStartupVerifyNilSafe(t *testing.T) {
	var buf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	s := &Server{cfg: Config{Logger: logger, Clock: clock.Real()}}
	s.verifyAdminAuditAtStartup(context.Background())
	s.publishFinding(integration.Finding{RuleID: adminAuditVerifyFailedRule})

	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.AdminAudit = adminaudit.NewStore(db, adminaudit.Options{})
	_ = db.Close()
	s.verifyAdminAuditAtStartup(context.Background())
	if logLine(buf.String(), "admin audit startup verification could not run") == nil {
		t.Errorf("a closed database was not logged:\n%s", buf.String())
	}
}

// TestVerifyFailedFinding: the Finding names the seq and reason of a failed
// check, and an unreadable chain gets reason verify_error with no error text.
func TestVerifyFailedFinding(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	f := verifyFailedFinding(adminaudit.Result{FirstBadSeq: 9, Reason: adminaudit.ReasonSignature, HeadSeq: 12}, nil, now)
	if f.RuleID != adminAuditVerifyFailedRule || f.Severity != integration.SevCritical || f.Ts != now ||
		string(f.Evidence) != "first_bad_seq=9 reason=signature head_seq=12" || !strings.Contains(f.Summary, "seq 9") ||
		!strings.HasPrefix(f.DedupKey, adminAuditVerifyFailedRule+":") {
		t.Errorf("finding = %+v", f)
	}
	f = verifyFailedFinding(adminaudit.Result{}, errors.New("disk I/O error at /secret/path"), now)
	if !strings.Contains(string(f.Evidence), "reason="+verifyErrorReason) || strings.Contains(f.Summary+string(f.Evidence), "/secret/path") {
		t.Errorf("error finding = %+v, want reason verify_error and no error text", f)
	}
}
