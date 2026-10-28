package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
)

// An unwritable backup dir makes every run fail: one ERROR line, exactly one
// backup_failed Finding, and the CP keeps serving /policy.
func TestBackup_FailureRaisesFinding(t *testing.T) {
	// The backup dir sits under a regular file, so every run fails (as root too).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pub := &fakePublisher{}
	logs := &syncBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, logs, Params{
			ConfigPath: writePolicyFile(t, "api.openai.com"), StateDir: filepath.Join(t.TempDir(), "state"),
			AnalyticsProvider: "memory", Listener: ln, OnReady: func(a string) { ready <- a },
			Backup:   BackupConfig{Dir: filepath.Join(blocker, "backups"), Interval: 24 * time.Hour, Keep: 3, Include: DefaultBackupInclude},
			Findings: pub,
		})
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("not ready")
	}
	for deadline := time.Now().Add(10 * time.Second); len(pub.all()) == 0 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
	}
	fs := pub.all()
	if len(fs) != 1 {
		t.Fatalf("findings = %+v, want exactly one", fs)
	}
	f := fs[0]
	if f.RuleID != "backup_failed" || f.Severity != integration.SevHigh || f.DedupKey != "backup_failed:run" {
		t.Errorf("finding = %+v", f)
	}
	resp, err := http.Get("http://" + addr + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /policy = %d", resp.StatusCode)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "cp_backup_failed") || !strings.Contains(out, "ERROR") {
		t.Errorf("no ERROR cp_backup_failed line in logs: %s", out)
	}
}

func staleHealth(t *testing.T, interval time.Duration, last time.Time) (*backupHealth, *fakePublisher, *clocktest.Fake) {
	t.Helper()
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	pub := &fakePublisher{}
	h := newBackupHealth(pub.PublishFinding, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), clk, interval,
		func() BackupStatus { return BackupStatus{LastSuccessAt: last} }, nil)
	return h, pub, clk
}

func TestBackup_StaleRaisesFinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)

	h, pub, _ := staleHealth(t, time.Hour, now.Add(-3*time.Hour))
	h.checkStale()
	h.checkStale() // the same episode: still one
	fs := pub.all()
	if len(fs) != 1 || fs[0].RuleID != "backup_stale" || fs[0].Severity != integration.SevHigh || fs[0].DedupKey != "backup_stale" {
		t.Fatalf("3h old: findings = %+v, want one backup_stale", fs)
	}
	h.BackupSucceeded("set") // a success ends the episode
	h.checkStale()
	if len(pub.all()) != 2 {
		t.Errorf("a new episode must raise again: %d findings", len(pub.all()))
	}

	h, pub, _ = staleHealth(t, time.Hour, now.Add(-90*time.Minute))
	h.checkStale()
	if len(pub.all()) != 0 {
		t.Errorf("90m old: findings = %+v, want none", pub.all())
	}

	// No success yet: the start time stands in, so 2 intervals after start is stale.
	h, pub, clk := staleHealth(t, time.Hour, time.Time{})
	clk.Advance(time.Hour)
	h.checkStale()
	if len(pub.all()) != 0 {
		t.Errorf("1h after start: findings = %+v, want none", pub.all())
	}
	clk.Advance(61 * time.Minute)
	h.checkStale()
	if len(pub.all()) != 1 {
		t.Errorf("2h01m after start with no success: findings = %+v, want one", pub.all())
	}
}

// The ticker fires every max(1m, interval/4) on the injected clock.
func TestBackup_StaleTicker(t *testing.T) {
	if got := (&backupHealth{interval: time.Hour}).tick(); got != 15*time.Minute {
		t.Errorf("tick(1h) = %s", got)
	}
	if got := (&backupHealth{interval: time.Minute}).tick(); got != time.Minute {
		t.Errorf("tick(1m) = %s, want the 1m floor", got)
	}
	h, pub, clk := staleHealth(t, time.Hour, time.Unix(1_800_000_000, 0).Add(-3*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go h.runStale(ctx, done)
	for deadline := time.Now().Add(5 * time.Second); clk.PendingTimers() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the staleness check never armed its timer")
		}
	}
	clk.Advance(15 * time.Minute)
	for deadline := time.Now().Add(5 * time.Second); len(pub.all()) == 0 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	if len(pub.all()) != 1 {
		t.Errorf("findings after one tick = %d, want 1", len(pub.all()))
	}
	cancel()
	<-done
}

func TestBackup_NoPipelineLogsError(t *testing.T) {
	logs := &syncBuf{}
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	h := newBackupHealth(srv.publishFinding, srv.cfg.Logger, srv.cfg.Clock, time.Hour, func() BackupStatus { return BackupStatus{} }, nil)
	h.BackupFailed("alerts", errors.New(strings.Repeat("e", 500)))
	out := logs.String()
	for _, want := range []string{`"msg":"cp_backup_failed"`, `"level":"ERROR"`, `"db":"alerts"`, `"msg":"finding_not_published"`, `"rule":"backup_failed"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s: %s", want, out)
		}
	}
	if strings.Contains(out, strings.Repeat("e", 201)) {
		t.Error("error text is not bounded")
	}
	h.checkStale() // never panics without a pipeline either
}

func setupBackup(t *testing.T, h http.Handler, cookie *http.Cookie) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/setup", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET setup = %d: %s", rec.Code, rec.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSetup_BackupStatusAdminOnly(t *testing.T) {
	e := newAuthzEnv(t)
	r := NewBackupRunner(BackupConfig{Dir: t.TempDir()}, BackupDeps{})
	r.stat = BackupStatus{LastSuccessAt: time.Unix(1_800_000_000, 0), LastSet: "20270115T080000Z", SizeBytes: 4096, LastError: "disk full"}
	e.srv.setBackupStatus(r)

	cookie := func(group string) *http.Cookie {
		return &http.Cookie{Name: e.srv.sessionCookie.Name, Value: e.session(t, group)}
	}
	m := setupBackup(t, e.h, cookie(groupAdmin))
	b, ok := m["backup"].(map[string]any)
	if !ok {
		t.Fatalf("admin setup has no backup: %v", m)
	}
	if b["enabled"] != true || b["lastSet"] != "20270115T080000Z" || b["sizeBytes"] != float64(4096) ||
		b["lastError"] != "disk full" || b["lastSuccessAt"] != "2027-01-15T08:00:00Z" {
		t.Errorf("backup = %v", b)
	}
	for _, g := range []string{groupViewer, groupEditor} {
		if _, has := setupBackup(t, e.h, cookie(g))["backup"]; has {
			t.Errorf("group %s sees the backup field", g)
		}
	}
}

func TestSetup_NoBackupFieldWhenDisabled(t *testing.T) {
	e := newAuthzEnv(t) // no runner registered: --backup-dir unset
	if _, has := setupBackup(t, e.h, &http.Cookie{Name: e.srv.sessionCookie.Name, Value: e.session(t, groupAdmin)})["backup"]; has {
		t.Error("setup has a backup field with backups disabled")
	}
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken})
	if _, has := setupBackup(t, srv.Handler(), nil)["backup"]; has {
		t.Error("console.auth none: setup has a backup field with backups disabled")
	}
}

// console.auth none has no roles: every caller is the admin.
func TestSetup_BackupStatusConsoleNone(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Console: config.ConsoleConfig{Auth: config.ConsoleAuthNone}})
	srv.setBackupStatus(NewBackupRunner(BackupConfig{Dir: t.TempDir()}, BackupDeps{}))
	b, ok := setupBackup(t, srv.Handler(), nil)["backup"].(map[string]any)
	if !ok || b["enabled"] != true {
		t.Errorf("none mode setup backup = %v", b)
	}
}
