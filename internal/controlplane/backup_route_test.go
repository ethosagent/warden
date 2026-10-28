package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/dashboard"
)

const backupPath = "/dashboard/api/backup"

// routeBackup wires a runner whose cp copy blocks until release is closed, the
// way Run wires it, onto e's dashboard. started is closed once a run is inside
// the copy.
func routeBackup(t *testing.T, e *auditEnv) (r *BackupRunner, started chan struct{}, release func()) {
	t.Helper()
	deps := fakeDeps(t, clocktest.NewFake(testBackupT0))
	started = make(chan struct{})
	gate := make(chan struct{})
	first := true
	deps.CP = BackupStore{Source: &fileSource{data: "cp", hook: func() {
		if first {
			first = false
			close(started)
		}
		<-gate
	}}}
	r = NewBackupRunner(testBackupConfig(t), deps)
	ctx, cancel := context.WithCancel(context.Background())
	e.srv.dash.SetBackup(func() error {
		if err := r.StartOnDemand(ctx); err != nil {
			if errors.Is(err, ErrBackupInProgress) {
				return dashboard.ErrBackupInProgress
			}
			return err
		}
		return nil
	})
	var once bool
	release = func() {
		if !once {
			once = true
			close(gate)
		}
	}
	t.Cleanup(func() {
		release()
		cancel()
		r.Wait()
	})
	return r, started, release
}

func backupRows(e *auditEnv) []adminaudit.Input {
	var out []adminaudit.Input
	for _, in := range e.rec.inputs() {
		if in.Action == "backup.run" {
			out = append(out, in)
		}
	}
	return out
}

func TestBackupRoute(t *testing.T) {
	t.Run("roles", func(t *testing.T) {
		e := newOIDCAuditEnv(t)
		r, started, release := routeBackup(t, e)
		for _, g := range []string{groupViewer, groupEditor} {
			if rec := e.send(e.session(t, g), "", http.MethodPost, backupPath, ""); rec.Code != http.StatusForbidden {
				t.Fatalf("%s POST backup = %d, want 403", g, rec.Code)
			}
		}
		if r.Status().LastSet != "" {
			t.Fatal("a refused call ran a backup")
		}
		admin := e.session(t, groupAdmin)
		rec := e.send(admin, "", http.MethodPost, backupPath, `{"ignored":true}`)
		if rec.Code != http.StatusAccepted || strings.TrimSpace(rec.Body.String()) != `{"started":true}` {
			t.Fatalf("admin POST backup = %d %s, want 202 started", rec.Code, rec.Body.String())
		}
		<-started
		// A second call while the run is active is refused synchronously.
		rec = e.send(admin, "", http.MethodPost, backupPath, "")
		if rec.Code != http.StatusConflict || strings.TrimSpace(rec.Body.String()) != `{"error":"backup_in_progress"}` {
			t.Fatalf("second POST backup = %d %s, want 409 backup_in_progress", rec.Code, rec.Body.String())
		}
		release()
		deadline := time.Now().Add(10 * time.Second)
		for r.Status().LastSet == "" {
			if time.Now().After(deadline) {
				t.Fatal("the accepted run never finished")
			}
			time.Sleep(5 * time.Millisecond)
		}
		// Exactly one backup.run row with outcome ok, for the accepted call.
		var ok []adminaudit.Input
		for _, in := range backupRows(e) {
			if in.Outcome == adminaudit.OutcomeOK {
				ok = append(ok, in)
			}
		}
		if len(ok) != 1 {
			t.Fatalf("%d ok backup.run rows, want 1: %+v", len(ok), backupRows(e))
		}
		if ok[0].Target != "backup" || ok[0].TargetRef != "backup" || ok[0].ActorRole != "admin" || ok[0].HTTPStatus != http.StatusAccepted {
			t.Errorf("row = %+v", ok[0])
		}
	})

	t.Run("disabled", func(t *testing.T) {
		e := newOIDCAuditEnv(t) // no SetBackup: --backup-dir unset
		if rec := e.send(e.session(t, groupAdmin), "", http.MethodPost, backupPath, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("POST backup with backups off = %d, want 404", rec.Code)
		}
	})

	t.Run("none mode fails closed without the bearer", func(t *testing.T) {
		e := newAuditEnv(t, auditEnvOpts{})
		routeBackup(t, e)
		if rec := e.send("", "", http.MethodPost, backupPath, ""); rec.Code != http.StatusForbidden {
			t.Fatalf("no-credential POST backup = %d, want 403", rec.Code)
		}
		if n := len(backupRows(e)); n != 0 {
			t.Fatalf("%d rows for a refused anonymous call", n)
		}
	})

	t.Run("none mode with the admin bearer", func(t *testing.T) {
		const adminTok = "cp-admin-s3cret"
		e := newAuditEnv(t, auditEnvOpts{token: dashTestToken, adminToken: adminTok})
		_, _, release := routeBackup(t, e)
		defer release()
		if rec := e.send("", "wrong", http.MethodPost, backupPath, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong bearer POST backup = %d, want 401", rec.Code)
		}
		if rec := e.send("", adminTok, http.MethodPost, backupPath, ""); rec.Code != http.StatusAccepted {
			t.Fatalf("admin bearer POST backup = %d, want 202", rec.Code)
		}
	})
}

func TestBackupRouteIsAuditedAdminMutation(t *testing.T) {
	row, ok := authzTable()[routeKey{http.MethodPost, backupPath}]
	if !ok {
		t.Fatal("POST /dashboard/api/backup has no authz row")
	}
	if row.MinRole.String() != "admin" || !row.Audited || row.Action != "backup.run" || row.Target != "backup" || row.Class != classAudited {
		t.Fatalf("row = %+v", row)
	}
}

func TestBackupStartOnDemand(t *testing.T) {
	r := NewBackupRunner(testBackupConfig(t), fakeDeps(t, clocktest.NewFake(testBackupT0)))
	if err := r.StartOnDemand(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Wait() // covers the on-demand run
	if r.Status().LastSet == "" {
		t.Fatal("Wait returned before the on-demand run finished")
	}
	if err := r.StartOnDemand(context.Background()); !errors.Is(err, ErrBackupStopped) {
		t.Fatalf("StartOnDemand after Wait = %v, want ErrBackupStopped", err)
	}
	// The refusal released the run lock: RunOnce still works.
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce after a refused StartOnDemand: %v", err)
	}
}
