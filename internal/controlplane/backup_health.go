package controlplane

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// Backup health (W-P1-OPS1-07): a backup that fails or goes quiet must be
// visible. backupHealth is the BackupReporter the runner reports to: a failed
// run logs ERROR cp_backup_failed and raises a backup_failed Finding, and a
// staleness check raises backup_stale when no run has succeeded for two
// intervals. Findings carry the db name and a bounded error text only: never
// row contents.

const (
	backupFailedRule = "backup_failed"
	backupStaleRule  = "backup_stale"

	// backupStaleFactor is how many intervals without a success make the
	// backups stale.
	backupStaleFactor = 2
	// backupStaleMinTick is the floor of the staleness check period.
	backupStaleMinTick = time.Minute
)

// backupHealth implements BackupReporter and owns the staleness check.
type backupHealth struct {
	publish  func(integration.Finding)
	log      *slog.Logger
	clk      clock.Clock
	interval time.Duration
	status   func() BackupStatus
	next     BackupReporter // an extra reporter (tests), optional

	started   time.Time
	staleSent atomic.Bool // a backup_stale Finding is out for this episode
}

var _ BackupReporter = (*backupHealth)(nil)

// newBackupHealth builds the reporter for a runner that backs up every
// interval. status reads the runner's last known state; next, if non-nil, is
// also told of every outcome.
func newBackupHealth(publish func(integration.Finding), log *slog.Logger, clk clock.Clock,
	interval time.Duration, status func() BackupStatus, next BackupReporter) *backupHealth {
	return &backupHealth{publish: publish, log: log, clk: clk, interval: interval, status: status, next: next, started: clk.Now()}
}

// BackupFailed logs the failure and publishes one backup_failed Finding for
// db. The alert pipeline dedups repeats by DedupKey.
func (h *backupHealth) BackupFailed(db string, err error) {
	msg := boundedBackupErr(err)
	h.log.Error("cp_backup_failed", "db", db, "error", msg)
	h.publish(integration.Finding{
		RuleID:   backupFailedRule,
		Category: "operations",
		Severity: integration.SevHigh,
		Subject:  integration.Subject{Tool: "backup"},
		Summary:  fmt.Sprintf("control plane backup of %s failed", db),
		Evidence: integration.Evidence(fmt.Sprintf("db=%s error=%s", db, msg)),
		DedupKey: backupFailedRule + ":" + db,
		Ts:       h.clk.Now(),
	})
	if h.next != nil {
		h.next.BackupFailed(db, err)
	}
}

// BackupSucceeded ends a staleness episode, so a later one raises again.
func (h *backupHealth) BackupSucceeded(set string) {
	h.staleSent.Store(false)
	if h.next != nil {
		h.next.BackupSucceeded(set)
	}
}

// boundedBackupErr is err's text cut to the runner's own error bound.
func boundedBackupErr(err error) string {
	msg := err.Error()
	if len(msg) > backupMaxErrLen {
		msg = strings.ToValidUTF8(msg[:backupMaxErrLen], "")
	}
	return msg
}

// tick is the staleness check period: max(1m, interval/4).
func (h *backupHealth) tick() time.Duration {
	return max(backupStaleMinTick, h.interval/4)
}

// checkStale publishes one backup_stale Finding per episode when the last
// success is older than two intervals. With no success yet, the CP's start
// time stands in for it, so a backup that never works is caught too.
func (h *backupHealth) checkStale() {
	last := h.status().LastSuccessAt
	if last.IsZero() {
		last = h.started
	}
	now := h.clk.Now()
	age := now.Sub(last)
	if age <= backupStaleFactor*h.interval {
		return
	}
	if !h.staleSent.CompareAndSwap(false, true) {
		return
	}
	h.publish(integration.Finding{
		RuleID:   backupStaleRule,
		Category: "operations",
		Severity: integration.SevHigh,
		Subject:  integration.Subject{Tool: "backup"},
		Summary:  fmt.Sprintf("no successful control plane backup for %s (interval %s)", age.Round(time.Minute), h.interval),
		Evidence: integration.Evidence(fmt.Sprintf("last_success=%s interval=%s", formatBackupTime(last), h.interval)),
		DedupKey: backupStaleRule,
		Ts:       now,
	})
}

// formatBackupTime is t as RFC3339 UTC, or "" for the zero time.
func formatBackupTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// runStale runs the staleness check every tick until ctx is cancelled, then
// closes done. It is a named function so a goroutine dump shows it.
func (h *backupHealth) runStale(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	for {
		t := h.clk.NewTimer(h.tick())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C():
		}
		h.checkStale()
	}
}

// setBackupStatus gives the dashboard's /setup the runner's status. It may be
// called after New: the dashboard closure reads it per request.
func (s *Server) setBackupStatus(r *BackupRunner) { s.backupRunner.Store(r) }

// backupStatusFor is the dashboard's status closure. It answers nil (no
// backup field) when backups are off, and for any caller but an admin: with
// console.auth none every caller is the admin, in oidc mode the session's
// role must be admin. Viewers and editors never see it.
func (s *Server) backupStatusFor(r *http.Request) *dashboard.BackupStatus {
	bk := s.backupRunner.Load()
	if bk == nil {
		return nil
	}
	if s.authMode() != config.ConsoleAuthNone {
		p, ok := PrincipalFrom(r.Context())
		if !ok || principalRole(s.cfg.Console, p) < config.RoleAdmin {
			return nil
		}
	}
	st := bk.Status()
	return &dashboard.BackupStatus{
		Enabled:       true,
		LastSuccessAt: formatBackupTime(st.LastSuccessAt),
		LastError:     st.LastError,
		LastSet:       st.LastSet,
		SizeBytes:     st.SizeBytes,
	}
}
