package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

// startupVerifyRows is how many of the newest chain rows the CP verifies at
// startup (the head signature among them). The full chain is the offline
// `control-plane admin-audit verify` command's job.
const startupVerifyRows = 1000

// adminAuditVerifyFailedRule is the rule id (and dedup-key prefix) of the
// Finding a failed startup verification publishes.
const adminAuditVerifyFailedRule = "admin_audit_verify_failed"

// StateMigrations is every cpstate migration the control plane registers,
// whatever its config says, so switching a feature off never trips the
// downgrade guard. Run, the harness and the offline CLIs (through
// adminaudit.OpenForCLI) all open warden-cp.db with this one list; a feature
// that adds tables appends its migrations here.
func StateMigrations() []cpstate.Migration {
	var migs []cpstate.Migration
	migs = append(migs, SessionMigrations()...)
	migs = append(migs, OIDCPendingMigrations()...)
	migs = append(migs, PolicyStoreMigrations()...)
	migs = append(migs, adminaudit.Migrations()...)
	return migs
}

// checkAdminAuditFlags validates the admin audit config against the flags
// before anything is opened: enabled needs a state dir, and the rotation flag
// is meaningless (so refused) with audit off.
func checkAdminAuditFlags(cc config.ConsoleConfig, stateDir string, p Params) error {
	if cc.AdminAudit.Enabled && stateDir == "" {
		return errors.New("control-plane: console.adminAudit.enabled needs --state-dir")
	}
	if !cc.AdminAudit.Enabled && p.AdminAuditNewSegment != "" {
		return fmt.Errorf("control-plane: %s needs console.adminAudit.enabled: true", adminaudit.NewSegmentFlag)
	}
	return nil
}

// openAdminAudit builds the admin audit store on the CP state database: it
// loads (or, on an empty chain, creates) the signing key and the HMAC key,
// runs the fail-closed key check, starts a new segment when asked, writes
// genesis on first use, installs em as the store's Emitter, and logs the
// key_id and public key. Key material is never logged.
func openAdminAudit(ctx context.Context, logger *slog.Logger, state *cpstate.DB, stateDir string, p Params, clk clock.Clock, em adminaudit.Emitter) (*adminaudit.Store, error) {
	keyFile := p.AdminAuditKeyFile
	if keyFile == "" {
		keyFile = adminaudit.DefaultKeyPath(stateDir)
	}
	keyFile = filepath.Clean(keyFile)
	s, err := adminaudit.Open(ctx, state, adminaudit.OpenOptions{
		KeyFile:    keyFile,
		NewSegment: p.AdminAuditNewSegment,
		Clock:      clk,
		Logger:     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("control-plane: admin audit: %w", err)
	}
	// Every entry committed from here on also goes to em (the warden.admin.v1
	// log line), so an off-host copy anchors the chain.
	s.SetEmitter(em)
	logger.Info("admin audit enabled",
		"key_id", s.KeyID(),
		"public_key", base64.StdEncoding.EncodeToString(s.PublicKey()),
		"key_file", keyFile)
	return s, nil
}

// verifyAdminAuditAtStartup runs the bounded chain check after the store
// opened (and so after its key check): the newest startupVerifyRows rows and
// the head signature. A failure is logged at ERROR and published as an
// admin_audit_verify_failed Finding, but never stops the CP: policy keeps
// being served, since refusing to serve would turn a tampered audit table
// into an outage. Nothing is written to the chain. A nil store is a no-op.
func (s *Server) verifyAdminAuditAtStartup(ctx context.Context) {
	st := s.cfg.AdminAudit
	if st == nil {
		return
	}
	logger := s.cfg.Logger
	res, err := st.VerifyTail(ctx, startupVerifyRows)
	if err != nil {
		// A chain the CP cannot even read is as suspicious as one that fails.
		logger.Error("admin audit startup verification could not run", "error", err,
			"hint", "run `warden control-plane admin-audit verify --state-dir <dir>`")
		s.publishFinding(verifyFailedFinding(adminaudit.Result{}, err, s.cfg.Clock.Now()))
		return
	}
	if res.OK {
		logger.Info("admin audit chain verified", "checked", res.Checked, "head_seq", res.HeadSeq)
		return
	}
	logger.Error("admin audit chain verification failed",
		"first_bad_seq", res.FirstBadSeq, "reason", res.Reason,
		"head_seq", res.HeadSeq, "checked", res.Checked,
		"hint", "stop changes and run `warden control-plane admin-audit verify --state-dir <dir>`; see docs/runbooks/admin-audit-key.md")
	s.publishFinding(verifyFailedFinding(res, nil, s.cfg.Clock.Now()))
}

// verifyErrorReason is the Finding reason when the startup check could not
// read the chain at all.
const verifyErrorReason = "verify_error"

// verifyFailedFinding builds the admin_audit_verify_failed Finding for a
// failed result, or for verifyErr when the check could not run. It carries
// only the seq, the reason and the head seq: no error text, no row content.
func verifyFailedFinding(res adminaudit.Result, verifyErr error, now time.Time) integration.Finding {
	reason := res.Reason
	if verifyErr != nil {
		reason = verifyErrorReason
	}
	summary := fmt.Sprintf("admin audit chain verification failed at seq %d (%s)", res.FirstBadSeq, reason)
	if verifyErr != nil {
		summary = "admin audit chain verification could not read the chain (" + reason + ")"
	}
	return integration.Finding{
		RuleID:   adminAuditVerifyFailedRule,
		Category: "security",
		Severity: integration.SevCritical,
		Subject:  integration.Subject{Tool: "admin_audit"},
		Summary:  summary,
		Evidence: integration.Evidence(fmt.Sprintf("first_bad_seq=%d reason=%s head_seq=%d", res.FirstBadSeq, reason, res.HeadSeq)),
		DedupKey: adminAuditVerifyFailedRule + ":admin_audit",
		Ts:       now,
	}
}

// FindingPublisher is how the control plane publishes a Finding. The alert
// pipeline's bus satisfies it; tests inject a fake through Server.findings.
type FindingPublisher interface {
	PublishFinding(f integration.Finding)
}

// publishFinding publishes f through the control plane's FindingPublisher: the
// test override when set, else the current alert manager's bus. A control
// plane with no alert pipeline (or whose manager failed to build) cannot
// deliver it, so the Finding is logged at ERROR by rule id and severity only.
func (s *Server) publishFinding(f integration.Finding) {
	if s.findings != nil {
		s.findings.PublishFinding(f)
		return
	}
	if s.pipeline != nil {
		if m := s.pipeline.CurrentManager(); m != nil {
			m.Bus().PublishFinding(f)
			return
		}
	}
	s.cfg.Logger.Error("finding_not_published", "rule", f.RuleID, "severity", f.Severity.String())
}

// runCheckpointLoop runs the admin audit checkpoint loop until ctx is
// cancelled, then closes done. It is a named function so a goroutine dump
// shows whether the loop is running.
func runCheckpointLoop(ctx context.Context, done chan<- struct{}, s *adminaudit.Store, e adminaudit.Emitter, interval time.Duration, clk clock.Clock) {
	defer close(done)
	adminaudit.RunCheckpoints(ctx, s, e, interval, clk)
}
