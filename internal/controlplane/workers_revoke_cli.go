package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// OfflineWorkerCerts is the worker certificate store opened straight on
// <state-dir>/warden-cp.db for `warden control-plane worker revoke`, with the
// control plane running or stopped. A running control plane sees the write
// within its 2 s data_version poll, which refreshes the revoked index and
// cancels the worker's held long-polls. The CLI stays thin (rule C1).
type OfflineWorkerCerts struct {
	db         *cpstate.DB
	st         *EnrollmentStore
	rec        adminaudit.Recorder // nil: admin audit was never enabled here
	closeAudit func() error
	actor      string
}

// OpenWorkerCertsOffline opens the state dir read-write. The admin audit
// recorder is opened first, so a missing or mismatching key fails before
// anything is written. keyFile "" means <stateDir>/cp-audit.key. The database
// must exist: there is nothing to revoke before a control plane has run.
func OpenWorkerCertsOffline(ctx context.Context, stateDir, keyFile string) (*OfflineWorkerCerts, error) {
	if stateDir == "" {
		return nil, errors.New("worker certs: --state-dir is required")
	}
	path := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("worker certs: no control plane state database at %s: %w", path, err)
	}
	rec, closeAudit, err := adminaudit.OpenForCLI(ctx, stateDir, keyFile, StateMigrations())
	if err != nil {
		return nil, fmt.Errorf("admin audit: %w", err)
	}
	db, err := cpstate.Open(ctx, path, StateMigrations())
	if err != nil {
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	st, err := NewEnrollmentStore(db, EnrollmentOptions{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	return &OfflineWorkerCerts{db: db, st: st, rec: rec, closeAudit: closeAudit, actor: adminaudit.CLIActor()}, nil
}

// AuditEnabled reports whether a revoke appends an admin audit row.
func (o *OfflineWorkerCerts) AuditEnabled() bool { return o.rec != nil }

// Close releases both database handles.
func (o *OfflineWorkerCerts) Close() error {
	err := o.db.Close()
	if o.closeAudit != nil {
		if cerr := o.closeAudit(); err == nil {
			err = cerr
		}
	}
	return err
}

// Revoke revokes the worker's unexpired certificates (only serial when it is
// not empty) and appends the worker.revoked audit row. It returns how many it
// revoked; 0 when they were all revoked already (still one audit row, as the
// console does). An unknown worker or serial is ErrCertNotFound.
func (o *OfflineWorkerCerts) Revoke(ctx context.Context, workerID, serial string) (int, error) {
	serial = strings.ToLower(serial)
	if serial != "" && !serialRe.MatchString(serial) {
		return 0, fmt.Errorf("%w: --serial must be lowercase hex", ErrInvalidInput)
	}
	var (
		serials []string
		err     error
	)
	if serial == "" {
		serials, err = o.st.RevokeWorker(ctx, workerID, o.actor, RevokeReasonAdmin)
	} else {
		serials, err = o.st.RevokeWorkerSerial(ctx, workerID, serial, o.actor, RevokeReasonAdmin)
	}
	if err != nil {
		return 0, err
	}
	if o.rec != nil {
		_, aerr := o.rec.Record(ctx, adminaudit.Input{
			Action: actionWorkerRevoked, Target: auditTargetWorkerCerts, TargetRef: workerRef(workerID),
			Details: map[string]string{adminaudit.DetailWorkerID: workerID, adminaudit.DetailCount: strconv.Itoa(len(serials))},
			Outcome: adminaudit.OutcomeOK,
		})
		if aerr != nil {
			return len(serials), fmt.Errorf("worker certs: %d certificate(s) of %s revoked but the admin audit append failed: %w", len(serials), workerID, aerr)
		}
	}
	return len(serials), nil
}
