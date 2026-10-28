package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

// ErrControlPlaneRunning is returned by RunOfflineBackup when the state dir's
// instance lock is held, i.e. a control plane (or another offline command) is
// using it. Its text is the operator-facing message.
var ErrControlPlaneRunning = errors.New("control plane is running; use POST /dashboard/api/backup or stop it")

// OfflineBackupParams are the inputs of `warden control-plane backup`.
type OfflineBackupParams struct {
	// StateDir is the CP's --state-dir; Backup.Dir its --backup-dir.
	StateDir string
	Backup   BackupConfig
	// AnalyticsDB and AlertsDB are the --analytics-db and --alerts-db values
	// ("" = the CP's defaults: <state-dir>/warden-fleet.db and a sibling of it
	// named warden-alerts.db).
	AnalyticsDB, AlertsDB string
	// Version is the warden version recorded in the manifest.
	Version string
	Logger  *slog.Logger
}

// RunOfflineBackup writes one backup set for a stopped control plane. It takes
// the state-dir lock (ErrControlPlaneRunning when held), opens the stores
// directly, runs the same runner a CP uses and releases everything. It never
// opens the admin audit store, so the manifest has no audit key fingerprint,
// and it starts no server. It never prunes older sets. The CP database is opened read-only; a database
// that does not exist is listed as skipped, except the CP's own, which is an
// error because there is nothing to back up without it.
func RunOfflineBackup(ctx context.Context, p OfflineBackupParams) (BackupResult, error) {
	if !p.Backup.Enabled() {
		return BackupResult{}, errors.New("--backup-dir is required")
	}
	p.Backup = p.Backup.withDefaults() // schedule and retention are not offline settings
	if err := p.Backup.Validate(p.StateDir); err != nil {
		return BackupResult{}, err
	}
	if fi, err := os.Stat(p.StateDir); err != nil || !fi.IsDir() {
		return BackupResult{}, fmt.Errorf("--state-dir %s is not a directory", p.StateDir)
	}
	release, err := cpstate.AcquireDirLock(p.StateDir)
	if errors.Is(err, cpstate.ErrLocked) {
		return BackupResult{}, ErrControlPlaneRunning
	}
	if err != nil {
		return BackupResult{}, err
	}
	defer func() { _ = release() }()

	// A one-off set must not delete sets the running control plane's retention
	// (--backup-keep) would have kept, so this run prunes none.
	p.Backup.Keep = math.MaxInt32

	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	deps := BackupDeps{
		ConfigPath: filepath.Join(p.StateDir, "config.yaml"), Version: p.Version, Logger: logger,
		CP:     BackupStore{Reason: "not included"},
		Alerts: BackupStore{Reason: "not included"},
		Fleet:  BackupStore{Reason: "not included"},
	}
	fleetPath := p.AnalyticsDB
	if fleetPath == "" {
		fleetPath = filepath.Join(p.StateDir, "warden-fleet.db")
	}
	alertsPath := p.AlertsDB
	if alertsPath == "" {
		alertsPath = filepath.Join(filepath.Dir(fleetPath), "warden-alerts.db")
	}

	if p.Backup.Has(BackupCP) {
		state, err := cpstate.OpenReadOnly(ctx, filepath.Join(p.StateDir, "warden-cp.db"), StateMigrations())
		if err != nil {
			return BackupResult{}, fmt.Errorf("control-plane state db: %w", err)
		}
		defer func() { _ = state.Close() }()
		deps.CP = BackupStore{Source: state, Path: state.Path()}
		deps.SchemaVersion = state.SchemaVersion
	}
	if p.Backup.Has(BackupAlerts) {
		deps.Alerts = BackupStore{Reason: "alert database not found: " + alertsPath}
		if fileExists(alertsPath) {
			st, err := integration.NewStore(alertsPath)
			if err != nil {
				return BackupResult{}, fmt.Errorf("alert store: %w", err)
			}
			defer func() { _ = st.Close() }()
			deps.Alerts = BackupStore{Source: st, Path: alertsPath}
		}
	}
	if p.Backup.Has(BackupFleet) {
		deps.Fleet = BackupStore{Reason: "fleet database not found: " + fleetPath}
		if fileExists(fleetPath) {
			st, err := analytics.NewFleetSQLiteStore(fleetPath, 0, 0)
			if err != nil {
				return BackupResult{}, fmt.Errorf("fleet store: %w", err)
			}
			defer func() { _ = st.Close() }()
			deps.Fleet = BackupStore{Source: st, Path: fleetPath}
		}
	}
	return NewBackupRunner(p.Backup, deps).RunOnce(ctx)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
