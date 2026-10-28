package harness

import (
	"path/filepath"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
)

// WithBackup boots the control plane with --backup-dir (and the --state-dir it
// requires): every source (cp, alerts, config, fleet) is included, the
// interval is 24h on the harness's fake clock, and the last 2 sets are kept.
// The harness's analytics provider is memory, so the fleet database is listed
// as skipped. In-process only.
func WithBackup() Option {
	return func(h *H) { h.wantBackup = true }
}

// BackupInterval and BackupKeep are WithBackup's schedule and retention.
const (
	BackupInterval = 24 * time.Hour
	BackupKeep     = 2
)

func (h *H) applyBackup(p *controlplane.Params) {
	if !h.wantBackup {
		return
	}
	if p.StateDir == "" {
		p.StateDir = filepath.Join(h.root, "cp-state")
	}
	p.Clock = h.fake
	p.Version = "harness"
	p.Backup = controlplane.BackupConfig{
		Dir: h.BackupDir(), Interval: BackupInterval, Keep: BackupKeep,
		Include: []string{controlplane.BackupCP, controlplane.BackupAlerts, controlplane.BackupConfigKey, controlplane.BackupFleet},
	}
}

// BackupDir is the control plane's --backup-dir. It needs WithBackup.
func (h *H) BackupDir() string {
	h.tb.Helper()
	if !h.wantBackup {
		h.tb.Fatal("harness: BackupDir needs the WithBackup option")
	}
	return filepath.Join(h.root, "cp-backups")
}

// StateDir is the control plane's --state-dir. It needs WithBackup.
func (h *H) StateDir() string {
	h.tb.Helper()
	if !h.wantBackup {
		h.tb.Fatal("harness: StateDir needs the WithBackup option")
	}
	return filepath.Join(h.root, "cp-state")
}
