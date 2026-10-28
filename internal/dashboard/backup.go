package dashboard

import (
	"errors"
	"io"
	"net/http"

	"github.com/ethosagent/warden/internal/adminaudit"
)

// ErrBackupInProgress is what a BackupStarter returns while a backup run is
// active; the route answers 409 backup_in_progress.
var ErrBackupInProgress = errors.New("backup already in progress")

// BackupStarter starts one backup run in the background and returns at once:
// nil when it started, ErrBackupInProgress when one is active. The control
// plane binds the run to its own context, never the request's.
type BackupStarter func() error

// maxBackupBody bounds the request body, which is ignored.
const maxBackupBody = 1 << 10

// SetBackup enables POST /dashboard/api/backup. Only a control plane started
// with --backup-dir calls it; without it the route answers 404.
func (s *Server) SetBackup(b BackupStarter) {
	s.backup = b
}

// handleBackup serves POST /dashboard/api/backup (admin, audited backup.run).
// The write guard has already run (Handler wraps every non-GET).
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.backup == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	// The body is ignored; drain a bounded amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, maxBackupBody))
	adminaudit.Annotate(r.Context(), "backup", nil)
	switch err := s.backup(); {
	case err == nil:
		writeJSONStatus(w, http.StatusAccepted, map[string]bool{"started": true})
	case errors.Is(err, ErrBackupInProgress):
		writeError(w, http.StatusConflict, "backup_in_progress")
	default:
		writeError(w, http.StatusInternalServerError, "cannot start the backup")
	}
}
