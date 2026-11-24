package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The admin audit gate (W-P1-AAUD-05): the control plane boots with
// console.adminAudit.enabled and a state dir, so it creates its signing and
// HMAC keys there and writes the chain's genesis entry before serving.

// WithAdminAudit boots the control plane with console.adminAudit.enabled: true
// and a state dir under the harness root. It combines with WithConsoleOIDC.
func WithAdminAudit() Option {
	return func(h *H) { h.wantAdminAudit = true }
}

// WithAdminAuditJSONLog is WithAdminAudit plus audit.jsonLog with a file
// output under the harness root (W-P1-JAUD-03): every admin audit row and
// checkpoint is also written as a warden.admin.v1 line.
func WithAdminAuditJSONLog() Option {
	return func(h *H) { h.wantAdminAudit, h.wantAdminJSONLog = true, true }
}

func (h *H) adminJSONLogPath() string { return filepath.Join(h.root, "cp-audit", "admin.jsonl") }

// auditJSONLogYAML renders the audit block of the control plane's config.
func (h *H) auditJSONLogYAML() string {
	if !h.wantAdminJSONLog {
		return ""
	}
	return "\naudit:\n  jsonLog:\n    enabled: true\n    output: file\n    path: " + h.adminJSONLogPath() + "\n"
}

// AdminAuditJSONLines returns the lines of the admin JSON stream file as it is
// now, in file order ("" lines dropped). The stream is written by a background
// goroutine, so callers poll until the line they expect appears.
func (h *H) AdminAuditJSONLines() []string {
	h.tb.Helper()
	if !h.wantAdminJSONLog {
		h.tb.Fatal("harness: AdminAuditJSONLines needs the WithAdminAuditJSONLog option")
	}
	raw, err := os.ReadFile(h.adminJSONLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		h.tb.Fatalf("harness: read the admin JSON stream: %v", err)
	}
	var out []string
	for _, ln := range strings.Split(string(raw), "\n") {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

// AdminAuditRow is one row of the control plane's admin_audit table.
type AdminAuditRow struct {
	Seq        int64
	Action     string
	AuthMethod string
	KeyID      string
	ActorRole  string
	Target     string
	TargetRef  string
	Outcome    string
	HTTPStatus int
	BeforeHash string
	AfterHash  string
	RequestID  string
	ClientIP   string
	// Details is the row's details object as stored (JSON).
	Details string
	// Sub and Email are the actor's from the side table ("" without a side row).
	Sub   string
	Email string
}

// AdminAuditRows reads the admin_audit table of the control plane's state
// database, read-only and oldest first: what the control plane stored,
// independent of its API.
func (h *H) AdminAuditRows() []AdminAuditRow {
	h.tb.Helper()
	if !h.wantAdminAudit {
		h.tb.Fatal("harness: AdminAuditRows needs the WithAdminAudit option")
	}
	path := filepath.Join(h.root, "cp-state", "warden-cp.db")
	if _, err := os.Stat(path); err != nil {
		h.tb.Fatalf("harness: control-plane state db: %v", err)
	}
	db, err := cpstate.OpenReadOnly(context.Background(), path, controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT a.seq, a.action, a.auth_method, a.key_id, a.actor_role, a.target,
		a.target_ref, a.outcome, a.http_status, a.before_hash, a.after_hash, a.request_id, a.client_ip,
		a.details_json, COALESCE(s.sub, ''), COALESCE(s.email, '')
		FROM admin_audit a LEFT JOIN admin_audit_actor s ON s.seq = a.seq ORDER BY a.seq`)
	if err != nil {
		h.tb.Fatalf("harness: read admin_audit: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AdminAuditRow
	for rows.Next() {
		var r AdminAuditRow
		if err := rows.Scan(&r.Seq, &r.Action, &r.AuthMethod, &r.KeyID, &r.ActorRole, &r.Target,
			&r.TargetRef, &r.Outcome, &r.HTTPStatus, &r.BeforeHash, &r.AfterHash, &r.RequestID, &r.ClientIP,
			&r.Details, &r.Sub, &r.Email); err != nil {
			h.tb.Fatalf("harness: scan an admin_audit row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read admin_audit: %v", err)
	}
	return out
}

// AdminAuditStateFile reports whether name exists in the control plane's
// state dir (for example the audit key files).
func (h *H) AdminAuditStateFile(name string) bool {
	h.tb.Helper()
	_, err := os.Stat(filepath.Join(h.root, "cp-state", name))
	return err == nil
}

// AdminAuditStateDir is the control plane's state dir (it holds warden-cp.db
// and, by default, the audit keys), for scenarios that drive the offline
// admin-audit verify and export functions against a live control plane.
func (h *H) AdminAuditStateDir() string {
	h.tb.Helper()
	if !h.wantAdminAudit {
		h.tb.Fatal("harness: AdminAuditStateDir needs the WithAdminAudit option")
	}
	return filepath.Join(h.root, "cp-state")
}

// EditControlPlaneConfig rewrites the control plane's served YAML outside the
// control plane, the way an operator's editor or a config tool would (a temp
// file renamed into place), and returns the new content's "file:<sha256>"
// state hash. The control plane serves it on its next re-read. With a state
// dir the served file is the copy the control plane seeded there.
func (h *H) EditControlPlaneConfig(edit func(string) string) string {
	h.tb.Helper()
	path := h.controlPlaneConfigPath()
	cur, err := os.ReadFile(path)
	if err != nil {
		h.tb.Fatalf("harness: read control-plane config: %v", err)
	}
	next := []byte(edit(string(cur)))
	tmp := path + ".edit"
	if err := os.WriteFile(tmp, next, 0o600); err != nil {
		h.tb.Fatalf("harness: write control-plane config: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		h.tb.Fatalf("harness: replace control-plane config: %v", err)
	}
	sum := sha256.Sum256(next)
	return "file:" + hex.EncodeToString(sum[:])
}

// ReadControlPlaneConfig returns the control plane's served YAML as it is on
// disk now (with a state dir, the copy the control plane seeded there).
func (h *H) ReadControlPlaneConfig() string {
	h.tb.Helper()
	cur, err := os.ReadFile(h.controlPlaneConfigPath())
	if err != nil {
		h.tb.Fatalf("harness: read control-plane config: %v", err)
	}
	return string(cur)
}

// controlPlaneConfigPath is the served YAML: the seeded copy in the state dir
// when the control plane has one, otherwise the config it was started with.
func (h *H) controlPlaneConfigPath() string {
	if h.wantAdminAudit || h.wantConsole || h.versionedPolicy || h.wantKeys {
		return filepath.Join(h.root, "cp-state", "config.yaml")
	}
	return filepath.Join(h.root, "cp-config.yaml")
}
