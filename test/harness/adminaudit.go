package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

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

// AdminAuditRow is one row of the control plane's admin_audit table.
type AdminAuditRow struct {
	Seq        int64
	Action     string
	AuthMethod string
	KeyID      string
	Target     string
	BeforeHash string
	AfterHash  string
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
	rows, err := db.SQL().Query(`SELECT seq, action, auth_method, key_id, target, before_hash, after_hash FROM admin_audit ORDER BY seq`)
	if err != nil {
		h.tb.Fatalf("harness: read admin_audit: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AdminAuditRow
	for rows.Next() {
		var r AdminAuditRow
		if err := rows.Scan(&r.Seq, &r.Action, &r.AuthMethod, &r.KeyID, &r.Target, &r.BeforeHash, &r.AfterHash); err != nil {
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
	if h.wantAdminAudit || h.wantConsole || h.versionedPolicy {
		return filepath.Join(h.root, "cp-state", "config.yaml")
	}
	return filepath.Join(h.root, "cp-config.yaml")
}
