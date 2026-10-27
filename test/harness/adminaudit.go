package harness

import (
	"context"
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
