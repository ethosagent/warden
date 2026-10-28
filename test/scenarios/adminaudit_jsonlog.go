package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/test/harness"
)

// The JSON admin stream (W-P1-JAUD-03): with audit.jsonLog enabled the control
// plane writes every admin audit row, and the periodic checkpoint, as a
// warden.admin.v1 line a SIEM shipper can read.

func adminAuditJSONLogOpts() []harness.Option {
	return []harness.Option{harness.WithAdminAuditJSONLog(), harness.WithControlPlaneAdminToken()}
}

// adminAuditJSONLogWritesLines: the startup checkpoint is a line; an admin
// policy write adds one ok line equal to its stored row; a refused (401)
// write adds none; no token value reaches the file.
func adminAuditJSONLogWritesLines(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin, worker := h.ControlPlaneAdminToken(), cp.Token()

	code, policy, err := cp.Do(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy = %d, %v", code, err)
	}
	if code, _, err := cp.Do(http.MethodPut, "/dashboard/api/policy", "wrong-token", []byte(policy)); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("PUT with a wrong bearer = %d, %v; want 401", code, err)
	}
	if code, body, err := cp.Do(http.MethodPut, "/dashboard/api/policy", admin, []byte(policy)); err != nil || code != http.StatusOK {
		t.Fatalf("PUT with the admin bearer = %d %q, %v", code, body, err)
	}
	rows := h.AdminAuditRows()
	stored := rows[len(rows)-1]

	var lines []auditlog.AdminRecord
	deadline := time.Now().Add(5 * time.Second)
	for {
		lines = lines[:0]
		for _, ln := range h.AdminAuditJSONLines() {
			var r auditlog.AdminRecord
			if err := json.Unmarshal([]byte(ln), &r); err != nil {
				t.Fatalf("admin stream line %q: %v", ln, err)
			}
			lines = append(lines, r)
		}
		if len(lines) >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(lines) != 2 {
		t.Fatalf("admin stream = %+v, want the startup checkpoint and one policy.write line", lines)
	}
	cpt, w := lines[0], lines[1]
	if cpt.Schema != "warden.admin.v1" || cpt.Action != auditlog.ActionCheckpoint || cpt.ChainSeq != 1 {
		t.Errorf("first line = %+v, want the genesis-head checkpoint", cpt)
	}
	if w.Schema != "warden.admin.v1" || w.Action != "policy.write" || w.Outcome != "ok" || w.Actor.Sub != "cp-admin-token" ||
		w.ChainSeq != stored.Seq || w.KeyID != stored.KeyID || w.BeforeHash != stored.BeforeHash || w.AfterHash != stored.AfterHash ||
		w.RequestID != stored.RequestID || w.AuthMethod != stored.AuthMethod {
		t.Errorf("write line = %+v, stored row = %+v", w, stored)
	}
	raw := strings.Join(h.AdminAuditJSONLines(), "\n")
	if strings.Contains(raw, admin) || strings.Contains(raw, worker) {
		t.Fatal("a control-plane token value reached the admin stream")
	}
}
