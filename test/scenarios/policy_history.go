package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/harness"
)

// The policy history scenario (W-P1-PVER-03): with --policy-store=versioned
// and admin audit on, a save that allows a host creates v2 and workers enforce
// it; the history lists v2 and v1 newest first; the diff of v1 against head
// names the host as removed; a rollback without If-Match is a 428 and creates
// nothing; a rollback to v1 with If-Match "v2" creates v3 with v1's doc, and
// workers deny the host again. The admin audit log records the rollback as
// policy.rollback with v2:<sha> before and v3:<sha> after.

func policyHistoryOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore(), harness.WithAdminAudit()}
}

// rollbackHost is allowed only by v2, which the rollback undoes.
const rollbackHost = "rollback.example.com"

func policyHistoryRollback(t *testing.T, h *harness.H) {
	h.Upstream(rollbackHost)
	cp := h.CP()
	send := func(method, path, ifMatch string, body []byte) harness.CPResponse {
		t.Helper()
		hdr := http.Header{}
		if ifMatch != "" {
			hdr.Set("If-Match", ifMatch)
		}
		resp, err := cp.Send(method, path, hdr, body)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := json.Unmarshal(send(http.MethodGet, "/dashboard/api/policy", "", nil).Body, &cur); err != nil {
		t.Fatal(err)
	}
	edit, err := json.Marshal(map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": rollbackHost}),
		"denylist":  cur.Denylist,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := send(http.MethodPost, "/dashboard/api/policy", `"v1"`, edit); r.Status != http.StatusOK || r.Header.Get(dashboard.PolicyVersionHeader) != "2" {
		t.Fatalf("save from v1 = %d %s, want 200 at v2", r.Status, r.Body)
	}
	h.Eventually("workers enforce v2", func() bool {
		return connectStatus(t, h, rollbackHost+":443") == http.StatusOK
	})

	var page struct {
		Head     int64                         `json:"head"`
		Versions []dashboard.PolicyVersionMeta `json:"versions"`
	}
	list := send(http.MethodGet, "/dashboard/api/policy/versions", "", nil)
	if err := json.Unmarshal(list.Body, &page); err != nil || list.Status != http.StatusOK {
		t.Fatalf("list = %d %s (%v)", list.Status, list.Body, err)
	}
	if page.Head != 2 || len(page.Versions) != 2 || page.Versions[0].Version != 2 || page.Versions[1].Version != 1 {
		t.Fatalf("list = %+v, want head 2 with v2, v1", page)
	}
	v1SHA := page.Versions[1].DocSHA256

	diff := send(http.MethodGet, "/dashboard/api/policy/versions/1/diff", "", nil)
	if diff.Status != http.StatusOK || !strings.Contains(string(diff.Body), `"from":2,"to":1`) ||
		!strings.Contains(string(diff.Body), `"key":"`+rollbackHost) || !strings.Contains(string(diff.Body), `"kind":"removed"`) {
		t.Fatalf("diff v1 against head = %d %s, want %s removed", diff.Status, diff.Body, rollbackHost)
	}

	if r := send(http.MethodPost, "/dashboard/api/policy/versions/1/rollback", "", nil); r.Status != http.StatusPreconditionRequired {
		t.Fatalf("rollback without If-Match = %d %s, want 428", r.Status, r.Body)
	}
	r := send(http.MethodPost, "/dashboard/api/policy/versions/1/rollback", `"v2"`, []byte(`{"note":"undo rollback host"}`))
	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"head":3,"changed":true`) || r.Header.Get(dashboard.PolicyVersionHeader) != "3" {
		t.Fatalf("rollback to v1 = %d %s, want 200 at v3", r.Status, r.Body)
	}
	h.Eventually("workers enforce the rollback", func() bool {
		return connectStatus(t, h, rollbackHost+":443") == http.StatusForbidden
	})
	var v3 dashboard.PolicyVersionDoc
	if err := json.Unmarshal(send(http.MethodGet, "/dashboard/api/policy/versions/3", "", nil).Body, &v3); err != nil {
		t.Fatal(err)
	}
	if v3.Source != "rollback" || v3.Message != "rollback to v1: undo rollback host" || v3.DocSHA256 != v1SHA {
		t.Fatalf("v3 = source %q message %q sha %s, want rollback of v1 (sha %s)", v3.Source, v3.Message, v3.DocSHA256, v1SHA)
	}

	var rows []harness.AdminAuditRow
	for _, row := range h.AdminAuditRows() {
		if row.Action == "policy.rollback" {
			rows = append(rows, row)
		}
	}
	// The 428 and the rollback.
	if len(rows) != 2 {
		t.Fatalf("%d policy.rollback audit rows, want 2: %+v", len(rows), rows)
	}
	ok := rows[1]
	if ok.Outcome != "ok" || ok.Target != "policy" || !strings.HasPrefix(ok.BeforeHash, "v2:") || ok.AfterHash != "v3:"+v1SHA {
		t.Errorf("rollback row outcome %q target %q before %q after %q, want ok policy v2:<sha> -> v3:%s", ok.Outcome, ok.Target, ok.BeforeHash, ok.AfterHash, v1SHA)
	}
}
