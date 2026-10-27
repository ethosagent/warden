package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/test/harness"
	"gopkg.in/yaml.v3"
)

// The admin audit gate (W-P1-AAUD-05): with console.adminAudit.enabled the
// control plane creates its audit keys in the state dir, writes the genesis
// entry before serving, and logs the key_id and public key, never key
// material. Workers keep pulling policy as before.

func adminAuditOpts() []harness.Option { return []harness.Option{harness.WithAdminAudit()} }

func adminAuditEnabledGenesis(t *testing.T, h *harness.H) {
	// The worker still gets its policy and allows traffic: audit is CP-local.
	h.Upstream("api.example.com")
	if status, _ := get(t, h, "https://api.example.com/v1/models", nil); status != http.StatusOK {
		t.Fatalf("allowed request = %d, want 200", status)
	}

	rows := h.AdminAuditRows()
	if len(rows) != 1 || rows[0].Action != adminaudit.ActionGenesis || rows[0].AuthMethod != adminaudit.AuthMethodSystem {
		t.Fatalf("admin_audit = %+v, want exactly the genesis entry", rows)
	}
	for _, f := range []string{adminaudit.DefaultKeyFileName, adminaudit.HMACKeyFileName} {
		if !h.AdminAuditStateFile(f) {
			t.Errorf("%s not created in the state dir", f)
		}
	}

	logs := h.Logs()
	if strings.Contains(logs, "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
	var found bool
	for _, line := range strings.Split(logs, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "admin audit enabled" {
			continue
		}
		found = true
		if rec["key_id"] != rows[0].KeyID {
			t.Errorf("logged key_id = %v, want the genesis key_id %s", rec["key_id"], rows[0].KeyID)
		}
		if pk, _ := rec["public_key"].(string); pk == "" {
			t.Error("startup line has no public_key")
		}
	}
	if !found {
		t.Error("no `admin audit enabled` startup line")
	}
}

// File-mode external edits (W-P1-AAUD-08): a hand edit of the served YAML is
// served as before and recorded as one config.external_change row carrying
// only the before and after file hashes; a dashboard save is not an external
// change, and content already recorded is not recorded again.

const externalChangeAction = "config.external_change"

func adminAuditExternalEdit(t *testing.T, h *harness.H) {
	// A dashboard save goes through a CP writer: it is the CP's own write.
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := h.CP().GetJSON("/dashboard/api/policy", &cur); err != nil {
		t.Fatalf("read the policy: %v", err)
	}
	if err := h.CP().PostJSON("/dashboard/api/policy", cur, nil); err != nil {
		t.Fatalf("dashboard policy save: %v", err)
	}

	// Each edit is the file as the dashboard save left it plus one allowlist
	// domain, so the edits differ only in that domain.
	var orig map[string]any
	withDomain := func(domain string) func(string) string {
		return func(body string) string {
			t.Helper()
			if orig == nil {
				if err := yaml.Unmarshal([]byte(body), &orig); err != nil {
					t.Fatalf("parse the served config: %v", err)
				}
			}
			var doc map[string]any
			b, _ := yaml.Marshal(orig)
			_ = yaml.Unmarshal(b, &doc)
			pol, _ := doc["policy"].(map[string]any)
			allow, _ := pol["allowlist"].([]any)
			pol["allowlist"] = append(allow, map[string]any{"domain": domain})
			out, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatalf("encode the edited config: %v", err)
			}
			return string(out)
		}
	}
	external := func() []harness.AdminAuditRow {
		var out []harness.AdminAuditRow
		for _, r := range h.AdminAuditRows() {
			if r.Action == externalChangeAction {
				out = append(out, r)
			}
		}
		return out
	}
	waitRows := func(n int, after string) {
		t.Helper()
		h.EventuallyWithin(15*time.Second, "a config.external_change row for "+after, func() bool {
			rows := external()
			return len(rows) >= n && rows[len(rows)-1].AfterHash == after
		})
	}
	served := func(domain string) bool {
		var p struct {
			Allowlist []struct {
				Domain string `json:"domain"`
			} `json:"allowlist"`
		}
		if h.CP().GetJSON("/policy", &p) != nil {
			return false
		}
		for _, e := range p.Allowlist {
			if e.Domain == domain {
				return true
			}
		}
		return false
	}

	first := h.EditControlPlaneConfig(withDomain("ext1.example.com"))
	waitRows(1, first)
	if !served("ext1.example.com") {
		t.Fatal("the external edit is not served")
	}
	second := h.EditControlPlaneConfig(withDomain("ext2.example.com"))
	waitRows(2, second)

	// Back to the first edit's content: served again, never recorded again.
	h.EditControlPlaneConfig(withDomain("ext1.example.com"))
	h.EventuallyWithin(15*time.Second, "the reverted edit to be served", func() bool {
		return served("ext1.example.com") && !served("ext2.example.com")
	})
	third := h.EditControlPlaneConfig(withDomain("ext3.example.com"))
	waitRows(3, third)

	rows := external()
	if len(rows) != 3 {
		t.Fatalf("config.external_change rows = %+v, want exactly 3 (save and repeat not recorded)", rows)
	}
	for i, want := range []string{first, second, third} {
		r := rows[i]
		if r.AfterHash != want || r.Target != "policy" || r.AuthMethod != adminaudit.AuthMethodSystem ||
			!strings.HasPrefix(r.BeforeHash, "file:") {
			t.Errorf("row %d = %+v, want target policy, auth system, after %s", i, r, want)
		}
	}
	if lineHas(h.Logs(), "served config changed", "ext1.example.com") {
		t.Error("the external-change log line carries file content")
	}
}

// lineHas reports whether one log line contains both a and b.
func lineHas(logs, a, b string) bool {
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, a) && strings.Contains(line, b) {
			return true
		}
	}
	return false
}
