package scenarios

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// grantEpochRevokeReport (W-P3-PORT-05): with per-user mappings served for
// support-bot, a worker bound to that agent without usersecrets/v1 is flagged
// noUserSecrets in the fleet view and listed by the revoke's epoch step, while
// one that advertises the capability is neither. The bump wakes a held long poll
// with the user key's epoch, no sub on the wire, and logs only the key prefix.
func grantEpochRevokeReport(t *testing.T, h *harness.H) {
	const oldWorker, newWorker = "old-worker-no-usersecrets", "new-worker-usersecrets"
	cp := h.CP()
	beat := func(id, body string) {
		t.Helper()
		if r := cp.DoWorker(http.MethodPost, "/control/heartbeat", cp.Token(), id, body); r.Status != http.StatusNoContent {
			t.Fatalf("heartbeat %s = %d %s", id, r.Status, r.Body)
		}
	}
	agent := `"agentID":"` + harness.PerUserAgent + `"`
	beat(oldWorker, `{"policyETag":"x",`+agent+`}`)
	beat(newWorker, `{"policyETag":"x","caps":["`+config.CapUserSecretsV1+`"],`+agent+`}`)

	admin, _ := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	h.Eventually("only the worker without usersecrets/v1 is flagged noUserSecrets", func() bool {
		h.Clock().Advance(1)
		beat(oldWorker, `{"policyETag":"x",`+agent+`}`)
		beat(newWorker, `{"policyETag":"x","caps":["`+config.CapUserSecretsV1+`"],`+agent+`}`)
		resp, body := consoleDo(t, admin, http.MethodGet, "/dashboard/api/workers", nil)
		var ws []dashboard.WorkerView
		if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &ws) != nil {
			return false
		}
		seen := 0
		for _, w := range ws {
			switch w.ProxyID {
			case newWorker:
				if w.NoUserSecrets {
					return false
				}
				seen++
			case oldWorker:
				if !w.NoUserSecrets {
					return false
				}
				seen++
			}
		}
		return seen == 2
	})

	alice, err := secrets.UserKey("https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatal(err)
	}
	first := cp.FetchBundle("")
	held := cp.HoldBundle(first.Header.Get("ETag"))
	out := cp.RevokeEpoch(alice)
	if out.Status != "ok" || out.Err != nil {
		t.Fatalf("revoke epoch step = %+v, want ok", out)
	}
	if !slices.Contains(out.WorkersWithoutCap, oldWorker) || slices.Contains(out.WorkersWithoutCap, newWorker) {
		t.Errorf("workers_without_cap = %v, want %s and not %s", out.WorkersWithoutCap, oldWorker, newWorker)
	}
	var woke harness.RawResponse
	h.Eventually("the bump wakes the held long poll", func() bool {
		select {
		case woke = <-held:
			return true
		default:
			return false
		}
	})
	got := h.VerifyBundle([]byte(woke.Body), bundleApplied(bundleSeqOf(t, h, first, bundle.State{})))
	epochs, err := bundle.ParseUserGrantEpochs(got.Bundle.Sections[bundle.SectionUserGrantEpochs])
	if err != nil || epochs[alice] == 0 || epochs[alice] != got.Seq {
		t.Fatalf("userGrantEpochs = %v (err %v), bundle seq %d", epochs, err, got.Seq)
	}
	for name, raw := range got.Bundle.Sections {
		if strings.Contains(string(raw), "alice") {
			t.Errorf("a subject is in the decoded %s section", name)
		}
	}
	logs := h.Logs()
	if !strings.Contains(logs, "grant_epoch_bumped") || !strings.Contains(logs, alice[:8]) || strings.Contains(logs, alice) || strings.Contains(logs, "alice-sub") {
		t.Errorf("grant_epoch_bumped log must carry only the 8-char key prefix:\n%s", logs)
	}
}
