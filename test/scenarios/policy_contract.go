package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/harness"
)

// The policy version contract scenario (W-P1-PVER-08): with
// --policy-store=versioned and admin audit on, the policy GET reports the head
// in its body and the X-Warden-Policy-Version header; a save naming the head
// with If-Match creates the next version that workers enforce; a second save
// from the same head is a 409 policy_conflict naming the new head and its
// author and creates nothing; a malformed If-Match is a 400; an llmProviders
// save moves the shared head, so a policy save from the old head conflicts.
// The admin audit log records the save as v<N>:<doc_sha256> before and after
// and the conflict as outcome rejected.

func policyContractOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore(), harness.WithAdminAudit()}
}

// conflictHost is allowed only by the stale save, which must never apply.
const conflictHost = "conflict.example.com"

func policyIfMatchConflict(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)
	h.Upstream(conflictHost)
	cp := h.CP()

	send := func(method, path, ifMatch string, body any) harness.CPResponse {
		t.Helper()
		var raw []byte
		if body != nil {
			var err error
			if raw, err = json.Marshal(body); err != nil {
				t.Fatal(err)
			}
		}
		hdr := http.Header{}
		if ifMatch != "" {
			hdr.Set("If-Match", ifMatch)
		}
		resp, err := cp.Send(method, path, hdr, raw)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
		Version   int64            `json:"version"`
	}
	get := send(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err := json.Unmarshal(get.Body, &cur); err != nil {
		t.Fatal(err)
	}
	if get.Status != http.StatusOK || cur.Version != 1 || get.Header.Get(dashboard.PolicyVersionHeader) != "1" {
		t.Fatalf("GET policy = %d version %d header %q, want 200 at v1", get.Status, cur.Version, get.Header.Get(dashboard.PolicyVersionHeader))
	}
	edit := func(host string) map[string]any {
		return map[string]any{"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": host}), "denylist": cur.Denylist}
	}

	if r := send(http.MethodPost, "/dashboard/api/policy", `"v1"`, edit(pverHost)); r.Status != http.StatusOK || r.Header.Get(dashboard.PolicyVersionHeader) != "2" {
		t.Fatalf("save from v1 = %d (version header %q) %s, want 200 at v2", r.Status, r.Header.Get(dashboard.PolicyVersionHeader), r.Body)
	}
	assertConflict := func(r harness.CPResponse, wantHead int64) {
		t.Helper()
		var body struct {
			Error  string            `json:"error"`
			Head   int64             `json:"head"`
			Author map[string]string `json:"author"`
		}
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Fatalf("409 body %s: %v", r.Body, err)
		}
		if r.Status != http.StatusConflict || body.Error != "policy_conflict" || body.Head != wantHead || body.Author["sub"] != "anonymous" {
			t.Fatalf("stale save = %d %s, want 409 policy_conflict at v%d by anonymous", r.Status, r.Body, wantHead)
		}
		if strings.Contains(string(r.Body), "example.com") {
			t.Fatalf("409 body carries doc content: %s", r.Body)
		}
	}
	assertConflict(send(http.MethodPost, "/dashboard/api/policy", `"v1"`, edit(conflictHost)), 2)
	if r := send(http.MethodPost, "/dashboard/api/policy", "v2", edit(conflictHost)); r.Status != http.StatusBadRequest {
		t.Fatalf("malformed If-Match = %d, want 400", r.Status)
	}

	// Policy and llmProviders share the head.
	providers := []map[string]any{{"name": "pver", "baseURL": "https://llm.example.com/v1", "model": "m1", "apiKeyEnv": "PVER_LLM_KEY"}}
	if r := send(http.MethodPost, "/dashboard/api/llmproviders", `"v2"`, providers); r.Status != http.StatusOK || r.Header.Get(dashboard.PolicyVersionHeader) != "3" {
		t.Fatalf("llmProviders save from v2 = %d %s, want 200 at v3", r.Status, r.Body)
	}
	assertConflict(send(http.MethodPost, "/dashboard/api/policy", `"v2"`, edit(conflictHost)), 3)

	h.Eventually("workers enforce the saved version", func() bool {
		return connectStatus(t, h, pverHost+":443") == http.StatusOK
	})
	if got := connectStatus(t, h, conflictHost+":443"); got != http.StatusForbidden {
		t.Errorf("CONNECT %s = %d, want 403 (the conflicting saves never applied)", conflictHost, got)
	}

	var saves []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		if r.Action == "policy.write" {
			saves = append(saves, r)
		}
	}
	// The save, the conflict, the malformed If-Match and the second conflict.
	if len(saves) != 4 {
		t.Fatalf("%d policy.write audit rows, want 4: %+v", len(saves), saves)
	}
	ok, conflict := saves[0], saves[1]
	if ok.Outcome != "ok" || !strings.HasPrefix(ok.BeforeHash, "v1:") || !strings.HasPrefix(ok.AfterHash, "v2:") {
		t.Errorf("save row outcome %q before %q after %q, want ok v1:<sha> -> v2:<sha>", ok.Outcome, ok.BeforeHash, ok.AfterHash)
	}
	if conflict.Outcome != "rejected" || conflict.HTTPStatus != http.StatusConflict || conflict.BeforeHash != ok.AfterHash || conflict.AfterHash != ok.AfterHash {
		t.Errorf("conflict row outcome %q status %d before %q after %q, want rejected 409 at %s", conflict.Outcome, conflict.HTTPStatus, conflict.BeforeHash, conflict.AfterHash, ok.AfterHash)
	}
	if !strings.HasPrefix(saves[3].BeforeHash, "v3:") || saves[3].Outcome != "rejected" {
		t.Errorf("shared-head conflict row outcome %q before %q, want rejected at v3", saves[3].Outcome, saves[3].BeforeHash)
	}
}
