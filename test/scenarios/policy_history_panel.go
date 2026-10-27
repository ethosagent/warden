package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/harness"
)

// The policy history panel scenarios (W-P1-PVER-04). Versioned: the console
// page carries the History panel; a policy save without If-Match is a 428 that
// creates nothing and workers keep denying the host; a save naming the head
// with a percent-encoded message creates v2 with that message in the history,
// and workers enforce it. File mode: the policy GET has no version and a save
// without If-Match still applies.

func policySaveIfMatchOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

// panelHost is allowed only by the save that names the head.
const panelHost = "panel.example.com"

func policySaveIfMatchRequired(t *testing.T, h *harness.H) {
	h.Upstream(panelHost)
	cp := h.CP()
	send := func(method, path string, hdr http.Header, body []byte) harness.CPResponse {
		t.Helper()
		resp, err := cp.Send(method, path, hdr, body)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	page := send(http.MethodGet, "/dashboard/", nil, nil)
	if page.Status != http.StatusOK || !strings.Contains(string(page.Body), `id="policyHistory"`) {
		t.Fatalf("GET /dashboard/ = %d, want the page with the History panel", page.Status)
	}

	edit := panelEdit(t, h, panelHost)
	if r := send(http.MethodPost, "/dashboard/api/policy", nil, edit); r.Status != http.StatusPreconditionRequired {
		t.Fatalf("save without If-Match = %d %s, want 428", r.Status, r.Body)
	}
	var cur struct {
		Version int64 `json:"version"`
	}
	if err := cp.GetJSON("/dashboard/api/policy", &cur); err != nil || cur.Version != 1 {
		t.Fatalf("head after a save without If-Match = v%d (%v), want v1", cur.Version, err)
	}
	if got := connectStatus(t, h, panelHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s after the refused save = %d, want 403", panelHost, got)
	}

	hdr := http.Header{"If-Match": {`"v1"`}, dashboard.PolicyMessageHeader: {"allow%20panel%20%E2%9C%93"}}
	if r := send(http.MethodPost, "/dashboard/api/policy", hdr, edit); r.Status != http.StatusOK || r.Header.Get(dashboard.PolicyVersionHeader) != "2" {
		t.Fatalf("save from v1 = %d %s, want 200 at v2", r.Status, r.Body)
	}
	var hist struct {
		Head     int64 `json:"head"`
		Versions []struct {
			Version int64  `json:"version"`
			Message string `json:"message"`
		} `json:"versions"`
	}
	if err := cp.GetJSON("/dashboard/api/policy/versions", &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Head != 2 || len(hist.Versions) != 2 || hist.Versions[0].Message != "allow panel ✓" {
		t.Fatalf("history = %+v, want v2 first with the save message", hist)
	}
	h.Eventually("workers enforce v2", func() bool {
		return connectStatus(t, h, panelHost+":443") == http.StatusOK
	})
}

func policyFileModeSaveWithoutIfMatch(t *testing.T, h *harness.H) {
	h.Upstream(panelHost)
	cp := h.CP()
	r, err := cp.Send(http.MethodGet, "/dashboard/api/policy", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.Body, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["version"]; ok || r.Header.Get(dashboard.PolicyVersionHeader) != "" {
		t.Fatalf("file mode GET policy reports a version: %s", r.Body)
	}
	if r, err := cp.Send(http.MethodPost, "/dashboard/api/policy", nil, panelEdit(t, h, panelHost)); err != nil || r.Status != http.StatusOK {
		t.Fatalf("file mode save without If-Match = %d %s (%v), want 200", r.Status, r.Body, err)
	}
	h.Eventually("workers enforce the file-mode save", func() bool {
		return connectStatus(t, h, panelHost+":443") == http.StatusOK
	})
}

// panelEdit is the live policy plus an allow entry for host, as a save body.
func panelEdit(t *testing.T, h *harness.H, host string) []byte {
	t.Helper()
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := h.CP().GetJSON("/dashboard/api/policy", &cur); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": host}),
		"denylist":  cur.Denylist,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
