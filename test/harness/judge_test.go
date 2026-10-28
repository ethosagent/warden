package harness

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
)

// TestWithFakeJudge: the fake counts what reaches it and the worker's judge is
// pointed at it.
func TestWithFakeJudge(t *testing.T) {
	h := New(t, WithFakeJudge())
	j := h.Judge()
	if j.Calls() != 0 {
		t.Fatalf("calls = %d before any request, want 0", j.Calls())
	}
	resp, err := http.Post(j.URL()+"/chat/completions", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || j.Calls() != 1 {
		t.Errorf("status %d, calls %d, want 200 and 1", resp.StatusCode, j.Calls())
	}
	if !h.workerParams(1).Config.(*fakes.FakeConfigProvider).Policy.Judge.Enabled {
		t.Error("the worker's judge is not enabled against the fake")
	}
}

// TestWithoutProxyCA: the worker boots with no TLS-termination CA and still
// tunnels an allowed destination.
func TestWithoutProxyCA(t *testing.T) {
	h := New(t, WithoutProxyCA())
	p := h.workerParams(1)
	if p.CACert != "" || p.CAKey != "" {
		t.Errorf("worker CA = %q / %q, want none", p.CACert, p.CAKey)
	}
	h.Upstream("api.example.com")
	if got := h.ConnectStatus("api.example.com:443"); got != http.StatusOK {
		t.Errorf("CONNECT = %d, want 200", got)
	}
}

// TestWithScopedAllow: the control plane serves the scoped entry in the
// projected scopedAllowlist, not in the plain allowlist.
func TestWithScopedAllow(t *testing.T) {
	h := New(t, WithScopedAllow("scoped.example.com", "eng", "ops"))
	var wire struct {
		Allowlist       []map[string]any `json:"allowlist"`
		ScopedAllowlist []struct {
			Domain string   `json:"domain"`
			Groups []string `json:"groups"`
		} `json:"scopedAllowlist"`
	}
	if err := h.CP().GetJSON("/policy", &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.ScopedAllowlist) != 1 || wire.ScopedAllowlist[0].Domain != "scoped.example.com" || strings.Join(wire.ScopedAllowlist[0].Groups, ",") != "eng,ops" {
		t.Errorf("scopedAllowlist = %+v, want scoped.example.com [eng ops]", wire.ScopedAllowlist)
	}
	for _, e := range wire.Allowlist {
		if e["domain"] == "scoped.example.com" {
			t.Errorf("the scoped entry is in the plain allowlist: %v", e)
		}
	}
}
