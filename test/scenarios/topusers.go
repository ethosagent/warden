package scenarios

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// topUsersAPI proves W-P1-VRFY-10 end to end: the analytics response carries a
// topUsers breakdown on the worker dashboard and on the control-plane dashboard
// (fed through its real ingest endpoint), with the same shape and figures, and
// the served page holds the user filter box. Events are seeded directly; the
// proxy stamps them with W-P1-VRFY-09.
func topUsersAPI(t *testing.T, h *harness.H) {
	now := time.Now().UTC()
	ev := func(at time.Duration, sub, email, decision string) analytics.Event {
		return analytics.Event{Timestamp: now.Add(at), Domain: "d.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://d.example.com/", Decision: decision, UserSub: sub, UserEmail: email}
	}
	seed := []analytics.Event{
		ev(0, "sub-alice", "alice@corp.example", "allow"),
		ev(time.Second, "sub-alice", "alice@corp.example", "deny"),
		ev(2*time.Second, "sub-bob", "bob@corp.example", "allow"),
		ev(3*time.Second, "", "", "allow"),
	}
	h.SeedEvents(seed...)
	if err := h.CP().IngestEvents("worker-1", seed); err != nil {
		t.Fatalf("seed the control plane: %v", err)
	}

	topUsers := func(get func(string) []byte) []analytics.UserCount {
		var resp struct {
			TopUsers []analytics.UserCount `json:"topUsers"`
		}
		if err := json.Unmarshal(get("/dashboard/api/analytics?range=24h"), &resp); err != nil {
			t.Fatalf("decode analytics: %v", err)
		}
		return resp.TopUsers
	}
	worker := func(path string) []byte {
		status, body := adminDo(t, h, "GET", path)
		if status != 200 {
			t.Fatalf("worker GET %s = %d: %s", path, status, body)
		}
		return body
	}
	cp := func(path string) []byte {
		var raw json.RawMessage
		if err := h.CP().GetJSON(path, &raw); err != nil {
			t.Fatalf("cp GET %s: %v", path, err)
		}
		return raw
	}

	want := []analytics.UserCount{
		{Sub: "sub-alice", Email: "alice@corp.example", Count: 2, Denied: 1},
		{Count: 1, Unattributed: true}, // ties break by sub, and "" sorts first
		{Sub: "sub-bob", Email: "bob@corp.example", Count: 1},
	}
	for name, get := range map[string]func(string) []byte{"worker": worker, "cp": cp} {
		h.Eventually(name+" dashboard to report the top users", func() bool {
			return len(topUsers(get)) == len(want)
		})
		got, _ := json.Marshal(topUsers(get))
		wantJSON, _ := json.Marshal(want)
		if string(got) != string(wantJSON) {
			t.Errorf("%s topUsers = %s, want %s", name, got, wantJSON)
		}
	}
	if page := string(worker("/dashboard/")); !strings.Contains(page, `id="actUser"`) {
		t.Errorf("worker dashboard page lacks the user filter box")
	}
}
