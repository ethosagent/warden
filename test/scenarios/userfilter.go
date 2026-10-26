package scenarios

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// userFilterAPI proves W-P1-VRFY-04 end to end: events carrying identity fields
// (seeded directly; the proxy stamps them with W-P1-VRFY-09) are filtered by
// ?user= on the worker dashboard and, on the control-plane
// dashboard (fed through its real ingest endpoint), for both the traffic and analytics APIs. An email in any case, or
// the sub, selects the same events; a hostile value matches nothing.
func userFilterAPI(t *testing.T, h *harness.H) {
	now := time.Now().UTC()
	seed := []analytics.Event{
		analytics.Event{Timestamp: now, Domain: "alice-1.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://alice-1.example.com/", Decision: "allow", UserSub: "sub-alice", UserEmail: "alice@corp.example", IdentityStatus: "valid"},
		analytics.Event{Timestamp: now.Add(time.Second), Domain: "alice-2.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://alice-2.example.com/", Decision: "deny", UserSub: "sub-alice", UserEmail: "alice@corp.example", IdentityStatus: "valid"},
		analytics.Event{Timestamp: now.Add(2 * time.Second), Domain: "bob-1.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://bob-1.example.com/", Decision: "allow", UserSub: "sub-bob", UserEmail: "bob@corp.example", IdentityStatus: "valid"},
	}
	h.SeedEvents(seed...)
	if err := h.CP().IngestEvents("worker-1", seed); err != nil {
		t.Fatalf("seed the control plane: %v", err)
	}

	type view struct {
		name string
		get  func(path string) []byte
	}
	views := []view{
		{"worker", func(path string) []byte {
			status, body := adminDo(t, h, "GET", path)
			if status != 200 {
				t.Fatalf("worker GET %s = %d: %s", path, status, body)
			}
			return body
		}},
		{"cp", func(path string) []byte {
			var raw json.RawMessage
			if err := h.CP().GetJSON(path, &raw); err != nil {
				t.Fatalf("cp GET %s: %v", path, err)
			}
			return raw
		}},
	}

	userDomains := func(v view, user string) []string {
		var evs []analytics.Event
		path := "/dashboard/api/traffic?user=" + url.QueryEscape(user)
		if err := json.Unmarshal(v.get(path), &evs); err != nil {
			t.Fatalf("%s: decode traffic: %v", v.name, err)
		}
		var out []string
		for _, e := range evs {
			out = append(out, e.Domain)
		}
		return out
	}
	requests := func(v view, user string) int {
		var resp struct {
			Totals struct {
				Requests int `json:"requests"`
			} `json:"totals"`
		}
		path := "/dashboard/api/analytics?range=24h&user=" + url.QueryEscape(user)
		if err := json.Unmarshal(v.get(path), &resp); err != nil {
			t.Fatalf("%s: decode analytics: %v", v.name, err)
		}
		return resp.Totals.Requests
	}

	for _, v := range views {
		h.Eventually(v.name+" dashboard to list the seeded events", func() bool {
			return len(userDomains(v, "bob@corp.example")) == 1
		})
		for _, who := range []string{"Alice@Corp.Example", "sub-alice"} {
			got := userDomains(v, who)
			if len(got) != 2 || got[0] != "alice-2.example.com" || got[1] != "alice-1.example.com" {
				t.Errorf("%s traffic ?user=%s = %v, want alice's two events (newest first)", v.name, who, got)
			}
		}
		if got := requests(v, "alice@corp.example"); got != 2 {
			t.Errorf("%s analytics user=alice requests = %d, want 2", v.name, got)
		}
		// Same range, different user right after: the cache must not serve alice's figures.
		if got := requests(v, "bob@corp.example"); got != 1 {
			t.Errorf("%s analytics user=bob requests = %d, want 1 (cache key must include user)", v.name, got)
		}
		if got := userDomains(v, "x' OR '1'='1"); len(got) != 0 {
			t.Errorf("%s traffic with an injection value = %v, want none", v.name, got)
		}
	}
}
