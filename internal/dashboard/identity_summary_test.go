package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

type identityBody struct {
	Identity *struct {
		ByStatus []struct {
			Status string `json:"status"`
			Count  int    `json:"count"`
		} `json:"byStatus"`
		TopReasons []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"topReasons"`
	} `json:"identity"`
}

func getIdentity(t *testing.T, ds *fakeDataSource) (identityBody, string) {
	t.Helper()
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	rr := doGet(t, h, "/dashboard/api/analytics?range=24h")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var b identityBody
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b, rr.Body.String()
}

func TestIdentitySummary(t *testing.T) {
	now := time.Now().UTC()
	ev := func(status, reason string) analytics.Event {
		return analytics.Event{Timestamp: now, Domain: "a.example", Decision: "allow", IdentityStatus: status, IdentityReason: reason}
	}
	ds := &fakeDataSource{}
	for i := 0; i < 3; i++ {
		ds.events = append(ds.events, ev("valid", ""))
	}
	for i := 0; i < 2; i++ {
		ds.events = append(ds.events, ev("invalid", "cnf_mismatch"))
	}
	ds.events = append(ds.events, ev("none", ""))
	// Six distinct reasons, so only the top five survive.
	for i, r := range []string{"bad_signature", "wrong_iss", "wrong_aud", "unknown_kid", "malformed"} {
		for n := 0; n <= i; n++ {
			ds.events = append(ds.events, ev("invalid", r))
		}
	}

	b, raw := getIdentity(t, ds)
	if b.Identity == nil {
		t.Fatalf("identity block missing: %s", raw)
	}
	counts := map[string]int{}
	for _, s := range b.Identity.ByStatus {
		counts[s.Status] = s.Count
	}
	if counts["valid"] != 3 || counts["none"] != 1 || counts["invalid"] != 2+15 {
		t.Errorf("byStatus = %v", counts)
	}
	if n := len(b.Identity.TopReasons); n != 5 {
		t.Fatalf("topReasons has %d entries, want 5: %+v", n, b.Identity.TopReasons)
	}
	if first := b.Identity.TopReasons[0]; first.Reason != "malformed" || first.Count != 5 {
		t.Errorf("top reason = %+v, want malformed x5", first)
	}
	for _, r := range b.Identity.TopReasons {
		if r.Reason == "cnf_mismatch" && r.Count != 2 {
			t.Errorf("cnf_mismatch = %d, want 2", r.Count)
		}
		if r.Reason == "bad_signature" {
			t.Errorf("lowest-count reason leaked into the top five: %+v", b.Identity.TopReasons)
		}
	}
}

func TestIdentitySummaryAbsent(t *testing.T) {
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: time.Now().UTC(), Domain: "a.example", Decision: "allow"},
	}}
	b, raw := getIdentity(t, ds)
	if b.Identity != nil {
		t.Errorf("identity block present without identity events: %s", raw)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(raw), &m)
	if _, ok := m["identity"]; ok {
		t.Error("identity key must be omitted, not null")
	}
}
