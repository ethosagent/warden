package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// TestTrafficAPIReturnsDenyReason (#409): every deny event carries a reason
// from the declared set, and the traffic API returns it so the dashboard can
// tell a default-deny from a denylist hit or a rate-limit deny. The API serves
// the events verbatim, so the assertion pins the field's presence and its JSON
// casing (the UI reads e.Reason).
func TestTrafficAPIReturnsDenyReason(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{
		events: []analytics.Event{
			{Timestamp: now, Domain: "evil.com", Port: 443, Protocol: "tcp", Decision: "deny", Reason: "policy_no_match"},
			{Timestamp: now.Add(time.Second), Domain: "blocked.test", Port: 443, Protocol: "tcp", Decision: "deny", Reason: "policy_denylist"},
			{Timestamp: now.Add(2 * time.Second), Domain: "rl.test", Port: 443, Protocol: "tcp", Decision: "deny", Reason: "rate_limited"},
			{Timestamp: now.Add(3 * time.Second), Domain: "api.test", Port: 443, Protocol: "https", Method: "POST", Decision: "deny", Reason: "method_not_allowed"},
			{Timestamp: now.Add(4 * time.Second), Domain: "api.test", Port: 443, Protocol: "https", Method: "GET", Decision: "allow"},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/traffic?decision=deny")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var events []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 deny events, got %d", len(events))
	}
	// Key by domain: the API may order events newest- or oldest-first.
	byDomain := map[string]string{}
	for _, e := range events {
		reason, _ := e["Reason"].(string)
		if reason == "" {
			t.Fatalf("deny event %+v carries no Reason", e)
		}
		byDomain[fmt.Sprint(e["Domain"])] = reason
	}
	want := map[string]string{
		"evil.com":     "policy_no_match",
		"blocked.test": "policy_denylist",
		"rl.test":      "rate_limited",
		"api.test":     "method_not_allowed",
	}
	for domain, reason := range want {
		if byDomain[domain] != reason {
			t.Errorf("%s: Reason = %q, want %q", domain, byDomain[domain], reason)
		}
	}
}

// TestActivityCSVIncludesReason guards the UI's CSV export: the Reason column
// must stay in the header the Activity page builds (index.html
// exportActivityCSV), or an exported deny loses the #409 reason.
func TestActivityCSVIncludesReason(t *testing.T) {
	index := string(indexHTML)
	if !strings.Contains(index, "'Timestamp','ProxyID','Method','Domain','Protocol','Decision','Reason',") {
		t.Fatal("activity CSV export header is missing the Reason column")
	}
}
