package analytics

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// goldenEvent is a fully populated identity-free Event. Its marshalled bytes
// are pinned in testdata/event_identity_free.golden.json, captured BEFORE the
// identity fields existed, so a regression that adds a user_* key to an
// unattributed event (and so breaks every old signed receipt) fails here.
func goldenEvent() Event {
	return Event{
		Timestamp:      time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Domain:         "api.openai.com",
		Port:           443,
		Protocol:       "https",
		Method:         "POST",
		URL:            "https://api.openai.com/v1/chat/completions",
		Decision:       "allow",
		ResponseStatus: 200,
		SecretRef:      "sha256:abcd1234...last4:sk-Ab",
		JudgeReason:    "routine completion",
		Tool:           "search",
		Reason:         "policy_match",
		AddrClass:      "private",
		CostUSD:        0.0123,
		Provider:       "openai",
		Compliance:     []string{"mitre:T1071"},
		ProxyID:        "proxy-1",
		DataClasses:    []string{"pii.contact"},
		DLPAction:      "monitor",
		DLPRule:        "default",
		DLPPartial:     true,
		UID:            "uid-1",
		LatencyMs:      42,
		SwappedRefs:    []string{"{{OPENAI_API_KEY}}"},
		Evidence:       []string{"••••abcd (len 20)"},
	}
}

func TestEventGoldenMarshal(t *testing.T) {
	got, err := json.Marshal(goldenEvent())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := os.ReadFile("testdata/event_identity_free.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != strings.TrimSpace(string(want)) {
		t.Fatalf("identity-free Event JSON changed:\n got: %s\nwant: %s", got, want)
	}
}
