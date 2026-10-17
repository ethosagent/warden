package scenarios

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// decisionLogging ports TestE2E_DecisionLogging: an allowed and a denied
// request both land in the analytics store with their domain, port and
// decision, secrets are referenced by hash only, and the event type has no
// body field at all.
func decisionLogging(t *testing.T, h *harness.H) {
	h.Upstream("api.example.com")
	h.Upstream("evil.example.com")

	if got := connectStatus(t, h, "evil.example.com:443"); got != 403 {
		t.Fatalf("CONNECT to the denied host = %d, want 403", got)
	}
	status, _ := get(t, h, "https://api.example.com/v1/models", map[string]string{"Authorization": "Bearer " + h.Placeholder("openai")})
	if status != 200 {
		t.Fatalf("GET to the allowed host = %d, want 200", status)
	}

	evs := h.Events()
	deny := eventsFor(evs, "evil.example.com", "deny")
	if len(deny) != 1 {
		t.Fatalf("deny events for evil.example.com = %d, want 1", len(deny))
	}
	if deny[0].Port != 443 {
		t.Errorf("deny event port = %d, want 443", deny[0].Port)
	}
	allow := eventsFor(evs, "api.example.com", "allow")
	if len(allow) != 1 {
		t.Fatalf("allow events for api.example.com = %d, want 1", len(allow))
	}
	if allow[0].Port != 443 {
		t.Errorf("allow event port = %d, want 443", allow[0].Port)
	}

	// Events never carry a body: a structural guarantee, so adding a Body field
	// to the type fails here.
	typ := reflect.TypeOf(analytics.Event{})
	for i := 0; i < typ.NumField(); i++ {
		switch strings.ToLower(typ.Field(i).Name) {
		case "body", "requestbody", "responsebody":
			t.Fatalf("analytics.Event must not have a body field, found %q", typ.Field(i).Name)
		}
	}
	for _, e := range evs {
		if e.SecretRef != "" && !strings.HasPrefix(e.SecretRef, "sha256:") {
			t.Errorf("SecretRef %q is not a sha256: reference", e.SecretRef)
		}
	}
	h.AssertCanaryNeverLeaked()
}
