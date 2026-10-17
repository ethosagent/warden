package scenarios

import (
	"net/http"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// allowlistedHTTPSSucceeds ports TestE2E_AllowlistedHTTPSSucceeds: a CONNECT to
// an allowlisted domain is admitted (200 Connection Established) and a real
// HTTPS request through the MITM tunnel reaches the upstream.
func allowlistedHTTPSSucceeds(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")

	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
		t.Fatalf("CONNECT to the allowlisted api.example.com = %d, want 200", got)
	}
	status, _ := get(t, h, "https://api.example.com/v1/models", nil)
	if status != http.StatusOK {
		t.Fatalf("GET through the tunnel = %d, want 200", status)
	}
	if got := len(u.Requests()); got != 1 {
		t.Errorf("the upstream saw %d request(s), want exactly the 1 the agent made", got)
	}
}
