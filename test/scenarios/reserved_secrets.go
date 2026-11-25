package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// The cp/ secret namespace is control-plane only (W-P2-WCA-07): /central/secrets
// and the dashboard secret store never list it and refuse to write or delete it
// (403 reserved_key), while ordinary keys keep working.
func reservedSecretNamespace(t *testing.T, h *harness.H) {
	cp := h.CP()
	tok := h.ControlPlaneAdminToken()

	if code, body, err := cp.Do(http.MethodPost, "/central/secrets", tok, []byte(`{"key":"plain-key","value":"v"}`)); err != nil || code != http.StatusNoContent {
		t.Fatalf("POST a normal key = %d %q (%v), want 204", code, body, err)
	}
	for _, c := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, "/central/secrets", []byte(`{"key":"cp/keys/ca/k1","value":"v"}`)},
		{http.MethodDelete, "/central/secrets/cp/keys/ca/k1", nil},
	} {
		code, body, err := cp.Do(c.method, c.path, tok, c.body)
		if err != nil || code != http.StatusForbidden || !strings.Contains(body, "reserved_key") {
			t.Errorf("%s %s = %d %q (%v), want 403 reserved_key", c.method, c.path, code, body, err)
		}
	}
	code, body, err := cp.Do(http.MethodGet, "/central/secrets", tok, nil)
	if err != nil || code != http.StatusOK || strings.Contains(body, "cp/") || !strings.Contains(body, "plain-key") {
		t.Errorf("GET /central/secrets = %d %q (%v), want the normal key and no cp/ key", code, body, err)
	}
	if logs := h.Logs(); !strings.Contains(logs, "reserved secret key refused") || strings.Contains(logs, "k1") {
		t.Error("want the refusal logged by prefix only, never the key tail")
	}
}
