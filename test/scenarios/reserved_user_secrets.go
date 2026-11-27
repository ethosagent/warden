package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// The per-user credential namespaces (W-P3-CSIG-06) live only in the CP-only
// consent.store. On the distributed store /central/secrets never lists them and
// refuses to write or delete them (403 reserved_key), so no console or API
// edit can plant or overwrite a per-user credential a worker could swap in.
func reservedUserSecretNamespaces(t *testing.T, h *harness.H) {
	cp := h.CP()
	tok := h.ControlPlaneAdminToken()

	if code, body, err := cp.Do(http.MethodPost, "/central/secrets", tok, []byte(`{"key":"plain-user-key","value":"v"}`)); err != nil || code != http.StatusNoContent {
		t.Fatalf("POST a normal key = %d %q (%v), want 204", code, body, err)
	}
	for _, key := range []string{"idp/0123456789abcdef0123456789abcdef", "users/0123456789abcdef0123456789abcdef/google", "revoking/0123456789abcdef0123456789abcdef/google", "oauth-clients/google"} {
		for _, c := range []struct {
			method, path string
			body         []byte
		}{
			{http.MethodPost, "/central/secrets", []byte(`{"key":"` + key + `","value":"planted"}`)},
			{http.MethodDelete, "/central/secrets/" + key, nil},
		} {
			code, body, err := cp.Do(c.method, c.path, tok, c.body)
			if err != nil || code != http.StatusForbidden || !strings.Contains(body, "reserved_key") {
				t.Errorf("%s %s = %d %q (%v), want 403 reserved_key", c.method, c.path, code, body, err)
			}
		}
	}
	code, body, err := cp.Do(http.MethodGet, "/central/secrets", tok, nil)
	if err != nil || code != http.StatusOK || !strings.Contains(body, "plain-user-key") {
		t.Fatalf("GET /central/secrets = %d %q (%v), want the normal key", code, body, err)
	}
	for _, ns := range []string{"idp/", "users/", "revoking/", "oauth-clients/"} {
		if strings.Contains(body, ns) {
			t.Errorf("GET /central/secrets lists a %s key: %q", ns, body)
		}
	}
	if logs := h.Logs(); strings.Contains(logs, "planted") || strings.Contains(logs, "0123456789abcdef") {
		t.Error("a refusal logged the value or the key tail")
	}
}
