package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

func tokenServiceDashboardOpts() []harness.Option {
	return tokenServiceOpts(harness.WithConsoleOIDC())
}

// tokenExchangeDashboardDisable: an agent disabled from the console is refused
// at its very next exchange, with no clock advance and so no registry Watch
// tick. The dashboard agent API and the token service share the control
// plane's one agent registry Store; with two Stores the token service would
// keep its stale snapshot and the disabled agent would keep minting.
func tokenExchangeDashboardDisable(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("dash-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	user := tokenUser(h, "user-0", "eng")
	// The harness registers from another connection: wait for the Watch once.
	h.Eventually("the registry watch sees the registered agent", func() bool {
		h.Clock().Advance(3 * time.Second)
		return exchangeForm(h, agent.Form(user, nil)).Status == http.StatusOK
	})

	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	call := func(method, target string, hdr http.Header) (int, []byte) {
		t.Helper()
		if hdr == nil {
			hdr = http.Header{}
		}
		hdr.Set("Content-Type", "application/json")
		if method != http.MethodGet {
			hdr.Set(controlplane.CSRFHeader, csrf)
		}
		resp, err := admin.DoBody(method, target, hdr, nil)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, body
	}
	status, body := call(http.MethodGet, agentsPathScn+"/dash-agent", nil)
	var view struct {
		Revision int64  `json:"revision"`
		Status   string `json:"status"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &view) != nil || view.Status != "active" {
		t.Fatalf("read agent = %d %s", status, body)
	}
	etag := `"r` + strconv.FormatInt(view.Revision, 10) + `"`
	if status, body = call(http.MethodPost, agentsPathScn+"/dash-agent/disable", http.Header{"If-Match": {etag}}); status != http.StatusOK {
		t.Fatalf("console disable = %d %s", status, body)
	}
	requireRefusal(t, "disabled from the console", exchangeForm(h, agent.Form(user, nil)), http.StatusUnauthorized, "invalid_client", "client_authentication_failed")
}
