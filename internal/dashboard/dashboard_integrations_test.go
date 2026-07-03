package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"

	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook factory so "available" is true
)

// newIntegrationsServer returns a dashboard server plus an in-memory instances
// store wired as the source, and a writer that mutates that store (simulating the
// control plane's persist+reload). editable is toggled by whether a writer is set.
func newIntegrationsServer(t *testing.T, withWriter bool) (*Server, *[]IntegrationInstanceStatus) {
	t.Helper()
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	store := &[]IntegrationInstanceStatus{}
	srv.SetIntegrationsSource(func() []IntegrationInstanceStatus { return *store })
	if withWriter {
		srv.SetIntegrationsWriter(func(insts []config.IntegrationInstance) error {
			next := make([]IntegrationInstanceStatus, 0, len(insts))
			for _, in := range insts {
				// Mirror the control plane's honest status: webhook has a runtime,
				// so mark it connected; anything else is unavailable.
				status := "connected"
				if in.Type != "webhook" {
					status = "unavailable"
				}
				next = append(next, IntegrationInstanceStatus{
					Name: in.Name, Type: in.Type, Status: status, Config: in.Config, Match: in.Match,
				})
			}
			*store = next
			return nil
		})
	}
	return srv, store
}

func getIntegrationsJSON(t *testing.T, srv *Server) integrationsResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/integrations", nil)
	rr := httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET integrations = %d, want 200", rr.Code)
	}
	var resp integrationsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode integrations response: %v", err)
	}
	return resp
}

func TestIntegrations_GETCatalogAlwaysPresent(t *testing.T) {
	// Nil source (worker): definitions still listed, instances empty, not editable.
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	resp := getIntegrationsJSON(t, srv)
	if len(resp.Definitions) != 2 {
		t.Fatalf("definitions = %d, want 2 (webhook, slack)", len(resp.Definitions))
	}
	if resp.Editable {
		t.Error("worker dashboard must not be editable")
	}
	if len(resp.Instances) != 0 {
		t.Errorf("nil source should yield empty instances, got %d", len(resp.Instances))
	}
	// webhook.available must reflect the real registry (its factory is registered),
	// slack.available must be false (no runtime).
	byType := map[string]integrationDefinition{}
	for _, d := range resp.Definitions {
		byType[d.Type] = d
	}
	if !byType["webhook"].Available {
		t.Error("webhook must be available (factory registered)")
	}
	if byType["slack"].Available {
		t.Error("slack must NOT be available (no runtime registered)")
	}
}

func TestIntegrations_WriteMethodsGated(t *testing.T) {
	// No writer configured (worker): POST and DELETE must both 405.
	srv, _ := newIntegrationsServer(t, false)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequest(method, "/dashboard/api/integrations?name=x", strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		srv.handleIntegrations(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s without writer = %d, want 405", method, rr.Code)
		}
	}
}

func TestIntegrations_CreateRejectsRawSecret(t *testing.T) {
	srv, store := newIntegrationsServer(t, true)
	body := `{"type":"webhook","name":"ops","config":{"url":"https://ops.example/hook","secret":"xoxb-REAL-TOKEN-1234"}}`
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/integrations", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("raw secret create = %d, want 400", rr.Code)
	}
	// The raw value must never be echoed back in the error.
	if strings.Contains(rr.Body.String(), "xoxb-REAL-TOKEN-1234") {
		t.Error("error response leaked the raw secret value")
	}
	if len(*store) != 0 {
		t.Error("a rejected create must not persist an instance")
	}
}

func TestIntegrations_CreateAcceptsEnvRefAndConnects(t *testing.T) {
	srv, _ := newIntegrationsServer(t, true)
	body := `{"type":"webhook","name":"ops","config":{"url":"https://ops.example/hook","secret":"${WEBHOOK_SECRET}"},"match":[{"severity":"high"}]}`
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/integrations", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("env-ref create = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp integrationsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(resp.Instances))
	}
	inst := resp.Instances[0]
	if inst.Status != "connected" {
		t.Errorf("webhook status = %q, want connected", inst.Status)
	}
	// The secret must surface as its ${ENV} ref, never a value; url shows its value.
	var sawSecretRef bool
	for _, f := range inst.Config {
		if f.Name == "secret" {
			if !f.Secret || f.Ref != "${WEBHOOK_SECRET}" || f.Value != "" {
				t.Errorf("secret field metadata wrong: %+v", f)
			}
			sawSecretRef = true
		}
	}
	if !sawSecretRef {
		t.Error("secret config field missing from view")
	}
	if inst.Match == "" || strings.Contains(inst.Match, "match-none") {
		t.Errorf("match summary should reflect the severity clause, got %q", inst.Match)
	}
}

func TestIntegrations_CreateRejectsDuplicateName(t *testing.T) {
	srv, _ := newIntegrationsServer(t, true)
	body := `{"type":"webhook","name":"dup","config":{"url":"https://a/hook"}}`
	for i, wantCode := range []int{http.StatusOK, http.StatusBadRequest} {
		req := httptest.NewRequest(http.MethodPost, "/dashboard/api/integrations", strings.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleIntegrations(rr, req)
		if rr.Code != wantCode {
			t.Fatalf("create #%d = %d, want %d", i, rr.Code, wantCode)
		}
	}
}

func TestIntegrations_CreateRejectsMissingRequiredAndUnavailableType(t *testing.T) {
	srv, _ := newIntegrationsServer(t, true)
	// Missing required url.
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/integrations", strings.NewReader(`{"type":"webhook","name":"nourl","config":{}}`))
	rr := httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing required field = %d, want 400", rr.Code)
	}
	// slack has no runtime → cannot be saved.
	req = httptest.NewRequest(http.MethodPost, "/dashboard/api/integrations", strings.NewReader(`{"type":"slack","name":"s","config":{"channel":"#x","botToken":"${SLACK_BOT_TOKEN}"}}`))
	rr = httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unavailable-type create = %d, want 400", rr.Code)
	}
}

func TestIntegrations_Delete(t *testing.T) {
	srv, store := newIntegrationsServer(t, true)
	*store = []IntegrationInstanceStatus{
		{Name: "a", Type: "webhook", Status: "connected", Config: map[string]any{"url": "https://a/hook"}},
		{Name: "b", Type: "webhook", Status: "connected", Config: map[string]any{"url": "https://b/hook"}},
	}
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/integrations?name=a", nil)
	rr := httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200", rr.Code)
	}
	if len(*store) != 1 || (*store)[0].Name != "b" {
		t.Errorf("after delete want [b], got %+v", *store)
	}
}

func TestIntegrations_MethodNotAllowed(t *testing.T) {
	srv, _ := newIntegrationsServer(t, true)
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/integrations", nil)
	rr := httptest.NewRecorder()
	srv.handleIntegrations(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d, want 405", rr.Code)
	}
}
