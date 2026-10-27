package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// newLLMProvidersServer wires a dashboard whose llmProviders source echoes an
// in-memory list (with a fake per-provider resolved status) and, optionally, a
// writer that records the last full list it received — simulating the CP/worker
// persist+reload. The source recomputes Resolved from an env-presence map so a
// PUT that changes the list is observable via the echoed GET view.
func newLLMProvidersServer(t *testing.T, withWriter bool) (*Server, *[]config.LLMProvider) {
	t.Helper()
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	stored := &[]config.LLMProvider{{
		Name: "openai-main", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", APIKeyEnv: "OPENAI_API_KEY",
	}}
	// Fake resolution: only OPENAI_API_KEY is "present" on this node.
	present := map[string]bool{"OPENAI_API_KEY": true}
	srv.SetLLMProvidersSource(func() LLMProvidersView {
		out := make([]LLMProviderView, 0, len(*stored))
		for _, p := range *stored {
			v := LLMProviderView{
				Name: p.Name, BaseURL: p.BaseURL, Model: p.Model, APIKeyEnv: p.APIKeyEnv,
				TimeoutSeconds: int(p.Timeout.Seconds()),
			}
			if present[p.APIKeyEnv] {
				v.Resolved = true
			} else {
				v.Reason = "env var " + p.APIKeyEnv + " is empty"
			}
			out = append(out, v)
		}
		return LLMProvidersView{Providers: out}
	})
	if withWriter {
		srv.SetLLMProvidersWriter(func(_ context.Context, ps []config.LLMProvider, _ WriteMeta) error {
			*stored = ps
			return nil
		})
	}
	return srv, stored
}

func getLLMProvidersJSON(t *testing.T, srv *Server) LLMProvidersView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/llmproviders", nil)
	rr := httptest.NewRecorder()
	srv.handleLLMProviders(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET llmproviders = %d, want 200", rr.Code)
	}
	var v LLMProvidersView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode llmproviders response: %v", err)
	}
	return v
}

func TestLLMProviders_GETReportsResolvedAndEditable(t *testing.T) {
	// No writer: read-only, editable=false, but providers + resolved status present.
	roSrv, _ := newLLMProvidersServer(t, false)
	v := getLLMProvidersJSON(t, roSrv)
	if v.Editable {
		t.Error("no writer should be editable=false")
	}
	if len(v.Providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(v.Providers))
	}
	p := v.Providers[0]
	if !p.Resolved {
		t.Errorf("openai-main should be resolved (OPENAI_API_KEY present); got %+v", p)
	}
	if p.Reason != "" {
		t.Errorf("resolved provider should have no reason; got %q", p.Reason)
	}

	// With writer: editable=true.
	rwSrv, _ := newLLMProvidersServer(t, true)
	if v := getLLMProvidersJSON(t, rwSrv); !v.Editable {
		t.Error("with writer should be editable=true")
	}
}

func TestLLMProviders_PUTNoWriterIs405(t *testing.T) {
	srv, _ := newLLMProvidersServer(t, false)
	body := `[{"name":"x","baseURL":"https://a","model":"m","apiKeyEnv":"X_KEY"}]`
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/llmproviders", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleLLMProviders(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT with no writer = %d, want 405", rr.Code)
	}
}

func TestLLMProviders_DELETEIs405(t *testing.T) {
	srv, _ := newLLMProvidersServer(t, true)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/llmproviders", nil)
	rr := httptest.NewRecorder()
	srv.handleLLMProviders(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE llmproviders = %d, want 405", rr.Code)
	}
}

// TestLLMProviders_PUTPersistsAndEchoesFreshStatus asserts a PUT hands the writer
// the FULL parsed list and the echoed GET reflects the new resolution status — here
// a second provider whose key env is absent reports UNRESOLVED with a value-free
// reason (env NAME only), while the first stays resolved.
func TestLLMProviders_PUTPersistsAndEchoesFreshStatus(t *testing.T) {
	srv, stored := newLLMProvidersServer(t, true)

	body := `[
	  {"name":"openai-main","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY","timeoutSeconds":30},
	  {"name":"anthropic-judge","baseURL":"https://api.anthropic.com/v1","model":"claude-haiku-4-5","apiKeyEnv":"ANTHROPIC_API_KEY"}
	]`
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/llmproviders", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleLLMProviders(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT llmproviders = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	// The writer received the full parsed list (2 providers, timeout mapped).
	if len(*stored) != 2 {
		t.Fatalf("stored providers = %d, want 2", len(*stored))
	}
	if (*stored)[0].Timeout.Seconds() != 30 {
		t.Errorf("stored[0] timeout = %v, want 30s", (*stored)[0].Timeout)
	}
	if (*stored)[1].APIKeyEnv != "ANTHROPIC_API_KEY" {
		t.Errorf("stored[1] apiKeyEnv = %q, want ANTHROPIC_API_KEY", (*stored)[1].APIKeyEnv)
	}

	// The echoed response reflects fresh resolution status.
	var v LLMProvidersView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	byName := map[string]LLMProviderView{}
	for _, p := range v.Providers {
		byName[p.Name] = p
	}
	if !byName["openai-main"].Resolved {
		t.Error("openai-main should stay resolved")
	}
	if byName["anthropic-judge"].Resolved {
		t.Error("anthropic-judge should be unresolved (its key env is absent on this node)")
	}
	if r := byName["anthropic-judge"].Reason; r == "" || !strings.Contains(r, "ANTHROPIC_API_KEY") {
		t.Errorf("unresolved reason should name the env var; got %q", r)
	}
}

// TestLLMProviders_SecretRefHygiene asserts apiKeyEnv is treated as a NAME: a value
// is never accepted, stored, or echoed. The request struct has no value field, so a
// submitted apiKeyEnv is stored verbatim as a name and the echoed view never carries
// a "value" key — the whole surface is secret-free by construction.
func TestLLMProviders_SecretRefHygiene(t *testing.T) {
	srv, stored := newLLMProvidersServer(t, true)
	// An operator mistakenly pastes a value-looking string into apiKeyEnv. It is a
	// NAME field, so it is stored as-is (a name that won't resolve) — never split into
	// or echoed as a value; no separate value field exists to leak.
	body := `[{"name":"x","baseURL":"https://a","model":"m","apiKeyEnv":"NAME_ONLY","value":"sk-should-be-ignored"}]`
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/llmproviders", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleLLMProviders(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	if len(*stored) != 1 || (*stored)[0].APIKeyEnv != "NAME_ONLY" {
		t.Fatalf("stored apiKeyEnv = %+v, want a single NAME_ONLY", *stored)
	}
	// The echoed body must not contain the injected value anywhere.
	if strings.Contains(rr.Body.String(), "sk-should-be-ignored") {
		t.Errorf("echoed view leaked a submitted value: %s", rr.Body.String())
	}
}
