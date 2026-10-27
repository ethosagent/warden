package dashboard

// dashboard_llmproviders.go backs the "LLM Providers" card: the shared, named
// `llmProviders:` registry (name + baseURL + model + apiKeyEnv NAME + timeout) that
// the inline judge and the Explore NL→SQL feature select from BY NAME. It mirrors
// the integrations/detection editors: a GET returns the configured providers with a
// read-only RESOLVED status (is the provider's key env present on the hosting node)
// plus an `editable` flag; a PUT/POST applies the FULL provider list. On a node
// without a writer the endpoint is read-only (PUT/POST → 405).
//
// SECRET-LOCAL: apiKeyEnv is an env-var NAME only — never a key VALUE. Nothing here
// accepts, stores, echoes, or logs a key value; the request body has NO value field,
// and Resolved/Reason report only the PRESENCE of the env on the hosting node with a
// bounded, value-free reason string.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// LLMProviderView is one registry entry rendered for the dashboard: the metadata the
// operator declared (name/baseURL/model/apiKeyEnv NAME/timeout) plus a read-only
// resolution status. Resolved reports whether the provider's apiKeyEnv is present on
// the HOSTING node; Reason is a bounded, value-free explanation when it is not (e.g.
// "env var OPENAI_API_KEY is empty") — NEVER a key value.
type LLMProviderView struct {
	Name           string `json:"name"`
	BaseURL        string `json:"baseURL"`
	Model          string `json:"model"`
	APIKeyEnv      string `json:"apiKeyEnv"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	Resolved       bool   `json:"resolved"`
	Reason         string `json:"reason,omitempty"`
}

// LLMProvidersView is the payload for GET /dashboard/api/llmproviders: the configured
// providers (with per-provider resolution status) and whether this dashboard can edit
// them (a writer is configured — control plane / local-only only).
type LLMProvidersView struct {
	Providers []LLMProviderView `json:"providers"`
	Editable  bool              `json:"editable"`
	// Version is the head policy version in versioned mode (the registry is
	// part of the versioned document); absent in file mode.
	Version int64 `json:"version,omitempty"`
}

// llmProviderReq is one entry in the PUT/POST body. It carries the apiKeyEnv NAME
// only — there is deliberately NO key-value field, so a secret can never be submitted,
// stored, or echoed. TimeoutSeconds mirrors config.LLMProviderSettings.
type llmProviderReq struct {
	Name           string `json:"name"`
	BaseURL        string `json:"baseURL"`
	Model          string `json:"model"`
	APIKeyEnv      string `json:"apiKeyEnv"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// SetLLMProvidersSource supplies the configured providers + their per-node resolution
// status. Set on any node that can report the registry (the control plane from the
// distributed settings; a worker from its own config). A nil source yields an empty,
// read-only list.
func (s *Server) SetLLMProvidersSource(fn func() LLMProvidersView) {
	s.llmProvidersSource = fn
}

// SetLLMProvidersWriter enables editing the registry from the dashboard. Like the
// integrations/detection writers it persists the FULL provider list to the served/own
// config file and reloads the live consumers (client map + judge + Explore
// SQLGenerator). fn receives the request context, which carries the caller's
// identity. Nodes without it leave this nil, so PUT/POST return 405.
func (s *Server) SetLLMProvidersWriter(fn func(context.Context, []config.LLMProvider, WriteMeta) error) {
	s.llmProvidersWriter = fn
}

// handleLLMProviders serves /dashboard/api/llmproviders, method-routed:
//   - GET      returns the configured providers + resolution status + editable flag.
//   - PUT/POST applies the FULL provider list (control plane / local-only only).
//   - other    → 405.
func (s *Server) handleLLMProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getLLMProviders(w, r)
	case http.MethodPost, http.MethodPut:
		s.putLLMProviders(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// getLLMProviders returns the configured providers + resolution status. A nil source
// yields an empty list; editable is true only where a writer is configured.
func (s *Server) getLLMProviders(w http.ResponseWriter, r *http.Request) {
	version, ok := s.versionForGet(w, r)
	if !ok {
		return
	}
	var v LLMProvidersView
	if s.llmProvidersSource != nil {
		v = s.llmProvidersSource()
	}
	if v.Providers == nil {
		v.Providers = []LLMProviderView{}
	}
	v.Editable = s.llmProvidersWriter != nil
	v.Version = version
	writeJSON(w, v)
}

// putLLMProviders applies an edited provider list. Like putDetection it exists only
// where a writer is configured; otherwise it returns 405 so the registry is never
// mutable from a read-only node. Structural validation (name required + unique,
// baseURL/model/apiKeyEnv required, non-negative timeout, and any dangling
// judge/explore reference) is enforced by the writer's full-loader round-trip, so an
// invalid edit is rejected there with the error. apiKeyEnv is a NAME only — the body
// has no value field to leak.
func (s *Server) putLLMProviders(w http.ResponseWriter, r *http.Request) {
	if s.llmProvidersWriter == nil {
		writeError(w, http.StatusMethodNotAllowed, "LLM provider editing is not available on this dashboard")
		return
	}
	var reqs []llmProviderReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&reqs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	providers := make([]config.LLMProvider, 0, len(reqs))
	for _, rq := range reqs {
		providers = append(providers, config.LLMProvider{
			Name:      strings.TrimSpace(rq.Name),
			BaseURL:   strings.TrimSpace(rq.BaseURL),
			Model:     strings.TrimSpace(rq.Model),
			APIKeyEnv: strings.TrimSpace(rq.APIKeyEnv),
			Timeout:   time.Duration(rq.TimeoutSeconds) * time.Second,
		})
	}
	meta, ok := s.writeMeta(w, r)
	if !ok {
		return
	}
	if err := s.llmProvidersWriter(r.Context(), providers, meta); err != nil {
		writeWriterError(w, err)
		return
	}
	// Echo back the now-current view so the UI refreshes from the authoritative
	// post-write (post-reload) state.
	s.getLLMProviders(w, r)
}
