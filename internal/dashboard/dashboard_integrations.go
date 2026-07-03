package dashboard

// dashboard_integrations.go backs the Settings → Integrations panel with a real,
// backend-configurable feature instead of hardcoded fiction. It serves a static
// CATALOG of integration type definitions (the Add-form schema) plus the live
// configured INSTANCES with an HONEST per-instance status, and — on the control
// plane only — lets an operator ADD/DELETE an instance that persists to the CP
// config and hot-reloads the live manager.
//
// Honesty + secrecy invariants enforced here:
//   - "connected" reflects REALITY (an instance actually running in the manager).
//     A type with no registered runtime factory reports "unavailable", never a
//     green connected dot.
//   - Secrets stay by-reference: any field marked `secret` in the catalog must be
//     an ${ENV} reference; a raw-looking value is rejected on write and never
//     logged, echoed, or persisted.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
)

// --- catalog (static type definitions the Add-form renders from) ---

// integrationField describes one config field of an integration type.
type integrationField struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "text" | "env"
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	Placeholder string `json:"placeholder,omitempty"`
}

// integrationDefinition is one integration type's catalog entry. Available is
// derived from the real runtime registry (integration.IsRegistered), never
// hardcoded, so the UI can only offer to SAVE a type that can actually run.
type integrationDefinition struct {
	Type        string             `json:"type"`
	DisplayName string             `json:"displayName"`
	Description string             `json:"description"`
	Available   bool               `json:"available"`
	Fields      []integrationField `json:"fields"`
}

// integrationCatalog returns the built-in integration type definitions. The
// `available` flag is derived from the live registry so it reflects which runtime
// factories are actually compiled in (webhook is; slack is not, yet).
func integrationCatalog() []integrationDefinition {
	return []integrationDefinition{
		{
			Type:        "webhook",
			DisplayName: "Webhook",
			Description: "POST each routed alert as JSON to an HTTP(S) endpoint. Optional signing secret: HMAC-SHA256, sent as X-Warden-Signature: v1=hex(hmac(secret, ts + '.' + body)) with X-Warden-Timestamp (unix seconds).",
			Available:   integration.IsRegistered("webhook"),
			Fields: []integrationField{
				{Name: "url", Label: "URL", Type: "text", Required: true, Placeholder: "https://ops.example.com/hook or ${WEBHOOK_URL}"},
				{Name: "secret", Label: "Signing secret", Type: "env", Secret: true, Placeholder: "${WEBHOOK_SECRET}"},
			},
		},
		{
			Type:        "slack",
			DisplayName: "Slack",
			Description: "Deliver alerts to a Slack channel. Runtime not built yet — see roadmap.",
			Available:   integration.IsRegistered("slack"),
			Fields: []integrationField{
				{Name: "channel", Label: "Channel", Type: "text", Required: true, Placeholder: "C0123456789 or #channel"},
				{Name: "botToken", Label: "Bot token", Type: "env", Required: true, Secret: true, Placeholder: "${SLACK_BOT_TOKEN}"},
				{Name: "appToken", Label: "App token", Type: "env", Secret: true, Placeholder: "${SLACK_APP_TOKEN}"},
			},
		},
	}
}

// findDefinition returns the catalog definition for typ, or (zero, false).
func findDefinition(typ string) (integrationDefinition, bool) {
	for _, d := range integrationCatalog() {
		if d.Type == typ {
			return d, true
		}
	}
	return integrationDefinition{}, false
}

// envRefRe matches Warden's ${ENV} reference form. A `secret` config field must
// match this — a raw-looking value (anything else) is rejected so a real token
// can never be persisted to the CP config.
var envRefRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

// --- injected source + writer (control-plane only) ---

// IntegrationInstanceStatus is one configured instance's runtime status plus its
// metadata, supplied by the control plane via SetIntegrationsSource. Config holds
// the operator-declared values (secrets are ${ENV} references, never raw values);
// Match is the routing predicate.
type IntegrationInstanceStatus struct {
	Name   string
	Type   string
	Status string // integration.StatusConnected | StatusUnavailable | StatusError
	Reason string
	Config map[string]any
	Match  []config.IntegrationMatch
}

// SetIntegrationsSource supplies the configured instances + their runtime status.
// Set only on the control plane; a worker leaves it nil so the endpoint reports
// the catalog with an empty instances list (the tab is not blank, but read-only).
func (s *Server) SetIntegrationsSource(fn func() []IntegrationInstanceStatus) {
	s.integrationsSource = fn
}

// SetIntegrationsWriter enables ADD/DELETE of integrations from the dashboard. It
// is a control-plane-only capability: the closure persists the FULL desired
// instance list to the served config and reloads the live manager. Workers never
// set this, so POST/DELETE return 405.
func (s *Server) SetIntegrationsWriter(fn func([]config.IntegrationInstance) error) {
	s.integrationsWriter = fn
}

// --- response views (metadata only; never a raw secret value) ---

// integrationConfigField is one instance config field rendered as metadata: the
// field name, whether it is set, whether the catalog marks it secret, and — for a
// secret — the ${ENV} REFERENCE (never a value). Non-secret fields surface their
// value (operator-entered metadata, e.g. a channel id or URL).
type integrationConfigField struct {
	Name   string `json:"name"`
	Set    bool   `json:"set"`
	Secret bool   `json:"secret"`
	Ref    string `json:"ref,omitempty"`
	Value  string `json:"value,omitempty"`
}

// integrationInstanceView is one configured instance rendered for the dashboard.
type integrationInstanceView struct {
	Name         string                   `json:"name"`
	Type         string                   `json:"type"`
	Status       string                   `json:"status"`
	StatusReason string                   `json:"statusReason,omitempty"`
	Match        string                   `json:"match"`
	Config       []integrationConfigField `json:"config"`
}

// integrationsResponse is the payload for GET /dashboard/api/integrations.
type integrationsResponse struct {
	Definitions []integrationDefinition   `json:"definitions"`
	Instances   []integrationInstanceView `json:"instances"`
	Editable    bool                      `json:"editable"`
}

// integrationCreateRequest is the body accepted by POST /dashboard/api/integrations.
type integrationCreateRequest struct {
	Type   string                    `json:"type"`
	Name   string                    `json:"name"`
	Config map[string]string         `json:"config"`
	Match  []config.IntegrationMatch `json:"match"`
}

// handleIntegrations serves /dashboard/api/integrations, method-routed:
//   - GET    lists the catalog + configured instances (+ editable flag).
//   - POST   creates an instance (control plane only; 405 otherwise).
//   - DELETE removes an instance by ?name= (control plane only; 405 otherwise).
func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getIntegrations(w, r)
	case http.MethodPost:
		s.createIntegration(w, r)
	case http.MethodDelete:
		s.deleteIntegration(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// getIntegrations returns the static catalog plus the live configured instances.
// A nil source (worker) yields an empty instances list; editable is true only
// where an integrations writer is configured (the control plane).
func (s *Server) getIntegrations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.integrationsPayload())
}

// integrationsPayload builds the GET body from the injected source. It is shared
// by GET and by the POST/DELETE success responses so the UI refreshes from the
// authoritative post-write state.
func (s *Server) integrationsPayload() integrationsResponse {
	resp := integrationsResponse{
		Definitions: integrationCatalog(),
		Instances:   []integrationInstanceView{},
		Editable:    s.integrationsWriter != nil,
	}
	if s.integrationsSource != nil {
		for _, inst := range s.integrationsSource() {
			resp.Instances = append(resp.Instances, instanceView(inst))
		}
	}
	return resp
}

// instanceView projects one source instance into its value-free view: the status
// (honest, from the manager), a bounded match summary, and per-field config
// metadata (secret fields as ${ENV} refs, non-secret fields as their value).
func instanceView(inst IntegrationInstanceStatus) integrationInstanceView {
	v := integrationInstanceView{
		Name:         inst.Name,
		Type:         inst.Type,
		Status:       inst.Status,
		StatusReason: inst.Reason,
		Match:        matchSummary(inst.Match),
		Config:       []integrationConfigField{},
	}
	def, ok := findDefinition(inst.Type)
	seen := map[string]struct{}{}
	if ok {
		for _, f := range def.Fields {
			seen[f.Name] = struct{}{}
			raw, present := inst.Config[f.Name]
			str, _ := raw.(string)
			cf := integrationConfigField{Name: f.Name, Set: present && str != "", Secret: f.Secret}
			if cf.Set {
				if f.Secret {
					// Only surface the value as a reference when it is an ${ENV} form.
					// A hand-edited raw secret (bypassing the write-path validation) is
					// marked set but NEVER echoed, so a value can't leak to the UI.
					if envRefRe.MatchString(str) {
						cf.Ref = str
					}
				} else {
					cf.Value = str
				}
			}
			v.Config = append(v.Config, cf)
		}
	}
	// Any config keys not in the catalog definition (e.g. a hand-edited config):
	// report name + set only, WITHOUT the value, so an unknown field can never leak.
	for k, raw := range inst.Config {
		if _, known := seen[k]; known {
			continue
		}
		str, _ := raw.(string)
		v.Config = append(v.Config, integrationConfigField{Name: k, Set: str != ""})
	}
	return v
}

// matchSummary renders the routing predicate as a short, bounded string. An empty
// match is match-none (explicit opt-in) and is surfaced honestly so the UI can
// warn that the instance receives no alerts.
func matchSummary(clauses []config.IntegrationMatch) string {
	if len(clauses) == 0 {
		return "match-none (receives no alerts)"
	}
	parts := make([]string, 0, len(clauses))
	for _, c := range clauses {
		var kv []string
		if c.Severity != "" {
			kv = append(kv, "severity="+c.Severity)
		}
		if c.Category != "" {
			kv = append(kv, "category="+c.Category)
		}
		if c.Domain != "" {
			kv = append(kv, "domain="+c.Domain)
		}
		if c.Rule != "" {
			kv = append(kv, "rule="+c.Rule)
		}
		if len(kv) == 0 {
			kv = append(kv, "any")
		}
		parts = append(parts, strings.Join(kv, " AND "))
	}
	return strings.Join(parts, " OR ")
}

// createIntegration validates a new instance and persists+reloads it via the
// injected writer. It gates exactly like putPolicy/putSettings: no writer (a
// worker) → 405. Validation rejects unknown/unavailable types, blank/duplicate
// names, missing required fields, and — critically — any `secret` field whose
// value is not an ${ENV} reference (a raw-looking value is rejected and never
// logged or echoed). On success it returns the updated instances payload.
func (s *Server) createIntegration(w http.ResponseWriter, r *http.Request) {
	if s.integrationsWriter == nil {
		writeError(w, http.StatusMethodNotAllowed, "integration editing is not available on this dashboard")
		return
	}
	var req integrationCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	def, ok := findDefinition(strings.TrimSpace(req.Type))
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown integration type")
		return
	}
	if !def.Available {
		writeError(w, http.StatusBadRequest, def.DisplayName+" runtime is not built yet — this integration cannot be saved")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Existing instances (for the uniqueness check and to build the full new list).
	existing := s.currentInstances()
	for _, e := range existing {
		if e.Name == name {
			writeError(w, http.StatusBadRequest, "an integration named "+name+" already exists")
			return
		}
	}

	// Build + validate config from the catalog fields only (ignore unknown keys).
	cfg := map[string]any{}
	for _, f := range def.Fields {
		raw := strings.TrimSpace(req.Config[f.Name])
		if raw == "" {
			if f.Required {
				writeError(w, http.StatusBadRequest, "field "+f.Name+" is required")
				return
			}
			continue
		}
		if f.Secret && !envRefRe.MatchString(raw) {
			// Never echo the offending value — only name the field and the required form.
			writeError(w, http.StatusBadRequest, "field "+f.Name+" must be an environment-variable reference like ${MY_SECRET}, not a raw value")
			return
		}
		cfg[f.Name] = raw
	}

	newInst := config.IntegrationInstance{Type: def.Type, Name: name, Config: cfg, Match: sanitizeMatch(req.Match)}
	if err := s.integrationsWriter(append(existing, newInst)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, s.integrationsPayload())
}

// deleteIntegration removes the named instance and persists+reloads the result.
// Like createIntegration it returns 405 when no writer is configured. It is
// idempotent: deleting an absent name still succeeds with the (unchanged) list.
func (s *Server) deleteIntegration(w http.ResponseWriter, r *http.Request) {
	if s.integrationsWriter == nil {
		writeError(w, http.StatusMethodNotAllowed, "integration editing is not available on this dashboard")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	kept := []config.IntegrationInstance{}
	for _, e := range s.currentInstances() {
		if e.Name == name {
			continue
		}
		kept = append(kept, e)
	}
	if err := s.integrationsWriter(kept); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, s.integrationsPayload())
}

// currentInstances reconstructs the configured instances from the source so a
// create/delete can compute the full desired list to hand the writer. A nil
// source yields none.
func (s *Server) currentInstances() []config.IntegrationInstance {
	if s.integrationsSource == nil {
		return nil
	}
	src := s.integrationsSource()
	out := make([]config.IntegrationInstance, 0, len(src))
	for _, inst := range src {
		out = append(out, config.IntegrationInstance{
			Type:   inst.Type,
			Name:   inst.Name,
			Config: inst.Config,
			Match:  sanitizeMatch(inst.Match),
		})
	}
	return out
}

// sanitizeMatch trims each clause and drops all-empty clauses. It returns nil for
// no usable clauses so an empty match round-trips as match-none.
func sanitizeMatch(in []config.IntegrationMatch) []config.IntegrationMatch {
	var out []config.IntegrationMatch
	for _, c := range in {
		clause := config.IntegrationMatch{
			Severity: strings.TrimSpace(c.Severity),
			Category: strings.TrimSpace(c.Category),
			Domain:   strings.TrimSpace(c.Domain),
			Rule:     strings.TrimSpace(c.Rule),
		}
		if clause.Severity == "" && clause.Category == "" && clause.Domain == "" && clause.Rule == "" {
			continue
		}
		out = append(out, clause)
	}
	return out
}
