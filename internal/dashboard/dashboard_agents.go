package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The agent registry admin API (W-P2-AREG-02): list, read, register, edit,
// disable and enable the agents the token service accepts. The handlers reach
// the registry through AgentRegistry (the dashboard imports neither agentreg
// nor controlplane). The routes answer only when SetAgentRegistry was called,
// which the control plane does; a worker dashboard answers 404. Roles, CSRF and
// the admin audit row are the control plane's authz table and middleware, not
// this file; the adapter owns the caller's identity and the audit annotation.
//
// Rows are never deleted, so there is no DELETE. Every edit and status change
// carries the revision the client saw as If-Match: "r<revision>" (the same
// value the ETag header of a read returns); a stale one is 409 agent_conflict.
// The views carry public JWKs, kid, alg and jkt only.

const (
	agentsPath = "/dashboard/api/agents"
	// maxAgentBody bounds a create or edit body: two public JWKs, a display
	// name and the group and scope lists fit in a small fraction of it.
	maxAgentBody = 64 << 10
)

// Errors an AgentRegistry returns. The handlers map each to a fixed status and
// body; none carries a submitted value.
var (
	// ErrAgentInvalid wraps every validation failure; the concrete error is an
	// *AgentInvalidError naming the field (400).
	ErrAgentInvalid = errors.New("invalid agent")
	// ErrAgentNotFound: no agent has the id (404).
	ErrAgentNotFound = errors.New("agent not found")
	// ErrAgentExists: the id is registered, disabled agents included (409).
	ErrAgentExists = errors.New("agent already exists")
	// ErrAgentKeyInUse: a key is already bound to another agent (409).
	ErrAgentKeyInUse = errors.New("key already bound to another agent")
	// ErrAgentConflict: the If-Match revision is no longer the stored one (409).
	ErrAgentConflict = errors.New("stale agent revision")
	// ErrAgentFull: the registry is at its size cap (422).
	ErrAgentFull = errors.New("agent registry is full")
	// ErrAgentStateRequired: the control plane has no state dir, so no registry
	// (503).
	ErrAgentStateRequired = errors.New("state dir required")
)

// AgentInvalidError is a validation failure. Field is the path of the
// offending field in the store's naming (the handler renders it in the API's);
// Reason is a fixed phrase. Neither holds a submitted value.
type AgentInvalidError struct{ Field, Reason string }

func (e *AgentInvalidError) Error() string { return ErrAgentInvalid.Error() + ": " + e.Field }

// Is makes errors.Is(err, ErrAgentInvalid) true.
func (e *AgentInvalidError) Is(target error) bool { return target == ErrAgentInvalid }

// AgentKeyView is one registered key: the ids and the public JWK (kty, crv, x,
// y and the kid, alg and use the registry set), never anything private.
type AgentKeyView struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	JKT string `json:"jkt"`
	JWK KeyJWK `json:"jwk"`
}

// AgentView is one agent as the API returns it. Times are RFC 3339 in UTC.
type AgentView struct {
	ID            string         `json:"id"`
	DisplayName   string         `json:"displayName,omitempty"`
	OwnerIss      string         `json:"ownerIss,omitempty"`
	OwnerSub      string         `json:"ownerSub,omitempty"`
	OwnerEmail    string         `json:"ownerEmail,omitempty"`
	Keys          []AgentKeyView `json:"keys"`
	AllowedGroups []string       `json:"allowedGroups"`
	AllowedScopes []string       `json:"allowedScopes"`
	Status        string         `json:"status"`
	Revision      int64          `json:"revision"`
	CreatedAt     string         `json:"createdAt"`
	CreatedBy     string         `json:"createdBy"`
	UpdatedAt     string         `json:"updatedAt"`
	UpdatedBy     string         `json:"updatedBy"`
}

// AgentInput is a create or edit body. Keys are the raw public JWK documents
// the operator supplied, so the registry can refuse private members; the owner
// is never taken from the body (a create records the caller, an edit keeps it).
type AgentInput struct {
	ID            string            `json:"id"`
	DisplayName   string            `json:"displayName"`
	Keys          []json.RawMessage `json:"keys"`
	AllowedGroups []string          `json:"allowedGroups"`
	AllowedScopes []string          `json:"allowedScopes"`
}

// AgentRegistry is the control plane's agent registry as the dashboard sees
// it. ctx carries the caller's console identity, which the implementation
// records as the actor and the owner of a new agent.
type AgentRegistry interface {
	// Ready is nil when the registry can serve, ErrAgentStateRequired when it
	// cannot (no state dir). Every route checks it first.
	Ready() error
	List(ctx context.Context) ([]AgentView, error)
	Get(ctx context.Context, id string) (AgentView, error)
	// Create registers in.ID with status active and revision 1.
	Create(ctx context.Context, in AgentInput) (AgentView, error)
	// Update replaces the editable fields of id if revision is still current.
	// in.ID is the path's id.
	Update(ctx context.Context, id string, revision int64, in AgentInput) (AgentView, error)
	// SetEnabled enables or disables id if revision is still current.
	SetEnabled(ctx context.Context, id string, enabled bool, revision int64) (AgentView, error)
}

// SetAgentRegistry enables the agent routes. Only the control plane calls it;
// elsewhere the routes answer 404.
func (s *Server) SetAgentRegistry(a AgentRegistry) { s.agents = a }

// agentPath splits /dashboard/api/agents/{id}[/disable|/enable]. ok is false
// for an empty id, another action, a nested path or a trailing slash.
func agentPath(p string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(p, agentsPath+"/")
	if !found || rest == "" {
		return "", "", false
	}
	id, action, hasAction := strings.Cut(rest, "/")
	if id == "" {
		return "", "", false
	}
	if !hasAction {
		return id, "", true
	}
	if action == "disable" || action == "enable" {
		return id, action, true
	}
	return "", "", false
}

// handleAgents serves GET (list) and POST (register) on /dashboard/api/agents.
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if s.agents == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.agents.Ready(); err != nil {
		writeAgentError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		list, err := s.agents.List(r.Context())
		if err != nil {
			writeAgentError(w, err)
			return
		}
		if list == nil {
			list = []AgentView{}
		}
		writeJSON(w, map[string]any{"agents": list})
		return
	}
	if !s.agentWritesAllowed(w) {
		return
	}
	in, ok := decodeAgentInput(w, r)
	if !ok {
		return
	}
	v, err := s.agents.Create(r.Context(), in)
	if err != nil {
		writeAgentError(w, err)
		return
	}
	w.Header().Set("Location", agentsPath+"/"+url.PathEscape(v.ID))
	w.Header().Set("ETag", agentETag(v.Revision))
	writeJSONStatus(w, http.StatusCreated, v)
}

// handleAgent serves one agent: GET, PUT, and POST on its disable and enable
// actions.
func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	id, action, ok := agentPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if s.agents == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch {
	case action == "" && r.Method != http.MethodGet && r.Method != http.MethodPut:
		methodNotAllowed(w, http.MethodGet, http.MethodPut)
		return
	case action != "" && r.Method != http.MethodPost:
		methodNotAllowed(w, http.MethodPost)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.agents.Ready(); err != nil {
		writeAgentError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		v, err := s.agents.Get(r.Context(), id)
		if err != nil {
			writeAgentError(w, err)
			return
		}
		w.Header().Set("ETag", agentETag(v.Revision))
		writeJSON(w, v)
		return
	}
	if !s.agentWritesAllowed(w) {
		return
	}
	rev, ok := agentIfMatch(w, r)
	if !ok {
		return
	}
	var (
		v   AgentView
		err error
	)
	if action == "" {
		in, ok := decodeAgentInput(w, r)
		if !ok {
			return
		}
		if in.ID != "" && in.ID != id {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_agent", "field": "id", "message": "must match the id in the path",
			})
			return
		}
		in.ID = id
		v, err = s.agents.Update(r.Context(), id, rev, in)
	} else {
		v, err = s.agents.SetEnabled(r.Context(), id, action == "enable", rev)
	}
	if err != nil {
		writeAgentError(w, err)
		return
	}
	w.Header().Set("ETag", agentETag(v.Revision))
	writeJSON(w, v)
}

// agentETag is the entity tag of a revision, the value If-Match carries back.
func agentETag(rev int64) string { return `"r` + strconv.FormatInt(rev, 10) + `"` }

// agentIfMatch reads the revision the client saw from If-Match: "r<n>". It
// answers 428 when the header is missing and 400 when it is not that form;
// there is deliberately no wildcard, which would void the compare-and-swap.
func agentIfMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" {
		writeJSONStatus(w, http.StatusPreconditionRequired, map[string]string{
			"error": "if_match_required", "message": `send If-Match: "r<revision>" from the ETag of a read`,
		})
		return 0, false
	}
	n, ok := strings.CutPrefix(h, `"r`)
	if ok {
		n, ok = strings.CutSuffix(n, `"`)
	}
	if ok {
		if rev, err := strconv.ParseInt(n, 10, 64); err == nil && rev > 0 && strconv.FormatInt(rev, 10) == n {
			return rev, true
		}
	}
	writeJSONStatus(w, http.StatusBadRequest, map[string]string{
		"error": "invalid_if_match", "message": `If-Match must be "r<revision>"`,
	})
	return 0, false
}

// agentWritesAllowed refuses a write unless the console has real identities
// (oidc): without one there is nobody to attribute a key or group change to.
// It fails closed: an unset or unknown mode refuses.
func (s *Server) agentWritesAllowed(w http.ResponseWriter) bool {
	if s.authMode == "oidc" {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]string{
		"error":   "use_cli",
		"message": "agents are not changed from the console without sign-in (console.auth: none); use `warden control-plane agent` on the control plane host",
	})
	return false
}

// decodeAgentInput reads a capped JSON body. Unknown fields are refused, so a
// field the API does not have (ownerSub, status) is an error, not ignored.
func decodeAgentInput(w http.ResponseWriter, r *http.Request) (AgentInput, bool) {
	var in AgentInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAgentBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(&in)
	if err == nil {
		// One JSON value only: trailing data is a malformed request.
		_, err = dec.Token()
		if errors.Is(err, io.EOF) {
			return in, true
		}
		if err == nil {
			err = errors.New("trailing data")
		}
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return AgentInput{}, false
	}
	writeJSONStatus(w, http.StatusBadRequest, map[string]string{
		"error": "invalid_json", "message": "body must be one JSON object with id, displayName, keys, allowedGroups and allowedScopes",
	})
	return AgentInput{}, false
}

func methodNotAllowed(w http.ResponseWriter, allow ...string) {
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// writeAgentError maps a registry error to a fixed body. Only the validation
// field and its fixed reason are echoed; anything else stays server-side (the
// control plane logs it).
func writeAgentError(w http.ResponseWriter, err error) {
	if writeHeld(w, err) {
		return
	}
	var cerr *ChangeError
	if errors.As(err, &cerr) {
		writeChangeError(w, err)
		return
	}
	switch {
	case errors.Is(err, ErrAgentStateRequired):
		writeError(w, http.StatusServiceUnavailable, "state_dir_required")
	case errors.Is(err, ErrAgentInvalid):
		body := map[string]string{"error": "invalid_agent"}
		var ie *AgentInvalidError
		if errors.As(err, &ie) {
			body["field"] = agentAPIField(ie.Field)
			body["message"] = ie.Reason
		}
		writeJSONStatus(w, http.StatusBadRequest, body)
	case errors.Is(err, ErrAgentNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrAgentExists):
		writeError(w, http.StatusConflict, "agent_exists")
	case errors.Is(err, ErrAgentKeyInUse):
		writeError(w, http.StatusConflict, "key_in_use")
	case errors.Is(err, ErrAgentConflict):
		writeError(w, http.StatusConflict, "agent_conflict")
	case errors.Is(err, ErrAgentFull):
		writeError(w, http.StatusUnprocessableEntity, "registry_full")
	default:
		writeError(w, http.StatusInternalServerError, "agent_registry_error")
	}
}

// agentAPIField renders a store field path in the API's member names.
func agentAPIField(f string) string {
	end := strings.IndexAny(f, "[.")
	if end < 0 {
		end = len(f)
	}
	switch f[:end] {
	case "display_name":
		return "displayName" + f[end:]
	case "allowed_groups":
		return "allowedGroups" + f[end:]
	case "allowed_scopes":
		return "allowedScopes" + f[end:]
	}
	return f
}
