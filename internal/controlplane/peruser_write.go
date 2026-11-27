package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The rollout guard of per-user secrets (W-P3-PUS-08). A worker that does not
// advertise usersecrets/v1 forwards the literal placeholder instead of swapping
// it, so a mapping enabled for an agent it serves would silently not work. The
// control plane therefore refuses a save that enables the block or adds an
// agent to a mapping while a connected worker bound to that agent lacks the
// capability, with 409 workers_lack_capability naming the workers, unless an
// admin passes force=true (audited with the worker ids, exactly like
// identity require mode). "Connected" is the registry's own meaning: a heartbeat
// or poll within the last staleAfter. A worker that appears later is not
// refused (the control plane cannot stop it); it leaks nothing.

// perUserPairs returns the (agent, placeholder) pairs c serves: empty when the
// block is disabled.
func perUserPairs(c config.PerUserSecretsConfig) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if !c.Enabled {
		return out
	}
	for _, m := range c.Mappings {
		for _, a := range m.Agents {
			if out[a] == nil {
				out[a] = map[string]bool{}
			}
			out[a][m.Placeholder] = true
		}
	}
	return out
}

// perUserAffected reports whether a worker serving agentID is affected by a
// change from have to want: want has a pair (agent, placeholder) have lacks.
func perUserAffected(have, want map[string]map[string]bool) func(agentID string) bool {
	return func(agentID string) bool {
		for placeholder := range want[agentID] {
			if !have[agentID][placeholder] {
				return true
			}
		}
		return false
	}
}

// perUserGuard refuses next, the block about to be saved, when it newly serves a
// mapping to an agent (the block newly enabled, or an agent added to a mapping
// relative to live) while a connected worker bound to that agent lacks
// usersecrets/v1. A worker that reports no agent id is never affected: the
// mapping reaches it only through an agent id. See forceWorkersLack for force.
func (s *Server) perUserGuard(ctx context.Context, live, next config.PerUserSecretsConfig) error {
	lacking, total := s.registry.WorkersLackingCap(config.CapUserSecretsV1, perUserAffected(perUserPairs(live), perUserPairs(next)))

	return s.forceWorkersLack(ctx, lacking, total, "per_user_secrets_forced", "per-user secrets (usersecrets/v1)")
}

// WritePerUserSecrets saves in as the perUserSecrets block of the served config
// and wakes the long poll, so the signed bundle carries the new mappings. The
// whole document is validated by the full loader first (placeholders against
// the static secrets included), an enabled block must pass the startup checks
// (consent.store, token service, signed bundles, registered providers), and the
// rollout guard runs on the result (see perUserGuard); a refused save changes
// nothing. Only an admin may call it (*dashboard.RoleRequiredError otherwise),
// and force=true on ctx is honoured only for an admin.
func (s *Server) WritePerUserSecrets(ctx context.Context, in config.PerUserSecretsConfig) error {
	// Admin only, checked here and not left to the route: under console.auth
	// oidc the principal must be an admin (an editor cannot change which agents
	// may swap user credentials, nor force); console.auth none has no roles and
	// its write guard is the admin bearer.
	if s.cfg.Console.Auth == config.ConsoleAuthOIDC {
		var role config.Role
		if p, ok := PrincipalFrom(ctx); ok {
			role = principalRole(s.cfg.Console, p)
		}
		if role < config.RoleAdmin {
			return &dashboard.RoleRequiredError{Need: config.RoleAdmin.String(), Fields: []string{"perUserSecrets"}}
		}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if in.Enabled && (s.cfg.PerUserLoad == nil || s.cfg.PerUserCheck == nil) {
		return &dashboard.InvalidPolicyError{Err: errors.New("per-user secrets are not available on this control plane")}
	}
	prov, err := config.NewLocalYAMLProvider(s.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("controlplane: read live config: %w", err)
	}
	cur, err := prov.GetPolicy()
	if err != nil {
		return fmt.Errorf("controlplane: read live config: %w", err)
	}
	live := cur.PerUserSecrets

	root := map[string]yaml.Node{}
	if data, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		_ = yaml.Unmarshal(data, &root)
	}
	node, err := config.EncodePerUserSecretsNode(in)
	if err != nil {
		return err
	}
	root["perUserSecrets"] = node
	if err := s.atomicWriteConfigChecked(root, func(p config.Policy) error {
		next := p.PerUserSecrets
		if next.Enabled {
			if err := s.cfg.PerUserCheck(next); err != nil {
				return &dashboard.InvalidPolicyError{Err: err}
			}
		}
		return s.perUserGuard(ctx, live, next)
	}); err != nil {
		return err
	}
	s.refresh()
	s.cfg.Logger.Info("control plane per-user secrets updated", "enabled", in.Enabled, "mappings", len(in.Mappings))
	return nil
}

// perUserSecretsPath is the admin route that saves the per-user block.
const (
	perUserSecretsPath        = "/dashboard/api/per-user-secrets"
	auditTargetPerUserSecrets = "per_user_secrets"
	maxPerUserSecretsBody     = 64 << 10
)

// perUserSecretsBody is the PUT body: the value-free block. Unknown members are
// refused, so no value field can be smuggled in.
type perUserSecretsBody struct {
	Enabled               bool                 `json:"enabled"`
	WorkerCacheTTLSeconds int                  `json:"workerCacheTTLSeconds"`
	Mappings              []perUserMappingBody `json:"mappings"`
}

type perUserMappingBody struct {
	Placeholder string   `json:"placeholder"`
	Provider    string   `json:"provider"`
	Scopes      []string `json:"scopes"`
	Domains     []string `json:"domains"`
	In          []string `json:"in"`
	Agents      []string `json:"agents"`
}

func (b perUserSecretsBody) config() config.PerUserSecretsConfig {
	c := config.PerUserSecretsConfig{Enabled: b.Enabled, WorkerCacheTTL: time.Duration(b.WorkerCacheTTLSeconds) * time.Second}
	for _, m := range b.Mappings {
		c.Mappings = append(c.Mappings, config.PerUserMapping{
			Placeholder: m.Placeholder, Provider: m.Provider, Scopes: m.Scopes,
			Domains: m.Domains, In: m.In, Agents: m.Agents,
		})
	}
	return c
}

// handlePerUserSecretsPut saves the block (PUT perUserSecretsPath). 409
// workers_lack_capability names the workers (retry with ?force=true as an
// admin), 403 role_required for a non-admin, 400 for an invalid block.
func (s *Server) handlePerUserSecretsPut(w http.ResponseWriter, r *http.Request) {
	if s.cfg.PerUserLoad == nil {
		writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "per_user_secrets_unavailable"})
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxPerUserSecretsBody+1))
	dec.DisallowUnknownFields()
	var body perUserSecretsBody
	if err := dec.Decode(&body); err != nil || dec.More() {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a JSON object with enabled, workerCacheTTLSeconds and mappings"})
		return
	}
	ctx := r.Context()
	if r.URL.Query().Get("force") == "true" {
		ctx = dashboard.WithForce(ctx)
	}
	err := s.WritePerUserSecrets(ctx, body.config())
	var lack *dashboard.WorkersLackCapabilityError
	var role *dashboard.RoleRequiredError
	var inv *dashboard.InvalidPolicyError
	switch {
	case err == nil:
		writeAuthJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.As(err, &lack):
		writeAuthJSON(w, http.StatusConflict, map[string]any{"error": "workers_lack_capability", "workers": append([]string{}, lack.Workers...)})
	case errors.As(err, &role):
		writeAuthJSON(w, http.StatusForbidden, map[string]any{"error": "role_required", "need": role.Need, "fields": role.Fields})
	case errors.As(err, &inv):
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_per_user_secrets", "message": boundedErr(inv.Err)})
	default:
		s.cfg.Logger.Error("per-user secrets write failed", "error", boundedErr(err))
		writeAuthJSON(w, http.StatusInternalServerError, map[string]string{"error": "write_failed"})
	}
}

// mountPerUserSecrets mounts the route like the token session routes: oidc mode
// behind the API key, session, audit and authz layers (admin; ScopeNone, so no
// API key reaches it), none mode behind the admin bearer.
func (s *Server) mountPerUserSecrets(mux *http.ServeMux, classify func(*http.Request) (authzRow, bool), oidc bool) {
	s.RegisterStateHasher(auditTargetPerUserSecrets, s.perUserSecretsHash)
	table := authzTable()
	var h http.Handler
	if oidc {
		h = s.apiKeyWrap(s.sessionAuditWrap(classify, requireRoleKeys(http.HandlerFunc(s.handlePerUserSecretsPut), table, s.cfg.Console, s.cfg.Logger, s.apiKeyCounts, s.keyOwnerBlocked)))
	} else {
		h = s.sessionAuditWrap(classify, s.bearerGate(http.HandlerFunc(s.handlePerUserSecretsPut)))
	}
	mux.Handle(perUserSecretsPath, methodOnly(http.MethodPut, h))
}

// perUserSecretsHash is the admin audit state hash of the block: a hash of the
// value-free section the block encodes to.
func (s *Server) perUserSecretsHash(context.Context) (string, error) {
	if s.cfg.PerUserLoad == nil {
		return "", errors.New("per-user secrets are not wired")
	}
	c, err := s.cfg.PerUserLoad()
	if err != nil {
		return "", err
	}
	raw, err := perUserSectionJSON(c)
	if err != nil {
		return "", err
	}
	return s.stateHashJSON(auditTargetPerUserSecrets, json.RawMessage(raw))
}
