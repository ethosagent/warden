package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/config"
)

// The API key management routes (W-P2-APIK-03). The control plane serves them
// itself, like /dashboard/api/sessions, behind the same chain as every admin
// route: key authenticator, session + CSRF, admin audit, authz table. They are
// mounted only with console.apiKeys.enabled; otherwise every one answers 404.
//
//	GET    /dashboard/api/api-keys             own keys (admin: all, ?owner_sub= filter)
//	POST   /dashboard/api/api-keys             create; OIDC console session only
//	DELETE /dashboard/api/api-keys?owner_sub=  admin: revoke every key of one owner
//	DELETE /dashboard/api/api-keys/{id}        owner or admin
//	GET    /dashboard/api/api-keys/self        any valid key (ScopeSelf)
//
// The plaintext key is in the 201 of a create and nowhere else: no list, no
// audit row, no log line. Rows are keyed on dashboard.APIKeysPath.
const (
	// apiKeysPath equals dashboard.APIKeysPath (TestAPIKeysPathMatchesDashboard);
	// the literals keep the mux-pattern walk of TestAuthzRouteCoverage able to
	// resolve them. apiKeysSubtree is the per-key subtree (/self and /{id}).
	apiKeysPath        = "/dashboard/api/api-keys"
	apiKeysSubtree     = "/dashboard/api/api-keys/"
	auditTargetAPIKeys = "api_keys"

	maxAPIKeyBodyBytes = 8 << 10
	maxOwnerSubLen     = 255
)

var apiKeyIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// apiKeyRef is the admin audit target_ref of a key.
func apiKeyRef(id string) string { return "api_key:" + id }

// apiKeyMgmtEnabled reports whether the management routes are served.
func (s *Server) apiKeyMgmtEnabled() bool {
	return s.apiKeys != nil && s.cfg.APIKeyStore != nil && s.cfg.APIKeyRegistry != nil && s.cfg.APIKeyIndex != nil
}

// mountAPIKeys mounts the management routes in oidc mode: the real handlers
// when API keys are on, 404 otherwise (the dashboard would answer the path with
// its own 404 anyway; the explicit mount keeps it independent of that).
func (s *Server) mountAPIKeys(mux *http.ServeMux, classify func(*http.Request) (authzRow, bool), table map[routeKey]authzRow) {
	if !s.apiKeyMgmtEnabled() {
		mux.Handle(apiKeysPath, http.NotFoundHandler())
		mux.Handle(apiKeysSubtree, http.NotFoundHandler())
		return
	}
	s.RegisterStateHasher(auditTargetAPIKeys, s.apiKeysStateHash)
	wrap := func(h http.HandlerFunc) http.Handler {
		return s.apiKeyWrap(s.sessionAuditWrap(classify, requireRoleKeys(h, table, s.cfg.Console, s.cfg.Logger, s.apiKeyCounts, s.keyOwnerBlocked)))
	}
	mux.Handle(apiKeysPath, wrap(s.handleAPIKeys))
	mux.Handle(apiKeysSubtree, wrap(s.handleAPIKeyItem))
}

// apiKeyView is one key as the API returns it. It has no field for the secret,
// the plaintext or the stored hash.
type apiKeyView struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Scopes          []string `json:"scopes"`
	EffectiveScopes []string `json:"effectiveScopes"`
	OwnerEmail      string   `json:"ownerEmail,omitempty"`
	// OwnerSub is returned to admins only (it keys revoke-by-owner).
	OwnerSub   string `json:"ownerSub,omitempty"`
	CreatedAt  string `json:"createdAt"`
	ExpiresAt  string `json:"expiresAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
	Status     string `json:"status"`
}

func scopeNames(scopes []apikeys.Scope) []string {
	out := make([]string, len(scopes))
	for i, sc := range scopes {
		out[i] = string(sc)
	}
	return out
}

// effectiveScopes are the key's scopes its owner's CURRENT role still covers.
func (s *Server) effectiveScopes(k apikeys.Key) []string {
	role, _ := s.cfg.Console.RoleFor(k.OwnerGroups)
	out := []string{}
	for _, sc := range k.Scopes {
		if min, ok := s.cfg.APIKeyRegistry.Lookup(sc); ok && role >= min {
			out = append(out, string(sc))
		}
	}
	return out
}

func (s *Server) apiKeyView(k apikeys.Key, now time.Time, admin bool) apiKeyView {
	// The Index holds the freshest last-use (the store only sees the 60s flush).
	if u, ok := s.cfg.APIKeyIndex.PendingUse(k.ID); ok && u.At.After(k.LastUsedAt) {
		k.LastUsedAt = u.At
	}
	v := apiKeyView{
		ID: k.ID, Name: k.Name, Description: k.Description, Scopes: scopeNames(k.Scopes),
		EffectiveScopes: s.effectiveScopes(k), OwnerEmail: k.OwnerEmail,
		CreatedAt: rfc3339(k.CreatedAt), ExpiresAt: rfc3339(k.ExpiresAt),
		LastUsedAt: rfc3339(k.LastUsedAt), RevokedAt: rfc3339(k.RevokedAt),
		Status: string(k.StatusAt(now)),
	}
	if admin {
		v.OwnerSub = k.OwnerSub
	}
	return v
}

func apiKeyError(w http.ResponseWriter, status int, code string) {
	writeAuthJSON(w, status, map[string]string{"error": code})
}

// handleAPIKeys serves /dashboard/api/api-keys. It runs inside the key
// authenticator, session, audit and authz layers (mountAPIKeys), so a Principal
// is present and the table's role floor has passed.
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		apiKeyError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listAPIKeys(w, r, p)
	case http.MethodPost:
		s.createAPIKey(w, r, p)
	case http.MethodDelete:
		s.revokeAPIKeysOfOwner(w, r, p)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		apiKeyError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAPIKeyItem serves the subtree: GET /self and DELETE /{id}.
func (s *Server) handleAPIKeyItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		apiKeyError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	seg := strings.TrimPrefix(r.URL.Path, apiKeysSubtree)
	switch {
	case seg == "self" && r.Method == http.MethodGet:
		s.apiKeySelf(w, p)
	case seg == "self":
		w.Header().Set("Allow", "GET")
		apiKeyError(w, http.StatusMethodNotAllowed, "method not allowed")
	case r.Method != http.MethodDelete:
		w.Header().Set("Allow", "DELETE")
		apiKeyError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		s.revokeAPIKey(w, r, p, seg)
	}
}

func (s *Server) isAdmin(p Principal) bool {
	return principalRole(s.cfg.Console, p) >= config.RoleAdmin
}

// ownsKey reports whether p is the human who owns k.
func ownsKey(p Principal, k apikeys.Key) bool {
	return p.Kind != PrincipalAPIKey && p.Kind != PrincipalBreakglass && k.OwnerSub == p.Sub && k.OwnerIss == p.Iss
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request, p Principal) {
	admin := s.isAdmin(p)
	filter := apikeys.ListFilter{}
	if ownerSub := r.URL.Query().Get("owner_sub"); ownerSub != "" {
		if len(ownerSub) > maxOwnerSubLen {
			apiKeyError(w, http.StatusBadRequest, "owner_sub_too_long")
			return
		}
		if !admin && ownerSub != p.Sub {
			apiKeyError(w, http.StatusForbidden, "forbidden")
			return
		}
		filter.OwnerSub = ownerSub
	} else if !admin {
		filter.OwnerSub = p.Sub
	}
	keys, err := s.cfg.APIKeyStore.List(r.Context(), filter)
	if err != nil {
		s.cfg.Logger.Error("api keys: list failed", "error", err)
		apiKeyError(w, http.StatusInternalServerError, "api key store error")
		return
	}
	now := s.cfg.Clock.Now()
	out := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		if !admin && !ownsKey(p, k) {
			continue // another issuer's key that shares this subject
		}
		out = append(out, s.apiKeyView(k, now, admin))
	}
	writeAuthJSON(w, http.StatusOK, out)
}

type createAPIKeyRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
	ExpiresIn   string   `json:"expiresIn"`
}

// createAPIKeyResponse is the one place the plaintext is ever returned.
type createAPIKeyResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"createdAt"`
	ExpiresAt string   `json:"expiresAt"`
	Key       string   `json:"key"`
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request, p Principal) {
	// Only an OIDC console session mints a key: not a break-glass session (no
	// durable identity to own it) and not a key (it could extend itself).
	if p.Kind != PrincipalSession || p.AuthMethod != adminaudit.AuthMethodOIDC {
		apiKeyError(w, http.StatusForbidden, "session_required")
		return
	}
	var req createAPIKeyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAPIKeyBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apiKeyError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	cc := s.cfg.Console.APIKeys
	ttl := cc.DefaultTTL
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 {
			apiKeyError(w, http.StatusBadRequest, "invalid_expires_in")
			return
		}
		ttl = d
	}
	reg := s.cfg.APIKeyRegistry
	scopes, err := reg.ParseScopes(req.Scopes)
	params := apikeys.CreateParams{
		Name: req.Name, Description: req.Description,
		OwnerIss: p.Iss, OwnerSub: p.Sub, OwnerEmail: p.Email, OwnerGroups: p.Groups,
		Scopes: scopes, TTL: ttl, MaxTTL: cc.MaxTTL, MaxActive: cc.MaxPerOwner,
	}
	if err == nil {
		err = params.Validate(reg)
	}
	if err != nil {
		writeCreateError(w, err)
		return
	}
	// The creator's CURRENT role caps the scopes: nobody mints access above
	// their own.
	role := principalRole(s.cfg.Console, p)
	var over []string
	for _, sc := range scopes {
		if min, _ := reg.Lookup(sc); role < min {
			over = append(over, string(sc))
		}
	}
	if len(over) > 0 {
		sort.Strings(over)
		writeAuthJSON(w, http.StatusForbidden, map[string]any{"error": "scope_exceeds_role", "scopes": over})
		return
	}
	plaintext, k, err := s.cfg.APIKeyStore.Create(r.Context(), params)
	if err != nil {
		s.createFailed(w, err)
		return
	}
	adminaudit.Annotate(r.Context(), apiKeyRef(k.ID), map[string]string{
		adminaudit.DetailScopes:    strings.Join(scopeNames(k.Scopes), ","),
		adminaudit.DetailExpiresAt: rfc3339(k.ExpiresAt),
	})
	s.cfg.Logger.Info("api_key_created", "key_id", k.ID, "owner_sub", p.Sub, "scopes", strings.Join(scopeNames(k.Scopes), ","))
	writeAuthJSON(w, http.StatusCreated, createAPIKeyResponse{
		ID: k.ID, Name: k.Name, Scopes: scopeNames(k.Scopes),
		CreatedAt: rfc3339(k.CreatedAt), ExpiresAt: rfc3339(k.ExpiresAt), Key: plaintext,
	})
}

// writeCreateError answers a validation failure; the text describes only the
// caller's own input.
func writeCreateError(w http.ResponseWriter, err error) {
	code := "invalid_request"
	switch {
	case errors.Is(err, apikeys.ErrUnknownScope):
		code = "unknown_scope"
	case errors.Is(err, apikeys.ErrNoScopes):
		code = "scopes_required"
	case errors.Is(err, apikeys.ErrDuplicateScope):
		code = "duplicate_scope"
	case errors.Is(err, apikeys.ErrInvalidTTL):
		code = "invalid_expires_in"
	}
	writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": code, "detail": err.Error()})
}

func (s *Server) createFailed(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apikeys.ErrNameTaken):
		apiKeyError(w, http.StatusConflict, "name_taken")
	case errors.Is(err, apikeys.ErrTooMany):
		apiKeyError(w, http.StatusConflict, "too_many_keys")
	case errors.Is(err, apikeys.ErrInvalidInput), errors.Is(err, apikeys.ErrInvalidTTL),
		errors.Is(err, apikeys.ErrUnknownScope), errors.Is(err, apikeys.ErrNoScopes), errors.Is(err, apikeys.ErrDuplicateScope):
		writeCreateError(w, err)
	default:
		s.cfg.Logger.Error("api keys: create failed", "error", err)
		apiKeyError(w, http.StatusInternalServerError, "api key store error")
	}
}

// revokeAPIKey revokes one key: its owner or an admin. The store notifies the
// Index before Revoke returns, so the key's next request is a 401.
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, p Principal, id string) {
	if !apiKeyIDPattern.MatchString(id) {
		apiKeyError(w, http.StatusNotFound, "api_key_not_found")
		return
	}
	k, err := s.cfg.APIKeyStore.Get(r.Context(), id)
	if errors.Is(err, apikeys.ErrNotFound) {
		apiKeyError(w, http.StatusNotFound, "api_key_not_found")
		return
	}
	if err != nil {
		s.cfg.Logger.Error("api keys: get failed", "error", err)
		apiKeyError(w, http.StatusInternalServerError, "api key store error")
		return
	}
	if !s.isAdmin(p) && !ownsKey(p, k) {
		apiKeyError(w, http.StatusForbidden, "forbidden")
		return
	}
	adminaudit.Annotate(r.Context(), apiKeyRef(id), map[string]string{
		adminaudit.DetailScopes:    strings.Join(scopeNames(k.Scopes), ","),
		adminaudit.DetailExpiresAt: rfc3339(k.ExpiresAt),
	})
	if !k.RevokedAt.IsZero() {
		adminaudit.Skip(r.Context()) // already revoked: nothing changed, no second row
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.cfg.APIKeyStore.Revoke(r.Context(), id, p.Sub); err != nil {
		if errors.Is(err, apikeys.ErrNotFound) {
			apiKeyError(w, http.StatusNotFound, "api_key_not_found")
			return
		}
		s.cfg.Logger.Error("api keys: revoke failed", "key_id", id, "error", err)
		apiKeyError(w, http.StatusInternalServerError, "api key store error")
		return
	}
	s.cfg.Logger.Info("api_key_revoked", "key_id", id, "by_sub", p.Sub)
	w.WriteHeader(http.StatusNoContent)
}

// revokeAPIKeysOfOwner is the admin offboarding call: every key of ?owner_sub=.
func (s *Server) revokeAPIKeysOfOwner(w http.ResponseWriter, r *http.Request, p Principal) {
	sub := r.URL.Query().Get("owner_sub")
	switch {
	case sub == "":
		apiKeyError(w, http.StatusBadRequest, "owner_sub_required")
		return
	case len(sub) > maxOwnerSubLen:
		apiKeyError(w, http.StatusBadRequest, "owner_sub_too_long")
		return
	}
	n, err := s.RevokeAPIKeysForOwner(r.Context(), "", sub, p.Sub)
	if err != nil {
		s.cfg.Logger.Error("api keys: revoke by owner failed", "owner_sub", sub, "error", err)
		apiKeyError(w, http.StatusInternalServerError, "api key store error")
		return
	}
	adminaudit.Annotate(r.Context(), "api_key:owner", map[string]string{adminaudit.DetailOp: "revoke_owner"})
	s.cfg.Logger.Info("api_keys_revoked_for_owner", "owner_sub", sub, "by_sub", p.Sub, "count", n)
	writeAuthJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// RevokeAPIKeysForOwner revokes every unrevoked key owned by (iss, sub) and
// returns how many (the count includes keys that expired without being revoked,
// which RevokeByOwner also marks). An empty iss means every issuer that has a key for sub. It
// is the one call offboarding paths use (the session revoke-by-sub route and a
// later Offboard(sub)); it goes through Store.RevokeByOwner so the Index stops
// accepting the keys before it returns. With API keys disabled it does nothing.
func (s *Server) RevokeAPIKeysForOwner(ctx context.Context, iss, sub, by string) (int, error) {
	st := s.cfg.APIKeyStore
	if st == nil {
		return 0, nil // API keys are disabled
	}
	if sub == "" || by == "" {
		return 0, apikeys.ErrInvalidInput
	}
	keys, err := st.List(ctx, apikeys.ListFilter{OwnerSub: sub})
	if err != nil {
		return 0, err
	}
	issuers := map[string]bool{}
	for _, k := range keys {
		if iss == "" || k.OwnerIss == iss {
			issuers[k.OwnerIss] = true
		}
	}
	total := 0
	for i := range issuers {
		n, err := st.RevokeByOwner(ctx, i, sub, by)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// apiKeySelf returns the calling key's own metadata for p4-admin-mcp.
func (s *Server) apiKeySelf(w http.ResponseWriter, p Principal) {
	if p.Kind != PrincipalAPIKey {
		apiKeyError(w, http.StatusBadRequest, "api_key_required")
		return
	}
	k, ok := s.cfg.APIKeyIndex.Key(p.KeyID)
	if !ok {
		apiKeyError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeAuthJSON(w, http.StatusOK, s.apiKeyView(k, s.cfg.Clock.Now(), false))
}

// apiKeysStateHash is the keyed hash of every key's id, scopes, expiry and
// revocation time (never a secret, hash or last-use time, which moves without
// an admin acting).
func (s *Server) apiKeysStateHash(ctx context.Context) (string, error) {
	keys, err := s.cfg.APIKeyStore.List(ctx, apikeys.ListFilter{})
	if err != nil {
		return "", err
	}
	type meta struct {
		ID      string   `json:"id"`
		Scopes  []string `json:"scopes"`
		Expires int64    `json:"expires_at"`
		Revoked int64    `json:"revoked_at"`
	}
	rows := make([]meta, 0, len(keys))
	for _, k := range keys {
		m := meta{ID: k.ID, Scopes: scopeNames(k.Scopes), Expires: k.ExpiresAt.Unix()}
		if !k.RevokedAt.IsZero() {
			m.Revoked = k.RevokedAt.Unix()
		}
		rows = append(rows, m)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return s.stateHashJSON(auditTargetAPIKeys, rows)
}
