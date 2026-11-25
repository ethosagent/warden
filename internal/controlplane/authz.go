package controlplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// routeKey identifies one served dashboard operation.
type routeKey struct{ Method, Path string }

// routeClass says how the admin audit middleware treats a route.
type routeClass string

const (
	// classAudited routes change admin state: each request by an
	// authenticated actor writes one admin audit row.
	classAudited routeClass = "audited"
	// classReadOnly routes change nothing, including the read-only POSTs
	// (query, query/generate, audit/verify, admin-audit/verify). No row.
	classReadOnly routeClass = "read-only"
	// classWorkerPlane routes serve workers (/policy, heartbeat, ingest,
	// healthz). They are never wrapped in the audit chain.
	classWorkerPlane routeClass = "worker-plane"
	// classAssertionAuth routes authenticate the caller with a signed client
	// assertion in the request body (POST /oauth2/token, W-P2-TOKX-03): no
	// session, no CSRF, no bearer. They are never wrapped in the admin audit
	// chain (machine issuance has its own records, W-P2-TOKX-04).
	classAssertionAuth routeClass = "assertion-authenticated"
	// classHandlerRecorded routes record their own entries (login, callback,
	// logout: W-P1-AAUD-07). The middleware never wraps them.
	classHandlerRecorded routeClass = "handler-recorded"
)

// authzRow is what the console requires for one route in oidc mode, and how
// the admin audit middleware treats it in every console.auth mode. It is a
// struct so later tickets (API-key scopes, per-field settings) can add fields
// without reshaping the table.
type authzRow struct {
	MinRole config.Role
	Action  string
	// Target names the admin state an audited route changes (policy,
	// settings, secrets, ...); it selects the state hasher.
	Target string
	// Audited is true exactly when Class is classAudited.
	Audited bool
	Class   routeClass
	// Scope is the API key scope a key must hold to reach the route
	// (W-P2-APIK-02): a registered scope, apikeys.ScopeNone (no key may reach it)
	// or apikeys.ScopeSelf (any valid key). Every row declares one explicitly;
	// the empty value is a classification gap and TestAuthzRouteCoverage fails
	// on it, so a new route is unreachable by keys until someone classifies it.
	Scope apikeys.Scope
	// SessionOnly marks a route a key must never reach AND that answers a key
	// 403 session_required instead of insufficient_scope: key creation, so no
	// key can mint or extend a key (W-P2-APIK-03).
	SessionOnly bool
}

// The P2 scopes the table names. They must be registered in
// apikeys.NewP2Registry (TestAuthzScopesRegistered).
const (
	scopePolicyRead  apikeys.Scope = "policy:read"
	scopePolicyWrite apikeys.Scope = "policy:write"
	// scopePolicyDraft creates a change draft (W-P2-APPR-04).
	scopePolicyDraft    apikeys.Scope = "policy:draft"
	scopeSettingsRead   apikeys.Scope = "settings:read"
	scopeTrafficRead    apikeys.Scope = "traffic:read"
	scopeAuditRead      apikeys.Scope = "audit:read"
	scopeAdminAuditRead apikeys.Scope = "adminaudit:read"
	// scopeWorkersAdmin guards workers/{id}/revoke (W-P2-WCA-05).
	scopeWorkersAdmin apikeys.Scope = "workers:admin"
	// The agent registry routes (W-P2-AREG-02).
	scopeAgentsRead  apikeys.Scope = "agents:read"
	scopeAgentsWrite apikeys.Scope = "agents:write"
	// TODO(W-P2-AREG-02, #72): GET agents rows take agents:read, writes take
	// agents:write. TODO(W-P2-WCA-08): worker-enrollments take workers:admin
	// (POST enrollments stays none).
	// The later approvals routes (emergency-apply, review) take none. Each
	// ticket adds its constants and rows here; the coverage test fails until
	// every row is classified.
)

// Row constructors keep the tables readable. The scope is the last argument so
// a row cannot be written without classifying it.
func readRow(role config.Role, action string, scope apikeys.Scope) authzRow {
	return authzRow{MinRole: role, Action: action, Class: classReadOnly, Scope: scope}
}

func auditedRow(role config.Role, action, target string, scope apikeys.Scope) authzRow {
	return authzRow{MinRole: role, Action: action, Target: target, Audited: true, Class: classAudited, Scope: scope}
}

// authzTable is the deny-by-default authorization table for the dashboard
// routes the control plane serves: a {method, path} with no row is refused for
// every role, GET included. A request is looked up by dashboard.RoutePath, so
// a templated route's row covers every concrete version path. Every
// dashboard.Routes() and cpDashboardRoutes()
// entry must have a row (TestAuthzRouteCoverage) and the row's Action must equal
// the route's. Every row has a Class; an audited row also names its Target.
//
// Settings writes need editor at the route; the settings writer then requires
// admin for any changed field outside config.EditorSettingsFields
// (writeSettingsAs). query/generate is editor-only and limited per session to
// queryGenerateLimit calls a minute (limitQueryGenerate).
func authzTable() map[routeKey]authzRow {
	const (
		get  = http.MethodGet
		post = http.MethodPost
		put  = http.MethodPut
		del  = http.MethodDelete

		viewer = config.RoleViewer
		editor = config.RoleEditor
		admin  = config.RoleAdmin

		none = apikeys.ScopeNone
	)
	rows := []struct {
		method, path string
		row          authzRow
	}{
		{get, "/dashboard/", readRow(viewer, "ui.read", none)},
		{get, "/dashboard/api/traffic", readRow(viewer, "traffic.read", scopeTrafficRead)},
		{get, "/dashboard/api/policy", readRow(viewer, "policy.read", scopePolicyRead)},
		{post, "/dashboard/api/policy", auditedRow(editor, "policy.write", "policy", scopePolicyWrite)},
		{put, "/dashboard/api/policy", auditedRow(editor, "policy.write", "policy", none)},
		{get, "/dashboard/api/settings", readRow(viewer, "settings.read", scopeSettingsRead)},
		{post, "/dashboard/api/settings", auditedRow(editor, "settings.write", "settings", none)},
		{put, "/dashboard/api/settings", auditedRow(editor, "settings.write", "settings", none)},
		{get, "/dashboard/api/secrets", readRow(viewer, "secrets.read", none)},
		{get, "/dashboard/api/endpoints", readRow(viewer, "endpoints.read", scopeTrafficRead)},
		{get, "/dashboard/api/analytics", readRow(viewer, "analytics.read", scopeTrafficRead)},
		{get, "/dashboard/api/mcp", readRow(viewer, "mcp.read", scopeTrafficRead)},
		{get, "/dashboard/api/workers", readRow(viewer, "workers.read", scopeTrafficRead)},
		{get, "/dashboard/api/query/schema", readRow(viewer, "query.schema", scopeTrafficRead)},
		{post, "/dashboard/api/query", readRow(viewer, "query.run", scopeTrafficRead)},
		{post, "/dashboard/api/query/generate", readRow(editor, "query.generate", none)},
		{get, "/dashboard/api/secretstore", readRow(viewer, "secretstore.read", none)},
		{post, "/dashboard/api/secretstore", auditedRow(admin, "secretstore.write", "secrets", none)},
		{del, "/dashboard/api/secretstore", auditedRow(admin, "secretstore.delete", "secrets", none)},
		{get, "/dashboard/api/alerts", readRow(viewer, "alerts.read", scopeTrafficRead)},
		{get, "/dashboard/api/integrations", readRow(viewer, "integrations.read", none)},
		{post, "/dashboard/api/integrations", auditedRow(admin, "integrations.write", "integrations", none)},
		{del, "/dashboard/api/integrations", auditedRow(admin, "integrations.delete", "integrations", none)},
		{get, "/dashboard/api/detection", readRow(viewer, "detection.read", scopePolicyRead)},
		{post, "/dashboard/api/detection", auditedRow(editor, "detection.write", "detection", scopePolicyWrite)},
		{put, "/dashboard/api/detection", auditedRow(editor, "detection.write", "detection", none)},
		{get, "/dashboard/api/llmproviders", readRow(viewer, "llmproviders.read", none)},
		{post, "/dashboard/api/llmproviders", auditedRow(admin, "llmproviders.write", "llmproviders", none)},
		{put, "/dashboard/api/llmproviders", auditedRow(admin, "llmproviders.write", "llmproviders", none)},
		{get, "/dashboard/api/audit", readRow(viewer, "audit.read", scopeAuditRead)},
		{post, "/dashboard/api/audit/verify", readRow(viewer, "audit.verify", scopeAuditRead)},
		// The admin audit log (W-P1-AAUD-03). verify is a read-only POST; the
		// public keys are not secret, so any role may read them.
		{get, "/dashboard/api/admin-audit", readRow(admin, "adminaudit.read", scopeAdminAuditRead)},
		{post, "/dashboard/api/admin-audit/verify", readRow(admin, "adminaudit.verify", scopeAdminAuditRead)},
		{get, "/dashboard/api/admin-audit/pubkey", readRow(viewer, "adminaudit.pubkey", scopeAdminAuditRead)},
		{get, "/dashboard/api/setup", readRow(viewer, "setup.read", none)},
		// Change drafts and the two-person rule (W-P2-APPR-04); 404 unless
		// console.approvals.enabled. Requests are matched on their template
		// ({id} is any draft id; dashboard.RoutePath). The author-only routes
		// (PUT, submit, withdraw, rebase) and the approver's role (the draft's
		// RequiredRole) are checked by the handler, not by this table. No API
		// key may approve or reject: the second person is always a human session.
		{get, "/dashboard/api/changes", readRow(viewer, "change.draft.list", scopePolicyRead)},
		{post, "/dashboard/api/changes", auditedRow(editor, "change.draft.create", auditTargetChangeDraft, scopePolicyDraft)},
		{get, "/dashboard/api/changes/{id}", readRow(viewer, "change.draft.read", scopePolicyRead)},
		{put, "/dashboard/api/changes/{id}", auditedRow(editor, "change.draft.update", auditTargetChangeDraft, scopePolicyWrite)},
		{get, "/dashboard/api/changes/{id}/diff", readRow(viewer, "change.draft.diff", scopePolicyRead)},
		{post, "/dashboard/api/changes/{id}/submit", auditedRow(editor, "change.draft.submit", auditTargetChangeDraft, scopePolicyWrite)},
		{post, "/dashboard/api/changes/{id}/withdraw", auditedRow(editor, "change.draft.withdraw", auditTargetChangeDraft, scopePolicyWrite)},
		{post, "/dashboard/api/changes/{id}/rebase", auditedRow(editor, "change.draft.rebase", auditTargetChangeDraft, scopePolicyWrite)},
		{post, "/dashboard/api/changes/{id}/approve", auditedRow(editor, "change.draft.approve", auditTargetChangeDraft, none)},
		{post, "/dashboard/api/changes/{id}/reject", auditedRow(editor, "change.draft.reject", auditTargetChangeDraft, none)},
		{post, "/dashboard/api/changes/{id}/replay", auditedRow(editor, "change.draft.replay", auditTargetChangeDraft, scopePolicyWrite)},
		// Policy history (W-P1-PVER-03). Requests are matched on their template
		// ({v} is any version segment; dashboard.RoutePath).
		{get, "/dashboard/api/policy/versions", readRow(viewer, "policy.versions.read", scopePolicyRead)},
		{get, "/dashboard/api/policy/versions/{v}", readRow(viewer, "policy.version.read", scopePolicyRead)},
		{get, "/dashboard/api/policy/versions/{v}/diff", readRow(viewer, "policy.diff", scopePolicyRead)},
		{post, "/dashboard/api/policy/versions/{v}/rollback", auditedRow(editor, "policy.rollback", "policy", none)},
		// On-demand backup (W-P1-OPS1-11); 404 unless --backup-dir is set.
		{post, "/dashboard/api/backup", auditedRow(admin, "backup.run", "backup", none)},
		// Worker tokens (W-P1-WTOK-03): viewers may list; minting and revoking are
		// admin only, and the handler also refuses them outside console.auth oidc.
		// Worker certificate revoke (W-P2-WCA-05): admin only; 404 unless
		// workerCA is enabled, and refused outside console.auth oidc (use_cli).
		{post, "/dashboard/api/workers/{id}/revoke", auditedRow(admin, actionWorkerRevoked, auditTargetWorkerCerts, scopeWorkersAdmin)},
		{get, "/dashboard/api/worker-tokens", readRow(viewer, "worker_token.read", none)},
		{post, "/dashboard/api/worker-tokens", auditedRow(admin, "worker_token.create", "worker_tokens", none)},
		{del, "/dashboard/api/worker-tokens/{id}", auditedRow(admin, "worker_token.revoke", "worker_tokens", none)},
		// The user block list (W-P1-BLOCK-11). Requests are matched on their
		// template ({id} is any entry id; dashboard.RoutePath).
		{get, "/dashboard/api/blocked-users", readRow(admin, "blocked_users.read", scopePolicyRead)},
		{post, "/dashboard/api/blocked-users", auditedRow(admin, "blocked_users.add", blockedUsersTarget, scopePolicyWrite)},
		{del, "/dashboard/api/blocked-users/{id}", auditedRow(admin, "blocked_users.remove", blockedUsersTarget, scopePolicyWrite)},
		// Signing keys (W-P2-KEYS-04): admin only; 404 unless keys.enabled. A
		// rotation is refused outside console.auth oidc (use_cli).
		{get, "/dashboard/api/keys", readRow(admin, "keys.read", none)},
		{post, "/dashboard/api/keys/rotate", auditedRow(admin, "keys.rotate_requested", auditTargetKeys, none)},
		// The agent registry (W-P2-AREG-02): viewers read, every write is admin
		// because a key or group change decides who can mint agent-bound tokens.
		// 404 unless the control plane set the seam. There is no DELETE row: an
		// unlisted method is refused for every role.
		{get, "/dashboard/api/agents", readRow(viewer, AgentActionList, scopeAgentsRead)},
		{post, "/dashboard/api/agents", auditedRow(admin, AgentActionCreate, AgentAuditTarget, scopeAgentsWrite)},
		{get, "/dashboard/api/agents/{id}", readRow(viewer, AgentActionRead, scopeAgentsRead)},
		{put, "/dashboard/api/agents/{id}", auditedRow(admin, AgentActionUpdate, AgentAuditTarget, scopeAgentsWrite)},
		{post, "/dashboard/api/agents/{id}/disable", auditedRow(admin, AgentActionDisable, AgentAuditTarget, scopeAgentsWrite)},
		{post, "/dashboard/api/agents/{id}/enable", auditedRow(admin, AgentActionEnable, AgentAuditTarget, scopeAgentsWrite)},
		// Served by the control plane itself, ahead of dash.Handler (cpDashboardRoutes).
		{get, "/dashboard/api/sessions", readRow(admin, "sessions.read", none)},
		{del, "/dashboard/api/sessions", auditedRow(admin, "sessions.revoke", "sessions", none)},
		// Token sessions (W-P2-TOKX-07): admin only; 404 unless tokenService.enabled.
		// ScopeNone like the console session routes: no API key lists or revokes
		// token sessions.
		{get, tokenSessionsListPath, readRow(admin, "token_sessions.read", none)},
		{post, tokenSessionsRevokeAllPath, auditedRow(admin, "token_sessions.revoke_all", auditTargetTokenSessions, none)},
		{post, tokenSessionRevokePath, auditedRow(admin, "token_sessions.revoke", auditTargetTokenSessions, none)},
		// API key management (W-P2-APIK-03), served by the control plane itself.
		// Every row is ScopeNone but /self: no key lists, creates or revokes keys.
		// The handlers apply the object-level rules (own keys unless admin; create
		// only from an OIDC session, capped by the creator's role).
		{get, apiKeysPath, readRow(viewer, "api_key.list", none)},
		{post, apiKeysPath, authzRow{MinRole: viewer, Action: "api_key.create", Target: auditTargetAPIKeys, Audited: true, Class: classAudited, Scope: none, SessionOnly: true}},
		{del, apiKeysPath, auditedRow(admin, "api_key.revoke_owner", auditTargetAPIKeys, none)},
		{del, apiKeysPath + "/{id}", auditedRow(viewer, "api_key.revoke", auditTargetAPIKeys, none)},
		{get, apiKeysPath + "/self", readRow(viewer, "api_key.self", apikeys.ScopeSelf)},
	}
	t := make(map[routeKey]authzRow, len(rows))
	for _, r := range rows {
		t[routeKey{r.method, r.path}] = r.row
	}
	return t
}

// cpRouteTable classifies the control plane's own routes outside /dashboard/,
// keyed by the method and the ServeMux pattern they are mounted on
// (/central/secrets/ is the DELETE /central/secrets/{key} subtree). Every
// pattern Server.Handler registers must appear here or in authzTable
// (TestAuthzRouteCoverage). MinRole documents the secrets gate
// (secretsAuthOK); the console authz middleware does not read this table.
func cpRouteTable() map[routeKey]authzRow {
	const (
		get  = http.MethodGet
		post = http.MethodPost
		del  = http.MethodDelete
	)
	// None of these is reachable with an API key (WorkerAuthenticator refuses a
	// wak_ bearer; the token endpoint authenticates with a client assertion;
	// the human routes answer a key 401 or 403), so every row is ScopeNone.
	const none = apikeys.ScopeNone
	worker := authzRow{Class: classWorkerPlane, Scope: none}
	assertion := authzRow{Action: "token.exchange", Class: classAssertionAuth, Scope: none}
	handler := func(action string) authzRow {
		return authzRow{Action: action, Class: classHandlerRecorded, Scope: none}
	}
	rows := []struct {
		method, path string
		row          authzRow
	}{
		{get, "/healthz", worker},
		// Public by design: a verifier fetches the JWKS and a load balancer
		// probes /readyz with no credential (W-P2-KEYS-04). The JWKS is mounted
		// only with keys.enabled.
		{get, "/readyz", worker},
		{get, jwksPath, worker},
		// The RFC 8693 token endpoint authenticates with a client assertion
		// in the body and is Audited:false; its RFC 8414 metadata is public
		// like the JWKS. Both are mounted only with tokenService.enabled.
		{post, tokenPath, assertion},
		{get, asMetadataPath, worker},
		{get, "/policy", worker},
		{post, "/control/heartbeat", worker},
		// Credential is the enrollment token; mounted only with workerCA enabled
		// and a state dir (W-P2-WCA-02).
		{post, enrollPath, worker},
		// Credential is the worker certificate, checked per request by the
		// authenticator; mounted with /control/enroll (W-P2-WCA-04).
		{post, renewPath, worker},
		{post, "/central/ingest", worker},
		{get, "/central/secrets", readRow(config.RoleAdmin, "secrets.read", none)},
		{post, "/central/secrets", auditedRow(config.RoleAdmin, "secrets.write", "secrets", none)},
		{del, "/central/secrets/", auditedRow(config.RoleAdmin, "secrets.delete", "secrets", none)},
		{get, "/auth/me", readRow(0, "auth.me", none)},
		{get, "/auth/login", handler("auth.login")},
		{get, "/auth/callback", handler("auth.callback")},
		{post, "/auth/logout", handler("auth.logout")},
		{post, "/auth/breakglass", handler("auth.breakglass")},
	}
	t := make(map[routeKey]authzRow, len(rows))
	for _, r := range rows {
		t[routeKey{r.method, r.path}] = r.row
	}
	return t
}

type actionKey struct{}

// ActionFrom returns the action name the authz table assigned to the request,
// for the admin audit middleware (W-P1-AAUD-02).
func ActionFrom(ctx context.Context) (string, bool) {
	a, ok := ctx.Value(actionKey{}).(string)
	return a, ok
}

// requireRole enforces the authz table on a console request. It needs withSession
// outside it: the Principal comes from the request context, and the role is
// recomputed from the CURRENT console config on every request, so a change to
// console.roles applies to live sessions after a restart. It never reads the
// Authorization header, so a shared or admin bearer cannot open a human route.
func requireRole(next http.Handler, table map[routeKey]authzRow, console config.ConsoleConfig, logger *slog.Logger) http.Handler {
	return requireRoleKeys(next, table, console, logger, nil, nil)
}

// requireRoleKeys is requireRole that decides API key Principals too, counting
// each outcome on counts (nil counts nothing). A key is allowed only
// when it holds the row's scope and its owner's CURRENT role covers the row;
// every other outcome is 403 insufficient_scope naming the scope the row needs
// ("none" for a route no key may reach), so a refusal says nothing about the
// owner's role. The refusal is chained as denied by the audit middleware
// outside this one.
func requireRoleKeys(next http.Handler, table map[routeKey]authzRow, console config.ConsoleConfig, logger *slog.Logger, counts *apiKeyCounters, ownerBlocked func(Principal) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			logDenied(logger, authzRow{}, 0, Principal{}, r)
			if strings.HasPrefix(r.URL.Path, "/dashboard/api/") {
				writeAuthzJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		role := principalRole(console, p) // zero (no role) when no group matches
		row, listed := table[routeKey{r.Method, dashboard.RoutePath(r.URL.Path)}]
		if !listed {
			logDenied(logger, row, role, p, r)
			writeAuthzJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if p.Kind == PrincipalAPIKey {
			if row.SessionOnly {
				counts.inc(APIKeyOutcomeInsufficientScope)
				logDenied(logger, row, role, p, r)
				writeAuthzJSON(w, http.StatusForbidden, map[string]string{"error": "session_required"})
				return
			}
			if ok, need := keyAuthorized(p, row, role); !ok || (ownerBlocked != nil && ownerBlocked(p)) {
				if ok {
					need = apikeys.ScopeNone // refused for who the owner is, not for a scope
				}
				counts.inc(APIKeyOutcomeInsufficientScope)
				logDenied(logger, row, role, p, r)
				writeAuthzJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope", "need": string(need)})
				return
			}
			counts.inc(APIKeyOutcomeOK)
		} else if role < row.MinRole {
			logDenied(logger, row, role, p, r)
			writeAuthzJSON(w, http.StatusForbidden, map[string]string{"error": "role_required", "need": row.MinRole.String()})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actionKey{}, row.Action)))
	})
}

// logDenied records a refusal. It logs the route and who, never a header,
// cookie, token or body.
func logDenied(logger *slog.Logger, row authzRow, role config.Role, p Principal, r *http.Request) {
	logger.Warn("console_authz_denied", "action", row.Action, "role", role.String(), "sub", p.Sub,
		"method", r.Method, "path", r.URL.Path)
}

func writeAuthzJSON(w http.ResponseWriter, status int, v map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sessionWriteGuard is the dashboard write guard in oidc mode. A write passes
// only with a Principal in the context; withSession puts one there only after
// the CSRF header and Origin checks passed for the session, and refuses a
// state-changing request that fails them before this guard runs. The guard never
// reads the Authorization header: the shared token and the admin bearer do not
// authenticate a human write.
func (s *Server) sessionWriteGuard() dashboard.WriteGuard {
	return func(r *http.Request) (int, string) {
		if _, ok := PrincipalFrom(r.Context()); !ok {
			return http.StatusUnauthorized, "console session required"
		}
		return 0, ""
	}
}
