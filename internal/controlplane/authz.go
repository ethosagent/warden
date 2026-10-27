package controlplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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
	// (query, query/generate, audit/verify). No row.
	classReadOnly routeClass = "read-only"
	// classWorkerPlane routes serve workers (/policy, heartbeat, ingest,
	// healthz). They are never wrapped in the audit chain.
	classWorkerPlane routeClass = "worker-plane"
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
}

// Row constructors keep the tables readable.
func readRow(role config.Role, action string) authzRow {
	return authzRow{MinRole: role, Action: action, Class: classReadOnly}
}

func auditedRow(role config.Role, action, target string) authzRow {
	return authzRow{MinRole: role, Action: action, Target: target, Audited: true, Class: classAudited}
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
	)
	rows := []struct {
		method, path string
		row          authzRow
	}{
		{get, "/dashboard/", readRow(viewer, "ui.read")},
		{get, "/dashboard/api/traffic", readRow(viewer, "traffic.read")},
		{get, "/dashboard/api/policy", readRow(viewer, "policy.read")},
		{post, "/dashboard/api/policy", auditedRow(editor, "policy.write", "policy")},
		{put, "/dashboard/api/policy", auditedRow(editor, "policy.write", "policy")},
		{get, "/dashboard/api/settings", readRow(viewer, "settings.read")},
		{post, "/dashboard/api/settings", auditedRow(editor, "settings.write", "settings")},
		{put, "/dashboard/api/settings", auditedRow(editor, "settings.write", "settings")},
		{get, "/dashboard/api/secrets", readRow(viewer, "secrets.read")},
		{get, "/dashboard/api/endpoints", readRow(viewer, "endpoints.read")},
		{get, "/dashboard/api/analytics", readRow(viewer, "analytics.read")},
		{get, "/dashboard/api/mcp", readRow(viewer, "mcp.read")},
		{get, "/dashboard/api/workers", readRow(viewer, "workers.read")},
		{get, "/dashboard/api/query/schema", readRow(viewer, "query.schema")},
		{post, "/dashboard/api/query", readRow(viewer, "query.run")},
		{post, "/dashboard/api/query/generate", readRow(editor, "query.generate")},
		{get, "/dashboard/api/secretstore", readRow(viewer, "secretstore.read")},
		{post, "/dashboard/api/secretstore", auditedRow(admin, "secretstore.write", "secrets")},
		{del, "/dashboard/api/secretstore", auditedRow(admin, "secretstore.delete", "secrets")},
		{get, "/dashboard/api/alerts", readRow(viewer, "alerts.read")},
		{get, "/dashboard/api/integrations", readRow(viewer, "integrations.read")},
		{post, "/dashboard/api/integrations", auditedRow(admin, "integrations.write", "integrations")},
		{del, "/dashboard/api/integrations", auditedRow(admin, "integrations.delete", "integrations")},
		{get, "/dashboard/api/detection", readRow(viewer, "detection.read")},
		{post, "/dashboard/api/detection", auditedRow(editor, "detection.write", "detection")},
		{put, "/dashboard/api/detection", auditedRow(editor, "detection.write", "detection")},
		{get, "/dashboard/api/llmproviders", readRow(viewer, "llmproviders.read")},
		{post, "/dashboard/api/llmproviders", auditedRow(admin, "llmproviders.write", "llmproviders")},
		{put, "/dashboard/api/llmproviders", auditedRow(admin, "llmproviders.write", "llmproviders")},
		{get, "/dashboard/api/audit", readRow(viewer, "audit.read")},
		{post, "/dashboard/api/audit/verify", readRow(viewer, "audit.verify")},
		{get, "/dashboard/api/setup", readRow(viewer, "setup.read")},
		// Policy history (W-P1-PVER-03). Requests are matched on their template
		// ({v} is any version segment; dashboard.RoutePath).
		{get, "/dashboard/api/policy/versions", readRow(viewer, "policy.versions.read")},
		{get, "/dashboard/api/policy/versions/{v}", readRow(viewer, "policy.version.read")},
		{get, "/dashboard/api/policy/versions/{v}/diff", readRow(viewer, "policy.diff")},
		{post, "/dashboard/api/policy/versions/{v}/rollback", auditedRow(editor, "policy.rollback", "policy")},
		// Worker tokens (W-P1-WTOK-03): viewers may list; minting and revoking are
		// admin only, and the handler also refuses them outside console.auth oidc.
		{get, "/dashboard/api/worker-tokens", readRow(viewer, "worker_token.read")},
		{post, "/dashboard/api/worker-tokens", auditedRow(admin, "worker_token.create", "worker_tokens")},
		{del, "/dashboard/api/worker-tokens/{id}", auditedRow(admin, "worker_token.revoke", "worker_tokens")},
		// Served by the control plane itself, ahead of dash.Handler (cpDashboardRoutes).
		{get, "/dashboard/api/sessions", readRow(admin, "sessions.read")},
		{del, "/dashboard/api/sessions", auditedRow(admin, "sessions.revoke", "sessions")},
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
	worker := authzRow{Class: classWorkerPlane}
	handler := func(action string) authzRow { return authzRow{Action: action, Class: classHandlerRecorded} }
	rows := []struct {
		method, path string
		row          authzRow
	}{
		{get, "/healthz", worker},
		{get, "/policy", worker},
		{post, "/control/heartbeat", worker},
		{post, "/central/ingest", worker},
		{get, "/central/secrets", readRow(config.RoleAdmin, "secrets.read")},
		{post, "/central/secrets", auditedRow(config.RoleAdmin, "secrets.write", "secrets")},
		{del, "/central/secrets/", auditedRow(config.RoleAdmin, "secrets.delete", "secrets")},
		{get, "/auth/me", readRow(0, "auth.me")},
		{get, "/auth/login", handler("auth.login")},
		{get, "/auth/callback", handler("auth.callback")},
		{post, "/auth/logout", handler("auth.logout")},
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
		role, _ := console.RoleFor(p.Groups) // zero (no role) when no group matches
		row, listed := table[routeKey{r.Method, dashboard.RoutePath(r.URL.Path)}]
		if !listed {
			logDenied(logger, row, role, p, r)
			writeAuthzJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if role < row.MinRole {
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
