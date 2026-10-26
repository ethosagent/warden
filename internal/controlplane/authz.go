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

// authzRow is what the console requires for one route in oidc mode. It is a
// struct so later tickets (admin audit, API-key scopes, per-field settings) can
// add fields without reshaping the table.
type authzRow struct {
	MinRole config.Role
	Action  string
}

// authzTable is the deny-by-default authorization table for the dashboard
// routes the control plane serves: a {method, path} with no row is refused for
// every role, GET included. Every dashboard.Routes() entry must have a row
// (TestAuthzRouteCoverage) and the row's Action must equal the route's.
//
// Settings writes are admin-only until W-P1-SSO-10 authorizes them per field;
// query/generate is editor-only until that ticket adds its rate limit.
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
		{get, "/dashboard/", authzRow{viewer, "ui.read"}},
		{get, "/dashboard/api/traffic", authzRow{viewer, "traffic.read"}},
		{get, "/dashboard/api/policy", authzRow{viewer, "policy.read"}},
		{post, "/dashboard/api/policy", authzRow{editor, "policy.write"}},
		{put, "/dashboard/api/policy", authzRow{editor, "policy.write"}},
		{get, "/dashboard/api/settings", authzRow{viewer, "settings.read"}},
		{post, "/dashboard/api/settings", authzRow{admin, "settings.write"}},
		{put, "/dashboard/api/settings", authzRow{admin, "settings.write"}},
		{get, "/dashboard/api/secrets", authzRow{viewer, "secrets.read"}},
		{get, "/dashboard/api/endpoints", authzRow{viewer, "endpoints.read"}},
		{get, "/dashboard/api/analytics", authzRow{viewer, "analytics.read"}},
		{get, "/dashboard/api/mcp", authzRow{viewer, "mcp.read"}},
		{get, "/dashboard/api/workers", authzRow{viewer, "workers.read"}},
		{get, "/dashboard/api/query/schema", authzRow{viewer, "query.schema"}},
		{post, "/dashboard/api/query", authzRow{viewer, "query.run"}},
		{post, "/dashboard/api/query/generate", authzRow{editor, "query.generate"}},
		{get, "/dashboard/api/secretstore", authzRow{viewer, "secretstore.read"}},
		{post, "/dashboard/api/secretstore", authzRow{admin, "secretstore.write"}},
		{del, "/dashboard/api/secretstore", authzRow{admin, "secretstore.delete"}},
		{get, "/dashboard/api/alerts", authzRow{viewer, "alerts.read"}},
		{get, "/dashboard/api/integrations", authzRow{viewer, "integrations.read"}},
		{post, "/dashboard/api/integrations", authzRow{admin, "integrations.write"}},
		{del, "/dashboard/api/integrations", authzRow{admin, "integrations.delete"}},
		{get, "/dashboard/api/detection", authzRow{viewer, "detection.read"}},
		{post, "/dashboard/api/detection", authzRow{editor, "detection.write"}},
		{put, "/dashboard/api/detection", authzRow{editor, "detection.write"}},
		{get, "/dashboard/api/llmproviders", authzRow{viewer, "llmproviders.read"}},
		{post, "/dashboard/api/llmproviders", authzRow{admin, "llmproviders.write"}},
		{put, "/dashboard/api/llmproviders", authzRow{admin, "llmproviders.write"}},
		{get, "/dashboard/api/audit", authzRow{viewer, "audit.read"}},
		{post, "/dashboard/api/audit/verify", authzRow{viewer, "audit.verify"}},
		{get, "/dashboard/api/setup", authzRow{viewer, "setup.read"}},
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
		row, listed := table[routeKey{r.Method, r.URL.Path}]
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
