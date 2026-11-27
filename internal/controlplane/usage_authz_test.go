package controlplane

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

const usageUsersPath = "/dashboard/api/usage/users"

// The per-user usage route needs a viewer: a viewer session reads it, no
// session gets 401 JSON, and a wak_ key reads it only with traffic:read
// (W-P3-PUL-05).
func TestAuthz_UserUsage(t *testing.T) {
	e := newAuthzEnv(t)
	rec := e.do(e.session(t, groupViewer), http.MethodGet, usageUsersPath, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"users":[]`) {
		t.Errorf("viewer = %d %s, want 200 with an empty users list", rec.Code, rec.Body.String())
	}
	rec = e.do(e.session(t, groupViewer), http.MethodGet, usageUsersPath+"?window=1y", "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_window") {
		t.Errorf("viewer bad window = %d %s, want 400 invalid_window", rec.Code, rec.Body.String())
	}
	rec = e.do("", http.MethodGet, usageUsersPath, "")
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("no session = %d %q %s, want 401 JSON", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	row, ok := authzTable()[routeKey{Method: http.MethodGet, Path: usageUsersPath}]
	if !ok || row.MinRole != config.RoleViewer || row.Scope != scopeTrafficRead {
		t.Errorf("authz row = %+v (found %v), want viewer + traffic:read", row, ok)
	}

	k := newKeyEnv(t, keyEnvOpts{})
	tok, _ := k.mint("alice", groupViewer, "traffic:read")
	wantStatus(t, k.do(tok, http.MethodGet, usageUsersPath, ""), http.StatusOK, "GET usage/users with traffic:read")
	other, _ := k.mint("alice", groupViewer, "policy:read")
	rec = k.do(other, http.MethodGet, usageUsersPath, "")
	wantStatus(t, rec, http.StatusForbidden, "GET usage/users with policy:read only")
	if !strings.Contains(rec.Body.String(), `"insufficient_scope"`) || !strings.Contains(rec.Body.String(), `"need":"traffic:read"`) {
		t.Errorf("body = %s, want insufficient_scope need traffic:read", rec.Body.String())
	}
}

// FlagNoUserLimits flags workers lacking userlimits/v1 only while the served
// policy has user limits.
func TestFlagNoUserLimits(t *testing.T) {
	mk := func() []dashboard.WorkerView {
		return []dashboard.WorkerView{
			{ProxyID: "legacy"},
			{ProxyID: "new", Caps: []string{config.CapUserLimitsV1}},
		}
	}
	off := mk()
	FlagNoUserLimits(off, false)
	if off[0].NoUserLimits || off[1].NoUserLimits {
		t.Errorf("flagged with no limits served: %+v", off)
	}
	on := mk()
	FlagNoUserLimits(on, true)
	if !on[0].NoUserLimits || on[1].NoUserLimits {
		t.Errorf("served limits: legacy must be flagged, new must not: %+v", on)
	}
}
