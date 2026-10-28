package scenarios

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Console denial for blocked principals (W-P1-BLOCK-07): blocking an admin
// ends their console session, refuses their next sign-in with 403 and one
// auth.blocked_login row, and break-glass still opens the console while every
// admin is blocked.

// blockedPrincipalDenied: ben blocks ada over the admin API; ada's session is
// revoked and her next sign-in is refused with no cookie; an offline write that
// blocks ben (the CLI path) ends his session within the watch tick; break-glass
// still signs in; the denial is one blocked_login row.
func blockedPrincipalDenied(t *testing.T, h *harness.H) {
	const path = "/dashboard/api/blocked-users"
	ada, _ := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	ben, bcsrf := consoleLogin(t, h, fakes.Valid("ben", "ben@example.com", harness.ConsoleAdminGroup))
	if resp, _ := consoleDo(t, ada, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("ada /auth/me before the block = %d, want 200", resp.StatusCode)
	}

	if resp, body := blockAPIDo(t, ben, bcsrf, http.MethodPost, path, `{"email":"Ada@example.com"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("ben blocks ada = %d %s, want 201", resp.StatusCode, body)
	}
	if resp, _ := consoleDo(t, ada, http.MethodGet, "/auth/me", nil); resp.StatusCode == http.StatusOK {
		t.Fatal("a blocked admin's session still works")
	}
	if rows := h.ConsoleSessions(); len(rows) != 1 || rows[0].Sub != "ben" {
		t.Fatalf("sessions table = %+v, want only ben's", rows)
	}

	retry, resp := consoleCallback(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked callback = %d, want 403", resp.StatusCode)
	}
	if cookieIn(resp, consoleSessionCookie) != nil {
		t.Fatal("a blocked principal got a session cookie")
	}
	if resp, _ := consoleDo(t, retry, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/auth/me after the refused login = %d, want 401", resp.StatusCode)
	}

	// The offline CLI's write: another handle on the state database.
	ctx := context.Background()
	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := controlplane.NewBlockStore(db, controlplane.BlockStoreOptions{}).Add(ctx, controlplane.BlockEntry{Sub: "ben"}, "cli:harness"); err != nil {
		t.Fatalf("BlockStore.Add: %v", err)
	}
	h.Eventually("ben's session is refused after the offline block", func() bool {
		resp, _ := consoleDo(t, ben, http.MethodGet, "/auth/me", nil)
		return resp.StatusCode != http.StatusOK
	})

	bg := h.ConsoleBrowser()
	resp, body := breakGlassPost(t, bg, harness.BreakGlassUsername, harness.BreakGlassPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("break-glass with every admin blocked = %d %s, want 200", resp.StatusCode, body)
	}
	if resp, body := consoleDo(t, bg, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"breakglass"`) {
		t.Fatalf("break-glass /auth/me = %d %s, want 200", resp.StatusCode, body)
	}

	var blocked int
	for _, r := range h.AdminAuditRows() {
		if r.Action != "auth.blocked_login" {
			continue
		}
		blocked++
		if r.Sub != "ada" || r.Outcome != adminaudit.OutcomeDenied || r.AuthMethod != adminaudit.AuthMethodOIDC ||
			r.HTTPStatus != http.StatusForbidden || r.Target != "session" {
			t.Errorf("blocked_login row = %+v", r)
		}
	}
	if blocked != 1 {
		t.Errorf("auth.blocked_login rows = %d, want 1: %+v", blocked, h.AdminAuditRows())
	}
}
