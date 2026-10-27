package dashboard

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// tagAt returns the source of the HTML tag (or JS string fragment of one) that
// contains the byte at i: from the last "<" before i to the next ">" after it.
func tagAt(html string, i int) string {
	a := strings.LastIndex(html[:i], "<")
	b := strings.Index(html[i:], ">")
	if a < 0 || b < 0 {
		return ""
	}
	return html[a : i+b+1]
}

var minRoleAttr = regexp.MustCompile(`data-min-role="([^"]*)"`)

// TestIndexRoleAware pins the role-aware dashboard (W-P1-SSO-11): every write
// control of the policy, settings, integrations, llmproviders and secretstore
// areas carries data-min-role with the role the server requires (authzTable
// for the route, config.SettingsFieldMinRole for the settings field it
// changes); the hiding is pure CSS keyed on a data-role attribute that is set
// only from a successful /auth/me; and the signed-in user and logout button
// are shown only then. Hiding is cosmetic: the server stays the only
// enforcement point.
func TestIndexRoleAware(t *testing.T) {
	html := servedIndex(t)
	editor, admin := config.RoleEditor.String(), config.RoleAdmin.String()
	settings := func(field string) string { return config.SettingsFieldMinRole(field).String() }

	// marker -> the role its control needs. Each marker must occur at least
	// once, and every tag containing it must carry exactly that data-min-role.
	controls := []struct{ marker, role, why string }{
		// policy: PUT /dashboard/api/policy is editor.
		{`id="allowAddBtn"`, editor, "policy.write"},
		{`id="denyAddBtn"`, editor, "policy.write"},
		{`pol-rm`, editor, "policy.write"},
		// settings: the route is editor; each control changes one field.
		{`id="dlpAddRuleBtn"`, settings("dlp"), "settings dlp"},
		{`id="dlpSaveBtn"`, settings("dlp"), "settings dlp"},
		{`dlp-rm`, settings("dlp"), "settings dlp"},
		{`id="judgeSaveBtn"`, settings("judge"), "settings judge"},
		{`id="mcpSaveBtn"`, settings("mcp"), "settings mcp"},
		{`addMcpTool(`, settings("mcp"), "settings mcp"},
		{`mcp-tool-rm`, settings("mcp"), "settings mcp"},
		{`id="rt-save"`, settings("logging"), "settings logging/compliance/cacheTTLSeconds"},
		{`id="rt-otel-switch"`, settings("observability"), "settings observability"},
		{`id="sb-save"`, settings("secrets"), "settings secrets"},
		{`id="exploreProvider"`, settings("explore"), "settings explore"},
		// integrations: POST/DELETE are admin.
		{`id="integrations-addbtn"`, admin, "integrations.write"},
		{`id="intg-save"`, admin, "integrations.write"},
		{`deleteIntegration(`, admin, "integrations.delete"},
		// llmproviders: PUT is admin.
		{`id="llmp-addbtn"`, admin, "llmproviders.write"},
		{`id="llmp-savebtn"`, admin, "llmproviders.write"},
		{`removeLLMProvider(`, admin, "llmproviders.write"},
		// secretstore: POST/DELETE are admin.
		{`id="secretAddBtn"`, admin, "secretstore.write"},
		{`onclick="saveSecret()"`, admin, "secretstore.write"},
		{`sec-rotate`, admin, "secretstore.write"},
		{`sec-del`, admin, "secretstore.delete"},
		// other editor-only writes.
		{`id="detectionSaveBtn"`, editor, "detection.write"},
		{`id="nlGenBtn"`, editor, "query.generate"},
	}
	for _, c := range controls {
		locs := regexp.MustCompile(regexp.QuoteMeta(c.marker)).FindAllStringIndex(html, -1)
		if len(locs) == 0 {
			t.Errorf("%s (%s): marker not found", c.marker, c.why)
			continue
		}
		for _, loc := range locs {
			tag := tagAt(html, loc[0])
			if !strings.HasPrefix(tag, "<button") && !strings.HasPrefix(tag, "<select") && !strings.HasPrefix(tag, "<label") {
				continue // a CSS rule or a JS reference to the id, not the control itself
			}
			m := minRoleAttr.FindStringSubmatch(tag)
			if m == nil || m[1] != c.role {
				t.Errorf("%s (%s): want data-min-role=%q on %.160s", c.marker, c.why, c.role, tag)
			}
		}
	}

	// Every static button on the write pages is gated, except the ones that
	// only navigate or reset local state.
	notWrites := []string{`data-sub=`, `onclick="toggleSecretForm()">Cancel`, `id="rt-reset"`}
	for _, page := range []string{"page-secrets", "page-guardrails", "page-mcp", "page-settings"} {
		start := strings.Index(html, `id="`+page+`"`)
		end := strings.Index(html[start:], "</section>")
		if start < 0 || end < 0 {
			t.Fatalf("section %s not found", page)
		}
		sec := html[start : start+end]
	buttons:
		for _, loc := range regexp.MustCompile(`<button\b`).FindAllStringIndex(sec, -1) {
			tag := sec[loc[0] : loc[0]+strings.Index(sec[loc[0]:], ">")+1]
			for _, ok := range notWrites {
				if strings.Contains(sec[loc[0]:min(len(sec), loc[0]+len(tag)+10)], ok) {
					continue buttons
				}
			}
			if !minRoleAttr.MatchString(tag) {
				t.Errorf("%s: write button without data-min-role: %.160s", page, tag)
			}
		}
	}

	// Only real role names: an unknown value would never be hidden.
	for _, m := range minRoleAttr.FindAllStringSubmatch(html, -1) {
		if m[1] != config.RoleViewer.String() && m[1] != editor && m[1] != admin {
			t.Errorf("data-min-role=%q is not viewer, editor or admin", m[1])
		}
	}

	// The CSS hides by rank: none hides everything gated, viewer hides editor
	// and admin, editor hides admin. Nothing is hidden without data-role.
	for _, sel := range []string{
		`html[data-role="none"] [data-min-role]`,
		`html[data-role="viewer"] [data-min-role="editor"]`,
		`html[data-role="viewer"] [data-min-role="admin"]`,
		`html[data-role="editor"] [data-min-role="admin"]`,
	} {
		if !strings.Contains(html, sel) {
			t.Errorf("CSS rule %q missing", sel)
		}
	}
	if !regexp.MustCompile(`\[data-min-role="admin"\]\s*\{\s*display:none\s*!important`).MatchString(html) {
		t.Error("the role rules must hide with display:none !important (beats the inline display the tabs set)")
	}

	// data-role is set in one place, applyRole, and applyRole runs only from
	// the successful /auth/me branch (oidc mode with a CSRF token).
	if n := strings.Count(html, "setAttribute('data-role'"); n != 1 {
		t.Errorf("setAttribute('data-role' appears %d times, want 1 (in applyRole)", n)
	}
	roleFn := funcBody(t, html, "function applyRole(")
	if !strings.Contains(roleFn, "setAttribute('data-role'") {
		t.Error("applyRole must set data-role")
	}
	if !strings.Contains(roleFn, "roleOf(m)") || !strings.Contains(funcBody(t, html, "function roleOf("), "ROLE_RANK") {
		t.Error("applyRole must map an unknown role to none (fail closed) via ROLE_RANK")
	}
	if n := strings.Count(html, "applyRole("); n != 2 { // declaration + one call
		t.Errorf("applyRole( appears %d times, want the declaration and one call in authInit", n)
	}
	region, _, _ := apiRegion(t, html)
	initBody := funcBody(t, region, "function authInit(){")
	if !regexp.MustCompile(`if\(me&&me\.csrf\)\{\s*authMode='oidc';\s*csrfToken=me\.csrf;\s*applyRole\(me\);`).MatchString(initBody) {
		t.Error("applyRole(me) must run only when /auth/me succeeded with a CSRF token")
	}

	// Signed-in user and logout: hidden until applyRole shows them; logout
	// goes through api() (CSRF header).
	if !regexp.MustCompile(`<div class="whoami" id="whoami" style="display:none">`).MatchString(html) {
		t.Error("the signed-in user chrome must be hidden by default (none mode shows nothing)")
	}
	if !strings.Contains(roleFn, "getElementById('whoami')") {
		t.Error("applyRole must show the signed-in user")
	}
	if !strings.Contains(html, `id="logoutBtn"`) {
		t.Error("logout button missing")
	}
	logout := funcBody(t, html, "async function logout(")
	if !strings.Contains(logout, "api('POST','/auth/logout')") {
		t.Error("logout must POST /auth/logout through api()")
	}
	if strings.Contains(roleFn, "innerHTML") || strings.Contains(logout, "innerHTML") {
		t.Error("the user's email and role come from the IdP: render them with textContent, never innerHTML")
	}

	// The topbar mode toggle writes settings: below editor it is a static badge.
	if !strings.Contains(funcBody(t, html, "async function onModeToggleClick("), "!roleAllows('editor')") {
		t.Error("onModeToggleClick must not write for a role below editor")
	}
}
