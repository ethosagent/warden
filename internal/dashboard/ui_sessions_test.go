package dashboard

import (
	"regexp"
	"strings"
	"testing"
)

// TestIndexSessionsPanel pins the admin Sessions panel (W-P1-SSO-08): the card
// and every control in it carry data-min-role="admin", it is hidden until
// loadSessions has seen an oidc admin from /auth/me, and both the list and the
// revoke go through api() (so the revoke carries X-Warden-CSRF). The server is
// the enforcement point; this only keeps the UI honest.
func TestIndexSessionsPanel(t *testing.T) {
	html := servedIndex(t)

	start := strings.Index(html, `id="sessions-card"`)
	if start < 0 {
		t.Fatal("Sessions panel (id=sessions-card) not found")
	}
	card := tagAt(html, start)
	if !strings.HasPrefix(card, "<div") || !strings.Contains(card, `data-min-role="admin"`) || !strings.Contains(card, "display:none") {
		t.Fatalf("sessions card must be a div with data-min-role=\"admin\", hidden by default: %s", card)
	}
	// The card must sit on the settings page.
	settings := strings.Index(html, `id="page-settings"`)
	if end := strings.Index(html[settings:], "</section>"); settings < 0 || start < settings || start > settings+end {
		t.Fatal("sessions card is not inside the settings page")
	}

	js := html[strings.Index(html, "<script>"):]
	load := funcBody(t, js, "async function loadSessions(){")
	revoke := funcBody(t, js, "async function revokeSessions(kind,value,what){")
	if !strings.Contains(load, "await authInit()") || !strings.Contains(load, "authMode!=='oidc'||!roleAllows('admin')") {
		t.Error("loadSessions must show the panel only to an oidc admin")
	}
	if !strings.Contains(load, "api('GET','/dashboard/api/sessions')") {
		t.Error("loadSessions must list through api('GET', ...)")
	}
	if !strings.Contains(revoke, "api('DELETE','/dashboard/api/sessions?'+kind+'='+encodeURIComponent(value))") {
		t.Error("revokeSessions must DELETE through api() with an encoded handle or sub")
	}
	if strings.Contains(strings.ToLower(load+revoke), "csrf") || strings.Contains(load+revoke, "fetch(") {
		t.Error("the panel must not handle CSRF or call fetch itself; api() does")
	}
	if !strings.Contains(funcBody(t, js, "async function loadSettings(){"), "loadSessions();") {
		t.Error("loadSettings must load the sessions panel")
	}

	// Every button the panel renders, static or from JS, is admin-gated.
	for _, marker := range []string{`id="sess-refresh"`, `sess-revoke"`, `sess-revoke-sub"`} {
		locs := regexp.MustCompile(regexp.QuoteMeta(marker)).FindAllStringIndex(html, -1)
		if len(locs) == 0 {
			t.Errorf("%s: not found", marker)
		}
		for _, loc := range locs {
			if tag := tagAt(html, loc[0]); strings.HasPrefix(tag, "<button") && !strings.Contains(tag, `data-min-role="admin"`) {
				t.Errorf("%s: button without data-min-role=\"admin\": %.160s", marker, tag)
			}
		}
	}
}
