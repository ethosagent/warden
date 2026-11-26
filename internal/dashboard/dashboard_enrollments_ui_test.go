package dashboard

import (
	"regexp"
	"strings"
	"testing"
)

// String-level tests on the served HTML, since the repo has no browser harness
// (like dashboard_workertokens_test.go).

func enrollJS(t *testing.T, html string) (load, create, revoke, show string) {
	t.Helper()
	js := html[strings.Index(html, "<script>"):]
	return funcBody(t, js, "async function loadEnrollments(){"),
		funcBody(t, js, "async function createEnrollment(){"),
		funcBody(t, js, "async function revokeEnrollment(id,name){"),
		funcBody(t, js, "function showEnrollToken(tok){")
}

func TestWorkerEnrollmentsPanelServedHTML(t *testing.T) {
	html := servedIndex(t)
	start := strings.Index(html, `id="enr-card"`)
	if start < 0 {
		t.Fatal("enrollment panel (id=enr-card) not found")
	}
	tokens := strings.Index(html, `id="wtok-card"`)
	if tokens < 0 || start < tokens || start > tokens+4000 {
		t.Error("the enrollment panel is not next to the worker tokens panel")
	}
	fleet := strings.Index(html, `id="page-fleet"`)
	end := strings.Index(html[fleet:], "</section>")
	if start < fleet || start > fleet+end {
		t.Fatal("panel is not inside the fleet page")
	}

	load, create, revoke, show := enrollJS(t, html)
	for what, want := range map[string]string{
		"list":   "api('GET','/dashboard/api/worker-enrollments')",
		"create": "api('POST','/dashboard/api/worker-enrollments'",
		"revoke": "api('DELETE','/dashboard/api/worker-enrollments/'+encodeURIComponent(id))",
	} {
		src := map[string]string{"list": load, "create": create, "revoke": revoke}[what]
		if !strings.Contains(src, want) {
			t.Errorf("%s must go through api(): want %s", what, want)
		}
	}
	if !strings.Contains(revoke, "window.confirm(") {
		t.Error("revoke must confirm first")
	}
	all := load + create + revoke + show
	if strings.Contains(strings.ToLower(all), "csrf") || strings.Contains(all, "fetch(") {
		t.Error("the panel must not handle CSRF or call fetch itself; api() sets X-Warden-CSRF")
	}
	// textContent only: nothing the server or the operator supplied becomes markup.
	js := html[strings.Index(html, "<script>"):]
	whole := funcBody(t, js, "function enEl(tag,text,cls){") + enrollStatus_(t, js) + all
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "localStorage", "sessionStorage"} {
		if strings.Contains(whole, bad) {
			t.Errorf("the enrollment panel uses %s", bad)
		}
	}
	// Admin only, and writes only for an oidc admin; none mode points to the CLI.
	if !strings.Contains(load, "authMode==='oidc'&&roleAllows('admin')") {
		t.Error("the panel must depend on an oidc admin")
	}
	if !strings.Contains(html, "warden control-plane enroll-token create") {
		t.Error("none-mode notice must point to `warden control-plane enroll-token create`")
	}
	for _, marker := range []string{`id="enr-new"`, `id="enr-create"`, `enr-revoke`} {
		for _, loc := range regexp.MustCompile(regexp.QuoteMeta(marker)).FindAllStringIndex(html, -1) {
			if tag := tagAt(html, loc[0]); strings.HasPrefix(tag, "<button") && !strings.Contains(tag, `data-min-role="admin"`) {
				t.Errorf("%s: button without data-min-role=\"admin\": %.160s", marker, tag)
			}
		}
	}
	if !strings.Contains(load, "b.setAttribute('data-min-role','admin')") {
		t.Error("the revoke button must carry data-min-role=admin")
	}
}

func enrollStatus_(t *testing.T, js string) string {
	t.Helper()
	return funcBody(t, js, "function enrollStatus(x){") + funcBody(t, js, "function enrollMsg(text){")
}

func TestWorkerEnrollmentsPanelShowOnce(t *testing.T) {
	html := servedIndex(t)
	i := strings.Index(html, `id="enrDialog"`)
	if i < 0 {
		t.Fatal("one-time token dialog (id=enrDialog) not found")
	}
	dlg := html[i : i+strings.Index(html[i:], "</dialog>")]
	if !strings.Contains(dlg, `id="enr-value"`) || !strings.Contains(dlg, `id="enr-copy"`) || !strings.Contains(dlg, "only once") {
		t.Error("dialog must hold the value, a copy button and the shown-once warning")
	}
	// The value element is empty in the served HTML: no token is ever rendered server-side.
	if m := regexp.MustCompile(`id="enr-value"[^>]*></code>`).FindString(dlg); m == "" {
		t.Error("enr-value must be empty in the served HTML")
	}
	js := html[strings.Index(html, "<script>"):]
	_, create, _, show := enrollJS(t, html)
	if !strings.Contains(show, "getElementById('enr-value').textContent=tok") {
		t.Error("showEnrollToken must set the value with textContent")
	}
	clear := funcBody(t, js, "function clearEnrollToken(){")
	if !strings.Contains(clear, "getElementById('enr-value').textContent=''") {
		t.Error("clearEnrollToken must empty the value")
	}
	if !strings.Contains(js, "dlg.addEventListener('close',clearEnrollToken)") {
		t.Error("the dialog's close event must clear the token")
	}
	// The token leaves the create response through one local, never a field.
	if !strings.Contains(create, "const tok=d&&d.token; d=null;") {
		t.Error("createEnrollment must drop the response object once it has the token")
	}
	if strings.Contains(create, "console.") || strings.Contains(create, "enrollMsg(tok") {
		t.Error("createEnrollment must not log or message the token")
	}
}
