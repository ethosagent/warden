package dashboard

import (
	"regexp"
	"strings"
	"testing"
)

// apiRegion returns the source between the api:begin and api:end markers: the
// one place allowed to call fetch().
func apiRegion(t *testing.T, html string) (string, int, int) {
	t.Helper()
	a, b := strings.Index(html, "/* api:begin */"), strings.Index(html, "/* api:end */")
	if a < 0 || b < a {
		t.Fatalf("api:begin/api:end markers not found (begin@%d end@%d)", a, b)
	}
	return html[a:b], a, b
}

// funcBody returns the source of the top-level JS function starting at decl,
// up to its closing "\n}\n".
func funcBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("%q not found", decl)
	}
	body := src[i:]
	if e := strings.Index(body, "\n}\n"); e > 0 {
		body = body[:e]
	}
	return body
}

// TestIndexAPIWrapper pins the dashboard's single fetch wrapper: every request
// goes through api(method, url, body); it learns the mode from /auth/me, adds
// X-Warden-CSRF only from a successful /auth/me, sends a 401 in oidc mode to
// /auth/login?next=, and takes the bearer prompt only when /auth/me is 404.
func TestIndexAPIWrapper(t *testing.T) {
	html := servedIndex(t)
	region, start, end := apiRegion(t, html)

	if !strings.Contains(region, "async function api(method,url,body,hdrs){") {
		t.Fatal("api(method,url,body) wrapper not found")
	}
	// No fetch( outside the wrapper region.
	for _, loc := range regexp.MustCompile(`\bfetch\(`).FindAllStringIndex(html, -1) {
		if loc[0] < start || loc[0] > end {
			t.Errorf("fetch( outside the api wrapper: %.100s", html[loc[0]:])
		}
	}
	// authFetch (the bearer path) is called from api() only.
	if n := strings.Count(html, "authFetch("); n != 2 { // its declaration + one call
		t.Errorf("authFetch( appears %d times, want the declaration and one call in api()", n)
	}

	// Mode discovery: /auth/me decides. 200 -> oidc with its csrf; 404 -> none;
	// 401 -> login redirect.
	initBody := funcBody(t, region, "function authInit(){")
	if !strings.Contains(initBody, "fetch('/auth/me'") {
		t.Error("authInit must fetch /auth/me")
	}
	ok, setCSRF := strings.Index(initBody, "if(r.ok){"), strings.Index(initBody, "csrfToken=me.csrf")
	if ok < 0 || setCSRF < ok {
		t.Error("the CSRF token must be taken only from a successful /auth/me")
	}
	if strings.Count(region, "csrfToken=") != 2 { // let csrfToken='' + the r.ok assignment
		t.Errorf("csrfToken assigned %d times, want the declaration and the r.ok branch only", strings.Count(region, "csrfToken="))
	}
	if strings.Count(html, "authMode='none'") != 1 || !regexp.MustCompile(`if\(r\.status===404\)\{\s*authMode='none'`).MatchString(initBody) {
		t.Error("none mode (the bearer path) must be chosen only on a 404 from /auth/me")
	}
	if !regexp.MustCompile(`if\(r\.status===401\)\{\s*authMode='oidc';\s*loginRedirect\(\)`).MatchString(initBody) {
		t.Error("a 401 from /auth/me must redirect to login")
	}

	apiBody := funcBody(t, region, "async function api(method,url,body,hdrs){")
	if !strings.Contains(apiBody, "await authInit()") {
		t.Error("api() must wait for /auth/me before sending")
	}
	if !regexp.MustCompile(`if\(authMode==='none'\) return authFetch\(`).MatchString(apiBody) {
		t.Error("api() must hand none mode (and only none mode) to the bearer path")
	}
	if !regexp.MustCompile(`if\(csrfToken&&[^)]*\) h\.set\('X-Warden-CSRF',csrfToken\)`).MatchString(apiBody) {
		t.Error("api() must add X-Warden-CSRF only when /auth/me gave a token")
	}
	if strings.Count(html, "'X-Warden-CSRF'") != 1 {
		t.Error("X-Warden-CSRF must be set in exactly one place (api())")
	}
	if !regexp.MustCompile(`if\(r\.status===401&&authMode==='oidc'\) loginRedirect\(\)`).MatchString(apiBody) {
		t.Error("api() must redirect a 401 to login in oidc mode")
	}
	if strings.Contains(apiBody, "Authorization") {
		t.Error("api() must not send the bearer itself; only the none-mode path does")
	}
	if !strings.Contains(region, "location.assign('/auth/login?next='+encodeURIComponent(") {
		t.Error("loginRedirect must go to /auth/login?next=<current page>")
	}
}

// TestIndexNoneModeBearerPrompt: in console.auth none the page still prompts
// for the admin token on a 401 (send, prompt, retry once), through the path
// api() takes when /auth/me is 404.
func TestIndexNoneModeBearerPrompt(t *testing.T) {
	html := servedIndex(t)
	region, _, _ := apiRegion(t, html)
	body := funcBody(t, region, "async function authFetch(")
	send, prompt, retry := strings.Index(body, "await send("), strings.Index(body, "window.prompt('Admin token"), strings.LastIndex(body, "await send(")
	if send < 0 || prompt < send || retry < prompt {
		t.Fatalf("bearer path must send, prompt for the admin token on 401, then retry (send@%d prompt@%d retry@%d)", send, prompt, retry)
	}
	if st := strings.Index(body, "r.status!==401"); st < 0 || st > prompt {
		t.Error("the prompt must be reached only on a 401")
	}
	if !strings.Contains(body, "h.set('Authorization','Bearer '+tok)") {
		t.Error("bearer path must send the token in Authorization")
	}
}
