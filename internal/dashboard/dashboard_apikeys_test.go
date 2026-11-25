package dashboard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

type fakeAPIKeys struct{ st APIKeySettings }

func (f fakeAPIKeys) APIKeySettings() APIKeySettings { return f.st }

func apiKeysBlock(t *testing.T, html string) string {
	t.Helper()
	a, b := strings.Index(html, "/* apikeys:begin */"), strings.Index(html, "/* apikeys:end */")
	if a < 0 || b < a {
		t.Fatal("index.html has no apikeys:begin/apikeys:end script block")
	}
	return html[a:b]
}

// TestAPIKeysTab: the bootstrap flag (apiKeys in /dashboard/api/setup) exists
// only with a source, carries the scope list, and the page script renders every
// value as text and never persists the plaintext.
func TestAPIKeysTab(t *testing.T) {
	// Hidden without a source.
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	rr := doGet(t, srv.Handler(), "/dashboard/api/setup")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["apiKeys"]; ok {
		t.Errorf("setup carries apiKeys without a source: %s", rr.Body.String())
	}
	if getSetup(t, srv).APIKeys != nil {
		t.Error("APIKeys set without a source")
	}

	// Enabled with one.
	srv.SetAPIKeys(fakeAPIKeys{APIKeySettings{
		Scopes:     []APIKeyScope{{Name: "policy:read", MinRole: "viewer"}, {Name: "workers:admin", MinRole: "admin"}},
		DefaultTTL: 3600, MaxTTL: 7200,
	}})
	got := getSetup(t, srv).APIKeys
	if got == nil || len(got.Scopes) != 2 || got.Scopes[1].MinRole != "admin" || got.DefaultTTL != 3600 || got.MaxTTL != 7200 {
		t.Fatalf("apiKeys = %+v", got)
	}
	// A source with no scopes still serializes a list, never null.
	srv.SetAPIKeys(fakeAPIKeys{})
	if body := doGet(t, srv.Handler(), "/dashboard/api/setup").Body.String(); !strings.Contains(body, `"scopes":[]`) {
		t.Errorf("empty scope list not []: %s", body)
	}
	srv.SetAPIKeys(nil)
	if getSetup(t, srv).APIKeys != nil {
		t.Error("SetAPIKeys(nil) did not hide the tab")
	}

	html := servedIndex(t)
	for _, want := range []string{
		`id="apiKeysNav" style="display:none"`,
		`id="page-apikeys"`,
		`id="ak-list"`,
		`akn.style.display=(s.apiKeys&&typeof s.apiKeys==='object')?'':'none'`,
		`case 'apikeys':     loadAPIKeys(); break;`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	js := apiKeysBlock(t, html)
	for _, want := range []string{
		`api('GET','/dashboard/api/api-keys')`,
		`api('POST','/dashboard/api/api-keys'`,
		`api('DELETE','/dashboard/api/api-keys/'+encodeURIComponent(k.id))`,
		`api('DELETE','/dashboard/api/api-keys?owner_sub='+encodeURIComponent(k.ownerSub))`,
		`filter(s=>roleAllows(s.minRole))`,
		`ak.admin=roleAllows('admin')`,
		`const AK_WARN_MS=7*24*3600*1000`,
		`document.getElementById('ak-dialog'); if(d) d.remove()`,
		`e.textContent=String(text)`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("api keys script lacks %q", want)
		}
	}
	// Escaping: values are text, never markup. The plaintext is never stored.
	for _, bad := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "fetch(", "localStorage", "sessionStorage", "console.log", "console.error", "console.info", "console.warn", "console.debug"} {
		if strings.Contains(js, bad) {
			t.Errorf("api keys script uses %q", bad)
		}
	}
}

// TestAPIKeysScriptEscapesName pins that a hostile key name reaches the DOM
// only through textContent (akEl), the one helper every cell goes through.
func TestAPIKeysScriptEscapesName(t *testing.T) {
	js := apiKeysBlock(t, servedIndex(t))
	if !strings.Contains(js, `c0.appendChild(akEl('b',k.name))`) {
		t.Error("the name cell is not built with akEl")
	}
	if strings.Contains(js, "<img") {
		t.Error("script contains literal markup")
	}
}

// TestAPIKeysPlaintextFlow pins where the plaintext may go: it is read from the
// 201 body once, handed to akShowSecret, and never assigned into page state.
func TestAPIKeysPlaintextFlow(t *testing.T) {
	js := apiKeysBlock(t, servedIndex(t))
	if n := strings.Count(js, "b.key"); n != 2 { // typeof check + the call
		t.Errorf("b.key occurs %d times, want 2 (type check and akShowSecret call)", n)
	}
	if n := strings.Count(js, "akShowSecret("); n != 2 { // definition + one call
		t.Errorf("akShowSecret occurs %d times, want 2", n)
	}
	a := strings.Index(js, "function akShowSecret(")
	b := strings.Index(js, "(function(){")
	if a < 0 || b < a {
		t.Fatal("cannot locate akShowSecret")
	}
	outside := js[:a] + js[b:]
	if strings.Contains(outside, "secret") {
		t.Error("the secret identifier is used outside akShowSecret")
	}
	for _, line := range strings.Split(js, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "ak.") && strings.Contains(l, "=") && (strings.Contains(l, "key)") || strings.Contains(l, ".key;") || strings.Contains(l, "secret")) && !strings.Contains(l, "ak.rows=d") {
			t.Errorf("possible page-state store of the key: %s", line)
		}
	}
}
