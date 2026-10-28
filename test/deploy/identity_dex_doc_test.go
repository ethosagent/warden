package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

const dexDocPath = "docs/identity-dex.md"

// fence is one fenced code block of a markdown document.
type fence struct {
	lang string   // first word of the info string (yaml, sh, text)
	tags []string // remaining words (warden-cp, warden-worker, run)
	body string
	line int // 1-based line of the opening fence
}

func (f fence) tagged(tag string) bool {
	for _, t := range f.tags {
		if t == tag {
			return true
		}
	}
	return false
}

// fences returns every fenced block of doc in order.
func fences(doc string) []fence {
	var out []fence
	var cur *fence
	var body []string
	for i, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "```") {
			if cur != nil {
				body = append(body, line)
			}
			continue
		}
		if cur == nil {
			words := strings.Fields(strings.TrimPrefix(trimmed, "```"))
			cur = &fence{line: i + 1}
			if len(words) > 0 {
				cur.lang, cur.tags = words[0], words[1:]
			}
			body = nil
			continue
		}
		cur.body = strings.Join(body, "\n") + "\n"
		out = append(out, *cur)
		cur = nil
	}
	return out
}

func readDexDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), dexDocPath))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// checkSnippets loads every warden-cp block with the strict console loader and
// every warden-worker block with the strict worker loader, and returns one
// message per failure. It reports a doc with no block of either kind.
func checkSnippets(t *testing.T, doc string) []string {
	t.Helper()
	dir := t.TempDir()
	var failures []string
	var cp, worker int
	for _, f := range fences(doc) {
		var load func(path string) error
		switch {
		case f.tagged("warden-cp"):
			cp++
			load = func(p string) error { _, err := config.LoadConsole(p); return err }
		case f.tagged("warden-worker"):
			worker++
			load = func(p string) error { _, err := config.NewLocalYAMLProvider(p); return err }
		default:
			continue
		}
		path := filepath.Join(dir, "snippet.yaml")
		if err := os.WriteFile(path, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := load(path); err != nil {
			failures = append(failures, "block at line "+strconv.Itoa(f.line)+": "+err.Error())
		}
	}
	if cp == 0 || worker == 0 {
		failures = append(failures, "the doc needs at least one warden-cp and one warden-worker block (found "+strconv.Itoa(cp)+" and "+strconv.Itoa(worker)+")")
	}
	return failures
}

// TestIdentityDexDocSnippets parses every config snippet in docs/identity-dex.md
// under the strict loaders, so a renamed or removed key fails here.
func TestIdentityDexDocSnippets(t *testing.T) {
	doc := readDexDoc(t)
	for _, msg := range checkSnippets(t, doc) {
		t.Error(msg)
	}

	// Red-first guard: the check must notice a key renamed in the doc.
	for _, c := range []struct{ from, to string }{
		{"allowedAZP:", "allowedAzp:"},
		{"internalIssuerURL:", "internalIssuerUrl:"},
		{"clientSecretEnv:", "clientSecretEnvVar:"},
		{"defaultMode:", "defaultmode:"},
	} {
		if !strings.Contains(doc, c.from) {
			t.Errorf("doc no longer contains %q, so the rename guard proves nothing; update this test", c.from)
			continue
		}
		if len(checkSnippets(t, strings.ReplaceAll(doc, c.from, c.to))) == 0 {
			t.Errorf("renaming %s to %s in the doc was not caught", c.from, c.to)
		}
	}
}

// TestIdentityDexDocHygiene holds the doc to the claims the ticket makes:
// real limits, no secrets or tokens, no foreign products, the old insecure
// issuer flag gone, and every link the contract and the roadmap expect.
func TestIdentityDexDocHygiene(t *testing.T) {
	doc := readDexDoc(t)

	for _, want := range []string{
		"8 KiB", "64 KiB", "16 KiB", "malformed_connect", "headers_too_large",
		"internalIssuerURL", "http://localhost:5556/dex", "id_token_hint",
		"v2.41.1", "password grant", "connector", "federated:id",
		"identity-contract.md", "no /etc/hosts edit",
	} {
		if !strings.Contains(strings.ToLower(doc), strings.ToLower(want)) {
			t.Errorf("doc is missing %q", want)
		}
	}
	for name, re := range map[string]*regexp.Regexp{
		"a stale limit":           regexp.MustCompile(`32 KiB|100 lines`),
		"a raw JWT":               regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}`),
		"a foreign product":       regexp.MustCompile(`(?i)keycloak|okta|auth0|azure ad|entra|authentik|zitadel|onelogin|ping ?identity|cognito`),
		"the removed issuer flag": regexp.MustCompile(`(?i)allowInsecure` + `Issuer`),
	} {
		if loc := re.FindStringIndex(doc); loc != nil {
			t.Errorf("doc contains %s: %q", name, doc[loc[0]:loc[1]])
		}
	}
	for i, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, "/etc/hosts") && !strings.Contains(line, "no /etc/hosts") {
			t.Errorf("line %d mentions /etc/hosts other than as \"no /etc/hosts edit\"", i+1)
		}
	}
	if !regexp.MustCompile(`(?i)issuer.*(permanent|never change)`).MatchString(doc) {
		t.Error("doc does not say the issuer is permanent")
	}
	if !regexp.MustCompile(`(?i)logout.*(Warden session|local)`).MatchString(doc) {
		t.Error("doc does not say logout is local")
	}
}

// TestIdentityDexDocLinked checks the doc is reachable from the pages that
// should point at it, and that it links the identity contract back (the
// contract's own acceptance greps these three files).
func TestIdentityDexDocLinked(t *testing.T) {
	root := repoRoot(t)
	for _, p := range []string{"README.md", "docs/control-plane.md", "docs/setup-guide.md", "deploy/compose/dex/README.md", "docs/identity-contract.md"} {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "identity-dex.md") {
			t.Errorf("%s does not link identity-dex.md", p)
		}
	}
	for _, p := range []string{"README.md", "docs/recipes/README.md", dexDocPath} {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "identity-contract.md") {
			t.Errorf("%s does not link identity-contract.md", p)
		}
	}
}
