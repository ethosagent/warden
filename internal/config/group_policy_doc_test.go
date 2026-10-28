package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/denyreason"
)

// Drift tests for docs/group-policy.md (W-P1-GPOL-13): the reasons the doc
// names must be the declared ones, the config example between its marker lines
// must load, and the entry points must link the doc.

const (
	groupPolicyDoc  = "group-policy.md"
	exampleStartTag = "# --- group-policy example ---"
	exampleEndTag   = "# --- end group-policy example ---"
	reasonsStartTag = "<!-- group-policy-reasons:start -->"
	reasonsEndTag   = "<!-- group-policy-reasons:end -->"
)

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

var reasonRow = regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\|")

// docReasons returns the reason ids in the first column of the doc's reasons
// table, which sits between the reasons marker comments.
func docReasons(t *testing.T) []string {
	t.Helper()
	doc := repoFile(t, "docs", groupPolicyDoc)
	start := strings.Index(doc, reasonsStartTag)
	end := strings.Index(doc, reasonsEndTag)
	if start < 0 || end < start {
		t.Fatalf("docs/%s has no %s ... %s block", groupPolicyDoc, reasonsStartTag, reasonsEndTag)
	}
	var out []string
	for _, m := range reasonRow.FindAllStringSubmatch(doc[start:end], -1) {
		out = append(out, m[1])
	}
	return out
}

func TestGroupPolicyDocReasons(t *testing.T) {
	want := []string{"identity_required", "group_not_allowed", "identity_groups_truncated"}
	got := docReasons(t)

	declared := map[string]bool{}
	for _, r := range denyreason.Declared() {
		declared[string(r)] = true
	}
	inDoc := map[string]bool{}
	for _, r := range got {
		inDoc[r] = true
		if !declared[r] {
			t.Errorf("doc reasons table lists %q, which is not in denyreason.Declared()", r)
		}
	}
	for _, r := range want {
		if !declared[r] {
			t.Errorf("%q is not in denyreason.Declared()", r)
		}
		if !inDoc[r] {
			t.Errorf("doc reasons table is missing %q", r)
		}
	}
	// A reason added later for identity or group denials must be documented too.
	for r := range declared {
		if (strings.HasPrefix(r, "identity_") || strings.HasPrefix(r, "group_")) && !inDoc[r] {
			t.Errorf("declared reason %q is about identity or groups but is not in the doc reasons table", r)
		}
	}
	if len(got) != len(inDoc) {
		t.Errorf("doc reasons table repeats a reason: %v", got)
	}
}

// uncomment strips one level of YAML comment from the example block.
func uncomment(block string) string {
	var b strings.Builder
	for _, l := range strings.Split(block, "\n") {
		l = strings.TrimRight(l, " ")
		switch {
		case l == "#":
			l = ""
		case strings.HasPrefix(l, "# "):
			l = l[2:]
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}

func TestExampleConfigGroupExample(t *testing.T) {
	cfg := repoFile(t, "configs", "config.example.yaml")
	start := strings.Index(cfg, exampleStartTag)
	end := strings.Index(cfg, exampleEndTag)
	if start < 0 || end < start {
		t.Fatalf("config.example.yaml has no %q ... %q block", exampleStartTag, exampleEndTag)
	}
	block := cfg[start+len(exampleStartTag) : end]
	prov, err := NewLocalYAMLProvider(writeTemp(t, uncomment(block)))
	if err != nil {
		t.Fatalf("uncommented example does not load: %v", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}

	var scoped, unscoped int
	for _, e := range pol.Allowlist {
		if len(e.Groups)+len(e.Users) > 0 {
			scoped++
		} else {
			unscoped++
		}
		for _, u := range e.Users {
			if strings.Contains(u, "@") && u != strings.ToLower(u) {
				t.Errorf("user %q was not normalized to lower case", u)
			}
		}
	}
	if scoped == 0 || unscoped == 0 {
		t.Errorf("example needs a scoped and an unscoped allow entry, got %d and %d", scoped, unscoped)
	}
	if pol.Identity.DefaultMode != IdentityModeAttribute {
		t.Errorf("identity.defaultMode = %q, want attribute (scoped rules need verified identity)", pol.Identity.DefaultMode)
	}
	var mcpScoped bool
	for _, tc := range pol.MCP.Tools.Constraints {
		if tc.AllowWhen != nil && len(tc.AllowWhen.Groups)+len(tc.AllowWhen.Users) > 0 {
			mcpScoped = true
		}
	}
	if !mcpScoped {
		t.Error("example has no MCP tool allowWhen with groups or users")
	}
	if w := LintScoped(pol); len(w) != 0 {
		t.Errorf("the example itself trips the shadow lint: %v", w)
	}
}

func TestGroupPolicyDocLinked(t *testing.T) {
	for _, f := range [][]string{{"docs", "architecture.md"}, {"README.md"}} {
		body := repoFile(t, f...)
		if !strings.Contains(body, "group-policy.md") {
			t.Errorf("%s does not link docs/group-policy.md", filepath.Join(f...))
		}
	}
	if !strings.Contains(repoFile(t, "docs", "architecture.md"), "](group-policy.md") {
		t.Error("docs/architecture.md must link the doc relative to docs/ (](group-policy.md...)")
	}
	if !strings.Contains(repoFile(t, "README.md"), "](docs/group-policy.md") {
		t.Error("README.md must link ](docs/group-policy.md...)")
	}
	cfg := repoFile(t, "configs", "config.example.yaml")
	if !strings.Contains(cfg, "docs/group-policy.md") {
		t.Error("config.example.yaml should point at docs/group-policy.md")
	}
}
