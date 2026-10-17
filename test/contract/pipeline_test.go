// Package contract checks the repo contract the autonomous pipeline reads:
// .agents/pipeline.yaml must match docs/pipeline.schema.json, and it must not
// promise anything the repo does not hold.
package contract

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	contractFile = ".agents/pipeline.yaml"
	schemaFile   = "docs/pipeline.schema.json"
)

func repoPath(rel string) string { return filepath.Join("..", "..", rel) }

func readYAML(t *testing.T, rel string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(repoPath(rel))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return doc
}

func readSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(repoPath(schemaFile))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s: %v", schemaFile, err)
	}
	return s
}

// validate checks v against a small subset of JSON Schema: $ref (local
// #/$defs/...), type, enum, const, required, properties,
// additionalProperties:false, items, minItems, minLength and pattern. It returns one
// message per violation.
func validate(root, schema map[string]any, v any, path string) []string {
	if ref, ok := schema["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		defs, _ := root["$defs"].(map[string]any)
		target, ok := defs[name].(map[string]any)
		if !ok {
			return []string{path + ": unresolved $ref " + ref}
		}
		return validate(root, target, v, path)
	}
	var errs []string
	if want, ok := schema["type"].(string); ok && !typeMatches(want, v) {
		return []string{fmt.Sprintf("%s: want %s, got %T", path, want, v)}
	}
	if c, ok := schema["const"]; ok && !jsonEqual(c, v) {
		errs = append(errs, fmt.Sprintf("%s: want %v, got %v", path, c, v))
	}
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if fmt.Sprint(e) == fmt.Sprint(v) {
				found = true
			}
		}
		if !found {
			errs = append(errs, fmt.Sprintf("%s: %v not in %v", path, v, enum))
		}
	}
	if pat, ok := schema["pattern"].(string); ok {
		if s, isStr := v.(string); isStr && !regexp.MustCompile(pat).MatchString(s) {
			errs = append(errs, fmt.Sprintf("%s: %q does not match %s", path, s, pat))
		}
	}
	if n, ok := schema["minLength"].(float64); ok {
		if s, isStr := v.(string); isStr && float64(len(s)) < n {
			errs = append(errs, fmt.Sprintf("%s: shorter than %v", path, n))
		}
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := schema["properties"].(map[string]any)
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				if _, has := x[r.(string)]; !has {
					errs = append(errs, fmt.Sprintf("%s: missing required %q", path, r))
				}
			}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub, known := props[k].(map[string]any)
			if !known {
				if schema["additionalProperties"] == false {
					errs = append(errs, fmt.Sprintf("%s: unknown key %q", path, k))
				}
				continue
			}
			errs = append(errs, validate(root, sub, x[k], path+"."+k)...)
		}
	case []any:
		if n, ok := schema["minItems"].(float64); ok && float64(len(x)) < n {
			errs = append(errs, fmt.Sprintf("%s: want at least %v items", path, n))
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, e := range x {
				errs = append(errs, validate(root, items, e, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	return errs
}

// jsonEqual compares like JSON Schema: 1 and 1.0 are equal, 1 and "1" are not.
func jsonEqual(a, b any) bool {
	if x, ok := toFloat(a); ok {
		y, ok := toFloat(b)
		return ok && x == y
	}
	return reflect.DeepEqual(a, b)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func typeMatches(want string, v any) bool {
	switch want {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		_, ok := v.(int)
		return ok
	}
	return false
}

func TestContractMatchesSchema(t *testing.T) {
	if errs := validate(readSchema(t), readSchema(t), readYAML(t, contractFile), "$"); len(errs) > 0 {
		t.Fatalf("%s does not match %s:\n%s", contractFile, schemaFile, strings.Join(errs, "\n"))
	}
}

func TestValidatorRejectsBadDocuments(t *testing.T) {
	s := readSchema(t)
	good := readYAML(t, contractFile)
	for name, mutate := range map[string]func(d map[string]any){
		"wrong version":  func(d map[string]any) { d["version"] = 2 },
		"string version": func(d map[string]any) { d["version"] = "1" },
		"unknown live_verify tier": func(d map[string]any) {
			d["live_verify"].(map[string]any)["tiers"] = []any{"bogus"}
		},
		"unknown review lens": func(d map[string]any) {
			d["reviews"].(map[string]any)["by_tier"].(map[string]any)["low"] = []any{"made-up-lens"}
		},
		"empty command": func(d map[string]any) {
			d["commands"].(map[string]any)["fast"].(map[string]any)["run"] = ""
		},
		"unknown key":      func(d map[string]any) { d["surprise"] = true },
		"missing commands": func(d map[string]any) { delete(d, "commands") },
		"command not an object": func(d map[string]any) {
			d["commands"].(map[string]any)["fast"] = "scripts/check.sh"
		},
		"unknown tier": func(d map[string]any) {
			d["reviews"].(map[string]any)["by_tier"].(map[string]any)["bogus"] = []any{"acceptance"}
		},
		"empty lens list": func(d map[string]any) {
			d["reviews"].(map[string]any)["by_tier"].(map[string]any)["low"] = []any{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := readYAML(t, contractFile)
			mutate(d)
			if errs := validate(s, s, d, "$"); len(errs) == 0 {
				t.Fatal("expected schema violations, got none")
			}
		})
	}
	if errs := validate(s, s, good, "$"); len(errs) != 0 {
		t.Fatalf("unmutated contract must be valid: %v", errs)
	}
}

// entry is one place the contract points at something in the repo.
type entry struct {
	name    string
	node    map[string]any
	pathKey string // "run" for commands, "path" for files
}

func sub(m map[string]any, k string) map[string]any {
	n, _ := m[k].(map[string]any)
	return n
}

func entries(doc map[string]any) []entry {
	var out []entry
	cmds, _ := doc["commands"].(map[string]any)
	for k, v := range cmds {
		out = append(out, entry{"commands." + k, v.(map[string]any), "run"})
	}
	add := func(name string, parent map[string]any, key, pathKey string) {
		if n, ok := parent[key].(map[string]any); ok {
			out = append(out, entry{name, n, pathKey})
		}
	}
	add("risk_map", doc, "risk_map", "path")
	add("protected", doc, "protected", "from_risk_map")
	add("reviews.dir", sub(doc, "reviews"), "dir", "path")
	add("live_verify.playbook", sub(doc, "live_verify"), "playbook", "path")
	add("evidence.pr_template", sub(doc, "evidence"), "pr_template", "path")
	return out
}

func exists(rel string) bool { return existsIn(repoPath(""), rel) }

func existsIn(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, rel))
	return err == nil
}

// makeTargets returns the target names declared in the Makefile.
func makeTargets(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(repoPath("Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+):`).FindAllStringSubmatch(string(b), -1) {
		targets[m[1]] = true
	}
	return targets
}

// honestyErrors returns one message per entry that promises something the repo
// rooted at root does not hold.
func honestyErrors(doc map[string]any, root string, targets map[string]bool) []string {
	var errs []string
	errf := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	all := entries(doc)
	for _, e := range all {
		planned, _ := e.node["planned"].(bool)
		if planned {
			if n, ok := e.node["issue"].(int); !ok || n <= 0 {
				errf("%s: planned entry must name its issue", e.name)
			}
			continue
		}
		switch e.pathKey {
		case "path":
			if p, _ := e.node["path"].(string); !existsIn(root, p) {
				errf("%s: %q does not exist; mark it planned or restore it", e.name, p)
			}
		case "from_risk_map":
			// protected derives from the risk map, so it can only be live
			// when the risk map is live and present.
			rm, _ := doc["risk_map"].(map[string]any)
			p, _ := rm["path"].(string)
			if rm == nil || rm["planned"] == true || !existsIn(root, p) {
				errf("%s: depends on the risk map, so it cannot be live before the risk map", e.name)
			}
		case "run":
			fields := strings.Fields(fmt.Sprint(e.node["run"]))
			switch {
			case len(fields) == 0:
				errf("%s: empty command", e.name)
			case fields[0] == "make":
				if len(fields) < 2 || !targets[fields[1]] {
					errf("%s: Makefile has no target for %q", e.name, e.node["run"])
				}
			case strings.Contains(fields[0], "/"):
				if !existsIn(root, fields[0]) {
					errf("%s: script %q does not exist", e.name, fields[0])
				}
			}
		}
	}
	return errs
}

func TestContractIsHonest(t *testing.T) {
	if errs := honestyErrors(readYAML(t, contractFile), repoPath(""), makeTargets(t)); len(errs) > 0 {
		t.Fatal(strings.Join(errs, "\n"))
	}
}

func TestProtectedFollowsRiskMap(t *testing.T) {
	live := t.TempDir()
	if err := os.MkdirAll(filepath.Join(live, ".agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, ".agents/risk.yaml"), []byte("gates: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	doc := func(riskPlanned bool) map[string]any {
		rm := map[string]any{"path": ".agents/risk.yaml"}
		if riskPlanned {
			rm["planned"], rm["issue"] = true, 354
		}
		return map[string]any{
			"risk_map":  rm,
			"protected": map[string]any{"from_risk_map": "gates"},
		}
	}
	for name, tc := range map[string]struct {
		riskPlanned bool
		root        string
		wantErr     bool
	}{
		"risk map live and present": {false, live, false},
		"risk map live but missing": {false, empty, true},
		"risk map still planned":    {true, live, true},
	} {
		t.Run(name, func(t *testing.T) {
			errs := honestyErrors(doc(tc.riskPlanned), tc.root, nil)
			if (len(errs) > 0) != tc.wantErr {
				t.Fatalf("wantErr=%v, got %v", tc.wantErr, errs)
			}
		})
	}
}

func TestReviewLensFilesExist(t *testing.T) {
	doc := readYAML(t, contractFile)
	reviews := doc["reviews"].(map[string]any)
	dir, _ := reviews["dir"].(map[string]any)["path"].(string)
	if planned, _ := reviews["dir"].(map[string]any)["planned"].(bool); planned {
		t.Skip("reviews.dir is planned")
	}
	for tier, lenses := range reviews["by_tier"].(map[string]any) {
		for _, l := range lenses.([]any) {
			if f := filepath.Join(dir, l.(string)+".md"); !exists(f) {
				t.Errorf("tier %s names lens %q but %s does not exist", tier, l, f)
			}
		}
	}
}

var validFormTypes = map[string]bool{"checkboxes": true, "dropdown": true, "input": true, "markdown": true, "textarea": true}

func TestIssueFormsAreValid(t *testing.T) {
	for _, f := range []string{"feature.yml", "bug.yml"} {
		t.Run(f, func(t *testing.T) {
			form := readYAML(t, ".github/ISSUE_TEMPLATE/"+f)
			for _, k := range []string{"name", "description", "body"} {
				if form[k] == nil {
					t.Fatalf("missing top-level %q", k)
				}
			}
			required := map[string]bool{}
			ids := map[string]bool{}
			for i, raw := range form["body"].([]any) {
				item := raw.(map[string]any)
				id, _ := item["id"].(string)
				typ, _ := item["type"].(string)
				if !validFormTypes[typ] {
					t.Fatalf("body[%d]: unknown type %q", i, typ)
				}
				if id == "" || item["attributes"] == nil || item["validations"] == nil {
					t.Fatalf("body[%d]: want id, attributes and validations", i)
				}
				if ids[id] {
					t.Fatalf("body[%d]: duplicate id %q", i, id)
				}
				ids[id] = true
				attrs := item["attributes"].(map[string]any)
				if attrs["label"] == nil {
					t.Fatalf("body[%d]: attributes need a label", i)
				}
				if typ == "dropdown" {
					if opts, _ := attrs["options"].([]any); len(opts) == 0 {
						t.Fatalf("body[%d]: dropdown needs options", i)
					}
				}
				if item["validations"].(map[string]any)["required"] == true {
					required[id] = true
				}
			}
			for _, id := range []string{"acceptance", "touches"} {
				if !required[id] {
					t.Errorf("field %q must exist and be required", id)
				}
			}
		})
	}
}

func TestPRTemplateHasEvidenceSections(t *testing.T) {
	b, err := os.ReadFile(repoPath(".github/pull_request_template.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "| Acceptance criterion | Evidence |") {
		t.Error("template lacks the criterion -> evidence table header row")
	}
	last := -1
	for _, want := range []string{"## Why", "Closes #", "## What changes", "## Acceptance criteria -> evidence", "## Risk tier", "## Review lenses", "## Not done"} {
		i := strings.Index(string(b), want)
		if i < 0 {
			t.Fatalf("template lacks %q", want)
		}
		if i < last {
			t.Errorf("%q is out of order", want)
		}
		last = i
	}
}
