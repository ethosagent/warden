package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
)

// The SIEM shipping guide, its shipper examples and the compose override are
// pinned to the schemas and the declared reason set here, so a change to one
// without the others fails in the default gate.
const (
	siemDocPath       = "../../docs/siem.md"
	siemVectorPath    = "../../docs/siem/vector.yaml"
	siemFluentPath    = "../../docs/siem/fluent-bit.conf"
	siemFluentParsers = "../../docs/siem/warden-parsers.conf"
	siemComposePath   = "../../deploy/compose/docker-compose.siem.yml"
)

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(b)
}

// docTable returns the body rows (cells trimmed) of the first markdown table
// after the first heading line that contains headingText.
func docTable(t *testing.T, doc, headingText string) [][]string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	i := 0
	for ; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "#") && strings.Contains(lines[i], headingText) {
			break
		}
	}
	if i == len(lines) {
		t.Fatalf("docs/siem.md has no heading containing %q", headingText)
	}
	var rows [][]string
	inTable := false
	for _, l := range lines[i+1:] {
		if strings.HasPrefix(l, "#") {
			break
		}
		if !strings.HasPrefix(strings.TrimSpace(l), "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cells := strings.Split(strings.Trim(strings.TrimSpace(l), "|"), "|")
		for k := range cells {
			cells[k] = strings.TrimSpace(cells[k])
		}
		if len(cells) > 0 && (strings.HasPrefix(cells[0], "---") || strings.HasPrefix(cells[0], ":--")) {
			continue
		}
		rows = append(rows, cells)
	}
	if len(rows) < 2 {
		t.Fatalf("docs/siem.md: no table under heading %q", headingText)
	}
	return rows[1:] // drop the header row
}

var backticked = regexp.MustCompile("^`([^`]+)`$")

// unquote returns the text of a single backticked cell.
func unquote(t *testing.T, cell string) string {
	t.Helper()
	m := backticked.FindStringSubmatch(cell)
	if m == nil {
		t.Fatalf("docs/siem.md: table cell %q must be a single backticked name", cell)
	}
	return m[1]
}

type schemaField struct{ typ, required string }

// flattenSchema maps every property (nested ones as parent.child) to its type
// and whether it is required at its own level.
func flattenSchema(s schemaObject, prefix string, out map[string]schemaField) {
	req := map[string]bool{}
	for _, r := range s.Required {
		req[r] = true
	}
	for name, p := range s.Properties {
		r := "no"
		if req[name] {
			r = "yes"
		}
		out[prefix+name] = schemaField{typ: p.Type, required: r}
		if p.Type == "object" {
			flattenSchema(p, prefix+name+".", out)
		}
	}
}

func loadSchemaFile(t *testing.T, path string) schemaObject {
	t.Helper()
	var s schemaObject
	if err := json.Unmarshal([]byte(readText(t, path)), &s); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return s
}

func TestSIEMDocFieldsMatchSchema(t *testing.T) {
	doc := readText(t, siemDocPath)
	for _, tc := range []struct{ heading, schemaFile string }{
		{"warden.decision.v1 fields", decisionSchemaPath},
		{"warden.admin.v1 fields", adminSchemaPath},
	} {
		want := map[string]schemaField{}
		flattenSchema(loadSchemaFile(t, tc.schemaFile), "", want)
		got := map[string]schemaField{}
		for _, row := range docTable(t, doc, tc.heading) {
			if len(row) < 4 {
				t.Errorf("%s: row %v needs name, type, required and description columns", tc.heading, row)
				continue
			}
			name := unquote(t, row[0])
			if _, dup := got[name]; dup {
				t.Errorf("%s: field %q is documented twice", tc.heading, name)
			}
			got[name] = schemaField{typ: row[1], required: row[2]}
		}
		names := make([]string, 0, len(want))
		for n := range want {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			g, ok := got[n]
			if !ok {
				t.Errorf("%s: field %q is in %s but not documented in docs/siem.md", tc.heading, n, filepath.Base(tc.schemaFile))
				continue
			}
			if g != want[n] {
				t.Errorf("%s: field %q documented as type=%q required=%q, schema says type=%q required=%q",
					tc.heading, n, g.typ, g.required, want[n].typ, want[n].required)
			}
		}
		for n := range got {
			if _, ok := want[n]; !ok {
				t.Errorf("%s: field %q is documented in docs/siem.md but not in %s", tc.heading, n, filepath.Base(tc.schemaFile))
			}
		}
	}
}

func TestSIEMDocReasonsMatchDeclared(t *testing.T) {
	doc := readText(t, siemDocPath)
	want := map[string]string{}
	for _, r := range denyreason.Declared() {
		want[string(r)] = "denyreason"
	}
	for _, r := range gatewayReasons {
		want[r] = "gateway"
	}
	got := map[string]string{}
	sawChain := false
	for _, row := range docTable(t, doc, "Deny reasons") {
		if len(row) < 3 {
			t.Errorf("reason row %v needs reason, source and meaning columns", row)
			continue
		}
		name := unquote(t, row[0])
		if name == "mcp_chain_<pattern>" {
			sawChain = true
			continue
		}
		if _, dup := got[name]; dup {
			t.Errorf("reason %q is listed twice", name)
		}
		got[name] = row[1]
	}
	if !sawChain {
		t.Error("the reason table must list the mcp_chain_<pattern> family")
	}
	for r, src := range want {
		g, ok := got[r]
		if !ok {
			t.Errorf("reason %q (%s) is declared but missing from the docs/siem.md reason table", r, src)
		} else if g != src {
			t.Errorf("reason %q: docs say source %q, want %q", r, g, src)
		}
	}
	for r := range got {
		if _, ok := want[r]; !ok {
			t.Errorf("docs/siem.md lists reason %q, which denyreason.Declared() and the gateway list do not", r)
		}
	}
}

func TestSIEMDocLinked(t *testing.T) {
	arch := readText(t, "../../docs/architecture.md")
	if !strings.Contains(arch, "siem.md#deny-reasons") {
		t.Error("docs/architecture.md must link to siem.md#deny-reasons")
	}
	for _, r := range denyreason.Declared() {
		if strings.Contains(arch, "`"+string(r)+"`") {
			t.Errorf("docs/architecture.md repeats reason %q; link to docs/siem.md instead", r)
		}
	}
	if !strings.Contains(readText(t, "../../README.md"), "docs/siem.md") {
		t.Error("README.md must link to docs/siem.md")
	}
}

type composeFile struct {
	Services map[string]struct {
		Image       string   `yaml:"image"`
		Volumes     []string `yaml:"volumes"`
		Environment any      `yaml:"environment"`
		Command     any      `yaml:"command"`
	} `yaml:"services"`
	Volumes map[string]any `yaml:"volumes"`
}

// volumeMounts returns source -> container target for a service's mounts.
func volumeMounts(vols []string) map[string]string {
	out := map[string]string{}
	for _, v := range vols {
		p := strings.Split(v, ":")
		if len(p) >= 2 {
			out[p[0]] = p[1]
		}
	}
	return out
}

func envNames(env any) map[string]bool {
	out := map[string]bool{}
	switch e := env.(type) {
	case []any:
		for _, v := range e {
			s, _ := v.(string)
			out[strings.SplitN(s, "=", 2)[0]] = true
		}
	case map[string]any:
		for k := range e {
			out[k] = true
		}
	}
	return out
}

var envRef = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)`)

func TestSIEMComposeAndExamples(t *testing.T) {
	var cf composeFile
	if err := yaml.Unmarshal([]byte(readText(t, siemComposePath)), &cf); err != nil {
		t.Fatalf("compose override is not valid YAML: %v", err)
	}
	proxy, ok := cf.Services["proxy"]
	if !ok {
		t.Fatal("compose override must extend the proxy service of docker-compose.yml")
	}
	vector, ok := cf.Services["vector"]
	if !ok {
		t.Fatal("compose override must add a vector service")
	}

	// One named volume is mounted into both the worker and Vector.
	pm, vm := volumeMounts(proxy.Volumes), volumeMounts(vector.Volumes)
	shared := ""
	for src := range pm {
		if _, declared := cf.Volumes[src]; declared {
			if _, inVector := vm[src]; inVector {
				shared = src
			}
		}
	}
	if shared == "" {
		t.Fatalf("no top-level named volume is mounted into both proxy (%v) and vector (%v)", pm, vm)
	}
	if !strings.HasSuffix(vector.Volumes[indexOfSource(vector.Volumes, shared)], ":ro") {
		t.Errorf("vector must mount %q read-only", shared)
	}

	// The worker config mounted over /etc/warden/config.yaml enables the stream
	// as a file under the shared mount.
	cfgPath := ""
	for src, dst := range pm {
		if dst == "/etc/warden/config.yaml" {
			cfgPath = filepath.Join(filepath.Dir(siemComposePath), src)
		}
	}
	if cfgPath == "" {
		t.Fatal("compose override must mount a worker config at /etc/warden/config.yaml")
	}
	prov, err := config.NewLocalYAMLProvider(cfgPath)
	if err != nil {
		t.Fatalf("worker config of the override does not load: %v", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	j := pol.Audit.JSONLog
	if !j.Enabled || j.Output != config.JSONLogOutputFile {
		t.Errorf("audit.jsonLog = enabled %v output %q, want enabled with output file", j.Enabled, j.Output)
	}
	if !strings.HasPrefix(j.Path, pm[shared]+"/") {
		t.Errorf("audit.jsonLog.path %q is not under the shared mount %q", j.Path, pm[shared])
	}

	// Vector example: valid YAML with a file source, a remap parse, a route on
	// the top-level schema field and a sink; every ${VAR} it reads is set by
	// the override's vector service.
	vecText := readText(t, siemVectorPath)
	var vec struct {
		Sources    map[string]map[string]any `yaml:"sources"`
		Transforms map[string]map[string]any `yaml:"transforms"`
		Sinks      map[string]map[string]any `yaml:"sinks"`
	}
	if err := yaml.Unmarshal([]byte(vecText), &vec); err != nil {
		t.Fatalf("docs/siem/vector.yaml is not valid YAML: %v", err)
	}
	if !hasType(vec.Sources, "file") || !hasType(vec.Transforms, "remap") || !hasType(vec.Transforms, "route") || len(vec.Sinks) == 0 {
		t.Errorf("vector.yaml needs a file source, remap and route transforms and a sink; got %d/%d/%d", len(vec.Sources), len(vec.Transforms), len(vec.Sinks))
	}
	for _, schema := range []string{SchemaDecisionV1, SchemaAdminV1} {
		if !strings.Contains(vecText, `.schema == "`+schema+`"`) {
			t.Errorf("vector.yaml must route on .schema == %q", schema)
		}
	}
	env := envNames(vector.Environment)
	for _, m := range envRef.FindAllStringSubmatch(stripComments(vecText), -1) {
		if !env[m[1]] {
			t.Errorf("vector.yaml reads ${%s}, which the compose vector service does not set", m[1])
		}
	}

	// Fluent Bit example: tail input, a json parser keyed on ts, and a
	// rewrite on the schema field with one rule per schema.
	fb := squash(readText(t, siemFluentPath))
	for _, need := range []string{"[INPUT]", "Name tail", "Parser warden_json", "Parsers_File warden-parsers.conf", "Name rewrite_tag",
		`Rule $schema ^` + regexp.QuoteMeta(SchemaDecisionV1) + `$ warden.decision false`,
		`Rule $schema ^` + regexp.QuoteMeta(SchemaAdminV1) + `$ warden.admin false`} {
		if !strings.Contains(fb, need) {
			t.Errorf("fluent-bit.conf lacks %q", need)
		}
	}
	parsers := squash(readText(t, siemFluentParsers))
	for _, need := range []string{"[PARSER]", "Name warden_json", "Format json", "Time_Key ts"} {
		if !strings.Contains(parsers, need) {
			t.Errorf("warden-parsers.conf lacks %q", need)
		}
	}
}

// squash collapses runs of whitespace so the checks above do not depend on
// column alignment.
func squash(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return strings.Join(out, "\n")
}

// stripComments drops whole-line YAML comments.
func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func indexOfSource(vols []string, src string) int {
	for i, v := range vols {
		if strings.HasPrefix(v, src+":") {
			return i
		}
	}
	return 0
}

func hasType(m map[string]map[string]any, typ string) bool {
	for _, v := range m {
		if v["type"] == typ {
			return true
		}
	}
	return false
}

var fencedBlock = regexp.MustCompile("(?s)```(json|jsonl)\n(.*?)```")

// checkExampleObject verifies one decoded example against the flattened schema:
// no key outside it, and every key required at its level present.
func checkExampleObject(t *testing.T, where string, obj map[string]any, fields map[string]schemaField, prefix string) {
	t.Helper()
	for k, v := range obj {
		f, ok := fields[prefix+k]
		if !ok {
			t.Errorf("%s: key %q is not in the schema", where, prefix+k)
			continue
		}
		if f.typ == "object" {
			if sub, ok := v.(map[string]any); ok {
				checkExampleObject(t, where, sub, fields, prefix+k+".")
			}
		}
	}
	for name, f := range fields {
		if f.required != "yes" || !strings.HasPrefix(name, prefix) || strings.Contains(strings.TrimPrefix(name, prefix), ".") {
			continue
		}
		if _, ok := obj[strings.TrimPrefix(name, prefix)]; !ok {
			t.Errorf("%s: required key %q is missing", where, name)
		}
	}
}

// TestSIEMDocExamples: every JSON line shown in docs/siem.md is a valid line of
// the schema its `schema` field names, so an example cannot rot.
func TestSIEMDocExamples(t *testing.T) {
	doc := readText(t, siemDocPath)
	decision, admin := map[string]schemaField{}, map[string]schemaField{}
	flattenSchema(loadSchemaFile(t, decisionSchemaPath), "", decision)
	flattenSchema(loadSchemaFile(t, adminSchemaPath), "", admin)
	enum, pattern := reasonSchema(t, loadDecisionSchema(t))
	chain := regexp.MustCompile(pattern)
	n := 0
	for _, m := range fencedBlock.FindAllStringSubmatch(doc, -1) {
		for _, line := range strings.Split(m[2], "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			where := "example " + strings.TrimSpace(line)[:40]
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Errorf("%s: not JSON: %v", where, err)
				continue
			}
			n++
			switch obj["schema"] {
			case SchemaDecisionV1:
				checkExampleObject(t, where, obj, decision, "")
				if r, ok := obj["reason"].(string); ok && !contains(enum, r) && !chain.MatchString(r) {
					t.Errorf("%s: reason %q is not in the schema", where, r)
				}
			case SchemaAdminV1:
				checkExampleObject(t, where, obj, admin, "")
			default:
				t.Errorf("%s: unknown schema %v", where, obj["schema"])
			}
		}
	}
	if n < 6 {
		t.Errorf("docs/siem.md shows %d example lines, want at least 6", n)
	}
}
