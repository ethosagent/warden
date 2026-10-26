package auditlog

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

const decisionSchemaPath = "../../docs/schemas/warden.decision.v1.json"

// schemaObject is the subset of JSON Schema 2020-12 the decision schema uses.
// Decoding is strict about nothing here on purpose: the tests below assert the
// shape they rely on.
type schemaObject struct {
	Schema               string                  `json:"$schema"`
	ID                   string                  `json:"$id"`
	Title                string                  `json:"title"`
	Description          string                  `json:"description"`
	Type                 string                  `json:"type"`
	AdditionalProperties *bool                   `json:"additionalProperties"`
	Required             []string                `json:"required"`
	Properties           map[string]schemaObject `json:"properties"`
	Const                any                     `json:"const"`
	Format               string                  `json:"format"`
	Enum                 []string                `json:"enum"`
	Pattern              string                  `json:"pattern"`
	AnyOf                []schemaObject          `json:"anyOf"`
	Items                *schemaObject           `json:"items"`
	Defs                 map[string]schemaObject `json:"$defs"`
}

func loadDecisionSchema(t *testing.T) schemaObject {
	t.Helper()
	b, err := os.ReadFile(decisionSchemaPath)
	if err != nil {
		t.Fatalf("decision schema missing: %v", err)
	}
	var s schemaObject
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("decision schema is not valid JSON: %v", err)
	}
	return s
}

// jsonTag returns the wire name and whether the field is omitempty.
func jsonTag(f reflect.StructField) (name string, omitempty bool, ok bool) {
	tag, has := f.Tag.Lookup("json")
	if !has || tag == "-" {
		return "", false, false
	}
	parts := strings.Split(tag, ",")
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
	}
	return parts[0], omitempty, true
}

// structTags returns the wire names of a struct type and the subset that are
// required (no omitempty).
func structTags(t reflect.Type) (all, required []string) {
	for i := 0; i < t.NumField(); i++ {
		name, omit, ok := jsonTag(t.Field(i))
		if !ok {
			continue
		}
		all = append(all, name)
		if !omit {
			required = append(required, name)
		}
	}
	sort.Strings(all)
	sort.Strings(required)
	return all, required
}

// populate fills every field of v (recursively, through pointers) with a
// non-zero value so a marshaled Record carries every key.
func populate(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		populate(s.Index(0))
		v.Set(s)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		populate(p.Elem())
		v.Set(p)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			populate(v.Field(i))
		}
	}
}

// jsonType names the JSON Schema type of a decoded JSON value.
func jsonType(v any) string {
	switch x := v.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case float64:
		if x == float64(int64(x)) {
			return "integer"
		}
		return "number"
	}
	return "unknown"
}

// compareObject checks one object level of the schema against a struct type and
// a marshaled instance of it, in both directions, naming each offending field.
func compareObject(t *testing.T, where string, s schemaObject, typ reflect.Type, inst map[string]any) {
	t.Helper()
	if s.Type != "object" {
		t.Errorf("%s: schema type = %q, want object", where, s.Type)
	}
	if s.AdditionalProperties == nil || *s.AdditionalProperties {
		t.Errorf("%s: additionalProperties must be false", where)
	}
	tags, required := structTags(typ)
	for _, name := range tags {
		prop, ok := s.Properties[name]
		if !ok {
			t.Errorf("%s: Record field %q has no schema property", where, name)
			continue
		}
		val, present := inst[name]
		if !present {
			t.Errorf("%s: populated Record did not marshal %q", where, name)
			continue
		}
		got := jsonType(val)
		want := prop.Type
		if want == "" {
			t.Errorf("%s.%s: schema property has no type", where, name)
		} else if got != want && (want != "number" || got != "integer") {
			t.Errorf("%s.%s: schema type %q, Record marshals %q", where, name, want, got)
		}
		if want == "array" {
			if prop.Items == nil || prop.Items.Type != "string" {
				t.Errorf("%s.%s: array items must be {type: string}", where, name)
			}
		}
	}
	for name := range s.Properties {
		if !contains(tags, name) {
			t.Errorf("%s: schema property %q is not a Record field", where, name)
		}
	}
	sortedReq := append([]string(nil), s.Required...)
	sort.Strings(sortedReq)
	for _, name := range required {
		if !contains(sortedReq, name) {
			t.Errorf("%s: %q is always written (no omitempty) but is not in schema required", where, name)
		}
	}
	for _, name := range sortedReq {
		if !contains(required, name) {
			t.Errorf("%s: schema requires %q but the Record may omit it", where, name)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestDecisionRecordMatchesSchema pins Record to the published schema in both
// directions: a Record field without a schema property, a schema property
// without a Record field, a required/omitempty mismatch or a type mismatch
// fails and names the field.
func TestDecisionRecordMatchesSchema(t *testing.T) {
	s := loadDecisionSchema(t)

	if !strings.Contains(s.Schema, "2020-12") {
		t.Errorf("$schema = %q, want JSON Schema 2020-12", s.Schema)
	}
	if s.Const != nil {
		t.Errorf("top level must not carry const")
	}

	var rec Record
	populate(reflect.ValueOf(&rec).Elem())
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var inst map[string]any
	if err := json.Unmarshal(raw, &inst); err != nil {
		t.Fatal(err)
	}
	compareObject(t, "record", s, reflect.TypeOf(rec), inst)

	user, ok := s.Properties["user"]
	if !ok {
		t.Fatal("schema has no user property")
	}
	uinst, _ := inst["user"].(map[string]any)
	if uinst == nil {
		t.Fatal("populated Record has no user object")
	}
	compareObject(t, "record.user", user, reflect.TypeOf(User{}), uinst)

	if c := s.Properties["schema"].Const; c != SchemaDecisionV1 {
		t.Errorf("schema.const = %v, want %q", c, SchemaDecisionV1)
	}
	if !contains(s.Required, "schema") || !contains(s.Required, "ts") {
		t.Error("schema and ts must be required")
	}
	if got := s.Properties["ts"].Format; got != "date-time" {
		t.Errorf("ts.format = %q, want date-time", got)
	}
}

// A real line must carry a ts the schema's date-time format accepts and a
// schema_rev matching the Go constant.
func TestDecisionLineTimestampIsDateTime(t *testing.T) {
	r := FromEvent(events(1)[0], sinkMeta, QueryDrop)
	if _, err := time.Parse(time.RFC3339Nano, r.TS); err != nil {
		t.Fatalf("ts %q is not RFC 3339: %v", r.TS, err)
	}
	if r.SchemaRev != SchemaRev || SchemaRev < 1 {
		t.Fatalf("schema_rev = %d", r.SchemaRev)
	}
}

// gatewayReasons is the list of MCP gateway verdict reasons, which
// internal/mcp/gateway declares and denyreason deliberately does not
// redeclare. TestDecisionSchemaReasons pins it to the gateway source.
var gatewayReasons = []string{
	"mcp_tool_denied", "mcp_tool_condition", "mcp_poisoning", "mcp_schema_drift",
	"mcp_args_injection", "mcp_args_leak", "mcp_args_pii", "mcp_args_constraint",
	"mcp_args_too_large", "mcp_result_injection", "mcp_result_leak", "mcp_result_pii",
	"mcp_fail_closed", "mcp_out_of_scope",
}

const chainPattern = `^mcp_chain_[a-z0-9_]+$`

var mcpLiteral = regexp.MustCompile(`^mcp_[a-z_]+$`)

// gatewayLiterals returns every string literal shaped like an mcp_* reason in
// the non-test files of internal/mcp/gateway.
func gatewayLiterals(t *testing.T) []string {
	t.Helper()
	dir := "../mcp/gateway"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && mcpLiteral.MatchString(s) {
				seen[s] = true
			}
			return true
		})
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// reasonSchema returns the enum and the pattern of the reason property's anyOf.
func reasonSchema(t *testing.T, s schemaObject) (enum []string, pattern string) {
	t.Helper()
	r, ok := s.Properties["reason"]
	if !ok {
		t.Fatal("schema has no reason property")
	}
	for _, a := range r.AnyOf {
		enum = append(enum, a.Enum...)
		if a.Pattern != "" {
			pattern = a.Pattern
		}
	}
	return enum, pattern
}

func TestDecisionSchemaReasons(t *testing.T) {
	enum, pattern := reasonSchema(t, loadDecisionSchema(t))
	if pattern != chainPattern {
		t.Errorf("reason pattern = %q, want %q", pattern, chainPattern)
	}

	want := map[string]bool{}
	for _, r := range denyreason.Declared() {
		want[string(r)] = true
	}
	for _, r := range gatewayReasons {
		want[r] = true
	}
	got := map[string]bool{}
	for _, r := range enum {
		if got[r] {
			t.Errorf("reason enum lists %q twice", r)
		}
		got[r] = true
	}
	for r := range want {
		if !got[r] {
			t.Errorf("reason %q is declared (denyreason or gateway list) but missing from the schema enum", r)
		}
	}
	for r := range got {
		if !want[r] {
			t.Errorf("schema enum lists %q, which denyreason.Declared() and the gateway list do not", r)
		}
	}

	// Source scan: a new mcp_* literal in the gateway must be a known reason
	// (or the chain prefix) so the schema cannot silently fall behind.
	chain := regexp.MustCompile(chainPattern)
	for _, lit := range gatewayLiterals(t) {
		if got[lit] || chain.MatchString(lit) || lit == "mcp_chain_" {
			continue
		}
		t.Errorf("internal/mcp/gateway has the literal %q: add it to gatewayReasons and the schema enum", lit)
	}
	// The gateway list must not carry a reason the gateway no longer uses.
	lits := map[string]bool{}
	for _, l := range gatewayLiterals(t) {
		lits[l] = true
	}
	for _, r := range gatewayReasons {
		if !lits[r] && !want[r] {
			t.Errorf("gatewayReasons lists %q, which no longer appears in internal/mcp/gateway", r)
		}
	}
	if !regexp.MustCompile(chainPattern).MatchString("mcp_chain_read_then_send") {
		t.Error("chain pattern does not accept a chain reason")
	}
}

func TestDecisionSchemaDescription(t *testing.T) {
	d := loadDecisionSchema(t).Description
	for _, need := range []string{
		"additive optional fields",
		"schema_rev",
		"v2",
		"one minor release",
		"ignore unknown fields",
		"sort by ts",
		"wall clock",
		"not ordered",
		"seq",
		"boot_id",
		"gap",
		"never holds query values",
	} {
		if !strings.Contains(d, need) {
			t.Errorf("schema description lacks %q", need)
		}
	}
}
