package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// validateSchema checks doc against the JSON Schema subset docs/check-report.schema.json
// uses: type, const, enum, required, properties, additionalProperties, items,
// minimum, minLength, maxLength and local $ref. A tiny validator keeps a
// third-party dependency out of a security product just for one test.
func validateSchema(root, schema map[string]any, doc any, path string) []string {
	if ref, ok := schema["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		defs, _ := root["$defs"].(map[string]any)
		sub, _ := defs[name].(map[string]any)
		return validateSchema(root, sub, doc, path)
	}
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, path+": "+fmt.Sprintf(f, a...)) }
	if c, ok := schema["const"]; ok && doc != c {
		bad("want const %v, got %v", c, doc)
	}
	if e, ok := schema["enum"].([]any); ok {
		found := false
		for _, v := range e {
			found = found || v == doc
		}
		if !found {
			bad("%v not in enum %v", doc, e)
		}
	}
	switch schema["type"] {
	case "object":
		obj, ok := doc.(map[string]any)
		if !ok {
			return append(errs, path+": want object")
		}
		props, _ := schema["properties"].(map[string]any)
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				if _, present := obj[r.(string)]; !present {
					bad("missing required %q", r)
				}
			}
		}
		for k, v := range obj {
			sub, known := props[k].(map[string]any)
			if !known {
				if schema["additionalProperties"] == false {
					bad("unexpected property %q", k)
				}
				continue
			}
			errs = append(errs, validateSchema(root, sub, v, path+"."+k)...)
		}
	case "array":
		arr, ok := doc.([]any)
		if !ok {
			return append(errs, path+": want array (not null)")
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, v := range arr {
				errs = append(errs, validateSchema(root, items, v, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	case "string":
		s, ok := doc.(string)
		if !ok {
			return append(errs, path+": want string")
		}
		if m, ok := schema["minLength"].(float64); ok && float64(utf8.RuneCountInString(s)) < m {
			bad("shorter than %v", m)
		}
		if m, ok := schema["maxLength"].(float64); ok && float64(utf8.RuneCountInString(s)) > m {
			bad("longer than %v", m)
		}
	case "integer", "number":
		n, ok := doc.(float64)
		if !ok || (schema["type"] == "integer" && n != float64(int64(n))) {
			return append(errs, path+": want integer")
		}
		if m, ok := schema["minimum"].(float64); ok && n < m {
			bad("below minimum %v", m)
		}
	case "boolean":
		if _, ok := doc.(bool); !ok {
			bad("want boolean")
		}
	}
	return errs
}

// assertValidReport fails unless raw is one JSON document valid against the schema file.
func assertValidReport(t *testing.T, raw []byte) {
	t.Helper()
	sb, err := os.ReadFile("../../docs/check-report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(sb, &schema); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, raw)
	}
	if dec.More() {
		t.Fatalf("more than one JSON document in output:\n%s", raw)
	}
	if errs := validateSchema(schema, schema, doc, "$"); len(errs) > 0 {
		t.Fatalf("report does not match docs/check-report.schema.json:\n%s\n%s", strings.Join(errs, "\n"), raw)
	}
}

func TestValidatorRejectsBadDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"extra property":  `{"schema":"warden.check.v1","ok":true,"durationMs":1,"stages":[],"x":1}`,
		"wrong schema id": `{"schema":"v2","ok":true,"durationMs":1,"stages":[]}`,
		"null findings":   `{"schema":"warden.check.v1","ok":true,"durationMs":1,"stages":[{"name":"a","tool":"t","ok":true,"durationMs":1,"findings":null}]}`,
		"empty fix":       `{"schema":"warden.check.v1","ok":false,"durationMs":1,"stages":[{"name":"a","tool":"t","ok":false,"durationMs":1,"findings":[{"rule":"r","severity":"error","message":"m","fix":""}]}]}`,
		"bad severity":    `{"schema":"warden.check.v1","ok":false,"durationMs":1,"stages":[{"name":"a","tool":"t","ok":false,"durationMs":1,"findings":[{"rule":"r","severity":"fatal","message":"m","fix":"f"}]}]}`,
		"two documents":   `{"schema":"warden.check.v1","ok":true,"durationMs":1,"stages":[]}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			sb, _ := os.ReadFile("../../docs/check-report.schema.json")
			var schema map[string]any
			_ = json.Unmarshal(sb, &schema)
			var d any
			dec := json.NewDecoder(strings.NewReader(doc))
			_ = dec.Decode(&d)
			if len(validateSchema(schema, schema, d, "$")) == 0 && !dec.More() {
				t.Errorf("validator accepted %s", name)
			}
		})
	}
}
