package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestPaths_RegistryMatchesDispatch keeps the registry honest: every Path
// constant is in protocolPaths and has a dispatch site (a reference outside
// paths.go), and protocolPaths holds nothing that is not a declared constant.
func TestPaths_RegistryMatchesDispatch(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "paths.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{} // const name -> value
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "Path" {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok {
				t.Fatalf("Path const %s must be a string literal", vs.Names[0].Name)
			}
			declared[vs.Names[0].Name] = strings.Trim(lit.Value, `"`)
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no Path constants in paths.go")
	}

	registered := map[string]bool{}
	for _, p := range ProtocolPaths() {
		registered[string(p)] = true
	}
	var names []string
	for name, val := range declared {
		names = append(names, name)
		if !registered[val] {
			t.Errorf("constant %s (%q) is not in protocolPaths", name, val)
		}
		delete(registered, val)
	}
	for val := range registered {
		t.Errorf("protocolPaths holds %q, which is not a declared Path constant", val)
	}

	// Each constant needs a dispatch site in non-test code other than paths.go.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, fn := range files {
		if fn == "paths.go" || strings.HasSuffix(fn, "_test.go") {
			continue
		}
		b, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	sort.Strings(names)
	for _, name := range names {
		if !regexp.MustCompile(`\b` + name + `\b`).MatchString(src.String()) {
			t.Errorf("registered path %s has no dispatch site: nothing calls reach(%s)", name, name)
		}
	}
}
