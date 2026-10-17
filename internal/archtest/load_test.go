package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTinyModule lays out a module with two packages, one importing the other,
// so the loader can be exercised without the repository around it.
func writeTinyModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":              "module example.com/tiny\n\ngo 1.24\n",
		"inner/inner.go":      "package inner\n\nvar Table = map[string]int{}\n\nfunc Add(a, b int) int { return a + b }\n",
		"inner/inner_test.go": "package inner\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) { _ = Table } //nolint:staticcheck\n",
		"outer/outer.go":      "package outer\n\nimport (\n\tin \"example.com/tiny/inner\"\n)\n\nvar _ = in.Add(1, 2)\n",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestLoadPackages(t *testing.T) {
	root := writeTinyModule(t)
	pkgs, err := LoadPackages(root, root+"/inner", root+"/outer")
	if err != nil {
		t.Fatalf("LoadPackages: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("loaded %d packages, want 2", len(pkgs))
	}
	byPath := map[string]*Package{}
	for _, p := range pkgs {
		byPath[p.Path] = p
	}
	inner := byPath["inner"]
	outer := byPath["outer"]
	if inner == nil || outer == nil {
		t.Fatalf("paths = %v", keys(byPath))
	}
	if outer.ImportPath != "example.com/tiny/outer" {
		t.Errorf("outer.ImportPath = %q", outer.ImportPath)
	}
	if outer.Name != "outer" {
		t.Errorf("outer.Name = %q", outer.Name)
	}
	if len(outer.Imports) != 1 || outer.Imports[0] != "example.com/tiny/inner" {
		t.Errorf("outer.Imports = %v", outer.Imports)
	}
	if len(outer.Files) != 1 {
		t.Fatalf("outer.Files = %d, want 1", len(outer.Files))
	}
	f := outer.Files[0]
	if f.Name != "outer/outer.go" || f.Test {
		t.Errorf("file = %+v", f)
	}
	// The import alias is the key the file's code uses, so selector resolution
	// goes through this map.
	if f.Imports["in"] != "example.com/tiny/inner" {
		t.Errorf("f.Imports = %v", f.Imports)
	}
	if len(inner.TestFiles) != 1 || !inner.TestFiles[0].Test {
		t.Errorf("inner.TestFiles = %v", inner.TestFiles)
	}
	if inner.TestFiles[0].Imports["testing"] != "testing" {
		t.Errorf("test file imports = %v", inner.TestFiles[0].Imports)
	}
}

func keys(m map[string]*Package) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLoadPackagesMissingDir(t *testing.T) {
	root := writeTinyModule(t)
	if _, err := LoadPackages(root, root+"/nope"); err == nil {
		t.Fatal("LoadPackages succeeded on a missing directory")
	}
}

func TestModuleOf(t *testing.T) {
	root := writeTinyModule(t)
	m, err := moduleOf(root)
	if err != nil {
		t.Fatal(err)
	}
	if m != "example.com/tiny" {
		t.Errorf("moduleOf = %q", m)
	}
	if _, err := moduleOf(t.TempDir()); err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("moduleOf outside a module = %v, want a go.mod error", err)
	}
}
