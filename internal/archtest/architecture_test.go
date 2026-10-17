package archtest

import (
	"bytes"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// repoRoot is the module root seen from this package.
const repoRoot = "../.."

// TestArchitecture is the gate scripts/check.sh runs: every rule of
// architecture.yaml against every package of the module, with the baseline of
// known violations applied. It also pins the two generated artifacts: the
// golangci config must be fresh, and go.mod may only require manifested
// modules (S3).
func TestArchitecture(t *testing.T) {
	archData, err := os.ReadFile(filepath.Join(repoRoot, "architecture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	arch, err := LoadArchitecture(archData)
	if err != nil {
		t.Fatal(err)
	}
	var baseline *Baseline
	if baseData, err := os.ReadFile(filepath.Join(repoRoot, "architecture.baseline.yaml")); err == nil {
		if baseline, err = LoadBaseline(baseData, arch); err != nil {
			t.Fatal(err)
		}
	}
	golangciData, err := os.ReadFile(filepath.Join(repoRoot, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	pkgs, err := LoadPackages(repoRoot, "./...")
	if err != nil {
		t.Fatal(err)
	}
	loadTime := time.Since(start)

	module, err := moduleOf(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	findings := NewEngine(arch, module, baseline).Run(pkgs)
	checkTime := time.Since(start)
	t.Logf("checked %d packages in %s (loaded in %s)", len(pkgs), checkTime, loadTime)

	for _, f := range findings {
		t.Errorf("%s", f.String())
	}

	t.Run("golangci-config-fresh", func(t *testing.T) {
		got, err := GenerateGolangCI(arch, golangciData, baseline)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(repoRoot, ".golangci.arch.yml"))
		if err != nil {
			t.Fatalf(".golangci.arch.yml is missing — run go run ./cmd/archgen: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Error(".golangci.arch.yml is stale — run go run ./cmd/archgen")
		}
	})

	t.Run("gomod-manifest", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		manifest := map[string]bool{}
		for _, m := range arch.Modules.Direct {
			manifest[m.Module] = true
		}
		for _, m := range arch.Modules.Indirect {
			manifest[m] = true
		}
		for _, m := range goModRequires(data) {
			if !manifest[m] {
				t.Errorf("module %s is required by go.mod but missing from the architecture.yaml module manifest (S3)", m)
			}
		}
	})
}

var (
	goModBlock = regexp.MustCompile(`(?s)require \(([^)]*)\)`)
	goModLine  = regexp.MustCompile(`(?m)^require (\S+) v\S+`)
	indirect   = regexp.MustCompile(`// indirect`)
)

// goModRequires returns every module path go.mod requires, from both the
// single-line and the block form.
func goModRequires(data []byte) []string {
	var out []string
	if m := goModBlock.FindSubmatch(data); m != nil {
		for _, line := range bytes.Split(m[1], []byte("\n")) {
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				out = append(out, string(fields[0]))
			}
		}
	}
	for _, m := range goModLine.FindAllSubmatch(data, -1) {
		out = append(out, string(m[1]))
	}
	_ = indirect // block entries carry the // indirect marker; the module name is what matters
	return out
}

// TestX2PolicyWire is the real-repo regression for the #349 review blocker:
// X2 must name the struct that actually carries the control-plane fields
// (config.Policy) and must fire when a field could reach a worker. It loads
// the real internal/config package, strips the json:"-" tag from one field of
// the loaded Policy copy, and expects X2 to name that field at its line. The
// committed source is untouched — only the in-memory AST is mutated.
func TestX2PolicyWire(t *testing.T) {
	archData, err := os.ReadFile(filepath.Join(repoRoot, "architecture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	arch, err := LoadArchitecture(archData)
	if err != nil {
		t.Fatal(err)
	}
	baseData, err := os.ReadFile(filepath.Join(repoRoot, "architecture.baseline.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := LoadBaseline(baseData, arch)
	if err != nil {
		t.Fatal(err)
	}
	module, err := moduleOf(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(repoRoot, "./internal/config")
	if err != nil {
		t.Fatal(err)
	}

	x2Findings := func() []Finding {
		var out []Finding
		for _, f := range NewEngine(arch, module, base).Run(pkgs) {
			if f.Rule == "X2" {
				out = append(out, f)
			}
		}
		return out
	}

	// Green: the committed Policy keeps every non-wire field off the wire.
	if got := x2Findings(); len(got) != 0 {
		t.Fatalf("X2 fires on the committed config.Policy: %v", got)
	}

	// Red: a copy of Policy whose LogLevel field no longer carries json:"-".
	field, pkg := policyField(t, pkgs, "LogLevel")
	field.Tag = &ast.BasicLit{Kind: token.STRING, ValuePos: field.Pos(), Value: "`json:\"level\"`"}
	wantLine := pkg.Fset.Position(field.Names[0].Pos()).Line
	got := x2Findings()
	if len(got) != 1 {
		t.Fatalf("X2 findings after untagging LogLevel = %v, want exactly one", got)
	}
	if got[0].File != "internal/config/config.go" || got[0].Line != wantLine {
		t.Errorf("X2 finding = %s:%d, want internal/config/config.go:%d", got[0].File, got[0].Line, wantLine)
	}
	if !strings.Contains(got[0].Message, "LogLevel") {
		t.Errorf("X2 message %q does not name LogLevel", got[0].Message)
	}
}

// policyField finds the named exported field of config.Policy in the loaded
// packages and returns it with its package (for positions).
func policyField(t *testing.T, pkgs []*Package, name string) (*ast.Field, *Package) {
	t.Helper()
	for _, p := range pkgs {
		if p.Path != "internal/config" {
			continue
		}
		for _, f := range p.Files {
			var found *ast.Field
			ast.Inspect(f.AST, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Policy" {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					for _, id := range field.Names {
						if id.Name == name {
							found = field
						}
					}
				}
				return true
			})
			if found != nil {
				return found, p
			}
		}
	}
	t.Fatalf("config.Policy has no field %s — update the regression test", name)
	return nil, nil
}
