package harness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// portSuffixes are the name endings that mark an exported interface as an
// external-dependency port. A new interface with one of these must either get
// a fake (Fakes) or an explicit, reasoned exclusion (Excluded).
var portSuffixes = []string{"Provider", "Store", "Client", "Dialer", "Clock", "Notifier", "Signer", "Fetcher", "Resolver", "Alerter", "Streamer"}

// namedPorts are real I/O ports whose names carry no suffix; they are held to
// the same rule. Add one here when a port is named for what it does.
var namedPorts = map[string]bool{"proxy.Judge": true, "dashboard.SQLGenerator": true}

func isPortName(pkg, name string) bool {
	if namedPorts[pkg+"."+name] {
		return true
	}
	for _, suf := range portSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// discoverPorts parses every non-test Go file under dir and returns the
// "<package>.<Interface>" name of each exported interface that is a port by
// name (see isPortName), plus each exported type alias whose target is such a
// port: either a selector (pkg.Port) or, in the same package, a bare ident.
func discoverPorts(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	seen := map[string]bool{}
	type alias struct{ pkg, name, targetPkg, target string }
	var aliases []alias
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				if !ts.Name.IsExported() {
					continue
				}
				if _, isIface := ts.Type.(*ast.InterfaceType); isIface && isPortName(f.Name.Name, ts.Name.Name) {
					seen[f.Name.Name+"."+ts.Name.Name] = true
				}
				if ts.Assign == token.NoPos {
					continue
				}
				switch x := ts.Type.(type) {
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok {
						aliases = append(aliases, alias{f.Name.Name, ts.Name.Name, id.Name, x.Sel.Name})
					}
				case *ast.Ident:
					aliases = append(aliases, alias{f.Name.Name, ts.Name.Name, f.Name.Name, x.Name})
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	// An alias of a port is the port under another name: it must be covered too.
	for changed := true; changed; {
		changed = false
		for _, a := range aliases {
			if !seen[a.pkg+"."+a.name] && (seen[a.targetPkg+"."+a.target] || isPortName(a.targetPkg, a.target)) {
				seen[a.pkg+"."+a.name] = true
				changed = true
			}
		}
	}
	ports := make([]string, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	return ports
}

// coverageProblems returns one message per port that has neither a fake nor an
// exclusion, plus registry entries that name no port or contradict each other.
func coverageProblems(ports []string, fakes map[string]FakeEntry, excluded map[string]string) []string {
	var problems []string
	isPort := map[string]bool{}
	for _, p := range ports {
		isPort[p] = true
		_, hasFake := fakes[p]
		reason, isExcl := excluded[p]
		switch {
		case hasFake && isExcl:
			problems = append(problems, "port "+p+" is in both Fakes and Excluded")
		case !hasFake && !isExcl:
			problems = append(problems, "port "+p+" has no fake: add it to harness.Fakes (with a conformance suite) or to harness.Excluded with a reason")
		case isExcl && strings.TrimSpace(reason) == "":
			problems = append(problems, "port "+p+" is excluded without a reason")
		}
	}
	for name, e := range fakes {
		if !isPort[name] {
			problems = append(problems, "Fakes entry "+name+" matches no port interface (renamed or removed?)")
		}
		if e.New == nil || e.Conformance == nil || e.Fake == "" {
			problems = append(problems, "Fakes entry "+name+" must set Fake, New and Conformance")
		}
	}
	for name := range excluded {
		if !isPort[name] {
			problems = append(problems, "Excluded entry "+name+" matches no port interface (stale exclusion)")
		}
	}
	sort.Strings(problems)
	return problems
}

func TestPortCoverage(t *testing.T) {
	ports := discoverPorts(t, filepath.Join("..", "..", "internal"))
	if len(ports) == 0 {
		t.Fatal("found no ports under ./internal: the scan is broken")
	}
	for _, p := range ports {
		if _, ok := Fakes[p]; ok {
			t.Logf("port %-34s fake %s", p, Fakes[p].Fake)
		} else {
			t.Logf("port %-34s excluded: %s", p, Excluded[p])
		}
	}
	for _, p := range coverageProblems(ports, Fakes, Excluded) {
		t.Error(p)
	}
}

// TestPortCoverage_NamesTheMissingPort proves the backstop: dropping any fake
// from the registry makes the check fail and name that port.
func TestPortCoverage_NamesTheMissingPort(t *testing.T) {
	ports := discoverPorts(t, filepath.Join("..", "..", "internal"))
	for victim := range Fakes {
		reduced := map[string]FakeEntry{}
		for k, v := range Fakes {
			if k != victim {
				reduced[k] = v
			}
		}
		problems := coverageProblems(ports, reduced, Excluded)
		if len(problems) != 1 || !strings.Contains(problems[0], victim) {
			t.Errorf("removing %s: problems = %v, want exactly one naming it", victim, problems)
		}
	}
}

func TestCoverageProblems_RejectsBadRegistry(t *testing.T) {
	ports := []string{"a.AStore", "b.BClient"}
	ok := FakeEntry{Fake: "f", New: func(testing.TB) any { return nil }, Conformance: func(*testing.T, any) {}}
	cases := map[string]struct {
		fakes    map[string]FakeEntry
		excluded map[string]string
		want     string
	}{
		"both":         {map[string]FakeEntry{"a.AStore": ok, "b.BClient": ok}, map[string]string{"a.AStore": "r"}, "both"},
		"empty reason": {map[string]FakeEntry{"a.AStore": ok}, map[string]string{"b.BClient": " "}, "without a reason"},
		"stale fake":   {map[string]FakeEntry{"a.AStore": ok, "b.BClient": ok, "c.CStore": ok}, nil, "matches no port"},
		"stale excl":   {map[string]FakeEntry{"a.AStore": ok, "b.BClient": ok}, map[string]string{"z.Z": "r"}, "stale exclusion"},
		"incomplete":   {map[string]FakeEntry{"a.AStore": {Fake: "f"}, "b.BClient": ok}, nil, "must set"},
	}
	for name, c := range cases {
		got := strings.Join(coverageProblems(ports, c.fakes, c.excluded), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: problems %q, want mention of %q", name, got, c.want)
		}
	}
}

func TestFakesConformance(t *testing.T) {
	for name, e := range Fakes {
		t.Run(name, func(t *testing.T) {
			e.Conformance(t, e.New(t))
		})
	}
}

// TestDiscoverPorts_CatchesAliasesAndNamedPorts proves the scan cannot be
// dodged by renaming: an alias of a port (selector or same-package ident), a
// suffix-less named port and the newer suffixes are all discovered.
func TestDiscoverPorts_CatchesAliasesAndNamedPorts(t *testing.T) {
	dir := t.TempDir()
	write := func(pkg, src string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pkg, pkg+".go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proxy", "package proxy\ntype Judge interface{ Evaluate() }\ntype NameResolver interface{ Lookup() }\ntype Plain interface{ X() }\n")
	write("sneaky", "package sneaky\nimport \"x/proxy\"\ntype Oracle = proxy.Judge\ntype Mirror = Oracle\ntype Other = proxy.Plain\n")
	write("sinks", "package sinks\ntype Alerter interface{ A() }\ntype Fetcher interface{ F() }\ntype EventStreamer interface{ S() }\n")

	got := strings.Join(discoverPorts(t, dir), " ")
	for _, want := range []string{"proxy.Judge", "proxy.NameResolver", "sneaky.Oracle", "sneaky.Mirror", "sinks.Alerter", "sinks.Fetcher", "sinks.EventStreamer"} {
		if !strings.Contains(got, want) {
			t.Errorf("discoverPorts missed %s; got %s", want, got)
		}
	}
	if strings.Contains(got, "proxy.Plain") || strings.Contains(got, "sneaky.Other") {
		t.Errorf("discoverPorts flagged a non-port: %s", got)
	}
}
