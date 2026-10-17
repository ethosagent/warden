package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/tools/report"
)

// suppressRe matches a directive that starts the comment: //nolint, // nolint or
// // #nosec. Prose that merely mentions them does not.
var suppressRe = regexp.MustCompile(`^//\s*(nolint\b|#nosec\b)`)

var testFuncRe = regexp.MustCompile(`^func\s+((?:Test|Benchmark|Fuzz|Example)\w*)\s*\(`)

type testDecl struct {
	file string
	line int
	name string
}

// testDecls lists the test, benchmark, fuzz and example functions of a tree,
// keyed by directory and name (a test moved to another package is reported:
// a human confirms that it is a move).
func testDecls(v *view) map[string]testDecl {
	out := map[string]testDecl{}
	for _, f := range v.match(isGoTest) {
		text, _ := v.text(f)
		dir := f[:strings.LastIndex("/"+f, "/")]
		for i, l := range strings.Split(text, "\n") {
			if m := testFuncRe.FindStringSubmatch(l); m != nil && m[1] != "TestMain" {
				out[dir+"::"+m[1]] = testDecl{f, i + 1, m[1]}
			}
		}
	}
	return out
}

// testsDeleted reports tests that base has and head lacks, including tests that
// were renamed (so that a human can confirm the rename) and fuzz targets
// dropped from scripts/fuzz-targets.txt.
func (d *diff) testsDeleted() []report.Finding {
	hd := testDecls(d.head)
	var out []report.Finding
	for key, b := range testDecls(d.base) {
		if _, ok := hd[key]; !ok {
			out = append(out, finding(kindTestDeleted, b.file, b.line,
				fmt.Sprintf("test %s was deleted or renamed (line is from base)", b.name), "restore the test, or keep its name if it was only moved or renamed"))
		}
	}
	const targets = "scripts/fuzz-targets.txt"
	bt, _ := d.base.text(targets)
	ht, _ := d.head.text(targets)
	if bt != "" {
		for _, l := range removed(bt, ht) {
			if !isComment(l.text) {
				out = append(out, finding(kindTestDeleted, targets, l.n,
					fmt.Sprintf("fuzz target %q was removed from the list (line is from base)", l.text), "restore the fuzz target"))
			}
		}
	}
	return out
}

// goSites are the places in a Go file that skip tests or hide lint findings,
// found in the syntax tree so that text inside a string is never mistaken for code.
type goSite struct {
	kind string // "skip", "short", "envguard", "build", "nolint"
	key  string // identifies the site without its line number
	line int
	text string
	// helper: the site is in code that takes a *testing.T, *testing.B, *testing.F or testing.TB
	helper bool
}

func collectSites(src []byte, name string, helpers map[string]bool) ([]goSite, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var sites []goSite
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			t := strings.TrimSpace(c.Text)
			line := fset.Position(c.Pos()).Line
			switch {
			case strings.HasPrefix(t, "//go:build"), strings.HasPrefix(t, "// +build"):
				sites = append(sites, goSite{kind: "build", key: t, line: line, text: t})
			case suppressRe.MatchString(t):
				sites = append(sites, goSite{kind: "nolint", key: t, line: line, text: t})
			}
		}
	}
	var fn string
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok {
			fn = fd.Name.Name
		} else {
			fn = ""
		}
		takesT := takesTesting(decl)
		before := len(sites)
		sites = append(sites, envGuards(fset, src, decl, fn, helpers)...)
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			text := string(src[fset.Position(call.Pos()).Offset:fset.Position(call.End()).Offset])
			text = strings.Join(strings.Fields(text), " ")
			switch sel.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				sites = append(sites, goSite{kind: "skip", key: fn + "|" + text, line: fset.Position(call.Pos()).Line, text: text})
			case "Short":
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testing" {
					sites = append(sites, goSite{kind: "short", key: fn + "|" + text, line: fset.Position(call.Pos()).Line, text: text})
				}
			}
			return true
		})
		for i := before; i < len(sites); i++ {
			sites[i].helper = takesT
		}
	}
	return sites, nil
}

// testingParam reports whether a parameter list takes *testing.T, *testing.B,
// *testing.F or testing.TB.
func testingParam(fl *ast.FieldList) bool {
	if fl == nil {
		return false
	}
	for _, p := range fl.List {
		t := p.Type
		if star, ok := t.(*ast.StarExpr); ok {
			t = star.X
		}
		sel, ok := t.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testing" {
			switch sel.Sel.Name {
			case "T", "B", "F", "TB":
				return true
			}
		}
	}
	return false
}

// takesTesting reports whether a declaration, or a function literal inside it,
// takes a testing handle.
func takesTesting(decl ast.Decl) bool {
	found := false
	ast.Inspect(decl, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			found = found || testingParam(fn.Type.Params)
		case *ast.FuncLit:
			found = found || testingParam(fn.Type.Params)
		}
		return !found
	})
	return found
}

// readsEnv reports whether an expression reads the environment or testing.Short,
// directly or through a variable in tainted.
func readsEnv(e ast.Node, tainted map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					pkg := id.Name + "." + sel.Sel.Name
					found = found || pkg == "os.Getenv" || pkg == "os.LookupEnv" || pkg == "testing.Short"
				}
			}
		case *ast.Ident:
			found = found || tainted[x.Name]
		}
		return !found
	})
	return found
}

// returnsEarly reports whether a block ends by leaving the function.
func returnsEarly(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}

// envGuards finds an early return among the top-level statements of a test
// function that is decided by the environment or by -short, directly or through
// a same-package helper that returns such a value (helpers): `if os.Getenv("CI") != "" { return }` makes
// the test pass without running it, just as t.Skip does.
func envGuards(fset *token.FileSet, src []byte, decl ast.Decl, fn string, helpers map[string]bool) []goSite {
	var sites []goSite
	check := func(typ *ast.FuncType, body *ast.BlockStmt) {
		if body == nil || !testingParam(typ.Params) {
			return
		}
		tainted := map[string]bool{}
		for h := range helpers {
			tainted[h] = true
		}
		for _, st := range body.List {
			switch s := st.(type) {
			case *ast.AssignStmt:
				if readsEnv(s, nil) {
					for _, lhs := range s.Lhs {
						if id, ok := lhs.(*ast.Ident); ok {
							tainted[id.Name] = true
						}
					}
				}
			case *ast.IfStmt:
				cond := ast.Node(s.Cond)
				if s.Init != nil {
					if a, ok := s.Init.(*ast.AssignStmt); ok && readsEnv(a, nil) {
						for _, lhs := range a.Lhs {
							if id, ok := lhs.(*ast.Ident); ok {
								tainted[id.Name] = true
							}
						}
					}
				}
				if returnsEarly(s.Body) && readsEnv(cond, tainted) {
					text := strings.Join(strings.Fields(string(src[fset.Position(s.Cond.Pos()).Offset:fset.Position(s.Cond.End()).Offset])), " ")
					sites = append(sites, goSite{kind: "envguard", key: fn + "|" + text, line: fset.Position(s.Pos()).Line, text: text})
				}
			}
		}
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			check(x.Type, x.Body)
		case *ast.FuncLit:
			check(x.Type, x.Body)
		}
		return true
	})
	return sites
}

// newSites returns the sites of head that base does not have, as a multiset per
// (kind, key). A file that does not exist on base has none.
func (d *diff) newSites(file string, kinds ...string) (sites []goSite, baseHad bool, err error) {
	ht, ok := d.head.text(file)
	if !ok {
		return nil, false, nil
	}
	bt, baseHad := d.base.text(file)
	if baseHad && bt == ht {
		return nil, true, nil
	}
	hs, err := collectSites([]byte(ht), file, d.head.envHelpers(dirOf(file)))
	if err != nil {
		return nil, baseHad, err
	}
	var bs []goSite
	if baseHad {
		bs, _ = collectSites([]byte(bt), file, d.base.envHelpers(dirOf(file))) // an unparseable base has no sites to subtract
	}
	count := map[string]int{}
	for _, s := range bs {
		count[s.kind+"|"+s.key]++
	}
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	for _, s := range hs {
		if !want[s.kind] {
			continue
		}
		k := s.kind + "|" + s.key
		if count[k] > 0 {
			count[k]--
			continue
		}
		sites = append(sites, s)
	}
	return sites, baseHad, nil
}

// testsSkipped reports a skip, a testing.Short guard or a build constraint
// newly added to a test file. A build tag on a brand-new file is a new test;
// only `ignore` there is a way of switching it off.
func (d *diff) testsSkipped() []report.Finding {
	var out []report.Finding
	for _, f := range d.head.match(isGoTest) {
		sites, baseHad, err := d.newSites(f, "skip", "short", "envguard", "build")
		if err != nil {
			out = append(out, finding(kindTestSkipped, f, 1, fmt.Sprintf("test file does not parse, so skips cannot be checked: %v", err), "fix the syntax error"))
			continue
		}
		for _, s := range sites {
			switch s.kind {
			case "skip":
				out = append(out, finding(kindTestSkipped, f, s.line, fmt.Sprintf("a test is skipped: %s", s.text), "remove the skip and fix the test"))
			case "short":
				out = append(out, finding(kindTestSkipped, f, s.line, "a testing.Short() guard was added, so -short runs fewer tests", "remove the guard"))
			case "envguard":
				out = append(out, finding(kindTestSkipped, f, s.line, envGuardMsg(s), "remove the guard so the test always runs"))
			case "build":
				if baseHad || strings.Contains(s.text, "ignore") {
					out = append(out, finding(kindTestSkipped, f, s.line,
						fmt.Sprintf("a build constraint was added to or changed on a test file, which can exclude it from the run: %s", s.text), "remove the constraint"))
				}
			}
		}
	}
	// test helpers: non-test files that take a testing handle can skip every
	// test that calls them.
	for _, f := range d.head.match(func(f string) bool { return isGo(f) && !isGoTest(f) && !strings.Contains("/"+f, "/testdata/") }) {
		sites, _, err := d.newSites(f, "skip", "short", "envguard")
		if err != nil {
			continue // a file that does not parse fails the build stage anyway
		}
		for _, s := range sites {
			if !s.helper {
				continue
			}
			msg := fmt.Sprintf("a test helper (%s takes a testing handle) can now skip the tests that call it: %s", f, s.text)
			if s.kind == "envguard" {
				msg = envGuardMsg(s)
			}
			out = append(out, finding(kindTestSkipped, f, s.line, msg, "remove the skip from the helper"))
		}
	}
	return out
}

func envGuardMsg(s goSite) string {
	return fmt.Sprintf("an early return guarded by the environment or -short was added at the top of a test, so it can pass without running: if %s", s.text)
}

// nolintAdded reports the lint-suppression directives that head adds.
func (d *diff) nolintAdded() []report.Finding {
	var out []report.Finding
	for _, f := range d.head.match(func(f string) bool { return isGo(f) && !strings.Contains("/"+f, "/testdata/") }) {
		sites, _, err := d.newSites(f, "nolint")
		if err != nil {
			continue // a file that does not parse fails the build stage anyway
		}
		for _, s := range sites {
			out = append(out, finding(kindNolint, f, s.line,
				fmt.Sprintf("a lint suppression was added: %s", s.text), "fix the finding instead of suppressing it"))
		}
	}
	return out
}

func dirOf(f string) string { return f[:strings.LastIndex("/"+f, "/")] }

// envHelpers names the functions and package variables of a directory that hold
// a value derived from os.Getenv, os.LookupEnv or testing.Short(): a function
// with a return that reads one of those (directly or through a local), or a
// package variable initialised from one. One level only; a helper that calls
// another helper is not followed.
func (v *view) envHelpers(dir string) map[string]bool {
	if v.helpers == nil {
		v.helpers = map[string]map[string]bool{}
	}
	if h, ok := v.helpers[dir]; ok {
		return h
	}
	out := map[string]bool{}
	v.helpers[dir] = out
	for _, f := range v.match(func(f string) bool { return isGo(f) && dirOf(f) == dir }) {
		text, _ := v.text(f)
		file, err := parser.ParseFile(token.NewFileSet(), f, text, 0)
		if err != nil {
			continue
		}
		for _, decl := range file.Decls {
			switch x := decl.(type) {
			case *ast.GenDecl:
				for _, sp := range x.Specs {
					if vs, ok := sp.(*ast.ValueSpec); ok && len(vs.Values) == len(vs.Names) {
						for i, val := range vs.Values {
							if readsEnv(val, nil) {
								out[vs.Names[i].Name] = true
							}
						}
					}
				}
			case *ast.FuncDecl:
				if x.Body != nil && x.Type.Results != nil && returnsEnv(x.Body) {
					out[x.Name.Name] = true
				}
			}
		}
	}
	return out
}

// returnsEnv reports whether a function body returns a value derived from the
// environment or -short.
func returnsEnv(body *ast.BlockStmt) bool {
	tainted := map[string]bool{}
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok && readsEnv(a, tainted) {
				for _, lhs := range a.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						tainted[id.Name] = true
					}
				}
			}
			return true
		})
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if r, ok := n.(*ast.ReturnStmt); ok {
			for _, res := range r.Results {
				found = found || readsEnv(res, tainted)
			}
		}
		return !found
	})
	return found
}
