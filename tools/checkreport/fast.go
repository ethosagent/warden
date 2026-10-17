package main

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// baseRef is the branch --fast measures a change against.
const baseRef = "origin/main"

// FastPlan says which packages `check.sh --fast` checks and why. In report mode
// it is the report's "fast" object, so a reader can see what was and was not
// covered. Full is set (and Packages is empty) when the plan fell back to the
// whole gate.
type FastPlan struct {
	Base     string    `json:"base"`
	Full     bool      `json:"full,omitempty"`
	Why      string    `json:"why,omitempty"`
	Packages []FastPkg `json:"packages"`
	Ignored  []string  `json:"ignored,omitempty"`
	Stages   []string  `json:"stages,omitempty"`
}

// FastPkg is one package in the plan. Reason is "changed: <file>",
// "imports <pkg>" or "test imports <pkg>" (paths relative to the module).
type FastPkg struct {
	Package string `json:"package"`
	Dir     string `json:"dir"`
	Reason  string `json:"reason"`
}

// listedPkg is the part of `go list -json` the planner needs.
type listedPkg struct {
	ImportPath   string
	Dir          string
	Imports      []string
	TestImports  []string
	XTestImports []string
	Deps         []string
}

// fastPlan decides what --fast checks. It never guesses: a base it cannot find,
// or a change it cannot map to packages with certainty, widens the plan.
func (r *runner) fastPlan() FastPlan {
	root := r.cfg.Root
	full := func(why string) FastPlan {
		return FastPlan{Base: baseRef, Full: true, Why: why, Packages: []FastPkg{}}
	}

	if res := r.exec(root, "git", "rev-parse", "--verify", "--quiet", baseRef+"^{commit}"); res.Err != nil || res.Code != 0 {
		return full(baseRef + " is not available (shallow clone or no remote); run `git fetch origin main`")
	}
	mb := r.exec(root, "git", "merge-base", baseRef, "HEAD")
	if mb.Err != nil || mb.Code != 0 {
		return full("no merge base with " + baseRef + " (shallow clone?); run `git fetch --unshallow`")
	}
	base := strings.TrimSpace(string(mb.Stdout))

	// Committed, staged and unstaged changes since the merge base, plus untracked files.
	diff := r.exec(root, "git", "diff", "--name-only", "--no-renames", base, "--")
	if diff.Err != nil || diff.Code != 0 {
		return full("git diff against " + baseRef + " failed")
	}
	untracked := r.exec(root, "git", "ls-files", "--others", "--exclude-standard")
	if untracked.Err != nil || untracked.Code != 0 {
		return full("git ls-files failed")
	}
	files := splitLines(string(diff.Stdout), string(untracked.Stdout))

	list := r.exec(root, "go", "list", "-json=ImportPath,Dir,Imports,TestImports,XTestImports,Deps", "./...")
	if list.Err != nil || list.Code != 0 {
		return full("go list ./... failed: " + firstLine(tail(list, 400)))
	}
	pkgs, err := decodeListed(list.Stdout)
	if err != nil {
		return full("cannot read go list output: " + err.Error())
	}
	return planFast(root, r.ctx.Module, short(base), files, pkgs)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func splitLines(parts ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		for _, l := range strings.Split(p, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

func decodeListed(data []byte) ([]listedPkg, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var out []listedPkg
	for dec.More() {
		var p listedPkg
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// widenFiles are files whose change can affect every package.
var widenFiles = map[string]string{
	"go.mod":           "go.mod changed",
	"go.sum":           "go.sum changed",
	".golangci.yml":    ".golangci.yml changed",
	".golangci.yaml":   ".golangci.yaml changed",
	"go.work":          "go.work changed",
	"scripts/check.sh": "scripts/check.sh changed",
}

// archFiles are the architecture definitions and the lint config generated
// from them. They are inputs of the architecture gate, not of any ordinary
// package, so instead of widening to the full gate they add the gate
// (internal/archtest) and its generator (cmd/archgen) to the plan.
var archFiles = map[string]string{
	"architecture.yaml":          "architecture.yaml changed",
	"architecture.baseline.yaml": "architecture.baseline.yaml changed",
	".golangci.arch.yml":         ".golangci.arch.yml changed",
}

// archDirs are the packages that enforce and generate the architecture checks.
var archDirs = []string{"cmd/archgen", "internal/archtest"}

// planFast maps changed files to packages and adds every package that imports
// them, directly or through other packages, in its code or its tests.
func planFast(root, module, base string, files []string, pkgs []listedPkg) FastPlan {
	plan := FastPlan{Base: baseRef + "@" + base, Packages: []FastPkg{}}
	rel := func(p string) string { return strings.TrimPrefix(strings.TrimPrefix(p, module), "/") }
	dirOf := func(p listedPkg) string {
		d, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return ""
		}
		return filepath.ToSlash(d)
	}

	// Deepest package directory first, so a file maps to its nearest package.
	byDir := map[string]listedPkg{}
	var dirs []string
	for _, p := range pkgs {
		d := dirOf(p)
		byDir[d] = p
		dirs = append(dirs, d)
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })

	reason := map[string]string{} // import path -> why
	// ripple marks changed packages whose importers are affected. A change to
	// only tests or testdata cannot alter what an importer compiles or runs.
	ripple := map[string]bool{}
	for _, f := range files {
		if why, ok := widenFiles[f]; ok {
			return FastPlan{Base: plan.Base, Full: true, Why: why + ": every package may be affected", Packages: []FastPkg{}}
		}
		hit := ""
		for _, d := range dirs {
			if (d == "." && path.Dir(f) == ".") || (d != "." && strings.HasPrefix(f, d+"/")) {
				hit = d
				break
			}
		}
		if hit == "" {
			plan.Ignored = append(plan.Ignored, f)
			continue
		}
		p := byDir[hit]
		if _, ok := reason[p.ImportPath]; !ok {
			reason[p.ImportPath] = "changed: " + f
		}
		if !testOnly(f) {
			ripple[p.ImportPath] = true
		}
	}

	// The architecture definitions re-run the gate and its generator, after the
	// per-file pass so a direct "changed:" reason still wins.
	for _, f := range files {
		why, ok := archFiles[f]
		if !ok {
			continue
		}
		for _, d := range archDirs {
			p, ok := byDir[d]
			if !ok {
				continue
			}
			if _, seen := reason[p.ImportPath]; !seen {
				reason[p.ImportPath] = why
			}
		}
	}

	// Reverse dependencies. A package is affected when a changed package is among
	// the packages its code depends on, or among those its tests import (and
	// what those depend on).
	byPath := map[string]listedPkg{}
	for _, p := range pkgs {
		byPath[p.ImportPath] = p
	}
	changed := map[string]bool{}
	for ip := range ripple {
		changed[ip] = true
	}
	for _, p := range pkgs {
		if _, already := reason[p.ImportPath]; already {
			continue
		}
		if dep := firstChangedDep(p.Imports, p.Deps, changed); dep != "" {
			reason[p.ImportPath] = "imports " + rel(dep)
			continue
		}
		for _, ti := range append(append([]string{}, p.TestImports...), p.XTestImports...) {
			if changed[ti] {
				reason[p.ImportPath] = "test imports " + rel(ti)
				break
			}
			if tp, ok := byPath[ti]; ok {
				if dep := firstChangedDep(nil, tp.Deps, changed); dep != "" {
					reason[p.ImportPath] = "test imports " + rel(ti) + " (which imports " + rel(dep) + ")"
					break
				}
			}
		}
	}

	for _, p := range pkgs {
		if why, ok := reason[p.ImportPath]; ok {
			plan.Packages = append(plan.Packages, FastPkg{Package: p.ImportPath, Dir: dirOf(p), Reason: why})
		}
	}
	sort.Slice(plan.Packages, func(i, j int) bool { return plan.Packages[i].Package < plan.Packages[j].Package })
	return plan
}

// testOnly reports whether a changed file can only affect its own package's tests.
func testOnly(f string) bool {
	return strings.HasSuffix(f, "_test.go") || strings.HasPrefix(f, "testdata/") || strings.Contains(f, "/testdata/")
}

// firstChangedDep returns the changed package that p depends on, preferring a
// direct import for a readable reason.
func firstChangedDep(imports, deps []string, changed map[string]bool) string {
	for _, i := range imports {
		if changed[i] {
			return i
		}
	}
	for _, d := range deps {
		if changed[d] {
			return d
		}
	}
	return ""
}

// relDirs renders the plan's packages as ./dir arguments for go and golangci-lint.
func (p FastPlan) relDirs() []string {
	out := make([]string, 0, len(p.Packages))
	for _, pk := range p.Packages {
		if pk.Dir == "." || pk.Dir == "" {
			out = append(out, ".")
		} else {
			out = append(out, "./"+pk.Dir)
		}
	}
	return out
}

// summary is the one-line human description of the plan.
func (p FastPlan) summary() string {
	if p.Full {
		return fmt.Sprintf("fast: running the FULL gate: %s", p.Why)
	}
	return fmt.Sprintf("fast: %d package(s) against %s", len(p.Packages), p.Base)
}
