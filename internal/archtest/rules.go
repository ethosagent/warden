package archtest

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// Finding is one rule violation, in the shape the gate reports it:
//
//	RULE-ID  file:line:  what is wrong  →  how to fix
type Finding struct {
	Rule    string
	Package string // module-relative
	File    string // repo-relative, /-separated
	Line    int
	Message string
	Fix     string
	// Item identifies WHAT violated the rule, in the vocabulary a baseline
	// entry's allow list uses: the offending import or called function, the
	// imported target package, the field name. Empty for violations that have
	// no finer identity than the package (C3's "no tests").
	Item string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s  %s:%d:  %s  →  %s", f.Rule, f.File, f.Line, f.Message, f.Fix)
}

// Override re-classifies a single package: the class ID, zone name or domain
// root to use instead of the architecture.yaml match. An empty Class or Zone
// means "deliberately unclassified" (so fixtures can exercise L8 and Z1).
type Override struct {
	Class  string
	Zone   string
	Domain string
}

// Engine checks loaded packages against the architecture.
type Engine struct {
	Arch      *Architecture
	Module    string
	Baseline  *Baseline
	Overrides map[string]Override
	SkipRules map[string]bool

	match  matcher
	byPath map[string]*Package
	out    []Finding
}

// NewEngine returns an engine for arch. Baseline may be nil (nothing is
// suppressed, no staleness check).
func NewEngine(arch *Architecture, module string, base *Baseline) *Engine {
	return &Engine{Arch: arch, Module: module, Baseline: base}
}

// Run checks every package and returns the surviving findings, sorted. Baseline
// entries that no violation matched come back as findings with rule "baseline"
// — a fixed violation must have its entry removed, so the baseline only shrinks.
func (e *Engine) Run(pkgs []*Package) []Finding {
	e.byPath = make(map[string]*Package, len(pkgs))
	for _, p := range pkgs {
		e.byPath[p.ImportPath] = p
	}
	for _, p := range pkgs {
		e.classify(p)
	}
	for _, p := range pkgs {
		e.checkImports(p)
	}
	for _, p := range pkgs {
		e.checkFiles(p)
		e.checkPackage(p)
	}
	e.checkRulePointers()
	if e.on("X2") {
		e.checkX2(e.Arch.Rule("X2")) // whole-module struct check: once per run, not per package
	}
	e.checkStaleBaseline()
	sort.Slice(e.out, func(i, j int) bool {
		a, b := e.out[i], e.out[j]
		return a.Package < b.Package || a.Package == b.Package &&
			(a.File < b.File || a.File == b.File &&
				(a.Line < b.Line || a.Line == b.Line && a.Rule < b.Rule))
	})
	out := e.out
	e.out = nil
	return out
}

// ---- classification ----

func (e *Engine) classify(p *Package) {
	ov, override := e.Overrides[p.Path]
	switch {
	case override:
		p.Class = e.Arch.Class(ov.Class) // nil when ov.Class is "": L8 territory
	default:
		for i := range e.Arch.Classes {
			if e.match.matchAny(e.Arch.Classes[i].Paths, p.Path) {
				p.Class = &e.Arch.Classes[i]
				break
			}
		}
	}
	switch {
	case override:
		p.Zone = ov.Zone // "" = deliberately unzoned
	default:
		for _, zone := range sortedKeys(e.Arch.Zones) {
			if e.match.matchAny(e.Arch.Zones[zone], p.Path) {
				p.Zone = zone
				break
			}
		}
	}
	switch {
	case override && ov.Domain != "":
		p.Domain = ov.Domain
	default:
		p.Domain = domainRoot(p.Path)
	}

	if p.Class == nil && e.on("L8") {
		e.fire("L8", p, e.fileOf(p), e.lineOf(p), fmt.Sprintf("package %s matches no class in architecture.yaml", p.Path))
	}
	if p.Zone == "" && e.on("Z1") {
		e.fire("Z1", p, e.fileOf(p), e.lineOf(p), fmt.Sprintf("package %s is in no zone (data plane, control plane, shared)", p.Path))
	}
	// Z3 — shared packages are domain-layer only (pure logic + tools/tests).
	if e.on("Z3") && p.Zone == "shared" && !sharedPure(p.Class) {
		layer := "unknown"
		if p.Class != nil {
			layer = p.Class.Layer
		}
		e.fireItem("Z3", p, e.fileOf(p), e.lineOf(p), layer,
			fmt.Sprintf("shared package %s is %s-layer, not domain logic", p.Path, layer))
	}
}

// sharedPure reports whether a class is allowed in the shared zone: pure logic
// (domain/decision) and the tool/test classes.
func sharedPure(c *Class) bool {
	if c == nil {
		return false
	}
	switch c.Layer {
	case "domain", "decision", "devtool", "testutil":
		return true
	}
	return false
}

// domainRoot is the first two path segments: the bounded context a package
// belongs to. It works for both shapes — internal/<domain>/adapters/<x> and
// internal/<domain>/<x> — and for nested packages like
// internal/integration/webhook.
func domainRoot(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return path
	}
	return parts[0] + "/" + parts[1]
}

// ---- import edges ----

func (e *Engine) checkImports(p *Package) {
	if p.Class == nil {
		return // L8 already reported
	}
	// devtool and testutil sit outside the layering model (the checker itself,
	// test fakes) but are still bound by the import bans.
	if p.Class.ID == "devtool" || p.Class.ID == "testutil" {
		e.checkBannedImports(p)
		e.checkBlockedModules(p)
		return
	}
	for _, imp := range p.Imports {
		e.checkEdge(p, imp)
		e.checkBannedImport(p, imp)
	}
	e.checkBlockedModules(p)
	// Z4 — side-call adapters in the data plane never open raw sockets; the
	// engine does, and everything else dials through the shared constructor.
	if e.on("Z4") && p.Zone == "data" && p.Class.ID == "repository" {
		var ctors []string
		if x4 := e.Arch.Rule("X4"); x4 != nil {
			ctors = x4.ClientConstructors
		}
		for _, f := range p.Files {
			// The named shared client constructor files may dial; any other file may not.
			if e.match.matchAny(ctors, f.Name) {
				continue
			}
			for _, is := range f.AST.Imports {
				if imp := unquote(is.Path.Value); imp == "net" || imp == "crypto/tls" {
					e.fireItem("Z4", p, f.Name, p.Fset.Position(is.Pos()).Line, imp,
						fmt.Sprintf("side-call adapter imports %s and could open its own socket", imp))
				}
			}
		}
	}
}

func (e *Engine) checkEdge(p *Package, imp string) {
	q := e.byPath[imp]
	if q == nil || q.Class == nil {
		return // not one of ours, or unclassified (reported on q itself)
	}
	impFile, line := e.importLoc(p, imp)

	// Z2 — the planes never cross, independent of the layer verdicts below.
	if e.on("Z2") && p.Zone == "data" && q.Zone == "control" {
		e.fireItem("Z2", p, impFile, line, q.Path, fmt.Sprintf("data-plane package imports control-plane package %s", q.Path))
	}

	// L2 — nothing imports an assembly package unless its class allows it.
	if q.Class.ID == "assembly" {
		if !e.match.matchAny(q.Class.ImportedBy, p.Path) {
			e.fireItem("L2", p, impFile, line, q.Path, fmt.Sprintf("imports assembly package %s", q.Path))
		}
		return
	}
	// S2 — production code never imports a *test package. The name-suffix
	// half skips the archtest package itself ("archtest" ends in "test" but
	// is a normal devtool package).
	if q.Class.ID == "testutil" || strings.HasSuffix(q.Path, "test") && q.Class.ID != "devtool" {
		e.fireItem("S2", p, impFile, line, q.Path, fmt.Sprintf("imports test-support package %s from production code", q.Path))
		return
	}

	importer := p.Class.ID
	switch {
	case isAdapterPath(q.Path):
		switch {
		case importer == "assembly":
			// assembly constructs adapters (S1)
		case importer == "domain" && p.Domain == q.Domain:
			e.fireItem("L5", p, impFile, line, q.Path, fmt.Sprintf("domain %s imports its own adapter %s", p.Domain, q.Path))
		case importer == "transport":
			e.fireItem("L6", p, impFile, line, q.Path, fmt.Sprintf("transport imports adapter %s", q.Path))
		case importer == "engine" || importer == "decision":
			e.fireItem("L4a", p, impFile, line, q.Path, fmt.Sprintf("data-plane %s imports adapter %s directly", importer, q.Path))
		case importer == "repository" && p.Domain != q.Domain:
			e.fireItem("L7", p, impFile, line, q.Path, fmt.Sprintf("repository %s imports another domain's adapter %s", p.Path, q.Path))
		case importer == "repository":
			// same bounded context (internal/integration and its webhook)
		case importer == "domain":
			e.fireItem("S5", p, impFile, line, q.Path, fmt.Sprintf("imports another domain's adapter %s instead of its package API", q.Path))
		}
		return
	}

	switch q.Class.ID {
	case "repository":
		switch importer {
		case "assembly":
			// only assembly talks to repositories (L1/S1)
		case "repository":
			if p.Domain != q.Domain {
				e.fireItem("L7", p, impFile, line, q.Path, fmt.Sprintf("repository %s imports another domain's repository %s", p.Path, q.Path))
			}
		case "transport":
			e.fireItem("L6", p, impFile, line, q.Path, fmt.Sprintf("transport imports repository %s", q.Path))
		case "engine", "decision":
			e.fireItem("L4a", p, impFile, line, q.Path, fmt.Sprintf("data-plane %s imports repository %s", importer, q.Path))
		default: // domain
			e.fireItem("L1", p, impFile, line, q.Path, fmt.Sprintf("domain %s imports repository %s", p.Path, q.Path))
		}
	case "transport":
		switch importer {
		case "repository":
			if p.Domain != q.Domain {
				e.fireItem("L7", p, impFile, line, q.Path, fmt.Sprintf("repository %s imports transport %s", p.Path, q.Path))
			}
		case "domain":
			e.fireItem("L1", p, impFile, line, q.Path, fmt.Sprintf("domain %s imports transport %s (upward)", p.Path, q.Path))
		case "engine", "decision":
			e.fireItem("L4a", p, impFile, line, q.Path, fmt.Sprintf("data-plane %s imports transport %s", importer, q.Path))
		}
	case "engine":
		switch importer {
		case "domain":
			e.fireItem("L1", p, impFile, line, q.Path, fmt.Sprintf("domain %s imports the engine %s (upward)", p.Path, q.Path))
		case "decision":
			e.fireItem("L4a", p, impFile, line, q.Path, fmt.Sprintf("decision stage %s imports the engine %s", p.Path, q.Path))
		}
	}
}

// isAdapterPath reports whether a package path has an adapters/ segment: the
// target shape for repositories.
func isAdapterPath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "adapters" {
			return true
		}
	}
	return false
}

// bannedOrder is the precedence of the import-ban rules, most specific first,
// so one import is reported once.
var bannedOrder = []string{"L6", "L4a", "L4", "L3", "C1", "X8"}

func (e *Engine) checkBannedImports(p *Package) {
	for _, imp := range p.Imports {
		e.checkBannedImport(p, imp)
	}
}

func (e *Engine) checkBannedImport(p *Package, imp string) {
	for _, id := range bannedOrder {
		r := e.Arch.Rule(id)
		if r == nil || !e.on(id) || !e.ruleApplies(r, p) {
			continue
		}
		if contains(r.BannedImports, imp) {
			file, line := e.importLoc(p, imp)
			e.emit(Finding{Rule: id, Package: p.Path, File: file, Line: line, Item: imp,
				Message: fmt.Sprintf("imports %q", imp), Fix: r.Fix})
			return
		}
	}
}

// checkBlockedModules enforces the blocked-module rules (C2): the module, or
// any subpackage of it, may not enter the import graph — in any class,
// including the layering-exempt ones.
func (e *Engine) checkBlockedModules(p *Package) {
	for i := range e.Arch.Rules {
		r := &e.Arch.Rules[i]
		if len(r.BlockedModules) == 0 || !e.on(r.ID) {
			continue
		}
		for _, imp := range p.Imports {
			for _, bm := range r.BlockedModules {
				if imp != bm.Module && !strings.HasPrefix(imp, bm.Module+"/") {
					continue
				}
				file, line := e.importLoc(p, imp)
				e.emit(Finding{Rule: r.ID, Package: p.Path, File: file, Line: line, Item: imp,
					Message: fmt.Sprintf("imports blocked module %q — %s", bm.Module, bm.Reason), Fix: r.Fix})
			}
		}
	}
}

// ruleApplies reports whether a rule with applies-to-classes / zone-filter /
// applies-to-paths data governs this package.
func (e *Engine) ruleApplies(r *Rule, p *Package) bool {
	if len(r.AppliesToClasses) > 0 {
		if p.Class == nil || !contains(r.AppliesToClasses, p.Class.ID) {
			return false
		}
	}
	if r.ZoneFilter != "" && p.Zone != r.ZoneFilter {
		return false
	}
	if len(r.AppliesToPaths) > 0 && !e.match.matchAny(r.AppliesToPaths, p.Path) {
		return false
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(z Zones) []string {
	out := make([]string, 0, len(z))
	for k := range z {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- emit helpers ----

// on reports whether a rule is checked by this engine (archtest-enforced and
// not skipped for this run).
func (e *Engine) on(rule string) bool {
	if e.SkipRules[rule] {
		return false
	}
	r := e.Arch.Rule(rule)
	return r != nil && strings.Contains(r.Checker, "archtest")
}

// emit applies the baseline: an entry suppresses a finding when it records the
// finding's violation item (or when the violation has no finer identity than
// the package), and counts as alive; anything else is kept. So a package that
// gains a violation item its entry does not list fails the gate even though the
// (rule, package) pair is baselined.
func (e *Engine) emit(f Finding) {
	if e.Baseline == nil {
		e.out = append(e.out, f)
		return
	}
	entry := e.Baseline.find(f.Rule, f.Package)
	if entry == nil {
		e.out = append(e.out, f)
		return
	}
	if f.Item == "" || entry.allows(f.Item) {
		e.Baseline.use(entry, f.Item)
		return
	}
	// The entry is alive, but this item is new — keep the finding and keep the
	// entry (it still covers the items it does record).
	e.Baseline.use(entry, "")
	e.out = append(e.out, f)
}

// hard records a finding that no baseline entry may suppress: it reports a
// defect in the gate's own inputs (a dangling rule pointer, a struct the rule
// cannot find) — a known-violation entry must never be able to hide one.
func (e *Engine) hard(f Finding) {
	e.out = append(e.out, f)
}

// fire checks that the rule applies to this run, then emits.
func (e *Engine) fire(rule string, p *Package, file string, line int, message string) {
	e.fireItem(rule, p, file, line, "", message)
}

// fireItem is fire with the violation item the baseline ratchet records.
func (e *Engine) fireItem(rule string, p *Package, file string, line int, item, message string) {
	if !e.on(rule) {
		return
	}
	e.emit(Finding{Rule: rule, Package: p.Path, File: file, Line: line, Item: item, Message: message, Fix: e.fix(rule)})
}

func (e *Engine) fix(rule string) string {
	if r := e.Arch.Rule(rule); r != nil && r.Fix != "" {
		return r.Fix
	}
	return "fix the violation"
}

func (e *Engine) fileOf(p *Package) string {
	if len(p.Files) > 0 {
		return p.Files[0].Name
	}
	if len(p.TestFiles) > 0 {
		return p.TestFiles[0].Name
	}
	return p.Path + ".go"
}

func (e *Engine) lineOf(p *Package) int {
	if len(p.Files) > 0 {
		return p.Files[0].Line
	}
	return 1
}

// importLoc returns the file and line an import appears on. When no
// production file imports it, the package's first file stands in.
func (e *Engine) importLoc(p *Package, imp string) (string, int) {
	for _, f := range p.Files {
		for _, is := range f.AST.Imports {
			if unquote(is.Path.Value) == imp {
				return f.Name, p.Fset.Position(is.Pos()).Line
			}
		}
	}
	return e.fileOf(p), e.lineOf(p)
}

// checkStaleBaseline fails the gate on baseline entries that no longer earn
// their place: a whole entry nothing matches any more (the violation is fixed),
// or a single recorded item that has disappeared while the entry itself still
// covers others. Either way the baseline only shrinks.
func (e *Engine) checkStaleBaseline() {
	if e.Baseline == nil {
		return
	}
	for _, entry := range e.Baseline.Entries {
		k := key(entry.Rule, entry.Package)
		if !e.Baseline.used[k] {
			e.emit(Finding{Rule: "baseline", Package: entry.Package,
				File: "architecture.baseline.yaml", Line: entry.Line,
				Message: fmt.Sprintf("entry (%s, %s) matches no finding — the violation is fixed", entry.Rule, entry.Package),
				Fix:     "remove the entry from architecture.baseline.yaml (the baseline only shrinks)"})
			continue
		}
		for _, item := range entry.Allow {
			if e.Baseline.usedItem[itemKey(entry.Rule, entry.Package, item)] {
				continue
			}
			e.emit(Finding{Rule: "baseline", Package: entry.Package,
				File: "architecture.baseline.yaml", Line: entry.Line,
				Message: fmt.Sprintf("entry (%s, %s) allows %q, which no longer occurs — that violation is fixed", entry.Rule, entry.Package, item),
				Fix:     "remove the item from architecture.baseline.yaml (the baseline only shrinks)"})
		}
	}
}

// checkRulePointers validates the proxy half of the rules: every
// Test…/Benchmark… function a rule's test field names must exist in this repo,
// so renaming a covering test fails the gate instead of silently unchecking the
// rule. A stage must be declared explicitly (`stage:`); free text is never
// accepted as a pointer.
func (e *Engine) checkRulePointers() {
	declared := map[string]bool{}
	for _, p := range e.byPath {
		for _, f := range p.TestFiles {
			for _, d := range f.AST.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv != nil {
					continue
				}
				if name := fd.Name.Name; strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Benchmark") {
					declared[name] = true
				}
			}
		}
	}
	for i := range e.Arch.Rules {
		r := &e.Arch.Rules[i]
		for _, tok := range testTokens(r.Test) {
			if declared[tok] {
				continue
			}
			e.hard(Finding{Rule: r.ID, File: "architecture.yaml",
				Message: fmt.Sprintf("test pointer %s matches no Test/Benchmark function in the repo", tok),
				Fix:     "name the real covering test in architecture.yaml (the rule is unchecked until it does)"})
		}
	}
}
