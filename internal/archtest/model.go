// Package archtest enforces Warden's architecture and security rules
// (GitHub issue #349). The rules live in architecture.yaml at the repo root;
// this package loads them, checks the packages of the current module against
// them, and renders the generated golangci-lint config (.golangci.arch.yml)
// that enforces the import and call bans in the lint stage too.
//
// The entry point is TestArchitecture in this package; scripts/check.sh runs
// it as its own stage (go test ./internal/archtest -run TestArchitecture).
package archtest

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// checker states a rule may have. enforced-by-golangci / enforced-by-archtest
// spell out which checker fails on a violation; proxy points at an existing
// test; planned records why a rule is not yet checkable.
const (
	CheckGolangci         = "golangci"
	CheckArchtest         = "archtest"
	CheckGolangciArchtest = "golangci+archtest"
	CheckArchtestProxy    = "archtest+proxy"
	CheckProxy            = "proxy"
	CheckPlanned          = "planned"
)

// Architecture is the parsed architecture.yaml.
type Architecture struct {
	Version int     `yaml:"version"`
	Classes []Class `yaml:"classes"`
	Zones   Zones   `yaml:"zones"`
	Rules   []Rule  `yaml:"rules"`
	Modules Modules `yaml:"modules"`
}

// Zones maps a zone name (data, control, shared) to the package paths in it.
type Zones map[string][]string

// Modules is the S3 manifest: every module go.mod may require.
type Modules struct {
	Direct   []ModuleEntry `yaml:"direct"`
	Indirect []string      `yaml:"indirect"`
}

// ModuleEntry is one manifested module. Layers lists the classes that may
// import it.
type ModuleEntry struct {
	Module string   `yaml:"module"`
	Layers []string `yaml:"layers"`
}

// Class is what a package IS. Paths are globs over module-relative package
// paths; the first match wins, so specific classes must come first.
type Class struct {
	ID         string   `yaml:"id"`
	Layer      string   `yaml:"layer"`
	ImportedBy []string `yaml:"imported-by"`
	Paths      []string `yaml:"paths"`
}

// checkStages are the stages scripts/check.sh declares (tools/checkreport runs
// the same list; its TestStagesDeclared keeps the two in step). A rule points
// at one explicitly with `stage:` — free text is not accepted, so a renamed
// stage fails here instead of silently unchecking the rule.
var checkStages = []string{
	"format", "vet", "archtest", "lint", "roadmap", "secrets", "build", "vulncheck",
	"test", "fuzz", "benchmark", "coverage", "integration",
}

// CheckStages returns the stage names a rule's `stage:` field may declare.
func CheckStages() []string { return append([]string(nil), checkStages...) }

// Rule is one architecture rule. Which fields are meaningful depends on the
// rule; unknown-to-this-package data is ignored by the checkers and only
// documents intent.
type Rule struct {
	ID      string `yaml:"id"`
	Title   string `yaml:"title"`
	Checker string `yaml:"checker"`
	Test    string `yaml:"test"`
	// Stage names the check.sh stage that carries a rule's proxy half (L4b's
	// benchmark smoke run). Declared explicitly — the validation rejects any
	// stage that check.sh does not declare.
	Stage  string `yaml:"stage"`
	Fix    string `yaml:"fix"`
	Reason string `yaml:"reason"`
	// Coverage splits a partly-checked rule into its enforced and planned
	// parts, so "what is not checked yet" is data, not prose.
	Coverage []RuleCoverage `yaml:"coverage"`

	BannedImports []string `yaml:"banned-imports"`
	BannedCalls   []string `yaml:"banned-calls"`
	// ReferencesToo extends a banned-calls rule to non-call references (the
	// golangci/forbidigo side): taking the banned function as a value is as
	// much a violation as calling it. Rules without it keep references legal —
	// assigning time.Now is the sanctioned clock injection, so L3 bans only
	// the call, which the archtest AST check sees precisely.
	ReferencesToo    bool            `yaml:"references-too"`
	AppliesToClasses []string        `yaml:"applies-to-classes"`
	ZoneFilter       string          `yaml:"zone-filter"`
	SignerPaths      []string        `yaml:"signer-paths"`
	ExecAllowedIn    []string        `yaml:"exec-allowed-in"`
	Structs          []StructRef     `yaml:"structs"`
	Prefixes         []PrefixRule    `yaml:"prefixes"`
	AppliesToPaths   []string        `yaml:"applies-to-paths"`
	RouteFiles       []string        `yaml:"route-files"`
	BlockedModules   []BlockedModule `yaml:"blocked-modules"`
	AllowedVars      string          `yaml:"allowed-vars"`
	ExceptTests      bool            `yaml:"except-tests"`
	WireTypes        []string        `yaml:"wire-types"`
}

// StructRef names a struct whose fields are pinned by X2. WireFields is the
// explicit allowlist of fields that genuinely ride the wire (Policy's
// Allowlist/Denylist); every other exported field must carry json:"-".
type StructRef struct {
	Package    string   `yaml:"package"`
	Type       string   `yaml:"type"`
	WireFields []string `yaml:"wire-fields"`
}

// RuleCoverage is one part of a rule: either the checker that enforces it
// today, or the reason it is not checkable yet. A rule with a planned part
// must say so here — a bare `reason:` is not a substitute (nothing unchecked
// may hide behind free text).
type RuleCoverage struct {
	Part     string `yaml:"part"`
	Enforced string `yaml:"enforced"` // a checker: archtest, golangci or proxy
	Planned  string `yaml:"planned"`  // why this part is not checkable yet
}

// PrefixRule is one reserved storage key prefix (X5).
type PrefixRule struct {
	Prefix        string   `yaml:"prefix"`
	UsedBy        string   `yaml:"used-by"`
	Builder       string   `yaml:"builder"`
	OwnerPackages []string `yaml:"owner-packages"`
}

// BlockedModule is a module C2 bans outright.
type BlockedModule struct {
	Module string `yaml:"module"`
	Reason string `yaml:"reason"`
}

// Rule returns the rule with the given ID, or nil.
func (a *Architecture) Rule(id string) *Rule {
	for i := range a.Rules {
		if a.Rules[i].ID == id {
			return &a.Rules[i]
		}
	}
	return nil
}

// Class returns the class with the given ID, or nil.
func (a *Architecture) Class(id string) *Class {
	for i := range a.Classes {
		if a.Classes[i].ID == id {
			return &a.Classes[i]
		}
	}
	return nil
}

// LoadArchitecture parses and validates architecture.yaml content.
func LoadArchitecture(data []byte) (*Architecture, error) {
	var arch Architecture
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(false)
	if err := dec.Decode(&arch); err != nil {
		return nil, fmt.Errorf("architecture.yaml: %w", err)
	}
	return &arch, arch.validate()
}

var knownCheckers = map[string]bool{
	CheckGolangci: true, CheckArchtest: true, CheckGolangciArchtest: true,
	CheckArchtestProxy: true, CheckProxy: true, CheckPlanned: true,
}

func (a *Architecture) validate() error {
	var errs []string
	if a.Version != 1 {
		errs = append(errs, fmt.Sprintf("unsupported version %d (want 1)", a.Version))
	}
	seenClass := map[string]bool{}
	for _, c := range a.Classes {
		if seenClass[c.ID] {
			errs = append(errs, fmt.Sprintf("duplicate class %s", c.ID))
		}
		seenClass[c.ID] = true
		if c.Layer == "" {
			errs = append(errs, fmt.Sprintf("class %s has no layer", c.ID))
		}
		if len(c.Paths) == 0 {
			errs = append(errs, fmt.Sprintf("class %s has no paths", c.ID))
		}
	}
	if len(a.Zones) == 0 {
		errs = append(errs, "no zones declared")
	}
	seenRule := map[string]bool{}
	for _, r := range a.Rules {
		if seenRule[r.ID] {
			errs = append(errs, fmt.Sprintf("duplicate rule %s", r.ID))
			continue
		}
		seenRule[r.ID] = true
		if !knownCheckers[r.Checker] {
			errs = append(errs, fmt.Sprintf("rule %s: unknown checker %q", r.ID, r.Checker))
		}
		switch r.Checker {
		case CheckProxy, CheckArchtestProxy:
			if r.Test == "" && r.Stage == "" {
				errs = append(errs, fmt.Sprintf("proxy rule %s needs test (the covering test) or stage (the covering check.sh stage)", r.ID))
			}
		case CheckPlanned:
			if r.Reason == "" {
				errs = append(errs, fmt.Sprintf("planned rule %s needs reason", r.ID))
			}
		default:
			if r.Fix == "" {
				errs = append(errs, fmt.Sprintf("rule %s needs fix (printed with every finding)", r.ID))
			}
		}
		if r.Stage != "" && !contains(checkStages, r.Stage) {
			errs = append(errs, fmt.Sprintf("rule %s: unknown stage %q (declare one of: %s)",
				r.ID, r.Stage, strings.Join(checkStages, ", ")))
		}
		for i, sr := range r.Structs {
			if sr.Package == "" {
				errs = append(errs, fmt.Sprintf("rule %s: structs[%d] needs package", r.ID, i))
			}
			if sr.Type == "" {
				errs = append(errs, fmt.Sprintf("rule %s: structs[%d] (%s) needs type", r.ID, i, sr.Package))
			}
			for _, wf := range sr.WireFields {
				if wf == "" {
					errs = append(errs, fmt.Sprintf("rule %s: structs[%d] (%s.%s) has an empty wire-fields entry", r.ID, i, sr.Package, sr.Type))
				}
			}
		}
		plannedPart := false
		for i, c := range r.Coverage {
			if c.Part == "" {
				errs = append(errs, fmt.Sprintf("rule %s: coverage[%d] needs part", r.ID, i))
			}
			switch {
			case c.Enforced == "" && c.Planned == "":
				errs = append(errs, fmt.Sprintf("rule %s: coverage[%d] (%s) needs enforced or planned", r.ID, i, c.Part))
			case c.Enforced != "" && c.Planned != "":
				errs = append(errs, fmt.Sprintf("rule %s: coverage[%d] (%s) cannot be both enforced and planned", r.ID, i, c.Part))
			case c.Enforced != "" && !contains([]string{CheckArchtest, CheckGolangci, CheckProxy}, c.Enforced):
				errs = append(errs, fmt.Sprintf("rule %s: coverage[%d] enforces with unknown checker %q", r.ID, i, c.Enforced))
			case c.Planned != "":
				plannedPart = true
			}
		}
		// Nothing unchecked may hide behind free text: a reason on a rule that
		// is not `planned` must name its parts in coverage instead.
		if r.Reason != "" && r.Checker != CheckPlanned && len(r.Coverage) == 0 {
			errs = append(errs, fmt.Sprintf("rule %s has a reason but no coverage — declare the enforced and planned parts (coverage:)", r.ID))
		}
		if plannedPart && r.Reason == "" {
			errs = append(errs, fmt.Sprintf("rule %s: planned coverage needs reason (what must land first)", r.ID))
		}
		for _, id := range r.AppliesToClasses {
			if !seenClass[id] {
				errs = append(errs, fmt.Sprintf("rule %s: unknown class %s in applies-to-classes", r.ID, id))
			}
		}
		if r.ZoneFilter != "" && !a.Zones.has(r.ZoneFilter) {
			errs = append(errs, fmt.Sprintf("rule %s: unknown zone %q in zone-filter", r.ID, r.ZoneFilter))
		}
	}
	if len(a.Modules.Direct) == 0 && len(a.Modules.Indirect) == 0 {
		errs = append(errs, "modules manifest is empty (S3)")
	}
	if len(errs) > 0 {
		return fmt.Errorf("architecture.yaml: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (z Zones) has(name string) bool {
	_, ok := z[name]
	return ok
}

// testToken matches a Go test or benchmark function name inside a rule's
// free-text test field: "internal/config/secretstore_test.go
// (TestSecretStore_UnknownBackend_Errors — an unknown backend fails)" yields
// TestSecretStore_UnknownBackend_Errors. Prose around it is ignored.
var testToken = regexp.MustCompile(`(?:Test|Benchmark)[A-Za-z0-9_]+`)

// testTokens returns the Test…/Benchmark… names a rule's test field points at.
func testTokens(test string) []string {
	return testToken.FindAllString(test, -1)
}

// matcher compiles the small glob language used in architecture.yaml (* is one
// path segment, ** is anything) and caches the results.
type matcher struct {
	cache map[string]*regexp.Regexp
}

// match reports whether path (/-separated) matches glob.
func (m *matcher) match(glob, path string) bool {
	if m.cache == nil {
		m.cache = map[string]*regexp.Regexp{}
	}
	re, ok := m.cache[glob]
	if !ok {
		re = globRegexp(glob)
		m.cache[glob] = re
	}
	return re.MatchString(path)
}

// matchAny reports whether path matches any glob.
func (m *matcher) matchAny(globs []string, path string) bool {
	for _, g := range globs {
		if m.match(g, path) {
			return true
		}
	}
	return false
}

// globRegexp translates "internal/*/adapters/**" into an anchored regexp.
// A trailing "/**" also matches the prefix itself, so internal/proxy/** covers
// the internal/proxy package.
func globRegexp(glob string) *regexp.Regexp {
	if base, ok := strings.CutSuffix(glob, "/**"); ok {
		return regexp.MustCompile("^" + quoteGlob(base) + "(/.*)?$")
	}
	return regexp.MustCompile("^" + quoteGlob(glob) + "$")
}

// quoteGlob translates the glob metacharacters of a path pattern: * is one
// path segment, ** is anything (including slashes). Everything else is literal.
func quoteGlob(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; {
		case c == '*' && i+1 < len(glob) && glob[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
