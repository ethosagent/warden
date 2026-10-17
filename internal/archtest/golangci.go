package archtest

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// The generated config merges into the checked-in .golangci.yml: depguard
// carries the import bans of every golangci-checked rule, forbidigo the banned
// calls (with type analysis, so an import alias cannot evade a ban), and
// gomodguard_v2 the S3 module manifest plus C2's blocked modules. Scopes that
// forbidigo cannot express per pattern (class membership, signer carve-outs)
// become exclusions.rules entries keyed on the rule ID in the message.

// depguardSettings is the linters.settings.depguard block of the generated
// config. One rule per banned-imports rule, named after its rule ID so the
// lint message names the architecture rule.
type depguardSettings struct {
	Rules map[string]depguardRule `yaml:"rules"`
}

type depguardRule struct {
	Files []string       `yaml:"files,omitempty"`
	Deny  []depguardDeny `yaml:"deny"`
}

type depguardDeny struct {
	Pkg  string `yaml:"pkg"`
	Desc string `yaml:"desc"`
}

// forbidigoSettings is the linters.settings.forbidigo block: one pattern per
// banned call, each message prefixed with the rule ID.
type forbidigoSettings struct {
	AnalyzeTypes bool              `yaml:"analyze-types"`
	Forbid       []forbidigoForbid `yaml:"forbid"`
}

type forbidigoForbid struct {
	Pattern string `yaml:"pattern"`       // matches <package name>.<symbol> — an alias cannot change it
	Pkg     string `yaml:"pkg,omitempty"` // regexp over the import path, disambiguating the name
	Msg     string `yaml:"msg"`
}

// gomodguardSettings is the linters.settings.gomodguard_v2 block: the S3
// manifest as the allowlist and the C2 blocked modules.
type gomodguardSettings struct {
	Allowed []gomodguardAllowed `yaml:"allowed,omitempty"`
	Blocked []gomodguardBlocked `yaml:"blocked,omitempty"`
}

type gomodguardAllowed struct {
	Module    string `yaml:"module"`
	MatchType string `yaml:"match-type,omitempty"`
}

type gomodguardBlocked struct {
	Module string `yaml:"module"`
	Reason string `yaml:"reason"`
}

// exclusionRule is one entry of linters.exclusions.rules. Every generated
// entry needs at least two conditions (path/linters/text) so it cannot
// silently mask unrelated findings.
type exclusionRule struct {
	Path       string   `yaml:"path,omitempty"`
	PathExcept string   `yaml:"path-except,omitempty"` // one regexp; scopes are an alternation
	Linters    []string `yaml:"linters,omitempty"`
	Text       string   `yaml:"text,omitempty"`
}

// GenerateGolangCI merges the golangci-enforced parts of arch — import bans,
// banned calls, module manifest — and the baseline suppressions into the base
// golangci-lint config. The base config is otherwise preserved verbatim; the
// result is the content of .golangci.arch.yml.
func GenerateGolangCI(arch *Architecture, base []byte, baseline *Baseline) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(base, &root); err != nil {
		return nil, fmt.Errorf("base golangci config: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("base golangci config: top level is not a mapping")
	}
	doc := root.Content[0]

	linters := ensureMap(doc, "linters")

	// depguard — one deny-list per golangci-checked banned-imports rule.
	depguard := &depguardSettings{Rules: map[string]depguardRule{}}
	// forbidigo — one pattern per golangci-checked banned-calls entry.
	forbidigo := &forbidigoSettings{AnalyzeTypes: true}
	// exclusions collected along the way.
	var exclusions []exclusionRule

	for i := range arch.Rules {
		r := &arch.Rules[i]
		if !strings.Contains(r.Checker, CheckGolangci) {
			continue
		}
		if len(r.BannedImports) > 0 {
			depguard.Rules[r.ID] = depguardRule{
				Files: depguardFiles(arch, r),
				Deny:  denyList(r),
			}
		}
		before := len(forbidigo.Forbid)
		// forbidigo matches any use of the name, calls and references alike,
		// so only rules that ban references get patterns here. The archtest
		// AST check owns the call-only bans.
		if r.ReferencesToo {
			for _, call := range r.BannedCalls {
				pattern, pkg := callPattern(call)
				forbidigo.Forbid = append(forbidigo.Forbid, forbidigoForbid{
					Pattern: pattern,
					Pkg:     pkg,
					Msg:     fmt.Sprintf("%s: %s", r.ID, r.Fix),
				})
			}
		}
		if len(forbidigo.Forbid) == before {
			continue // this rule bans no calls; its scope exclusion would be dead
		}
		// The ban is production-only; the X rules' extra carve-outs come from
		// the rule data.
		exclusions = append(exclusions, ruleExclusions(arch, r)...)
	}
	if len(forbidigo.Forbid) > 0 {
		exclusions = append([]exclusionRule{{Path: `_test\.go$`, Linters: []string{"forbidigo"}}},
			exclusions...)
	}

	if len(depguard.Rules) > 0 {
		enable(linters, "depguard")
		mapSet(ensureMap(linters, "settings"), "depguard", nodeOf(depguard))
	}
	if len(forbidigo.Forbid) > 0 {
		enable(linters, "forbidigo")
		mapSet(ensureMap(linters, "settings"), "forbidigo", nodeOf(forbidigo))
	}

	// gomodguard_v2 — a golangci-checked rule with blocked modules (C2) turns
	// the S3 manifest into the allowlist alongside the blocklist.
	var gomodguard gomodguardSettings
	for _, m := range arch.Modules.Direct {
		gomodguard.Allowed = append(gomodguard.Allowed, gomodguardAllowed{Module: m.Module})
	}
	for i := range arch.Rules {
		r := &arch.Rules[i]
		if !strings.Contains(r.Checker, CheckGolangci) {
			continue
		}
		for _, b := range r.BlockedModules {
			gomodguard.Blocked = append(gomodguard.Blocked, gomodguardBlocked(b))
		}
	}
	if len(gomodguard.Blocked) > 0 {
		enable(linters, "gomodguard_v2")
		mapSet(ensureMap(linters, "settings"), "gomodguard_v2", nodeOf(gomodguard))
	}

	// Baseline entries become path+text exclusions: the violation exists today
	// and must not fail the lint stage, while anything outside the package
	// still does.
	if baseline != nil {
		for _, e := range baseline.Entries {
			exclusions = append(exclusions, exclusionRule{
				Path:    packageFileRegexp(e.Package),
				Text:    e.Rule + ":",
				Linters: []string{"depguard", "forbidigo"},
			})
		}
	}
	if len(exclusions) > 0 {
		seq := ensureSeq(ensureMap(linters, "exclusions"), "rules")
		for _, x := range exclusions {
			seq.Content = append(seq.Content, nodeOf(x))
		}
	}

	// Path rendering must not depend on where golangci-lint is invoked from or
	// how the config was found: the default mode anchors to the config file's
	// directory, which moves with --config and fails path-anchored exclusions
	// in checkouts elsewhere. Every path this config carries (exclusion
	// regexps, depguard ${base-path} globs) is module-root anchored, so pin
	// the mode to the module.
	run := ensureMap(doc, "run")
	mapSet(run, "relative-path-mode", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "gomod"})

	doc.Content[0].HeadComment = "Code generated by cmd/archgen from architecture.yaml — DO NOT EDIT.\n" +
		"Regenerate with: go run ./cmd/archgen"

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// enable adds a linter to linters.enable unless it is already listed.
func enable(linters *yaml.Node, name string) {
	seq := ensureSeq(linters, "enable")
	for _, item := range seq.Content {
		if item.Value == name {
			return
		}
	}
	seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name})
}

// depguardFiles returns the file globs a rule's depguard entry applies to:
// the file globs of its classes, minus the other classes' paths (so a class
// path that prefixes another's — internal/mcp and internal/mcp/gateway —
// cannot leak into the rule), minus test files. depguard matches file globs
// against absolute paths; ${base-path} is the placeholder golangci replaces
// with the module root.
func depguardFiles(arch *Architecture, r *Rule) []string {
	var files []string
	seen := map[string]bool{}
	add := func(g string) {
		if !seen[g] {
			seen[g] = true
			files = append(files, g)
		}
	}
	switch {
	case len(r.AppliesToClasses) > 0:
		in := map[string]bool{}
		for _, id := range r.AppliesToClasses {
			in[id] = true
			if c := arch.Class(id); c != nil {
				for _, p := range c.Paths {
					add("${base-path}/" + fileGlob(p))
				}
			}
		}
		for _, c := range arch.Classes {
			if in[c.ID] {
				continue
			}
			for _, p := range c.Paths {
				add("!${base-path}/" + fileGlob(p))
			}
		}
		// zone-filter narrows the classes further: the zone lists partition
		// the repo (Z1), so excluding every other zone's paths leaves exactly
		// the intersection.
		if r.ZoneFilter != "" {
			for _, zone := range sortedKeys(arch.Zones) {
				if zone == r.ZoneFilter {
					continue
				}
				for _, p := range arch.Zones[zone] {
					add("!${base-path}/" + fileGlob(p))
				}
			}
		}
	case r.ZoneFilter != "":
		for _, p := range arch.Zones[r.ZoneFilter] {
			add("${base-path}/" + fileGlob(p))
		}
	case len(r.AppliesToPaths) > 0:
		for _, p := range r.AppliesToPaths {
			add("${base-path}/" + fileGlob(p))
		}
	}
	return append(files, "!**/*_test.go")
}

// denyList turns a rule's banned-imports into depguard deny entries, each
// description carrying the rule ID so humans and baseline exclusions can key
// on it.
func denyList(r *Rule) []depguardDeny {
	deny := make([]depguardDeny, 0, len(r.BannedImports))
	for _, imp := range r.BannedImports {
		deny = append(deny, depguardDeny{Pkg: imp, Desc: fmt.Sprintf("%s: %s", r.ID, r.Fix)})
	}
	return deny
}

// ruleExclusions returns the exclusions that carve a call ban down to the
// rule's scope: forbidigo patterns cannot carry per-pattern file scopes, so
// the inverse scopes become path / path-except exclusions keyed on the rule
// ID in the message.
func ruleExclusions(arch *Architecture, r *Rule) []exclusionRule {
	var out []exclusionRule
	// X1: signing is allowed inside the signer adapters.
	if len(r.SignerPaths) > 0 {
		out = append(out, exclusionRule{
			Path:    anyPathRegexp(r.SignerPaths),
			Linters: []string{"forbidigo"},
			Text:    r.ID + ":",
		})
	}
	// Scope by explicit paths (X7) or by class membership (L3): keep findings
	// only inside the scope. path-except is one regexp, so multiple globs
	// become a single alternation.
	switch {
	case len(r.AppliesToPaths) > 0:
		out = append(out, exclusionRule{
			PathExcept: anyPathRegexp(r.AppliesToPaths),
			Linters:    []string{"forbidigo"},
			Text:       r.ID + ":",
		})
	case len(r.AppliesToClasses) > 0:
		var globs []string
		for _, id := range r.AppliesToClasses {
			if c := arch.Class(id); c != nil {
				globs = append(globs, c.Paths...)
			}
		}
		out = append(out, exclusionRule{
			PathExcept: anyPathRegexp(globs),
			Linters:    []string{"forbidigo"},
			Text:       r.ID + ":",
		})
	}
	return out
}

// callPattern turns "crypto/ed25519.Sign" into the forbidigo pattern and the
// package regexp that match it: with analyze-types, forbidigo matches patterns
// against <package name>.<symbol> (so an import alias cannot evade the ban)
// and pkg against the import path (so a same-named package cannot trip it).
func callPattern(call string) (pattern, pkg string) {
	i := strings.LastIndex(call, ".")
	if i < 0 {
		return "^" + regexp.QuoteMeta(call) + "$", ""
	}
	path, sel := call[:i], call[i+1:]
	name := path[strings.LastIndex(path, "/")+1:]
	return "^" + regexp.QuoteMeta(name+"."+sel) + "$", "^" + regexp.QuoteMeta(path) + "$"
}

// fileGlob turns a package-path glob into a file-path glob: a package is its
// directory, so package internal/foo owns the files internal/foo/*.go.
func fileGlob(g string) string {
	switch {
	case g == "**":
		return "**"
	case strings.HasSuffix(g, "/**"):
		return g // already matches the files of every package below the prefix
	case strings.HasSuffix(g, "/*"):
		return g + "/*.go" // exactly the files of the packages the glob names
	default:
		return g + "/**"
	}
}

// anyPathRegexp renders globs as one anchored file-path regexp. Exclusions
// match file paths, while the globs classify package paths, so every glob's
// package regexp gains a file-name tail: a plain package path covers exactly
// that package's .go files (a subpackage classifies separately —
// internal/mcp is decision, internal/mcp/gateway is engine), and a ** tree
// covers every file under it.
func anyPathRegexp(globs []string) string {
	parts := make([]string, 0, len(globs))
	for _, g := range globs {
		re := globRegexp(g).String()
		parts = append(parts, strings.TrimSuffix(strings.TrimPrefix(re, "^"), "$")+`/[^/]*\.go`)
	}
	if len(parts) == 1 {
		return "^" + parts[0] + "$"
	}
	return "^(" + strings.Join(parts, "|") + ")$"
}

// packageFileRegexp is the anchored regexp matching exactly the files of one
// package: internal/scan → ^internal/scan/[^/]*\.go$.
func packageFileRegexp(pkg string) string {
	return "^" + quoteGlob(pkg) + `/[^/]*\.go$`
}

// nodeOf renders a typed settings/exclusion value as a yaml node. It panics
// on marshal errors, which for these plain-data types cannot happen.
func nodeOf(v any) *yaml.Node {
	data, err := yaml.Marshal(v)
	if err != nil {
		panic("archtest: marshal generated config part: " + err.Error())
	}
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		panic("archtest: re-parse generated config part: " + err.Error())
	}
	return n.Content[0]
}

// mapGet returns the value node of a mapping node for key, or nil.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapSet replaces or appends key → val in a mapping node.
func mapSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}

// ensureMap returns parent's key mapping, creating it when missing.
func ensureMap(parent *yaml.Node, key string) *yaml.Node {
	if v := mapGet(parent, key); v != nil && v.Kind == yaml.MappingNode {
		return v
	}
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapSet(parent, key, n)
	return n
}

// ensureSeq returns parent's key sequence, creating it when missing.
func ensureSeq(parent *yaml.Node, key string) *yaml.Node {
	if v := mapGet(parent, key); v != nil && v.Kind == yaml.SequenceNode {
		return v
	}
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	mapSet(parent, key, n)
	return n
}
