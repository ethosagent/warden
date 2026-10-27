package main

import (
	"fmt"
	"strings"

	"github.com/ethosagent/warden/tools/report"
	"gopkg.in/yaml.v3"
)

const (
	archFile     = "architecture.yaml"
	baselineFile = "architecture.baseline.yaml"
)

// Rule fields in which a removed item means something is no longer banned or
// checked, and fields in which an added item means something is now allowed.
var (
	archBanLists   = []string{"banned-imports", "banned-calls", "applies-to-classes", "applies-to-paths", "blocked-modules", "wire-types", "structs", "prefixes"}
	archAllowLists = []string{"exec-allowed-in", "signer-paths", "route-files", "wire-fields", "allowed-vars", "shared-repositories"}
	// classes that are exempt from layering: a package moved into one escapes the rules.
	archExemptClasses = map[string]bool{"devtool": true, "testutil": true, "assembly": true}
)

type archRule struct {
	node *yaml.Node
	line int
}

func archRules(root *yaml.Node) map[string]archRule {
	out := map[string]archRule{}
	rules, _ := path(root, "rules")
	if rules == nil {
		return out
	}
	for _, r := range rules.Content {
		if id, _ := mapGet(r, "id"); id != nil {
			out[id.Value] = archRule{r, r.Line}
		}
	}
	return out
}

func checkerTokens(rule *yaml.Node) map[string]bool {
	out := map[string]bool{}
	if c, _ := mapGet(rule, "checker"); c != nil {
		for _, t := range strings.Split(c.Value, "+") {
			out[strings.TrimSpace(t)] = true
		}
	}
	return out
}

// downgraded reports whether head's checker covers less than base's: a checker
// half dropped, or a rule that was proxied by a test now only planned.
func downgraded(b, h map[string]bool) bool {
	hStrong := h["archtest"] || h["golangci"]
	bStrong := b["archtest"] || b["golangci"]
	for t := range b {
		switch t {
		case "archtest", "golangci":
			if !h[t] {
				return true
			}
		case "proxy":
			// proxy next to a checker is its own half of the rule (a test that
			// carries it); proxy alone may be replaced by a real checker.
			if !h["proxy"] && (bStrong || !hStrong) {
				return true
			}
		}
	}
	return false
}

type covPart struct {
	enforced bool
	line     int
}

// coverageParts maps each coverage part's text to whether it is enforced today
// and the line of its enforced/planned key.
func coverageParts(rule *yaml.Node) map[string]covPart {
	out := map[string]covPart{}
	cov, _ := mapGet(rule, "coverage")
	if cov == nil {
		return out
	}
	for _, p := range cov.Content {
		text, _ := mapGet(p, "part")
		enforced, ek := mapGet(p, "enforced")
		_, pk := mapGet(p, "planned")
		if text == nil {
			continue
		}
		line := p.Line
		if ek != nil {
			line = ek.Line
		} else if pk != nil {
			line = pk.Line
		}
		out[text.Value] = covPart{enforced != nil, line}
	}
	return out
}

func loadYAML(v *view, name string) (*yaml.Node, bool, error) {
	text, ok := v.text(name)
	if !ok {
		return nil, false, nil
	}
	n, err := parseYAML(text)
	return n, true, err
}

// architecture compares architecture.yaml (#349): a rule removed, a checker
// downgraded, a ban shortened, an allowance widened, a package moved to an
// exempt class.
func (d *diff) architecture() []report.Finding {
	b, bok, berr := loadYAML(d.base, archFile)
	if !bok || berr != nil || b == nil {
		return nil
	}
	h, hok, herr := loadYAML(d.head, archFile)
	if !hok {
		return []report.Finding{finding(kindArchRemoved, archFile, 1, "architecture.yaml was deleted, so no architecture rule is checked", "restore the file")}
	}
	if herr != nil || h == nil {
		return []report.Finding{finding(kindArchRemoved, archFile, 1, fmt.Sprintf("architecture.yaml does not parse, or is empty: %v", herr), "fix the YAML")}
	}
	var out []report.Finding
	hr := archRules(h)
	for id, br := range archRules(b) {
		hrule, ok := hr[id]
		if !ok {
			out = append(out, finding(kindArchRemoved, archFile, br.line,
				fmt.Sprintf("architecture rule %s was removed (line is from base)", id), "restore the rule"))
			continue
		}
		out = append(out, ruleDiff(id, br.node, hrule.node, hrule.line)...)
	}
	out = append(out, classDiff(b, h)...)
	return out
}

func ruleDiff(id string, b, h *yaml.Node, ruleLine int) []report.Finding {
	var out []report.Finding
	_, ck := mapGet(h, "checker")
	at := func(k *yaml.Node) int { return lineOr(k, ruleLine) }
	bt, ht := checkerTokens(b), checkerTokens(h)
	if downgraded(bt, ht) {
		bc, _ := mapGet(b, "checker")
		hc, _ := mapGet(h, "checker")
		now := "(none)"
		if hc != nil {
			now = hc.Value
		}
		out = append(out, finding(kindArchDown, archFile, at(ck),
			fmt.Sprintf("architecture rule %s was downgraded from checker %q to %q", id, bc.Value, now), "keep the rule enforced"))
	}
	bp, hp := coverageParts(b), coverageParts(h)
	_, covKey := mapGet(h, "coverage")
	for part, was := range bp {
		now, present := hp[part]
		if was.enforced && !now.enforced {
			line := at(covKey)
			if present {
				line = now.line
			}
			out = append(out, finding(kindArchDown, archFile, line,
				fmt.Sprintf("architecture rule %s: coverage part %q is no longer enforced", id, part), "keep that part enforced"))
		}
	}
	for _, field := range archBanLists {
		bv, _ := mapGet(b, field)
		hv, hk := mapGet(h, field)
		for _, gone := range goneItems(items(bv), items(hv)) {
			out = append(out, finding(kindArchLoosened, archFile, at(hk),
				fmt.Sprintf("architecture rule %s: %s no longer lists %s", id, field, gone.canon), "keep the item banned"))
		}
	}
	for _, field := range archAllowLists {
		bv, _ := mapGet(b, field)
		hv, _ := mapGet(h, field)
		for _, n := range newItems(items(bv), items(hv)) {
			out = append(out, finding(kindArchLoosened, archFile, n.line,
				fmt.Sprintf("architecture rule %s: %s now allows %s", id, field, n.canon), "do not widen what the rule allows"))
		}
	}
	if bv, _ := mapGet(b, "references-too"); bv != nil && truthy(bv) {
		if hv, hk := mapGet(h, "references-too"); hv == nil || !truthy(hv) {
			out = append(out, finding(kindArchLoosened, archFile, at(hk),
				fmt.Sprintf("architecture rule %s: references-too was switched off, so holding a banned function without calling it passes", id), "keep references-too: true"))
		}
	}
	if hv, hk := mapGet(h, "except-tests"); hv != nil && truthy(hv) {
		if bv, _ := mapGet(b, "except-tests"); bv == nil || !truthy(bv) {
			out = append(out, finding(kindArchLoosened, archFile, at(hk),
				fmt.Sprintf("architecture rule %s: except-tests was introduced, so test files are exempt", id), "keep the rule applying to tests"))
		}
	}
	return out
}

// classDiff reports a path added to a class that is exempt from layering.
func classDiff(b, h *yaml.Node) []report.Finding {
	var out []report.Finding
	classPaths := func(root *yaml.Node) map[string][]item {
		m := map[string][]item{}
		cs, _ := path(root, "classes")
		if cs == nil {
			return m
		}
		for _, c := range cs.Content {
			id, _ := mapGet(c, "id")
			ps, _ := mapGet(c, "paths")
			if id != nil {
				m[id.Value] = items(ps)
			}
		}
		return m
	}
	bm := classPaths(b)
	for id, hp := range classPaths(h) {
		if !archExemptClasses[id] {
			continue
		}
		for _, n := range newItems(bm[id], hp) {
			out = append(out, finding(kindArchLoosened, archFile, n.line,
				fmt.Sprintf("path %s was added to the %s class, which is exempt from layering rules", n.canon, id), "classify the package where its rules apply"))
		}
	}
	return out
}

// baseline holds architecture.baseline.yaml to "it may only shrink": no new
// entry, and no new item in any entry's allow list.
func (d *diff) baseline() []report.Finding {
	b, bok, berr := loadYAML(d.base, baselineFile)
	if !bok || berr != nil || b == nil {
		return nil
	}
	h, hok, herr := loadYAML(d.head, baselineFile)
	if !hok {
		return nil // deleted: the baseline shrank to nothing
	}
	if herr != nil || h == nil {
		return []report.Finding{finding(kindBaseline, baselineFile, 1, fmt.Sprintf("the baseline does not parse, or is empty: %v", herr), "fix the YAML")}
	}
	type entry struct {
		allow []item
		line  int
	}
	read := func(root *yaml.Node) map[string]entry {
		m := map[string]entry{}
		list, _ := path(root, "baseline")
		if list == nil {
			return m
		}
		for _, e := range list.Content {
			rule, _ := mapGet(e, "rule")
			pkg, pk := mapGet(e, "package")
			allow, _ := mapGet(e, "allow")
			if rule != nil && pkg != nil {
				m[rule.Value+" "+pkg.Value] = entry{items(allow), pk.Line}
			}
		}
		return m
	}
	be := read(b)
	var out []report.Finding
	for key, he := range read(h) {
		bent, ok := be[key]
		if !ok {
			out = append(out, finding(kindBaseline, baselineFile, he.line,
				fmt.Sprintf("a new baseline entry %q allows a violation that is not there today; the baseline may only shrink", key), "fix the violation instead of baselining it"))
			continue
		}
		for _, n := range newItems(bent.allow, he.allow) {
			out = append(out, finding(kindBaseline, baselineFile, n.line,
				fmt.Sprintf("baseline entry %q gained the allowed item %s; the baseline may only shrink", key, n.canon), "fix the violation instead of allowing it"))
		}
	}
	return out
}
