package archtest

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Baseline is the parsed architecture.baseline.yaml: the violations that exist
// today, by rule ID and package (never by line — a moved violation stays
// baselined; a FIXED violation leaves a stale entry and fails the gate, so the
// baseline only ever shrinks).
//
// Each entry also records WHAT it allows — the exact violation items (the
// offending imports, called functions, or target packages) — so a package that
// GAINS a violation of an already-baselined rule still fails the gate: the
// (rule, package) key alone would hide it.
type Baseline struct {
	Entries []BaselineEntry `yaml:"baseline"`

	used     map[string]bool
	usedItem map[string]bool
}

// BaselineEntry suppresses the rule's violations in package — and only the
// items its allow list records. Line is the line of the entry in the baseline
// file, for stale-entry reports.
type BaselineEntry struct {
	Rule    string   `yaml:"rule"`
	Package string   `yaml:"package"`
	Why     string   `yaml:"why"`
	Allow   []string `yaml:"allow"` // the violation items allowed in this package
	Line    int      `yaml:"-"`
}

// allows reports whether item is one of the violation items the entry records.
func (e *BaselineEntry) allows(item string) bool {
	return contains(e.Allow, item)
}

// LoadBaseline parses and validates baseline content against arch: every entry
// must name a rule architecture.yaml declares, and name it at most once.
func LoadBaseline(data []byte, arch *Architecture) (*Baseline, error) {
	// Decode twice: once into the typed struct, once into a node tree for the
	// line numbers of each entry (the typed decode loses them).
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("baseline.yaml: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("baseline.yaml: %w", err)
	}
	if seq := baselineSequence(&doc); seq != nil {
		for i, item := range seq.Content {
			if i < len(b.Entries) {
				b.Entries[i].Line = item.Line
			}
		}
	}
	var errs []string
	seen := map[string]bool{}
	for _, e := range b.Entries {
		if e.Rule == "" {
			errs = append(errs, fmt.Sprintf("line %d: entry needs rule", e.Line))
			continue
		}
		if e.Package == "" {
			errs = append(errs, fmt.Sprintf("line %d: entry needs package", e.Line))
		}
		if arch != nil && arch.Rule(e.Rule) == nil {
			errs = append(errs, fmt.Sprintf("line %d: rule %s is not declared in architecture.yaml", e.Line, e.Rule))
		}
		if seen[key(e.Rule, e.Package)] {
			errs = append(errs, fmt.Sprintf("line %d: duplicate entry (%s, %s)", e.Line, e.Rule, e.Package))
		}
		seen[key(e.Rule, e.Package)] = true
		for _, item := range e.Allow {
			if item == "" {
				errs = append(errs, fmt.Sprintf("line %d: entry (%s, %s) has an empty allow item", e.Line, e.Rule, e.Package))
			}
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("baseline.yaml: %s", strings.Join(errs, "; "))
	}
	b.used = map[string]bool{}
	b.usedItem = map[string]bool{}
	return &b, nil
}

func baselineSequence(doc *yaml.Node) *yaml.Node {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "baseline" {
			return root.Content[i+1]
		}
	}
	return nil
}

// find returns the entry suppressing rule in package, or nil.
func (b *Baseline) find(rule, pkg string) *BaselineEntry {
	for i := range b.Entries {
		if b.Entries[i].Rule == rule && b.Entries[i].Package == pkg {
			return &b.Entries[i]
		}
	}
	return nil
}

// use marks an entry — and, when item is not empty, that item — as matched by a
// live finding.
func (b *Baseline) use(entry *BaselineEntry, item string) {
	if entry == nil {
		return
	}
	if b.used == nil {
		b.used = map[string]bool{}
	}
	b.used[key(entry.Rule, entry.Package)] = true
	if item != "" {
		if b.usedItem == nil {
			b.usedItem = map[string]bool{}
		}
		b.usedItem[itemKey(entry.Rule, entry.Package, item)] = true
	}
}

func key(rule, pkg string) string { return rule + "\x00" + pkg }

func itemKey(rule, pkg, item string) string { return key(rule, pkg) + "\x00" + item }
