package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/tools/report"
	"gopkg.in/yaml.v3"
)

// listsOnlyGrowAreLoosening are the golangci-lint lists in which a new item
// means something is no longer checked.
var exclusionLists = [][]string{
	{"linters", "disable"},
	{"linters", "exclusions", "rules"},
	{"linters", "exclusions", "paths"},
	{"linters", "exclusions", "presets"},
	{"formatters", "exclusions", "paths"},
	{"issues", "exclude"},
	{"issues", "exclude-rules"},
	{"issues", "exclude-dirs"},
	{"issues", "exclude-files"},
	{"run", "skip-dirs"},
	{"run", "skip-files"},
}

// switchedOffKeys name lists inside a linter's settings in which an item turns
// a check off.
var switchedOffKeys = map[string]bool{
	"disable": true, "disabled": true, "exclude": true, "excludes": true, "exclude-functions": true,
	"exclude-rules": true, "exclude-files": true, "exclude-dirs": true, "ignore": true, "ignored": true,
	"skip": true, "skip-files": true, "skip-dirs": true,
}

// lint compares the golangci-lint configs: a linter no longer enabled, a new
// exclusion, a disabled linter, a setting that switches a check off, a cap on
// the issues reported, tests no longer linted.
func (d *diff) lint() []report.Finding {
	var out []report.Finding
	for _, f := range d.base.match(isGolangci) {
		bt, _ := d.base.text(f)
		ht, ok := d.head.text(f)
		if !ok {
			out = append(out, finding(kindLint, f, 1, fmt.Sprintf("%s was deleted, so its linters no longer run (line is from base)", f), "restore the config"))
			continue
		}
		b, berr := parseYAML(bt)
		h, herr := parseYAML(ht)
		if herr != nil || h == nil {
			out = append(out, finding(kindLint, f, 1, fmt.Sprintf("%s does not parse, or is empty: %v", f, herr), "fix the YAML"))
			continue
		}
		if berr != nil || b == nil {
			continue
		}
		out = append(out, lintPair(f, b, h)...)
	}
	return out
}

func lintPair(f string, b, h *yaml.Node) []report.Finding {
	var out []report.Finding
	for _, p := range [][]string{{"linters", "enable"}, {"formatters", "enable"}} {
		bv, _ := path(b, p...)
		hv, hk := path(h, p...)
		for _, gone := range goneItems(items(bv), items(hv)) {
			line := lineOr(hk, 1)
			if hk == nil {
				_, line2 := path(h, p[0])
				line = lineOr(line2, 1)
			}
			out = append(out, finding(kindLint, f, line,
				fmt.Sprintf("%s %q is no longer enabled (%s.enable)", p[0][:len(p[0])-1], gone.canon, p[0]), "keep it enabled and fix what it reports"))
		}
	}
	for _, p := range exclusionLists {
		bv, _ := path(b, p...)
		hv, _ := path(h, p...)
		for _, n := range newItems(items(bv), items(hv)) {
			out = append(out, finding(kindLint, f, n.line,
				fmt.Sprintf("lint exclusion added under %s: %s", strings.Join(p, "."), n.canon), "fix the code instead of excluding it from lint"))
		}
	}
	if v, k := path(h, "run", "tests"); v != nil && strings.EqualFold(v.Value, "false") {
		if bv, _ := path(b, "run", "tests"); bv == nil || !strings.EqualFold(bv.Value, "false") {
			out = append(out, finding(kindLint, f, k.Line, "tests are no longer linted (run.tests: false)", "lint the tests too"))
		}
	}
	for _, key := range []string{"max-issues-per-linter", "max-same-issues"} {
		bv, _ := path(b, "issues", key)
		hv, hk := path(h, "issues", key)
		if hv == nil {
			continue
		}
		if capped(hv, bv) {
			out = append(out, finding(kindLint, f, hk.Line,
				fmt.Sprintf("issues.%s now caps what lint reports (%s); 0 means unlimited", key, hv.Value), "keep the cap at 0"))
		}
	}
	bs, _ := path(b, "linters", "settings")
	hs, _ := path(h, "linters", "settings")
	out = append(out, settingsDiff(f, "linters.settings", bs, hs)...)
	return out
}

// capped reports whether head's issue cap is stricter than base's (0 = unlimited).
func capped(head, base *yaml.Node) bool {
	hn, err := strconv.Atoi(head.Value)
	if err != nil || hn == 0 {
		return false
	}
	if base == nil {
		return true
	}
	bn, err := strconv.Atoi(base.Value)
	return err != nil || bn == 0 || hn < bn
}

// settingsDiff walks linter settings and reports new items in lists that switch
// checks off: exclude/disable-style lists, and "-CHECK" entries in a checks list.
func settingsDiff(f, at string, b, h *yaml.Node) []report.Finding {
	var out []report.Finding
	if h == nil || h.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(h.Content); i += 2 {
		k, hv := h.Content[i].Value, h.Content[i+1]
		bv, _ := mapGet(b, k)
		switch {
		case hv.Kind == yaml.MappingNode:
			out = append(out, settingsDiff(f, at+"."+k, bv, hv)...)
		case hv.Kind == yaml.SequenceNode && (switchedOffKeys[k] || k == "checks"):
			for _, n := range newItems(items(bv), items(hv)) {
				if k == "checks" && !strings.HasPrefix(n.canon, "-") {
					continue
				}
				out = append(out, finding(kindLint, f, n.line,
					fmt.Sprintf("a check is switched off in %s.%s: %s", at, k, n.canon), "keep the check on and fix what it reports"))
			}
		}
	}
	return out
}

var (
	configFlagRe = regexp.MustCompile(`(?:^|\s)(?:--config|-c)(?:=|\s+)(\S+)`)
	// any golangci-lint config file name, wherever the tree or a script mentions it.
	golangciFileRe = regexp.MustCompile(`(?:^|/)\.?golangci[\w.\-]*\.(?:ya?ml|toml|json)$`)
	golangciRefRe  = regexp.MustCompile(`\.?golangci[\w.\-]*\.(?:ya?ml|toml|json)\b`)
)

type configRef struct {
	val  string
	file string
	line int
}

// lintConfigRefs lists the `--config X` values of the golangci-lint commands in
// check.sh and the CI files.
func lintConfigRefs(v *view) []configRef {
	var out []configRef
	for _, f := range append([]string{checkScript}, v.match(isCIFile)...) {
		text, _ := v.text(f)
		for _, l := range splitLines(text) {
			if isComment(l.text) || !strings.Contains(l.text, "golangci") {
				continue
			}
			if m := configFlagRe.FindStringSubmatch(l.text); m != nil {
				out = append(out, configRef{cleanToken(m[1]), f, l.n})
			}
		}
	}
	return out
}

// lintConfigs holds the lint stage to the config file it runs with, and keeps a
// weaker config from being introduced or referenced: a PR that swaps the file
// `--config` points at, or adds .golangci.loose.yml, loosens lint without
// touching the config the lint check compares.
func (d *diff) lintConfigs() []report.Finding {
	var out []report.Finding
	baseRefs, headRefs := lintConfigRefs(d.base), lintConfigRefs(d.head)
	baseVals, headVals := map[string]bool{}, map[string]bool{}
	for _, r := range baseRefs {
		baseVals[r.val] = true
	}
	for _, r := range headRefs {
		headVals[r.val] = true
		if !baseVals[r.val] {
			out = append(out, finding(kindLintConfig, r.file, r.line,
				fmt.Sprintf("golangci-lint now runs with --config %s, which base does not use", r.val), "keep the config the lint stage runs with"))
		}
	}
	for _, r := range baseRefs {
		if headVals[r.val] {
			continue
		}
		file, line := r.file, r.line
		note := " (line is from base)"
		if len(headRefs) > 0 {
			file, line, note = headRefs[0].file, headRefs[0].line, ""
		} else {
			if text, ok := d.head.text(checkScript); ok {
				if n := lineMatching(text, regexp.MustCompile(`go run .*golangci-lint`)); n > 0 {
					file, line, note = checkScript, n, ""
				}
			}
		}
		out = append(out, finding(kindLintConfig, file, line,
			fmt.Sprintf("golangci-lint no longer runs with --config %s%s", r.val, note), "keep the config the lint stage runs with"))
	}
	known := map[string]bool{}
	for _, f := range d.base.files {
		if golangciFileRe.MatchString("/" + f) {
			known[f[strings.LastIndex("/"+f, "/"):]] = true
		}
	}
	for _, f := range d.head.files {
		if golangciFileRe.MatchString("/"+f) && !d.base.has(f) {
			out = append(out, finding(kindLintConfig, f, 1, fmt.Sprintf("a new golangci-lint config file %s was introduced", f), "extend the existing lint config instead"))
		}
	}
	for _, f := range append([]string{checkScript}, d.head.match(isCIFile)...) {
		bt, _ := d.base.text(f)
		ht, _ := d.head.text(f)
		for _, l := range added(bt, ht) {
			if isComment(l.text) {
				continue
			}
			for _, name := range golangciRefRe.FindAllString(l.text, -1) {
				if !known[name] {
					out = append(out, finding(kindLintConfig, f, l.n,
						fmt.Sprintf("%s refers to the golangci-lint config %s, which base does not have", f, name), "extend the existing lint config instead"))
				}
			}
		}
	}
	return out
}
