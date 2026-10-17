package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/tools/report"
)

const checkScript = "scripts/check.sh"

// pin is one place a gate setting (a coverage minimum, a tool version) is set:
// the default in scripts/check.sh or an override in a CI workflow.
type pin struct {
	val  string
	vec  []float64 // numeric form; nil when val cannot be read
	file string
	line int
}

func scriptPinRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`^\s*` + name + `="\$\{` + name + `:-([^}"]*)\}"`)
}

func overrideRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[\s"'])` + name + `\s*[:=]\s*["']?([^\s"']+)`)
}

type parseVec func(string) []float64

func parseNumber(s string) []float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return nil
	}
	return []float64{f}
}

// parseVersion reads vMAJOR.MINOR.PATCH (a pre-release or build suffix is
// ignored, a missing part is zero); anything else, such as "latest", is unreadable.
func parseVersion(s string) []float64 {
	m := regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$`).FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	v := make([]float64, 3)
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.ParseFloat(m[i+1], 64)
		}
	}
	return v
}

func less(a, b []float64) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// pins returns the script default and the CI overrides of one setting.
func (v *view) pins(name string, parse parseVec) (def *pin, ci []pin) {
	if text, ok := v.text(checkScript); ok {
		re := scriptPinRe(name)
		assign := regexp.MustCompile(`^\s*` + name + `=`)
		for i, l := range strings.Split(text, "\n") {
			if m := re.FindStringSubmatch(l); m != nil {
				def = &pin{val: m[1], vec: parse(m[1]), file: checkScript, line: i + 1}
				break
			}
			if def == nil && assign.MatchString(l) {
				def = &pin{val: strings.TrimSpace(l), file: checkScript, line: i + 1}
			}
		}
	}
	re := overrideRe(name)
	for _, f := range v.match(isCIFile) {
		text, _ := v.text(f)
		for i, l := range strings.Split(text, "\n") {
			if isComment(strings.TrimSpace(l)) {
				continue
			}
			if m := re.FindStringSubmatch(l); m != nil {
				ci = append(ci, pin{val: m[1], vec: parse(m[1]), file: f, line: i + 1})
			}
		}
	}
	return def, ci
}

// effective is what CI runs with: the lowest readable override, else the default.
func effective(def *pin, ci []pin) *pin {
	var best *pin
	for i := range ci {
		if ci[i].vec != nil && (best == nil || less(ci[i].vec, best.vec)) {
			best = &ci[i]
		}
	}
	if best != nil {
		return best
	}
	if def != nil && def.vec != nil {
		return def
	}
	return nil
}

// pinCheck compares one setting between base and head and reports a lowered
// value, an override that cannot be read, or a default that disappeared.
func (d *diff) pinCheck(name, kind, label string, parse parseVec, undo string) []report.Finding {
	bdef, bci := d.base.pins(name, parse)
	hdef, hci := d.head.pins(name, parse)
	if bdef == nil || bdef.vec == nil {
		return nil // nothing readable on base to hold head to
	}
	var out []report.Finding
	unreadable := func(p pin, where string) {
		out = append(out, finding(kind, p.file, p.line,
			fmt.Sprintf("%s %q in %s cannot be read as a value, so it cannot be checked against %s", label, p.val, where, bdef.val), undo))
	}
	if hdef == nil || hdef.vec == nil {
		p := pin{val: "(missing)", file: checkScript, line: 1}
		if hdef != nil {
			p = *hdef
		}
		unreadable(p, "the default in "+checkScript)
	}
	known := map[string]bool{}
	for _, p := range bci {
		known[p.file+"|"+p.val] = true
	}
	for _, p := range hci {
		if p.vec == nil && !known[p.file+"|"+p.val] {
			unreadable(p, "an override in "+p.file)
		}
	}
	reported := map[*pin]bool{}
	lowered := func(b, h *pin, what string) {
		if b != nil && h != nil && !reported[h] && less(h.vec, b.vec) {
			reported[h] = true
			out = append(out, finding(kind, h.file, h.line,
				fmt.Sprintf("%s lowered from %s to %s in %s:%d%s", label, b.val, h.val, h.file, h.line, what), undo))
		}
	}
	if hdef != nil && hdef.vec != nil {
		lowered(bdef, hdef, "")
	}
	lowered(effective(bdef, bci), effective(hdef, hci), " (what CI runs with)")
	return out
}

func (d *diff) pins() []report.Finding {
	var out []report.Finding
	out = append(out, d.pinCheck("COVERAGE_MIN", kindCoverage, "coverage minimum", parseNumber,
		"restore the old COVERAGE_MIN and raise coverage with tests instead")...)
	out = append(out, d.pinCheck("GOLANGCI_VERSION", kindTool, "GOLANGCI_VERSION pin", parseVersion,
		"keep the pinned golangci-lint version, or upgrade it")...)
	out = append(out, d.pinCheck("GOVULNCHECK_VERSION", kindTool, "GOVULNCHECK_VERSION pin", parseVersion,
		"keep the pinned govulncheck version, or upgrade it")...)
	return out
}

func lineMatching(text string, re *regexp.Regexp) int {
	for i, l := range strings.Split(text, "\n") {
		if re.MatchString(l) {
			return i + 1
		}
	}
	return 0
}

var (
	skipRe = regexp.MustCompile(`\|\|\s*true\b|^exit\s+0\b|\bif\s+false\b|\bSKIP[A-Z_]*\b|\bset\s+\+e\b`)
	// -short and -skip make `go test` pass by not running tests.
	testFlagRe = regexp.MustCompile(`\bgo test\b.*\s-(short|skip)\b`)
	cmdVerbRe  = regexp.MustCompile(`^(go (?:test|vet|build|run)|gofmt)\b`)
	errexitRe  = regexp.MustCompile(`^\s*set\s+-[A-Za-z]*e`)
)

// scriptEdits finds the ways a stage can keep its banner and still not
// run: a command removed or commented out, `|| true`, an early exit, a skip
// switch, errexit dropped, `go test -short`.
func (d *diff) scriptEdits() []report.Finding {
	b, bok := d.base.text(checkScript)
	h, hok := d.head.text(checkScript)
	if !bok || !hok {
		return nil
	}
	var out []report.Finding
	for _, l := range addedMatching(b, h, skipRe) {
		out = append(out, finding(kindStageSkipped, checkScript, l.n,
			fmt.Sprintf("a check.sh stage can now be skipped or ignored: %q", l.text), "remove the bypass and fix what the stage reports"))
	}
	if lineMatching(b, errexitRe) > 0 && lineMatching(h, errexitRe) == 0 {
		out = append(out, finding(kindStageSkipped, checkScript, lineMatching(b, errexitRe),
			"`set -e` was removed from check.sh, so a failing stage no longer fails the gate (line is where it was on base)", "restore `set -euo pipefail`"))
	}
	count := func(text string) map[string]int {
		c := map[string]int{}
		for _, l := range splitLines(text) {
			if m := cmdVerbRe.FindString(l.text); m != "" && !isComment(l.text) {
				c[m]++
			}
		}
		return c
	}
	bc, hc := count(b), count(h)
	reported := map[string]bool{}
	for _, l := range removed(b, h) {
		m := cmdVerbRe.FindString(l.text)
		if m != "" && !isComment(l.text) && hc[m] < bc[m] && !reported[m] {
			reported[m] = true
			out = append(out, finding(kindStageSkipped, checkScript, l.n,
				fmt.Sprintf("a `%s` command of check.sh was removed or commented out (%q; line is from base), so its stage no longer runs it", m, l.text),
				"restore the command"))
		}
	}
	for _, l := range addedMatching(b, h, testFlagRe) {
		out = append(out, finding(kindTestSkipped, checkScript, l.n,
			fmt.Sprintf("`go test` now skips tests: %q", l.text), "run the full test set"))
	}
	for _, f := range d.head.match(isCIFile) {
		bt, _ := d.base.text(f)
		ht, _ := d.head.text(f)
		for _, l := range addedMatching(bt, ht, testFlagRe) {
			out = append(out, finding(kindTestSkipped, f, l.n, fmt.Sprintf("`go test` now skips tests: %q", l.text), "run the full test set"))
		}
	}
	return out
}

var (
	vulnIDRe   = regexp.MustCompile(`\bGO-\d{4}-\d{4,}\b`)
	vulnToolRe = regexp.MustCompile(`(?i)vulncheck`)
	vulnHideRe = regexp.MustCompile(`(?i)exclude|ignore|suppress|-show\s+none|\|\|\s*true|grep\s+-v`)
	vulnFileRe = regexp.MustCompile(`(?i)(govulncheck|vulncheck|vuln)[^/]*(ignore|exclude|suppress|allow)`)
)

// vuln finds a govulncheck result being hidden: a vulnerability id filtered or
// allowed, the tool's failure ignored, an exclusion flag, an ignore file.
func (d *diff) vuln() []report.Finding {
	var out []report.Finding
	files := append([]string{checkScript}, d.head.match(isCIFile)...)
	for _, f := range files {
		bt, _ := d.base.text(f)
		ht, ok := d.head.text(f)
		if !ok {
			continue
		}
		for _, l := range added(bt, ht) {
			if isComment(l.text) {
				continue
			}
			if vulnIDRe.MatchString(l.text) || vulnToolRe.MatchString(l.text) && vulnHideRe.MatchString(l.text) {
				out = append(out, finding(kindVuln, f, l.n,
					fmt.Sprintf("the vulnerability scan can now be suppressed: %q", l.text), "fix or upgrade the vulnerable dependency instead of hiding the finding"))
			}
		}
	}
	for _, f := range d.head.files {
		if !d.base.has(f) && vulnFileRe.MatchString(f) {
			out = append(out, finding(kindVuln, f, 1,
				"a new file looks like a govulncheck ignore list", "fix or upgrade the vulnerable dependency instead of listing it"))
		}
	}
	return out
}
