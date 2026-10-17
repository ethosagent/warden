package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/tools/report"
)

// maskQuotes blanks the inside of every quoted string, keeping offsets, so that
// a `go test` or a `;` inside a string is never taken for shell syntax.
func maskQuotes(s string) string {
	b := []byte(s)
	var q byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case q == 0 && (c == '"' || c == '\''):
			q = c
		case q != 0 && c == q:
			q = 0
		case q == '"' && c == '\\' && i+1 < len(b):
			b[i], b[i+1] = ' ', ' '
			i++
		case q != 0:
			b[i] = ' '
		}
	}
	return string(b)
}

var (
	// gate variables whatever the stage commands say: the pinned settings, the
	// switches and package lists of the stages, and the coverage figure.
	gateVars = map[string]bool{
		"COVERAGE_MIN": true, "GOLANGCI_VERSION": true, "GOVULNCHECK_VERSION": true, "FUZZTIME": true,
		"PKG_STAGES": true, "LINT_PKGS": true, "PKGS": true, "FAST": true, "total": true,
	}
	varUseRe   = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)`)
	assignRe   = regexp.MustCompile(`(?:^|[;&|]|\bthen\b|\bdo\b|\belse\b)\s*(?:export\s+|readonly\s+|local\s+|declare\s+(?:-\w+\s+)?)?([A-Za-z_]\w*)(\+?)=`)
	canonicalR = regexp.MustCompile(`^([A-Za-z_]\w*)="\$\{([A-Za-z_]\w*):-[^}"]*\}"$`)
)

// gateVarsOf is the set of variables whose value decides what a stage checks:
// the fixed list and every variable a stage command of the script uses.
func gateVarsOf(text string) map[string]bool {
	out := map[string]bool{}
	for k := range gateVars {
		out[k] = true
	}
	for _, s := range parseStages(text) {
		if s.name == "" {
			continue // option parsing and report modes, before the stages
		}
		for _, c := range s.cmds {
			for _, m := range varUseRe.FindAllStringSubmatch(c.text, -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

func assignKind(name string) string {
	switch {
	case name == "COVERAGE_MIN" || name == "total":
		return kindCoverage
	case strings.HasSuffix(name, "_VERSION"):
		return kindTool
	}
	return kindStageSkipped
}

// assignments finds a gate variable assigned a value that base does not assign:
// `COVERAGE_MIN=1` after the defaults disables the coverage gate without
// touching the default pinCheck compares. The canonical `X="${X:-default}"` line
// is pinCheck's; a PKGS or LINT_PKGS line that replaces one of base's is compared
// by tokens in stageCommands, so only an additional one is new here.
func (d *diff) assignments() []report.Finding {
	bt, bok := d.base.text(checkScript)
	ht, hok := d.head.text(checkScript)
	if !bok || !hok {
		return nil
	}
	vars := gateVarsOf(bt)
	type site struct {
		l    lineRef
		name string
		plus bool
	}
	sites := func(text string) (out []site) {
		for _, l := range splitLines(text) {
			if isComment(l.text) {
				continue
			}
			m := assignRe.FindStringSubmatch(maskQuotes(l.text))
			if m == nil || !vars[m[1]] {
				continue
			}
			if c := canonicalR.FindStringSubmatch(l.text); c != nil && c[1] == c[2] {
				continue
			}
			out = append(out, site{l, m[1], m[2] == "+"})
		}
		return out
	}
	have := map[string]int{}
	plain := map[string]int{}
	for _, s := range sites(bt) {
		have[s.l.text]++
		if !s.plus {
			plain[s.name]++
		}
	}
	var out []report.Finding
	for _, s := range sites(ht) {
		if have[s.l.text] > 0 {
			have[s.l.text]--
			if !s.plus {
				plain[s.name]--
			}
			continue
		}
		if (s.name == "PKGS" || s.name == "LINT_PKGS") && !s.plus && plain[s.name] > 0 {
			plain[s.name]--
			continue
		}
		out = append(out, finding(assignKind(s.name), checkScript, s.l.n,
			fmt.Sprintf("check.sh assigns %s a value that base does not (%q), which can change what a stage checks", s.name, s.l.text),
			"remove the assignment; change the default line itself if the value is meant to change"))
	}
	return out
}

var guardRe = regexp.MustCompile(`^(?:if|elif|case|while|until)\b|&&|\|\|`)

var bannerDefRe = regexp.MustCompile(`^banner\(\)`)

// guardLines lists the lines of a script that decide whether something runs,
// keyed by the stage they follow so that a guard moved to another stage is new.
// Only the part from the `banner()` definition on counts: before it the script
// parses its options and hands over to the report modes, which leave before any
// stage runs (an `exit 0` there is still a stage-skipped finding).
func guardLines(text string) map[string][]lineRef {
	out := map[string][]lineRef{}
	cur := ""
	ls := splitLines(text)
	for i, l := range ls {
		if bannerDefRe.MatchString(l.text) {
			ls = ls[i:]
			break
		}
	}
	for _, l := range ls {
		if m := bannerRe.FindStringSubmatch(l.text); m != nil {
			cur = m[1]
			continue
		}
		if !isComment(l.text) && guardRe.MatchString(maskQuotes(l.text)) {
			out[cur] = append(out[cur], l)
		}
	}
	return out
}

// stageGuards reports an `if`, `case`, `&&` or `||` line that head has and base
// does not, around or inside a stage: a stage that keeps its banner and its
// command can still be made to run only sometimes.
func (d *diff) stageGuards() []report.Finding {
	bt, bok := d.base.text(checkScript)
	ht, hok := d.head.text(checkScript)
	if !bok || !hok {
		return nil
	}
	bg, hg := guardLines(bt), guardLines(ht)
	var out []report.Finding
	for stage, ls := range hg {
		have := map[string]int{}
		for _, l := range bg[stage] {
			have[l.text]++
		}
		for _, l := range ls {
			if have[l.text] > 0 {
				have[l.text]--
				continue
			}
			where := fmt.Sprintf("after the %q stage", stage)
			if stage == "" {
				where = "before the first stage"
			}
			out = append(out, finding(kindStageGuard, checkScript, l.n,
				fmt.Sprintf("a condition was added or changed %s: %q; a stage behind a condition may not run", where, l.text),
				"run the stage unconditionally"))
		}
	}
	return out
}

// bannerDuplicates reports a stage banner that head has more often than base: a
// decoy banner satisfies the name match while the real stage is changed.
func (d *diff) bannerDuplicates() []report.Finding {
	bt, bok := d.base.text(checkScript)
	ht, hok := d.head.text(checkScript)
	if !bok || !hok {
		return nil
	}
	count := func(text string) (map[string]int, map[string][]int) {
		c, at := map[string]int{}, map[string][]int{}
		for _, l := range splitLines(text) {
			if m := bannerRe.FindStringSubmatch(l.text); m != nil {
				c[m[1]]++
				at[m[1]] = append(at[m[1]], l.n)
			}
		}
		return c, at
	}
	bc, _ := count(bt)
	hc, hat := count(ht)
	var out []report.Finding
	for name, n := range hc {
		if bc[name] > 0 && n > bc[name] {
			line := hat[name][bc[name]]
			out = append(out, finding(kindStageDup, checkScript, line,
				fmt.Sprintf("the banner of stage %q appears %d times in check.sh, base has %d; a second banner can stand in for a stage that no longer runs", name, n, bc[name]),
				"keep one banner per stage"))
		}
	}
	return out
}

var (
	swallowRe   = regexp.MustCompile(`\|\|\s*(?:true\b|:(?:\s|;|$)|echo\b|printf\b|exit\s+0\b)|;\s*true\b`)
	ifNotGateRe = regexp.MustCompile(`^(?:if|elif)\s+!\s+(?:go (?:test|vet|build|run)|gofmt)\b`)
	failsRe     = regexp.MustCompile(`\bexit\s+(?:[1-9]|\$)|\bfalse\b|\breturn\s+[1-9]`)
)

// swallowed finds a gate command whose failure is ignored in a way skipRe does
// not see: `|| echo`, `; true`, or `if ! go test …; then :` with a then-branch
// that does not fail.
func (d *diff) swallowed() []report.Finding {
	bt, bok := d.base.text(checkScript)
	ht, hok := d.head.text(checkScript)
	if !bok || !hok {
		return nil
	}
	var out []report.Finding
	for _, l := range addedMatching(bt, ht, swallowRe) {
		out = append(out, finding(kindStageSkipped, checkScript, l.n,
			fmt.Sprintf("a check.sh command can now fail without failing the gate: %q", l.text), "remove the bypass and fix what the stage reports"))
	}
	all := splitLines(ht)
	for _, a := range added(bt, ht) {
		if isComment(a.text) || !ifNotGateRe.MatchString(a.text) {
			continue
		}
		var branch strings.Builder
		for i, l := range all {
			if l.n != a.n {
				continue
			}
			rest := a.text
			if j := strings.Index(rest, "then"); j >= 0 {
				rest = rest[j+len("then"):]
			} else {
				rest = ""
			}
			branch.WriteString(rest)
			for _, nx := range all[i+1:] {
				if nx.text == "fi" || strings.HasPrefix(nx.text, "else") || strings.HasPrefix(nx.text, "elif") {
					break
				}
				branch.WriteString("\n" + nx.text)
				if strings.Contains(rest, "fi") {
					break
				}
			}
			break
		}
		if !failsRe.MatchString(branch.String()) {
			out = append(out, finding(kindStageSkipped, checkScript, a.n,
				fmt.Sprintf("a check.sh gate command fails into a branch that does not fail: %q", a.text), "exit 1 in the branch, or drop the `if !`"))
		}
	}
	return out
}
