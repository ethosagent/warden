package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ethosagent/warden/tools/report"
)

// A stage of scripts/check.sh is the run of lines after a `banner "name ..."`
// line. The script is only ever READ as text: gatecheck holds a token and the
// head script is the PR author's code, so it must never be executed here.
type scriptStage struct {
	name  string
	line  int // of the banner; 0 for the lines before the first banner
	cmds  []cmdLine
	exits []lineRef // the `exit N` lines that make the stage fail
}

type cmdLine struct {
	n      int
	text   string
	key    string          // what runs: "go test", "go vet", "go run <tool>", "PKGS="
	tokens map[string]bool // its flags and arguments, quotes stripped
}

var bannerRe = regexp.MustCompile(`^\s*banner "(\S+)`)

// scriptVerbRe finds the commands whose flags and package patterns carry the
// meaning of a stage. It runs on the line with its strings blanked, and only a
// command position counts: the start of a line, or after `;`, `&&`, `||`, `|`,
// `then`, `do`, `else`, with any VAR=value prefixes. A `go test` inside a string
// or an assignment is text, not a command.
var scriptVerbRe = regexp.MustCompile(`(?:^|[;&|]|\bthen\b|\bdo\b|\belse\b)\s*(?:\w+=\S*\s+)*(go (?:test|vet|build|run)|gofmt)\b()`)

// pkgAssignRe matches the lines that choose the package patterns of the stages.
var pkgAssignRe = regexp.MustCompile(`^(PKGS|LINT_PKGS)=\(?(.*?)\)?$`)

func cleanToken(s string) string { return strings.Trim(s, `"'();`) }

func tokensOf(fields []string) map[string]bool {
	out := map[string]bool{}
	for _, f := range fields {
		if t := cleanToken(f); t != "" {
			out[t] = true
		}
	}
	return out
}

// parseCmd reads one script line as a command, or reports that it is none
// (a comment, a banner, an echo).
func parseCmd(n int, text string) (cmdLine, bool) {
	if isComment(text) || strings.HasPrefix(text, "echo ") || strings.HasPrefix(text, "printf ") || strings.HasPrefix(text, "banner") {
		return cmdLine{}, false
	}
	if m := pkgAssignRe.FindStringSubmatch(text); m != nil {
		return cmdLine{n, text, m[1] + "=", tokensOf(strings.Fields(m[2]))}, true
	}
	loc := scriptVerbRe.FindStringSubmatchIndex(maskQuotes(text))
	if loc == nil {
		return cmdLine{}, false
	}
	key, rest := text[loc[2]:loc[3]], strings.Fields(text[loc[4]:])
	if key == "go run" {
		for i, f := range rest {
			if c := cleanToken(f); !strings.HasPrefix(c, "-") {
				key += " " + strings.SplitN(c, "@", 2)[0]
				rest = append(rest[:i:i], rest[i+1:]...)
				break
			}
		}
	}
	return cmdLine{n, text, key, tokensOf(rest)}, true
}

// parseStages splits a script into its stages; stage "" holds what precedes the
// first banner. A stage name that repeats is merged.
func parseStages(text string) []*scriptStage {
	pre := &scriptStage{}
	out := []*scriptStage{pre}
	byName := map[string]*scriptStage{"": pre}
	cur := pre
	for _, l := range splitLines(text) {
		if m := bannerRe.FindStringSubmatch(l.text); m != nil {
			if s, ok := byName[m[1]]; ok {
				cur = s
			} else {
				cur = &scriptStage{name: m[1], line: l.n}
				byName[m[1]], out = cur, append(out, cur)
			}
			continue
		}
		if exitRe.MatchString(l.text) {
			cur.exits = append(cur.exits, l)
		}
		if c, ok := parseCmd(l.n, l.text); ok {
			cur.cmds = append(cur.cmds, c)
		}
	}
	return out
}

func stageByName(ss []*scriptStage) map[string]*scriptStage {
	m := map[string]*scriptStage{}
	for _, s := range ss {
		m[s.name] = s
	}
	return m
}

// stageList compares the banners of base's and head's check.sh: a stage that
// base runs and head does not is a removed check, a banner with a new name a
// renamed one.
func (d *diff) stageList() []report.Finding {
	bt, bok := d.base.text(checkScript)
	if !bok {
		return nil // nothing to hold head to
	}
	ht, hok := d.head.text(checkScript)
	if !hok {
		return []report.Finding{finding(kindStageList, checkScript, 1,
			fmt.Sprintf("%s was deleted, so no stage runs (line is from base)", checkScript), "restore the script")}
	}
	bs, hs := parseStages(bt), parseStages(ht)
	hby, bby := stageByName(hs), stageByName(bs)
	var gone, fresh []*scriptStage
	for _, s := range bs[1:] {
		if hby[s.name] == nil {
			gone = append(gone, s)
		}
	}
	for _, s := range hs[1:] {
		if bby[s.name] == nil {
			fresh = append(fresh, s)
		}
	}
	var out []report.Finding
	for i, s := range gone {
		if i < len(fresh) {
			out = append(out, finding(kindStageRenamed, checkScript, fresh[i].line,
				fmt.Sprintf("check.sh stage %q is now called %q; a banner is how a stage is recognised (stage was at line %d on base)", s.name, fresh[i].name, s.line),
				"keep the banner name"))
			continue
		}
		out = append(out, finding(kindStageRemoved, checkScript, s.line,
			fmt.Sprintf("check.sh stage %q was removed (line is where it was on base)", s.name), "put the stage back"))
	}
	return out
}

// bestMatch returns the command among cands that has the most of want's tokens.
func bestMatch(want cmdLine, cands []cmdLine) (best cmdLine, missing []string) {
	most := -1
	for _, c := range cands {
		var miss []string
		for t := range want.tokens {
			if !c.tokens[t] {
				miss = append(miss, t)
			}
		}
		sort.Strings(miss)
		if most < 0 || len(want.tokens)-len(miss) > most {
			best, missing, most = c, miss, len(want.tokens)-len(miss)
		}
		if len(miss) == 0 {
			return c, nil
		}
	}
	return best, missing
}

var (
	// the lines that decide whether coverage passes: they must stay as written.
	coverageIntactRe = regexp.MustCompile(`\$\{total\}\s*<\s*\$\{COVERAGE_MIN\}|go tool cover -func|coverage\.product\.out`)
	exitRe           = regexp.MustCompile(`^exit\s+[1-9]`)
	coverageHeadRe   = regexp.MustCompile(`\btotal\b|COVERAGE_MIN|coverage\.product\.out`)
)

// stageCommands holds each command of a base stage to the flags and package
// patterns it had: a stage can keep its banner and still be neutered by a
// `go test` that lost -race, -coverprofile or -fuzz, or a ./... narrowed to one
// package. It also keeps the coverage comparison and the failing exits intact.
func (d *diff) stageCommands() []report.Finding {
	bt, bok := d.base.text(checkScript)
	ht, hok := d.head.text(checkScript)
	if !bok || !hok {
		return nil
	}
	bs, hs := parseStages(bt), parseStages(ht)
	hby := stageByName(hs)
	var out []report.Finding
	for _, b := range bs {
		h := hby[b.name]
		if h == nil {
			continue // reported as removed or renamed
		}
		for _, bc := range b.cmds {
			var cands []cmdLine
			for _, hc := range h.cmds {
				if hc.key == bc.key {
					cands = append(cands, hc)
				}
			}
			if len(cands) == 0 {
				out = append(out, finding(kindStageCmd, checkScript, bc.n,
					fmt.Sprintf("stage %q no longer runs `%s` (line is from base)", b.name, bc.key), "restore the command"))
				continue
			}
			best, missing := bestMatch(bc, cands)
			if len(missing) > 0 {
				out = append(out, finding(kindStageCmd, checkScript, best.n,
					fmt.Sprintf("stage %q: `%s` lost %s, which base has (%q), so it checks less", b.name, bc.key, strings.Join(missing, " "), bc.text),
					"restore the flags and the package pattern"))
			}
		}
		out = append(out, exitsKept(b, h)...)
	}
	out = append(out, d.coverageIntact(bt, ht)...)
	return out
}

// exitsKept reports a stage with fewer failing `exit N` lines than on base.
func exitsKept(b, h *scriptStage) []report.Finding {
	if len(h.exits) >= len(b.exits) {
		return nil
	}
	kind := kindStageCmd
	if b.name == "coverage" {
		kind = kindCoverageCmd
	}
	l := b.exits[len(h.exits)]
	return []report.Finding{finding(kind, checkScript, l.n,
		fmt.Sprintf("stage %q lost a failing exit (%q; line is from base), so it can no longer fail the gate", b.name, l.text), "restore the exit")}
}

func (d *diff) coverageIntact(bt, ht string) []report.Finding {
	var out []report.Finding
	for _, l := range removed(bt, ht) {
		if isComment(l.text) || !coverageIntactRe.MatchString(l.text) {
			continue
		}
		n, what := l.n, "(line is from base)"
		for _, a := range added(bt, ht) {
			if !isComment(a.text) && coverageHeadRe.MatchString(a.text) {
				n, what = a.n, fmt.Sprintf("(was %q)", l.text)
				break
			}
		}
		out = append(out, finding(kindCoverageCmd, checkScript, n,
			fmt.Sprintf("the coverage gate was changed: %q is no longer in check.sh %s", l.text, what), "restore the coverage comparison as it was"))
	}
	return out
}
