package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// defaultFuzzTime is how long each fuzz target runs in the gate: long enough to
// replay the corpus and explore a little, short enough to stay in the inner loop.
// The nightly workflow runs the same targets for much longer.
const defaultFuzzTime = "5s"

// fuzzTarget is one line of the targets file: a Fuzz function and its package.
type fuzzTarget struct{ Name, Pkg string }

// readFuzzTargets parses scripts/fuzz-targets.txt: "FuzzName ./pkg" per line,
// '#' starts a comment. scripts/check.sh and the nightly workflow read the same
// file, so there is one list to keep.
func readFuzzTargets(path string) ([]fuzzTarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []fuzzTarget
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "Fuzz") {
			return nil, fmt.Errorf("%s:%d: want \"FuzzName ./pkg\", got %q", path, n, sc.Text())
		}
		out = append(out, fuzzTarget{fields[0], fields[1]})
	}
	return out, sc.Err()
}

func (r *runner) fuzzTime() string {
	if r.cfg.FuzzTime == "" {
		return defaultFuzzTime
	}
	return r.cfg.FuzzTime
}

func (r *runner) fuzzTargetsPath() string {
	p := r.cfg.FuzzTargets
	if p == "" {
		p = "scripts/fuzz-targets.txt"
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(r.cfg.Root, p)
}

// stageFuzz runs every fuzz target for a short fixed time. The stage's metrics
// state the budget, so the cost of the stage is visible in the report.
func (r *runner) stageFuzz() Stage {
	targets, err := readFuzzTargets(r.fuzzTargetsPath())
	if err != nil {
		return Stage{Findings: []Finding{crashed("fuzz", "cannot read the fuzz target list: "+err.Error())}}
	}
	d, err := time.ParseDuration(r.fuzzTime())
	if err != nil || d <= 0 {
		return Stage{Findings: []Finding{crashed("fuzz", fmt.Sprintf("bad fuzz time %q", r.fuzzTime()))}}
	}
	var fs []Finding
	for _, t := range targets {
		res := r.exec(r.cfg.Root, "go", "test", "-run", "^$", "-fuzz", "^"+t.Name+"$", "-fuzztime="+r.fuzzTime(), "-json", t.Pkg)
		fs = append(fs, parseFuzz(t, res, r.ctx)...)
	}
	st := finish("fuzz", execResult{}, fs)
	st.Metrics = map[string]any{
		"targets":           len(targets),
		"fuzzTimePerTarget": r.fuzzTime(),
		"fuzzBudgetSeconds": (time.Duration(len(targets)) * d).Seconds(),
	}
	return st
}

var (
	fuzzCrasher = regexp.MustCompile(`Failing input written to (\S+)`)
	fuzzRerun   = regexp.MustCompile(`go test -run=(\S+)`)
)

// parseFuzz turns one failed fuzz run into a finding that names the crasher
// file and the command that replays it. Compile errors are left to
// buildFindings, as in the test stage.
func parseFuzz(t fuzzTarget, res execResult, c parseCtx) []Finding {
	if res.Err != nil {
		return []Finding{crashed("fuzz", t.Name+": could not run go test: "+res.Err.Error())}
	}
	if res.Code == 0 {
		return nil
	}
	if fs := buildFindings(res.Stdout, c); len(fs) > 0 {
		return fs
	}
	var text strings.Builder
	sc := newLineScanner(res.Stdout)
	for sc.Scan() {
		var ev testEvent
		if line := strings.TrimSpace(sc.Text()); line != "" && line[0] == '{' && json.Unmarshal([]byte(line), &ev) == nil && ev.Action == "output" {
			text.WriteString(ev.Output)
		}
	}
	out := text.String()
	f := Finding{Rule: "fuzz/failed", Severity: sevError, Output: strings.TrimSpace(out)}
	f.Message = fmt.Sprintf("%s failed in %s", t.Name, t.Pkg)
	f.Fix = fmt.Sprintf("run `go test -run '^%s$' %s` to see it, fix the cause", t.Name, t.Pkg)
	if m := fuzzCrasher.FindStringSubmatch(out); m != nil {
		f.Rule = "fuzz/crash"
		f.File = filepath.ToSlash(filepath.Join(strings.TrimPrefix(t.Pkg, "./"), m[1]))
		f.Message = fmt.Sprintf("%s found a crashing input, saved to %s", t.Name, f.File)
		replay := ""
		if rm := fuzzRerun.FindStringSubmatch(out); rm != nil {
			replay = fmt.Sprintf("replay it with `go test -run=%s %s`, ", rm[1], t.Pkg)
		}
		f.Fix = replay + "fix the cause, then keep the file as a regression seed. A crash in a security check (policy, CONNECT parsing, MCP) is a security finding: report it, do not just delete the file"
	}
	return []Finding{f}
}
