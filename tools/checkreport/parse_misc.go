package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// ---- gofmt ----

// parseGofmt turns `gofmt -l .` into one finding per unformatted file. stderr
// carries syntax errors (gofmt cannot format a file that does not parse).
func parseGofmt(stdout, stderr []byte) []Finding {
	var out []Finding
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	for sc.Scan() {
		file := strings.TrimSpace(sc.Text())
		if file == "" || strings.HasPrefix(file, "vendor/") {
			continue
		}
		out = append(out, Finding{
			Rule: "gofmt/unformatted", Severity: sevError, File: file,
			Message: "file is not gofmt-formatted",
			Fix:     fmt.Sprintf("run `gofmt -w %s`", file),
		})
	}
	for _, f := range parseCompileLines(string(stderr), parseCtx{}) {
		f.Rule = "gofmt/syntax-error"
		f.Fix = fmt.Sprintf("fix the syntax error at `%s`; gofmt cannot format a file that does not parse", loc(f.File, f.Line))
		out = append(out, f)
	}
	return out
}

// ---- coverage ----

// pkgCoverage is one package's statement coverage, in the coverage metrics.
type pkgCoverage struct {
	Package string  `json:"package"`
	Percent float64 `json:"percent"`
}

// round1 rounds to one decimal, the precision `go tool cover -func` prints and
// the old gate compared against.
func round1(f float64) float64 { return math.Round(f*10) / 10 }

// coverageByPackage aggregates a Go coverage profile into per-package statement
// coverage, lowest first. It matches `go tool cover`'s own accounting: a block
// is covered when its count is non-zero. Files under tools/ are skipped, to
// match the plain gate, which filters them out of the profile.
func coverageByPackage(profile []byte, module string) (pkgs []pkgCoverage, total float64, err error) {
	type acc struct{ covered, total int }
	var allCovered, allTotal int
	pk := map[string]*acc{}
	sc := bufio.NewScanner(bytes.NewReader(profile))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// file.go:3.10,5.2 2 1
		colon := strings.LastIndex(line, ":")
		fields := strings.Fields(line[colon+1:])
		if colon < 0 || len(fields) != 3 {
			return nil, 0, fmt.Errorf("malformed coverage line %q", line)
		}
		n, err1 := strconv.Atoi(fields[1])
		cnt, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil, 0, fmt.Errorf("malformed coverage line %q", line)
		}
		file := line[:colon]
		dir := file[:max(strings.LastIndex(file, "/"), 0)]
		dir = strings.TrimPrefix(strings.TrimPrefix(dir, module), "/")
		if dir == "" {
			dir = "."
		}
		// Developer tooling is not product code: it must not lift the gate.
		if dir == "tools" || strings.HasPrefix(dir, "tools/") {
			continue
		}
		a := pk[dir]
		if a == nil {
			a = &acc{}
			pk[dir] = a
		}
		a.total += n
		allTotal += n
		if cnt > 0 {
			a.covered += n
			allCovered += n
		}
	}
	if len(pk) == 0 {
		return nil, 0, errors.New("coverage profile has no blocks")
	}
	out := make([]pkgCoverage, 0, len(pk))
	for d, a := range pk {
		p := 100.0
		if a.total > 0 {
			p = float64(a.covered) / float64(a.total) * 100
		}
		out = append(out, pkgCoverage{Package: d, Percent: round1(p)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Percent != out[j].Percent {
			return out[i].Percent < out[j].Percent
		}
		return out[i].Package < out[j].Package
	})
	if allTotal > 0 {
		total = round1(float64(allCovered) / float64(allTotal) * 100)
	}
	return out, total, sc.Err()
}

const lowestPackages = 5

// coverageStage evaluates the coverage gate on a profile. Like the old awk gate
// it fails only when the one-decimal total is strictly below minPct.
func coverageStage(profile []byte, module string, minPct float64) Stage {
	pkgs, total, err := coverageByPackage(profile, module)
	if err != nil {
		return Stage{Findings: []Finding{crashed("coverage", "cannot read coverage profile: "+err.Error())}}
	}
	lowest := pkgs[:min(lowestPackages, len(pkgs))]
	st := Stage{Metrics: map[string]any{"total": total, "min": minPct, "lowest": lowest}}
	if total < minPct {
		var names []string
		for _, p := range lowest {
			names = append(names, fmt.Sprintf("%s (%.1f%%)", p.Package, p.Percent))
		}
		st.Findings = []Finding{{
			Rule: "coverage/below-minimum", Severity: sevError,
			Message: fmt.Sprintf("total coverage %.1f%% is below minimum %s%%", total, strconv.FormatFloat(minPct, 'f', -1, 64)),
			Fix:     "add tests for the lowest-covered packages: " + strings.Join(names, ", ") + "; do not lower COVERAGE_MIN",
		}}
	}
	return st
}

// ---- roadmap ----

// parseRoadmap parses `go run docs/roadmap/gen.go check -json`.
func parseRoadmap(data []byte) []Finding {
	var res struct {
		OK     bool
		Stale  []string
		Errors []string
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return []Finding{crashed("roadmap", "unreadable gen.go check -json output: "+err.Error())}
	}
	var out []Finding
	for _, s := range res.Stale {
		f := Finding{
			Rule: "roadmap/stale", Severity: sevError, File: s,
			Message: "generated roadmap file is out of date with docs/roadmap/tickets.json",
			Fix:     "run `go run docs/roadmap/gen.go docs` and commit the regenerated files; never hand-edit them",
		}
		if file, ok := strings.CutSuffix(s, " (orphaned)"); ok {
			f.Rule, f.File = "roadmap/orphaned", file
			f.Message = "generated roadmap file no longer has a matching feature"
		}
		out = append(out, f)
	}
	for _, e := range res.Errors {
		out = append(out, Finding{
			Rule: "roadmap/invalid", Severity: sevError, File: "docs/roadmap/tickets.json",
			Message: e,
			Fix:     "fix docs/roadmap/tickets.json as the message says, then run `go run docs/roadmap/gen.go docs`",
		})
	}
	return out
}
