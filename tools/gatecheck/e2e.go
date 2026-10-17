package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/tools/report"
	"gopkg.in/yaml.v3"
)

const e2eWorkflowFile = ".github/workflows/e2e.yml"

// e2eMaxMinutes is the longest the e2e job may be allowed to run.
const e2eMaxMinutes = 15

var (
	// e2eRun matches the step that runs the suite: the go test invocation or the make target.
	e2eRun   = regexp.MustCompile(`\bgo\s+test\b[^\n]*-tags[ =]+"?e2e\b[^\n]*\./test/e2e\b|(^|[\s;&|])make\s+e2e(\s|$)`)
	setPlusE = regexp.MustCompile(`\bset\s+\+[a-z]*e`)
)

// e2e holds the `e2e` check to what the base had: a PR that rewrites the
// workflow could otherwise make its own required check pass without running the
// suite. With no e2e.yml on the base (the PR that adds it) there is nothing to
// compare and nothing is reported; the head-side shape test in tools/riskmap
// covers that case, and this check applies from the next PR on.
func (d *diff) e2e() []report.Finding {
	bt, ok := d.base.text(e2eWorkflowFile)
	if !ok {
		return nil
	}
	bw, err := parseWorkflow(bt)
	if err != nil {
		return nil
	}
	if bj, _ := mapGet(jobsOf(bw.root), "e2e"); bj == nil {
		return nil // the base had no e2e job to hold
	}
	ht, ok := d.head.text(e2eWorkflowFile)
	if !ok {
		return []report.Finding{finding(kindCIMissing, e2eWorkflowFile, 1,
			"the e2e workflow was deleted; risk.yml waits for its `e2e` check on every critical PR", "restore the workflow")}
	}
	hw, err := parseWorkflow(ht)
	if err != nil {
		return []report.Finding{finding(kindCIMissing, e2eWorkflowFile, 1, fmt.Sprintf("the e2e workflow no longer parses: %v", err), "fix the YAML")}
	}
	return e2eJobFindings(hw.root)
}

func jobsOf(root *yaml.Node) *yaml.Node {
	jobs, _ := mapGet(root, "jobs")
	return jobs
}

// e2eJobFindings checks the head's e2e job on its own.
func e2eJobFindings(root *yaml.Node) []report.Finding {
	const f = e2eWorkflowFile
	jobs := jobsOf(root)
	job, key := mapGet(jobs, "e2e")
	if job == nil {
		return []report.Finding{finding(kindCIWeakened, f, 1,
			"the job id `e2e` is gone; risk.yml waits for a check run with that name", "keep a job with id and name `e2e`")}
	}
	var out []report.Finding
	if name, k := mapGet(job, "name"); name == nil || name.Value != "e2e" {
		line := key.Line
		if k != nil {
			line = k.Line
		}
		out = append(out, finding(kindCIWeakened, f, line,
			"the e2e job's name is no longer `e2e`; the check run name is what risk.yml waits for", "name the job `e2e`"))
	}
	if v, k := mapGet(job, "continue-on-error"); v != nil && truthy(v) {
		out = append(out, finding(kindCIWeakened, f, k.Line,
			fmt.Sprintf("the e2e job can fail without failing the check: `continue-on-error: %s`", v.Value), "remove it"))
	}
	if v, k := mapGet(job, "timeout-minutes"); v == nil {
		out = append(out, finding(kindCIWeakened, f, key.Line, "the e2e job has no timeout-minutes", fmt.Sprintf("set timeout-minutes to at most %d", e2eMaxMinutes)))
	} else if n, err := strconv.Atoi(v.Value); err != nil || n > e2eMaxMinutes {
		out = append(out, finding(kindCIWeakened, f, k.Line,
			fmt.Sprintf("the e2e job's timeout-minutes is %q, above the %d-minute limit (or not a plain number)", v.Value, e2eMaxMinutes), fmt.Sprintf("set it to at most %d", e2eMaxMinutes)))
	}
	steps, _ := mapGet(job, "steps")
	var run *yaml.Node
	var step *yaml.Node
	if steps != nil {
		for _, st := range steps.Content {
			if r, _ := mapGet(st, "run"); r != nil && e2eRun.MatchString(r.Value) {
				run, step = r, st
				break
			}
		}
	}
	if run == nil {
		return append(out, finding(kindCIWeakened, f, key.Line,
			"the e2e job no longer has a step that runs `go test -tags e2e ./test/e2e/` (or `make e2e`)", "run the suite in the e2e job"))
	}
	for _, key := range []string{"continue-on-error", "if"} {
		v, k := mapGet(step, key)
		if v == nil || (key == "continue-on-error" && !truthy(v)) {
			continue
		}
		out = append(out, finding(kindCIWeakened, f, k.Line,
			fmt.Sprintf("the step that runs the e2e suite can now fail without failing the check or be skipped: `%s: %s`", key, v.Value), "remove it so the suite always runs and always blocks"))
	}
	first := run.Line // a block scalar's text starts on the line after its `|`
	if run.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		first++
	}
	for i, line := range strings.Split(run.Value, "\n") {
		if swallowRe.MatchString(line) || setPlusE.MatchString(line) {
			out = append(out, finding(kindCIWeakened, f, first+i,
				fmt.Sprintf("the e2e run step ignores a failure: %q", strings.TrimSpace(line)), "remove the bypass and fix what the suite reports"))
		}
	}
	return out
}
