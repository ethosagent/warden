package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/tools/report"
	"gopkg.in/yaml.v3"
)

// gateRun matches a shell command that runs the gate.
var gateRun = regexp.MustCompile(`(^|[\s;&|])(\./)?scripts/check\.sh\b`)

// gateStep is a workflow step that runs scripts/check.sh.
type gateStep struct {
	job     string
	jobKey  *yaml.Node // the job id node
	jobMap  *yaml.Node // the job mapping
	step    *yaml.Node
	run     *yaml.Node
	runText string
}

type workflow struct {
	root  *yaml.Node
	gates []gateStep
}

func parseWorkflow(text string) (*workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("empty workflow")
	}
	w := &workflow{root: doc.Content[0]}
	jobs, _ := mapGet(w.root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return w, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job := jobs.Content[i+1]
		steps, _ := mapGet(job, "steps")
		if steps == nil {
			continue
		}
		for _, st := range steps.Content {
			run, _ := mapGet(st, "run")
			if run != nil && gateRun.MatchString(run.Value) {
				w.gates = append(w.gates, gateStep{job: jobs.Content[i].Value, jobKey: jobs.Content[i], jobMap: job, step: st, run: run, runText: run.Value})
			}
		}
	}
	return w, nil
}

// mapGet returns the value node and key node of key in a mapping.
func mapGet(n *yaml.Node, key string) (val, k *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1], n.Content[i]
		}
	}
	return nil, nil
}

// triggers is the set of events a workflow runs on.
func triggers(root *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	on, k := mapGet(root, "on")
	if on == nil {
		on, k = mapGet(root, "true") // YAML 1.1 readers turn `on` into a boolean
	}
	if on == nil {
		return out
	}
	switch on.Kind {
	case yaml.ScalarNode:
		out[on.Value] = k
	case yaml.SequenceNode:
		for _, e := range on.Content {
			out[e.Value] = e
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			out[on.Content[i].Value] = on.Content[i]
		}
	}
	return out
}

// truthy reports whether a YAML value switches something on. An expression is
// treated as on: it can evaluate either way.
func truthy(n *yaml.Node) bool {
	return n != nil && !strings.EqualFold(strings.TrimSpace(n.Value), "false")
}

// ci checks that CI still runs the gate, with --integration, on pull requests,
// unconditionally, and without letting it fail quietly.
func (d *diff) ci() []report.Finding {
	var out []report.Finding
	for _, f := range d.base.match(isWorkflow) {
		bt, _ := d.base.text(f)
		bw, err := parseWorkflow(bt)
		if err != nil || len(bw.gates) == 0 {
			continue // not a gate workflow
		}
		firstRun := bw.gates[0].run.Line
		ht, ok := d.head.text(f)
		if !ok {
			out = append(out, finding(kindCIMissing, f, firstRun,
				fmt.Sprintf("workflow %s, which ran scripts/check.sh, was deleted (line is from base)", f), "restore the workflow"))
			continue
		}
		hw, err := parseWorkflow(ht)
		if err != nil {
			out = append(out, finding(kindCIMissing, f, 1, fmt.Sprintf("workflow %s no longer parses: %v", f, err), "fix the YAML"))
			continue
		}
		if len(hw.gates) == 0 {
			out = append(out, finding(kindCIMissing, f, firstRun,
				fmt.Sprintf("%s no longer runs scripts/check.sh (line is where it ran on base)", f), "run scripts/check.sh in CI again"))
			continue
		}
		out = append(out, d.gateSteps(f, bw, hw)...)
	}
	return out
}

func (d *diff) gateSteps(f string, bw, hw *workflow) []report.Finding {
	var out []report.Finding
	// the job that ran the gate must still exist: its id is a required status check
	hjobs := map[string]bool{}
	for _, g := range hw.gates {
		hjobs[g.job] = true
	}
	seenJob := map[string]bool{}
	bflags := map[string]bool{}
	for _, g := range bw.gates {
		if !seenJob[g.job] && !hjobs[g.job] {
			out = append(out, finding(kindCIWeakened, f, g.jobKey.Line,
				fmt.Sprintf("job %q no longer runs the gate; branch protection requires a check with this name (line is from base)", g.job), "keep the gate in the same job"))
		}
		seenJob[g.job] = true
		for _, lvl := range []struct {
			name string
			n    *yaml.Node
		}{{"step", g.step}, {"job", g.jobMap}} {
			for _, key := range []string{"if", "continue-on-error"} {
				if v, _ := mapGet(lvl.n, key); v != nil {
					bflags[g.job+"|"+lvl.name+"|"+key] = true
				}
			}
		}
	}
	// --integration
	hasIntegration := func(w *workflow) bool {
		for _, g := range w.gates {
			if strings.Contains(g.runText, "--integration") {
				return true
			}
		}
		return false
	}
	if hasIntegration(bw) && !hasIntegration(hw) {
		out = append(out, finding(kindCIIntegr, f, hw.gates[0].run.Line,
			"CI no longer passes --integration to scripts/check.sh, so the integration tests do not run", "put --integration back"))
	}
	for _, g := range hw.gates {
		if regexp.MustCompile(`(^|\s)--fast\b`).MatchString(g.runText) {
			out = append(out, finding(kindCIWeakened, f, g.run.Line,
				"CI runs scripts/check.sh --fast, which checks only part of the repository", "run the full gate in CI"))
		}
		for _, lvl := range []struct {
			name string
			n    *yaml.Node
		}{{"step", g.step}, {"job", g.jobMap}} {
			for _, key := range []string{"if", "continue-on-error"} {
				v, k := mapGet(lvl.n, key)
				if v == nil || bflags[g.job+"|"+lvl.name+"|"+key] {
					continue
				}
				if key == "continue-on-error" && !truthy(v) {
					continue
				}
				what := "can now be skipped by a condition"
				if key == "continue-on-error" {
					what = "can now fail without failing the workflow"
				}
				out = append(out, finding(kindCIWeakened, f, k.Line,
					fmt.Sprintf("the %s that runs the gate (%s) %s: `%s: %s`", lvl.name, g.job, what, key, v.Value), "remove it so the gate always runs and always blocks"))
			}
		}
	}
	// pull requests
	bt, ht := triggers(bw.root), triggers(hw.root)
	if k, ok := bt["pull_request"]; ok {
		if _, still := ht["pull_request"]; !still {
			out = append(out, finding(kindCIWeakened, f, k.Line,
				"the gate no longer runs on pull requests (line is from base)", "keep the pull_request trigger"))
		}
	}
	return out
}
