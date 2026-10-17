package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/tools/risk"
	"gopkg.in/yaml.v3"
)

// These tests hold the real repository to the contracts the checks rely on, so
// a refactor of ci.yml, check.sh or the lint config cannot silently blind them.

func TestRealCIWorkflowRunsTheGate(t *testing.T) {
	w, err := parseWorkflow(mustRead(t, "../../.github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.gates) == 0 || w.gates[0].job != "check" {
		t.Fatalf("ci.yml must run scripts/check.sh in the job named check (a required status check): %+v", w.gates)
	}
	if !strings.Contains(w.gates[0].runText, "--integration") {
		t.Errorf("ci.yml gate step lost --integration: %q", w.gates[0].runText)
	}
	if _, ok := triggers(w.root)["pull_request"]; !ok {
		t.Error("ci.yml must run on pull_request")
	}
}

func TestRealCheckShDefaultsAreReadable(t *testing.T) {
	d := &view{cache: map[string]string{checkScript: mustRead(t, "../../scripts/check.sh")}, files: []string{checkScript}}
	for name, parse := range map[string]parseVec{"COVERAGE_MIN": parseNumber, "GOLANGCI_VERSION": parseVersion, "GOVULNCHECK_VERSION": parseVersion} {
		if def, _ := d.pins(name, parse); def == nil || def.vec == nil {
			t.Errorf("%s default in scripts/check.sh is not readable by gatecheck: %+v", name, def)
		}
	}
}

func TestRealRepoAgainstItselfHasNoFindings(t *testing.T) {
	root := dirTree{"../.."}
	fs, err := Compare(root, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("a tree compared with itself weakened nothing, got:\n%s", dump(fs))
	}
}

func TestRealLintConfigRequiresNolintReasons(t *testing.T) {
	root, err := parseYAML(mustRead(t, "../../.golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	en, _ := path(root, "linters", "enable")
	for _, it := range items(en) {
		enabled = enabled || it.canon == "nolintlint"
	}
	if !enabled {
		t.Fatal("nolintlint must be enabled in .golangci.yml")
	}
	for _, key := range []string{"require-explanation", "require-specific"} {
		if v, _ := path(root, "linters", "settings", "nolintlint", key); v == nil || v.Value != "true" {
			t.Errorf("nolintlint %s must be true", key)
		}
	}
}

func TestRealRiskMapGatesCoverTheGateFiles(t *testing.T) {
	m, err := risk.Parse([]byte(mustRead(t, "../../.agents/risk.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	// every file gatecheck itself reads to find a weakening must be protected
	for _, f := range []string{checkScript, archFile, baselineFile, ".golangci.yml", ".golangci.arch.yml",
		".github/workflows/ci.yml", ".github/workflows/gates.yml", ".github/workflows/risk.yml",
		".github/actions/gate/action.yml", ".golangci.arch.yaml", ".golangci.yaml",
		".agents/risk.yaml", "scripts/fuzz-targets.txt", "tools/gatecheck/compare.go", "tools/approval/approval.go",
		"tools/risk/risk.go", "tools/riskmap/main.go", "tools/checkreport/runner.go"} {
		if got := m.Classify([]string{f}).Tier; got != risk.Gates {
			t.Errorf("%s is %s, want gates", f, got)
		}
	}
	if _, err := os.Stat("../../.github/workflows/gates.yml"); err != nil {
		t.Error(err)
	}
}

var usesRe = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)(.*)$`)

func TestRealWorkflowsPinActionsToCommitSHAs(t *testing.T) {
	pinned := regexp.MustCompile(`^[\w.\-]+/[\w.\-/]+@[0-9a-f]{40}$`)
	for _, f := range []string{"gates.yml", "risk.yml", "e2e.yml"} {
		text := mustRead(t, "../../.github/workflows/"+f)
		ms := usesRe.FindAllStringSubmatch(text, -1)
		if len(ms) == 0 {
			t.Fatalf("%s uses no action: the test would pass for nothing", f)
		}
		for _, m := range ms {
			if !pinned.MatchString(m[1]) || !regexp.MustCompile(`^\s*#\s*v\d`).MatchString(m[2]) {
				t.Errorf("%s: %q must be pinned to a full commit SHA with a version comment (# vN), got %q", f, m[1], m[2])
			}
		}
	}
}

// The gates job holds a token and the PR author controls head/: nothing in head/
// may run there, and git must run in the base checkout (a stale fork lacks the
// base commit).
func TestRealGatesWorkflowNeverRunsHeadCode(t *testing.T) {
	w, err := parseWorkflow(mustRead(t, "../../.github/workflows/gates.yml"))
	if err != nil {
		t.Fatal(err)
	}
	jobs, _ := mapGet(w.root, "jobs")
	steps, _ := mapGet(mapGetValue(jobs, "gates"), "steps")
	if steps == nil {
		t.Fatal("gates.yml has no gates job with steps")
	}
	headRef := regexp.MustCompile(`(^|[\s;&|(="'])(\./)?head/|\bcd\s+head\b|-C\s+head\b|-dir\s+head\b`)
	runs := 0
	for _, st := range steps.Content {
		run, _ := mapGet(st, "run")
		if run == nil {
			continue
		}
		runs++
		if headRef.MatchString(run.Value) {
			t.Errorf("a gates.yml step touches head/ outside of gatecheck's -head argument:\n%s", run.Value)
		}
	}
	text := mustRead(t, "../../.github/workflows/gates.yml")
	for _, want := range []string{"-dir base", "refs/pull/${{ github.event.pull_request.number }}/head:refs/remotes/pr/head", "secrets.GATES_TOKEN || github.token"} {
		if !strings.Contains(text, want) {
			t.Errorf("gates.yml lost %q", want)
		}
	}
	if runs == 0 {
		t.Fatal("gates.yml has no run step")
	}
}

func mapGetValue(n *yaml.Node, key string) *yaml.Node {
	v, _ := mapGet(n, key)
	return v
}

func TestRealRiskWorkflowTolerantAndPaged(t *testing.T) {
	text := mustRead(t, "../../.github/workflows/risk.yml")
	if !strings.Contains(text, "gh api --paginate") {
		t.Error("risk.yml must page the e2e check-runs read")
	}
	if strings.Contains(text, `--remove-label "$remove"`) {
		t.Error("risk.yml removes all other tier labels in one call, which fails when one is absent")
	}
}
