package main

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// risk.yml makes a risk:critical PR wait for a check run named `e2e` on its head
// commit and fail after 30 minutes without one (#351). A pull_request `paths`
// filter that misses a critical path means that PR never gets the run, so the
// workflow's filter must cover every critical glob in .agents/risk.yaml. These
// tests keep the two from drifting apart.

type riskFile struct {
	Tiers map[string][]string `yaml:"tiers"`
}

type e2eStep struct {
	Run           string `yaml:"run"`
	If            string `yaml:"if"`
	ContinueOnErr string `yaml:"continue-on-error"`
	Shell         string `yaml:"shell"`
}

type e2eWorkflow struct {
	On struct {
		PullRequest struct {
			Paths []string `yaml:"paths"`
		} `yaml:"pull_request"`
		Schedule     []map[string]string `yaml:"schedule"`
		WorkflowCall struct {
			Inputs map[string]struct {
				Type string `yaml:"type"`
			} `yaml:"inputs"`
		} `yaml:"workflow_call"`
	} `yaml:"on"`
	Jobs map[string]struct {
		Name           string    `yaml:"name"`
		TimeoutMinutes int       `yaml:"timeout-minutes"`
		ContinueOnErr  string    `yaml:"continue-on-error"`
		Steps          []e2eStep `yaml:"steps"`
	} `yaml:"jobs"`
}

func readRepoFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestE2EWorkflowPathsCoverEveryCriticalGlob(t *testing.T) {
	var rf riskFile
	if err := yaml.Unmarshal(readRepoFile(t, "../../.agents/risk.yaml"), &rf); err != nil {
		t.Fatal(err)
	}
	critical := rf.Tiers["critical"]
	if len(critical) == 0 {
		t.Fatal("no critical globs in .agents/risk.yaml: the test would pass for nothing")
	}
	var wf e2eWorkflow
	if err := yaml.Unmarshal(readRepoFile(t, "../../.github/workflows/e2e.yml"), &wf); err != nil {
		t.Fatal(err)
	}
	paths := wf.On.PullRequest.Paths
	if len(paths) == 0 {
		t.Fatal("e2e.yml has no pull_request paths filter")
	}
	if miss := uncoveredCritical(critical, paths); len(miss) > 0 {
		t.Errorf("e2e.yml pull_request paths do not cover these critical globs from .agents/risk.yaml, so a PR touching only them would wait 30 minutes for an `e2e` check that never runs (add them to the paths filter): %s", strings.Join(miss, ", "))
	}
}

// risk.yml looks for a check run named exactly `e2e`; release.yml and the
// nightly depend on the other entry points.
func TestE2EWorkflowShape(t *testing.T) {
	var wf e2eWorkflow
	if err := yaml.Unmarshal(readRepoFile(t, "../../.github/workflows/e2e.yml"), &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["e2e"]
	if !ok || job.Name != "e2e" {
		t.Errorf("the job id and name must both be `e2e` (risk.yml waits for that check run); got id present %v, name %q", ok, job.Name)
	}
	if job.TimeoutMinutes != 15 {
		t.Errorf("timeout-minutes = %d, want 15", job.TimeoutMinutes)
	}
	for _, p := range e2eRunProblems(job.ContinueOnErr, job.Steps) {
		t.Error(p)
	}
	if len(wf.On.Schedule) == 0 {
		t.Error("e2e.yml has no nightly schedule")
	}
	if in, ok := wf.On.WorkflowCall.Inputs["image"]; !ok || in.Type != "string" {
		t.Error("e2e.yml must accept a string `image` input on workflow_call (the release passes its digest)")
	}
}

// The identity suite runs in its own job so `e2e` keeps its 15-minute cap.
// risk.yml waits for it on critical PRs and the release waits for the whole
// called workflow, so it gets the same guard as `e2e`: id and name, the cap, and
// a run step that always runs and cannot swallow a failure.
func TestE2EIdentityJobShape(t *testing.T) {
	var wf e2eWorkflow
	if err := yaml.Unmarshal(readRepoFile(t, "../../.github/workflows/e2e.yml"), &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["e2e-identity"]
	if !ok || job.Name != "e2e-identity" {
		t.Fatalf("the job id and name must both be `e2e-identity` (risk.yml waits for that check run); got id present %v, name %q", ok, job.Name)
	}
	if job.TimeoutMinutes < 1 || job.TimeoutMinutes > 15 {
		t.Errorf("timeout-minutes = %d, want 1..15", job.TimeoutMinutes)
	}
	if job.ContinueOnErr != "" && job.ContinueOnErr != "false" {
		t.Errorf("the e2e-identity job has continue-on-error: %s", job.ContinueOnErr)
	}
	run := regexp.MustCompile(`(^|[\s;&|])make\s+e2e-identity(\s|$)`)
	found := false
	for _, st := range job.Steps {
		if !run.MatchString(st.Run) {
			continue
		}
		found = true
		if st.If != "" || (st.ContinueOnErr != "" && st.ContinueOnErr != "false") {
			t.Errorf("the step that runs the identity suite must always run and block (if %q, continue-on-error %q)", st.If, st.ContinueOnErr)
		}
		if strings.Contains(st.Run, "|") && st.Shell != "bash" {
			t.Errorf("the identity run step pipes the suite into tee; it needs `shell: bash` so pipefail holds (shell %q)", st.Shell)
		}
		for _, line := range strings.Split(st.Run, "\n") {
			if e2eSwallowRe.MatchString(line) {
				t.Errorf("the identity run step ignores a failure: %q", strings.TrimSpace(line))
			}
		}
	}
	if !found {
		t.Error("the e2e-identity job has no step that runs `make e2e-identity`")
	}
	rk := string(readRepoFile(t, "../../.github/workflows/risk.yml"))
	if !strings.Contains(rk, `.name == "e2e-identity"`) {
		t.Error("risk.yml's e2e-required must wait for the `e2e-identity` check run as well as `e2e`")
	}
}

func TestUncoveredCriticalDetectsAGap(t *testing.T) {
	critical := []string{"internal/proxy/**", "deploy/compose/docker-compose*.yml", "Dockerfile", "scripts/gen-certs.sh"}
	full := []string{"internal/proxy/**", "deploy/**", "Dockerfile", "**/Dockerfile", "scripts/gen-certs.sh"}
	if miss := uncoveredCritical(critical, full); len(miss) != 0 {
		t.Fatalf("full list reported gaps: %v", miss)
	}
	for _, tc := range []struct {
		name  string
		paths []string
		want  []string
	}{
		{"glob missing", []string{"deploy/**", "Dockerfile", "**/Dockerfile", "scripts/gen-certs.sh"}, []string{"internal/proxy/**"}},
		{"narrower directory", []string{"internal/proxy/tls/**", "deploy/**", "Dockerfile", "**/Dockerfile", "scripts/gen-certs.sh"}, []string{"internal/proxy/**"}},
		{"one literal file instead of the glob", []string{"internal/proxy/**", "deploy/compose/docker-compose.yml", "Dockerfile", "**/Dockerfile", "scripts/gen-certs.sh"}, []string{"deploy/compose/docker-compose*.yml"}},
		{"root Dockerfile only (the risk glob matches any depth)", []string{"internal/proxy/**", "deploy/**", "Dockerfile", "scripts/gen-certs.sh"}, []string{"Dockerfile"}},
	} {
		if got := uncoveredCritical(critical, tc.paths); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: uncovered = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// uncoveredCritical returns the critical globs that some changed file could hit
// without matching any pattern in paths.
//
// Risk globs are matched by tools/risk (a slash-less one matches the file name
// at any depth); workflow `paths` use GitHub's syntax (a slash-less pattern
// matches the repo root only). For each critical glob this builds concrete
// files it matches, with `*` and `**` filled in different ways and a slash-less
// glob also placed under a directory, and requires every one to match some
// workflow pattern. Sample-based, so it can miss an exotic overlap, but it is
// conservative: a narrower or literal pattern fails.
func uncoveredCritical(critical, paths []string) []string {
	var res []*regexp.Regexp
	for _, p := range paths {
		res = append(res, ghGlob(p))
	}
	var miss []string
	for _, c := range critical {
		for _, file := range sampleFiles(c) {
			covered := false
			for _, re := range res {
				covered = covered || re.MatchString(file)
			}
			if !covered {
				miss = append(miss, c)
				break
			}
		}
	}
	return miss
}

// sampleFiles builds repo-relative files that the risk glob matches.
func sampleFiles(glob string) []string {
	bases := []string{glob}
	if !strings.Contains(glob, "/") {
		bases = append(bases, "x/y/"+glob) // risk matches the name at any depth
	}
	var out []string
	for _, b := range bases {
		for _, star := range []string{"x", "a-b.c"} {
			for _, dstar := range []string{"x", "x/y/z"} {
				s := strings.ReplaceAll(b, "**", "\x00")
				s = strings.ReplaceAll(s, "*", star)
				out = append(out, strings.ReplaceAll(s, "\x00", dstar))
			}
		}
	}
	return out
}

// ghGlob compiles a GitHub Actions filter pattern: `*` stays inside one path
// segment, `**` crosses directories, `?` is one non-slash character, and a
// `**/` prefix may match nothing.
func ghGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

var (
	e2eRunRe     = regexp.MustCompile(`\bgo\s+test\b[^\n]*-tags[ =]+"?e2e\b[^\n]*\./test/e2e\b|(^|[\s;&|])make\s+e2e(\s|$)`)
	e2eSwallowRe = regexp.MustCompile(`\|\|\s*(?:true\b|:(?:\s|;|$)|echo\b|printf\b|exit\s+0\b)|;\s*true\b|\bset\s+\+[a-z]*e`)
)

// e2eRunProblems says what is wrong with the step that runs the suite. The
// e2e check is only worth its name if the suite really runs and a failure fails
// the job. tools/gatecheck holds a PR to this against the base; this is the
// same guard on the head, and the only one while e2e.yml is new.
func e2eRunProblems(jobCOE string, steps []e2eStep) []string {
	var out []string
	if jobCOE != "" && jobCOE != "false" {
		out = append(out, "the e2e job has continue-on-error: "+jobCOE+"; a failing suite would not fail the check")
	}
	found := false
	for _, st := range steps {
		if !e2eRunRe.MatchString(st.Run) {
			continue
		}
		found = true
		if st.If != "" {
			out = append(out, "the step that runs the suite has `if: "+st.If+"`; it must always run")
		}
		if st.ContinueOnErr != "" && st.ContinueOnErr != "false" {
			out = append(out, "the step that runs the suite has continue-on-error: "+st.ContinueOnErr)
		}
		for _, line := range strings.Split(st.Run, "\n") {
			if e2eSwallowRe.MatchString(line) {
				out = append(out, "the step that runs the suite ignores a failure: "+line)
			}
		}
	}
	if !found {
		out = append(out, "the e2e job has no step that runs `go test -tags e2e ./test/e2e/` (or `make e2e`)")
	}
	return out
}

func TestE2ERunProblemsDetectsNeutering(t *testing.T) {
	good := "go test -tags e2e -count=1 ./test/e2e/ -json > e2e.jsonl"
	for _, tc := range []struct {
		name  string
		job   string
		steps []e2eStep
		fails bool
	}{
		{"good", "", []e2eStep{{Run: good}}, false},
		{"make target", "", []e2eStep{{Run: "make e2e"}}, false},
		{"|| true", "", []e2eStep{{Run: good + " || true"}}, true},
		{"|| exit 0", "", []e2eStep{{Run: good + " || exit 0"}}, true},
		{"set +e", "", []e2eStep{{Run: "set +e\n" + good}}, true},
		{"step continue-on-error", "", []e2eStep{{Run: good, ContinueOnErr: "true"}}, true},
		{"step made conditional", "", []e2eStep{{Run: good, If: "github.actor != 'x'"}}, true},
		{"job continue-on-error", "true", []e2eStep{{Run: good}}, true},
		{"run step removed", "", []e2eStep{{Run: "make e2e-down"}}, true},
	} {
		if got := e2eRunProblems(tc.job, tc.steps); (len(got) > 0) != tc.fails {
			t.Errorf("%s: problems = %v, want failure %v", tc.name, got, tc.fails)
		}
	}
}
