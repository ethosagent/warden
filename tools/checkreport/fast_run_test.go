package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeFastExec answers the planner's git and go list calls with a canned change
// (internal/a changed, internal/b imports it) and records every other command.
func fakeFastExec(calls *[]string) execFunc {
	const listed = `{"ImportPath":"example.com/x/internal/a","Dir":"%ROOT%/internal/a","Deps":[]}
{"ImportPath":"example.com/x/internal/b","Dir":"%ROOT%/internal/b","Imports":["example.com/x/internal/a"],"Deps":["example.com/x/internal/a"]}
{"ImportPath":"example.com/x/internal/c","Dir":"%ROOT%/internal/c","Deps":[]}
`
	return func(dir, name string, args ...string) execResult {
		line := name + " " + strings.Join(args, " ")
		switch {
		case name == "git" && args[0] == "rev-parse":
			return execResult{Stdout: []byte("deadbeef\n")}
		case name == "git" && args[0] == "merge-base":
			return execResult{Stdout: []byte("0123456789abcdef0123\n")}
		case name == "git" && args[0] == "diff":
			return execResult{Stdout: []byte("internal/a/a.go\ndocs/x.md\n")}
		case name == "git" && args[0] == "ls-files":
			return execResult{}
		case name == "go" && args[0] == "list":
			return execResult{Stdout: []byte(strings.ReplaceAll(listed, "%ROOT%", dir))}
		}
		*calls = append(*calls, line)
		return execResult{}
	}
}

func fastRunner(t *testing.T, calls *[]string, human *bytes.Buffer) *runner {
	t.Helper()
	root := t.TempDir()
	return &runner{
		cfg:   config{Root: root, Fast: true, CoverageMin: 70, GolangciVersion: "v2.12.2", GovulncheckVersion: "v1.5.0"},
		ctx:   parseCtx{Root: root, Module: "example.com/x"},
		exec:  fakeFastExec(calls),
		human: human,
		goVer: "go1.24",
	}
}

// --fast in report mode: only the per-package stages run, on exactly the planned
// packages, and the report says which packages and why.
func TestRunFastReport(t *testing.T) {
	var calls []string
	var human bytes.Buffer
	r := fastRunner(t, &calls, &human)
	rep, code := r.Run(NewScrubber(nil))
	if code != 0 || !rep.OK {
		t.Fatalf("code=%d ok=%v report=%+v", code, rep.OK, rep)
	}
	var names []string
	for _, st := range rep.Stages {
		names = append(names, st.Name)
	}
	if got := strings.Join(names, ","); got != "format,vet,archtest,lint,test" {
		t.Errorf("stages = %s, want format,vet,archtest,lint,test", got)
	}
	if rep.Fast == nil || rep.Fast.Full || len(rep.Fast.Packages) != 2 {
		t.Fatalf("report.fast = %+v", rep.Fast)
	}
	if rep.Fast.Packages[0].Reason != "changed: internal/a/a.go" || rep.Fast.Packages[1].Reason != "imports internal/a" {
		t.Errorf("reasons = %+v", rep.Fast.Packages)
	}
	if len(rep.Fast.Ignored) != 1 || rep.Fast.Ignored[0] != "docs/x.md" {
		t.Errorf("ignored = %v", rep.Fast.Ignored)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{
		"go vet -json ./internal/a ./internal/b",
		"golangci-lint@v2.12.2 run --output.json.path=",
		"go test -race -json ./internal/a ./internal/b",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "./internal/a ./internal/b") || strings.Contains(joined, "./internal/c") {
		t.Errorf("lint must be scoped to the plan:\n%s", joined)
	}
	for _, banned := range []string{"-coverprofile", "govulncheck", "-bench", "-fuzz", "go build", "gen.go"} {
		if strings.Contains(joined, banned) {
			t.Errorf("--fast must not run %q:\n%s", banned, joined)
		}
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	assertValidReport(t, b)
}

func TestRunFastNoGoChange(t *testing.T) {
	var calls []string
	var human bytes.Buffer
	r := fastRunner(t, &calls, &human)
	base := r.exec
	r.exec = func(dir, name string, args ...string) execResult {
		if name == "git" && args[0] == "diff" {
			return execResult{Stdout: []byte("docs/x.md\n")}
		}
		return base(dir, name, args...)
	}
	rep, code := r.Run(NewScrubber(nil))
	if code != 0 || len(rep.Stages) != 1 || rep.Stages[0].Name != "format" {
		t.Fatalf("code=%d stages=%+v", code, rep.Stages)
	}
	if !strings.Contains(human.String(), "no Go package changed") {
		t.Errorf("human output should say nothing changed:\n%s", human.String())
	}
	b, _ := json.Marshal(rep)
	assertValidReport(t, b)
}

// A fast run that cannot find origin/main runs the whole gate and says so.
func TestRunFastFallsBackToFullGate(t *testing.T) {
	var calls []string
	var human bytes.Buffer
	r := fastRunner(t, &calls, &human)
	base := r.exec
	r.exec = func(dir, name string, args ...string) execResult {
		if name == "git" && args[0] == "rev-parse" {
			return execResult{Code: 128}
		}
		return base(dir, name, args...)
	}
	r.cfg.FuzzTargets = writeTargets(t, "FuzzOne ./one\n")
	rep, _ := r.Run(NewScrubber(nil))
	if rep.Fast == nil || !rep.Fast.Full || !strings.Contains(rep.Fast.Why, "origin/main") {
		t.Fatalf("report.fast = %+v", rep.Fast)
	}
	if !strings.Contains(human.String(), "FULL gate") {
		t.Errorf("message missing:\n%s", human.String())
	}
	var names []string
	for _, st := range rep.Stages {
		names = append(names, st.Name)
	}
	if got := strings.Join(names, ","); got != "format,vet,archtest,lint,roadmap,build,vulncheck,test,fuzz,benchmark,coverage" {
		t.Errorf("full-gate fallback ran %s", got)
	}
	b, _ := json.Marshal(rep)
	assertValidReport(t, b)
}

func writeTargets(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fuzz-targets.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
