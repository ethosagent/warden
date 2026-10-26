package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/archtest"
)

// copyFixture builds a throwaway module from testdata/fixtures/<name>. Sources
// are stored as *.txt so gofmt, vet and lint ignore the deliberately broken code.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", "fixtures", name)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if !strings.HasSuffix(rel, ".txt") || strings.HasPrefix(filepath.Base(rel), "mock-") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, strings.TrimSuffix(rel, ".txt"))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "go.mod")); err != nil {
		if err := os.WriteFile(filepath.Join(dst, "go.mod"), []byte("module example.com/fx\n\ngo 1.24\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// mockExec replays captured lint/govulncheck output (those tools are slow and
// need the network) and runs everything else for real.
func mockExec(t *testing.T, fixture string) execFunc {
	return func(dir, name string, args ...string) execResult {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "golangci-lint@"):
			b, err := os.ReadFile(filepath.Join("testdata", "fixtures", fixture, "mock-golangci.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range args {
				if p, ok := strings.CutPrefix(a, "--output.json.path="); ok {
					if err := os.WriteFile(p, b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			return execResult{Code: 1}
		case strings.Contains(joined, "govulncheck@"):
			b, err := os.ReadFile(filepath.Join("testdata", "fixtures", fixture, "mock-govulncheck.json"))
			if err != nil {
				t.Fatal(err)
			}
			return execResult{Stdout: b}
		case strings.Contains(joined, "./internal/archtest"):
			// The gate is replayed: a fixture module does not carry
			// internal/archtest, and the engine has its own tests.
			b, err := os.ReadFile(filepath.Join("testdata", "fixtures", fixture, "mock-archtest.json"))
			if err != nil {
				t.Fatal(err)
			}
			return execResult{Stdout: b, Code: 1}
		}
		return osExec(dir, name, args...)
	}
}

func runFixture(t *testing.T, fixture, root string, cfg config, environ []string) (*Report, int) {
	t.Helper()
	cfg.Root = root
	if cfg.CoverageMin == 0 {
		cfg.CoverageMin = 70
	}
	cfg.GolangciVersion, cfg.GovulncheckVersion = "v2.12.2", "v1.5.0"
	mod, err := readModule(root)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: cfg, ctx: parseCtx{Root: root, Module: mod}, exec: mockExec(t, fixture), human: io.Discard, goVer: "go-test"}
	rep, code := r.Run(NewScrubber(environ))
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	assertValidReport(t, b)
	return rep, code
}

func stageByName(t *testing.T, rep *Report, name string) Stage {
	t.Helper()
	for _, st := range rep.Stages {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("no stage %q in %+v", name, rep.Stages)
	return Stage{}
}

// TestEachStageFixture is the ticket's acceptance table: a fixture that breaks
// each stage, and for each the report names the stage, rule, file, line and a
// non-empty fix.
func TestEachStageFixture(t *testing.T) {
	cases := []struct {
		name, fixture, stage, rule, file string
		line                             int
		cfg                              config
	}{
		{"unformatted file", "unformatted", "format", "gofmt/unformatted", "a.go", 0, config{Only: []string{"format"}}},
		{"vet error", "vet", "vet", "vet/printf", "a.go", 6, config{Only: []string{"vet"}}},
		{"architecture violation (replayed)", "archtest", "archtest", "archtest/X3", "internal/worker/worker.go", 41, config{Only: []string{"archtest"}}},
		{"lint error (replayed)", "lint", "lint", "errcheck", "a.go", 9, config{Only: []string{"lint"}}},
		{"compile error", "compile", "build", "build/compile-error", "a.go", 4, config{Only: []string{"build"}}},
		{"vulnerable module (mocked)", "vuln", "vulncheck", "GO-2026-5030", "a.go", 9, config{Only: []string{"vulncheck"}}},
		{"failing test", "failtest", "test", "test/failed", "a_test.go", 7, config{Only: []string{"test"}}},
		{"data race", "race", "test", "test/data-race", "a_test.go", 8, config{Only: []string{"test"}}},
		{"benchmark panic", "benchpanic", "benchmark", "benchmark/panic", "a_test.go", 7, config{Only: []string{"benchmark"}}},
		{"coverage below minimum", "lowcov", "coverage", "coverage/below-minimum", "", 0, config{Only: []string{"test", "coverage"}}},
		{"failing integration test", "integration", "integration", "integration/failed", "test/integration/a_test.go", 8, config{Only: []string{"integration"}, Integration: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := copyFixture(t, tc.fixture)
			rep, code := runFixture(t, tc.fixture, root, tc.cfg, nil)
			if rep.OK || code == 0 {
				t.Fatalf("a broken fixture must fail the report: ok=%v code=%d", rep.OK, code)
			}
			st := stageByName(t, rep, tc.stage)
			if st.OK {
				t.Fatalf("stage %s should have failed: %+v", tc.stage, st)
			}
			var found *Finding
			for i, f := range st.Findings {
				if f.Rule == tc.rule {
					found = &st.Findings[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no finding with rule %q: %+v", tc.rule, st.Findings)
			}
			// The race fixture's two writes are on lines 8 (goroutine) and 9 (test
			// body); the race detector reports whichever access it catches second,
			// which depends on scheduling, so either line is the race's location.
			raceOtherLine := tc.rule == "test/data-race" && found.Line == 9
			if found.File != tc.file || (found.Line != tc.line && !raceOtherLine) {
				t.Errorf("location = %s:%d, want %s:%d", found.File, found.Line, tc.file, tc.line)
			}
			if found.Fix == "" || found.Message == "" || found.Severity != "error" {
				t.Errorf("incomplete finding: %+v", found)
			}
		})
	}
}

func TestCoverageMetricsAreReportedEvenWhenPassing(t *testing.T) {
	root := copyFixture(t, "clean")
	rep, code := runFixture(t, "clean", root, config{Only: []string{"test", "coverage"}, CoverageMin: 70}, nil)
	if !rep.OK || code != 0 {
		t.Fatalf("clean fixture should pass: code=%d %+v", code, rep)
	}
	m := stageByName(t, rep, "coverage").Metrics
	if m["total"] != 100.0 || m["min"] != 70.0 {
		t.Errorf("metrics: %+v", m)
	}
}

func TestFailFastSkipsLaterStagesAndKeepGoingRunsThem(t *testing.T) {
	root := copyFixture(t, "unformatted")
	cfg := config{Only: []string{"format", "vet"}}
	rep, _ := runFixture(t, "unformatted", root, cfg, nil)
	if vet := stageByName(t, rep, "vet"); !vet.Skipped || vet.OK {
		t.Errorf("fail-fast should skip vet: %+v", vet)
	}
	cfg.KeepGoing = true
	rep, _ = runFixture(t, "unformatted", root, cfg, nil)
	if vet := stageByName(t, rep, "vet"); vet.Skipped || !vet.OK {
		t.Errorf("keep-going should run vet: %+v", vet)
	}
}

func TestCoverageSkippedWhenTestsFail(t *testing.T) {
	root := copyFixture(t, "failtest")
	rep, _ := runFixture(t, "failtest", root, config{Only: []string{"test", "coverage"}, KeepGoing: true}, nil)
	if c := stageByName(t, rep, "coverage"); !c.Skipped {
		t.Errorf("coverage must not be judged on a partial profile: %+v", c)
	}
}

func TestCanarySecretNeverReachesReport(t *testing.T) {
	const envCanary = "canary-token-value-4711"
	root := copyFixture(t, "canary")
	env := []string{"CHECKREPORT_CANARY_TOKEN=" + envCanary}
	t.Setenv("CHECKREPORT_CANARY_TOKEN", envCanary)
	var human bytes.Buffer
	cfg := config{Only: []string{"test"}, GolangciVersion: "v", GovulncheckVersion: "v", CoverageMin: 70, Root: root}
	mod, _ := readModule(root)
	r := &runner{cfg: cfg, ctx: parseCtx{Root: root, Module: mod}, exec: osExec, human: &human, goVer: "x"}
	rep, code := r.Run(NewScrubber(env))
	if code == 0 || rep.OK {
		t.Fatal("canary test must fail")
	}
	b, _ := json.Marshal(rep)
	assertValidReport(t, b)
	for _, secret := range []string{"AKIAABCDEFGHIJKLMNOP", envCanary} {
		if strings.Contains(string(b), secret) || strings.Contains(human.String(), secret) {
			t.Errorf("secret %q leaked:\nreport: %s\nhuman: %s", secret, b, human.String())
		}
	}
	if !strings.Contains(string(b), "test/failed") {
		t.Errorf("the failure itself must still be reported: %s", b)
	}
}

func TestStaleRoadmapFixture(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, "docs", "roadmap"), os.DirFS("../../docs/roadmap")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/fx\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	readme := filepath.Join(root, "docs", "roadmap", "README.md")
	b, _ := os.ReadFile(readme)
	if err := os.WriteFile(readme, append(b, "hand edit\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, code := runFixture(t, "unformatted", root, config{Only: []string{"roadmap"}}, nil)
	st := stageByName(t, rep, "roadmap")
	if code == 0 || st.OK || len(st.Findings) != 1 {
		t.Fatalf("stale roadmap must fail: code=%d %+v", code, st)
	}
	f := st.Findings[0]
	if f.Rule != "roadmap/stale" || f.File != "docs/roadmap/README.md" || !strings.Contains(f.Fix, "gen.go docs") {
		t.Errorf("finding: %+v", f)
	}
}

// TestRoadmapGeneratorTestFailureFailsStage pins that report mode runs the
// generator's own tests (check.sh does, in plain mode) and that a failing one
// fails the roadmap stage with a finding, so both modes give the same verdict.
func TestRoadmapGeneratorTestFailureFailsStage(t *testing.T) {
	root := copyFixture(t, "clean")
	failJSON := readTestdata(t, "gotest_fail.json")
	var ran []string
	cfg := config{Root: root, Only: []string{"roadmap"}, KeepGoing: true, GolangciVersion: "v", GovulncheckVersion: "v", CoverageMin: 70}
	r := &runner{cfg: cfg, ctx: parseCtx{Root: root, Module: "example.com/fx"}, human: io.Discard, goVer: "x",
		exec: func(dir, name string, args ...string) execResult {
			ran = append(ran, strings.Join(args, " "))
			if len(args) > 0 && args[0] == "test" {
				return execResult{Stdout: failJSON, Code: 1}
			}
			return execResult{Stdout: []byte(`{"ok":true}`)}
		}}
	rep, code := r.Run(NewScrubber(nil))
	st := stageByName(t, rep, "roadmap")
	if code == 0 || st.OK || len(st.Findings) != 1 || st.Findings[0].Rule != "roadmap/failed" {
		t.Fatalf("a failing generator test must fail the stage: code=%d %+v", code, st)
	}
	want := "test -json docs/roadmap/gen.go docs/roadmap/gen_test.go"
	if len(ran) != 2 || ran[1] != want {
		t.Errorf("commands run = %q, want the check then %q", ran, want)
	}
}

func TestCrashingToolBecomesFinding(t *testing.T) {
	root := copyFixture(t, "clean")
	cfg := config{Root: root, Only: []string{"format", "lint"}, KeepGoing: true, GolangciVersion: "v", GovulncheckVersion: "v", CoverageMin: 70}
	r := &runner{cfg: cfg, ctx: parseCtx{Root: root, Module: "example.com/fx"}, human: io.Discard, goVer: "x",
		exec: func(dir, name string, args ...string) execResult {
			if name == "gofmt" {
				return execResult{Err: os.ErrNotExist, Code: -1}
			}
			return execResult{Code: 2, Stderr: []byte("golangci-lint: config invalid")} // dies, writes no JSON
		}}
	rep, code := r.Run(NewScrubber(nil))
	b, _ := json.Marshal(rep)
	assertValidReport(t, b)
	if code == 0 || rep.OK {
		t.Fatal("crashes must fail the run")
	}
	for _, name := range []string{"format", "lint"} {
		st := stageByName(t, rep, name)
		if len(st.Findings) != 1 || st.Findings[0].Rule != "stage/crashed" || st.Findings[0].Fix == "" {
			t.Errorf("%s: %+v", name, st)
		}
	}
	if o := stageByName(t, rep, "lint").Findings[0].Output; !strings.Contains(o, "config invalid") {
		t.Errorf("tool output should be attached: %q", o)
	}
}

// TestStagesDeclared keeps runner stage names in step with the stage names
// architecture rules may declare (`stage:`): a stage the runner adds must be
// declarable, and a declared stage must exist here — otherwise a rule points
// at a stage the gate never runs.
func TestStagesDeclared(t *testing.T) {
	r := &runner{cfg: config{Integration: true, CoverageMin: 70, GolangciVersion: "v2.12.2", GovulncheckVersion: "v1.5.0"}}
	declared := map[string]bool{}
	for _, d := range r.stages() {
		declared[d.name] = true
	}
	allowed := archtest.CheckStages()
	if len(allowed) != len(declared) {
		t.Errorf("archtest declares %d stages, the runner runs %d — keep the lists in step", len(allowed), len(declared))
	}
	for _, s := range allowed {
		if !declared[s] {
			t.Errorf("archtest.CheckStages has %q but the runner has no such stage", s)
		}
	}
	for s := range declared {
		if !containsStage(allowed, s) {
			t.Errorf("runner stage %q is not in archtest.CheckStages — rules cannot declare it", s)
		}
	}
}

func containsStage(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
