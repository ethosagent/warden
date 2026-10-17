package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// config is everything one run needs. scripts/check.sh is the single source of
// the tool versions and the coverage minimum, and passes them in.
type config struct {
	Root               string
	Integration        bool
	KeepGoing          bool
	CoverageMin        float64
	GolangciVersion    string
	GovulncheckVersion string
	Only               []string // run only these stages (tests, debugging)

	// Fast checks only the packages changed since origin/main plus their
	// importers (see fastPlan), and skips the stages that are not per-package.
	Fast bool
	// FuzzTime is the -fuzztime given to each fuzz target; FuzzTargets is the
	// file listing them (relative to Root), the single list check.sh and the
	// nightly workflow share.
	FuzzTime    string
	FuzzTargets string
}

type execResult struct {
	Stdout, Stderr []byte
	Code           int
	Err            error // the tool could not be started
}

// execFunc runs a command in dir. It is a seam so tests can replay captured
// output of tools that are slow or need the network (golangci-lint, govulncheck).
type execFunc func(dir, name string, args ...string) execResult

func osExec(dir, name string, args ...string) execResult {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	res := execResult{}
	err := cmd.Run()
	res.Stdout, res.Stderr = out.Bytes(), errb.Bytes()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.Code = ee.ExitCode()
	default:
		res.Err, res.Code = err, -1
	}
	return res
}

type runner struct {
	cfg   config
	ctx   parseCtx
	exec  execFunc
	human io.Writer
	goVer string

	testFailed bool // the test stage ran and failed, so coverage.out is incomplete

	plan *FastPlan // set when cfg.Fast resolved to a package subset
}

// stageDef is one check.sh stage. The title is the banner text check.sh prints
// for the same stage (a test keeps the two in step).
type stageDef struct {
	name  string
	title string
	tool  func(r *runner) string
	run   func(r *runner) Stage
}

func (r *runner) stages() []stageDef {
	goTool := func(r *runner) string { return "go@" + r.goVer }
	defs := []stageDef{
		{"format", "format (gofmt)", func(r *runner) string { return "gofmt@" + r.goVer }, (*runner).stageFormat},
		{"vet", "vet (go vet ./...)", goTool, (*runner).stageVet},
		{"archtest", "archtest (go test ./internal/archtest -run TestArchitecture)", goTool, (*runner).stageArchtest},
		{"lint", fmt.Sprintf("lint (golangci-lint %s)", r.cfg.GolangciVersion), func(r *runner) string { return "golangci-lint@" + r.cfg.GolangciVersion }, (*runner).stageLint},
		{"roadmap", "roadmap (go run docs/roadmap/gen.go check)", goTool, (*runner).stageRoadmap},
		{"build", "build (go build ./...)", goTool, (*runner).stageBuild},
		{"vulncheck", fmt.Sprintf("vulncheck (govulncheck %s)", r.cfg.GovulncheckVersion), func(r *runner) string { return "govulncheck@" + r.cfg.GovulncheckVersion }, (*runner).stageVuln},
		{"test", "test (go test -race -coverprofile)", goTool, (*runner).stageTest},
		{"fuzz", fmt.Sprintf("fuzz (go test -fuzz, %s per target)", r.fuzzTime()), goTool, (*runner).stageFuzz},
		{"benchmark", "benchmark smoke (go test -bench . -benchtime=1x)", goTool, (*runner).stageBench},
		{"coverage", fmt.Sprintf("coverage gate (min %s%%)", fmtFloat(r.cfg.CoverageMin)), func(*runner) string { return "go tool cover" }, (*runner).stageCoverage},
	}
	if r.cfg.Integration {
		defs = append(defs, stageDef{"integration", "integration (go test -tags=integration)", goTool, (*runner).stageIntegration})
	}
	if r.plan != nil {
		// --fast: per-package stages only. Everything else (build, vulncheck,
		// roadmap, fuzz, benchmark, coverage) is whole-repo work for the full gate.
		keep := map[string]bool{"format": true}
		if len(r.plan.Packages) > 0 {
			// archtest checks the whole repo every time but lives in one small
			// package, so it stays in the inner loop too (and the fast plan
			// adds this package whenever the architecture files change).
			keep["vet"], keep["lint"], keep["archtest"], keep["test"] = true, true, true, true
		}
		var out []stageDef
		for _, d := range defs {
			if keep[d.name] {
				out = append(out, d)
			}
		}
		defs = out
	}
	if len(r.cfg.Only) == 0 {
		return defs
	}
	var out []stageDef
	for _, d := range defs {
		for _, o := range r.cfg.Only {
			if d.name == o {
				out = append(out, d)
			}
		}
	}
	return out
}

// Run executes the stages and returns the finished (scrubbed) report plus the
// exit code scripts/check.sh should exit with: 0 when every stage passed, else
// the code the first failing stage's tool would have exited with.
func (r *runner) Run(sc *Scrubber) (*Report, int) {
	start := time.Now()
	rep := &Report{}
	code := 0
	stopped := false
	if r.cfg.Fast {
		plan := r.fastPlan()
		fmt.Fprintln(r.human, plan.summary())
		if !plan.Full {
			r.plan = &plan
			for _, pk := range plan.Packages {
				fmt.Fprintf(r.human, "  %s  (%s)\n", pk.Package, pk.Reason)
			}
			if len(plan.Packages) == 0 {
				fmt.Fprintln(r.human, "  no Go package changed: only the format check runs")
			}
		}
		for _, d := range r.stages() {
			plan.Stages = append(plan.Stages, d.name)
		}
		rep.Fast = &plan
	}
	for _, d := range r.stages() {
		if stopped {
			rep.Stages = append(rep.Stages, Stage{Name: d.name, Tool: d.tool(r), Skipped: true})
			continue
		}
		fmt.Fprintf(r.human, "\n=== %s ===\n", d.title)
		st := runStage(d.name, d.tool(r), func() Stage { return d.run(r) })
		// Finalize per stage so the human output below is scrubbed too.
		one := &Report{Stages: []Stage{st}}
		one.Finalize(sc)
		st = one.Stages[0]
		rep.Stages = append(rep.Stages, st)
		renderHuman(r.human, st)
		if !st.OK {
			if code == 0 {
				code = st.exit()
			}
			if !r.cfg.KeepGoing {
				stopped = true
			}
		}
	}
	rep.DurationMs = time.Since(start).Milliseconds()
	rep.Finalize(sc)
	if rep.OK {
		fmt.Fprintf(r.human, "\n=== all checks passed ===\n")
	} else {
		var bad []string
		for _, st := range rep.Stages {
			if !st.OK {
				bad = append(bad, st.Name)
			}
		}
		fmt.Fprintf(r.human, "\n=== FAILED: %s ===\n", strings.Join(bad, ", "))
	}
	return rep, code
}

// exit is the exit code check.sh used for this stage before the report existed.
func (s Stage) exit() int {
	if s.Name == "vulncheck" {
		return 3 // govulncheck's "vulnerabilities found" status
	}
	return 1
}

func renderHuman(w io.Writer, st Stage) {
	if st.OK {
		if t, ok := st.Metrics["total"]; ok && st.Name == "coverage" {
			fmt.Fprintf(w, "total coverage: %v%%\n", t)
		}
		fmt.Fprintln(w, "ok")
		return
	}
	for _, f := range st.Findings {
		where := f.File
		if where != "" && f.Line > 0 {
			where += fmt.Sprintf(":%d", f.Line)
			if f.Col > 0 {
				where += fmt.Sprintf(":%d", f.Col)
			}
		}
		if where != "" {
			where += ": "
		}
		fmt.Fprintf(w, "%s[%s] %s\n  fix: %s\n", where, f.Rule, firstLine(f.Message), f.Fix)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func fmtFloat(f float64) string { return strings.TrimSuffix(fmt.Sprintf("%g", f), ".0") }

// ---- stages ----

// tail returns the last n bytes of the combined output, where tools put the
// reason they stopped.
func tail(res execResult, n int) string {
	all := append(append([]byte{}, res.Stdout...), res.Stderr...)
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return strings.TrimSpace(string(all))
}

// finish adds the stage/crashed finding when a tool failed or died but the
// parser found nothing to blame, so a non-zero exit never reads as a pass.
func finish(stage string, res execResult, fs []Finding) Stage {
	if res.Err != nil {
		fs = append(fs, crashed(stage, "could not run the tool: "+res.Err.Error()))
	} else if res.Code != 0 && !hasError(fs) {
		f := crashed(stage, fmt.Sprintf("the tool exited with status %d without reporting a finding", res.Code))
		f.Output = tail(res, outputCap)
		fs = append(fs, f)
	}
	return Stage{Findings: fs}
}

func hasError(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == sevError || f.Severity == "" {
			return true
		}
	}
	return false
}

func (r *runner) stageFormat() Stage {
	res := r.exec(r.cfg.Root, "gofmt", "-l", ".")
	return finish("format", res, parseGofmt(res.Stdout, res.Stderr))
}

func (r *runner) stageVet() Stage {
	res := r.exec(r.cfg.Root, "go", append([]string{"vet", "-json"}, r.pkgArgs()...)...)
	fs := parseVet(res.Stdout, r.ctx)
	// Packages that do not compile never reach the analyzers; their errors are
	// plain text on stderr.
	fs = append(fs, parseCompileLines(string(res.Stderr), r.ctx)...)
	return finish("vet", res, fs)
}

func (r *runner) stageLint() Stage {
	tmp, err := os.MkdirTemp("", "checkreport-lint")
	if err != nil {
		return Stage{Findings: []Finding{crashed("lint", err.Error())}}
	}
	defer os.RemoveAll(tmp)
	jsonPath := filepath.Join(tmp, "lint.json")
	// The generated .golangci.arch.yml is the base config plus the
	// architecture linters, so one run enforces both. internal/archtest's
	// golangci-config-fresh subtest keeps the file from going stale.
	args := []string{"run", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + r.cfg.GolangciVersion,
		"run", "--output.json.path=" + jsonPath, "--config", ".golangci.arch.yml"}
	if r.plan != nil {
		args = append(args, r.pkgArgs()...)
	}
	res := r.exec(r.cfg.Root, "go", args...)
	data, rerr := os.ReadFile(jsonPath)
	if rerr != nil {
		return finish("lint", res, nil)
	}
	return finish("lint", res, parseLint(data, r.ctx))
}

// stageArchtest runs the architecture gate: every rule of architecture.yaml
// against every package, with architecture.baseline.yaml applied, plus the
// freshness pin on .golangci.arch.yml and the go.mod module manifest. One
// small package, all of ./... — cheap enough for --fast to always pay for.
func (r *runner) stageArchtest() Stage {
	res := r.exec(r.cfg.Root, "go", "test", "-json", "./internal/archtest", "-run", "TestArchitecture")
	return finish("archtest", res, parseArchtest(res.Stdout, r.ctx))
}

func (r *runner) stageRoadmap() Stage {
	res := r.exec(r.cfg.Root, "go", "run", "docs/roadmap/gen.go", "check", "-json")
	st := finish("roadmap", res, parseRoadmap(res.Stdout))
	// The generator's own tests are behind the roadmapgen build tag, so ./... never runs
	// them; check.sh runs them in this stage and so must report mode.
	tres := r.exec(r.cfg.Root, "go", "test", "-json", "docs/roadmap/gen.go", "docs/roadmap/gen_test.go")
	st.Findings = append(st.Findings, finish("roadmap", tres, parseGoTest("roadmap", tres.Stdout, r.ctx)).Findings...)
	return st
}

func (r *runner) stageBuild() Stage {
	res := r.exec(r.cfg.Root, "go", "build", "-json", "./...")
	fs := buildFindings(res.Stdout, r.ctx)
	return finish("build", res, fs)
}

func (r *runner) stageVuln() Stage {
	res := r.exec(r.cfg.Root, "go", "run", "golang.org/x/vuln/cmd/govulncheck@"+r.cfg.GovulncheckVersion, "-format", "json", "./...")
	return finish("vulncheck", res, parseVuln(res.Stdout, r.ctx))
}

func (r *runner) stageTest() Stage {
	// A leftover profile from an earlier run must never be mistaken for this one.
	_ = os.Remove(filepath.Join(r.cfg.Root, "coverage.out"))
	args := []string{"test", "-race"}
	if r.plan == nil {
		args = append(args, "-coverprofile=coverage.out")
	}
	args = append(args, "-json")
	res := r.exec(r.cfg.Root, "go", append(args, r.pkgArgs()...)...)
	st := finish("test", res, parseGoTest("test", res.Stdout, r.ctx))
	r.testFailed = hasError(st.Findings)
	return st
}

func (r *runner) stageBench() Stage {
	res := r.exec(r.cfg.Root, "go", "test", "-run", "^$", "-bench", ".", "-benchtime=1x", "-json", "./...")
	return finish("benchmark", res, parseGoTest("benchmark", res.Stdout, r.ctx))
}

// stageCoverage reads the profile the test stage wrote. When the tests failed
// the profile is incomplete, so the gate is not evaluated (it is skipped, as in
// the fail-fast script, where it is never reached).
func (r *runner) stageCoverage() Stage {
	profile, err := os.ReadFile(filepath.Join(r.cfg.Root, "coverage.out"))
	if r.testFailed || err != nil {
		return Stage{Skipped: true}
	}
	return coverageStage(profile, r.ctx.Module, r.cfg.CoverageMin)
}

func (r *runner) stageIntegration() Stage {
	res := r.exec(r.cfg.Root, "go", "test", "-tags=integration", "-json", "./test/integration/...")
	return finish("integration", res, parseGoTest("integration", res.Stdout, r.ctx))
}

var moduleLine = regexp.MustCompile(`(?m)^module\s+(\S+)`)

// readModule returns the module path from root/go.mod.
func readModule(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	m := moduleLine.FindSubmatch(b)
	if m == nil {
		return "", errors.New("no module line in go.mod")
	}
	return string(m[1]), nil
}

// pkgArgs is the package list the per-package stages run on: everything, or the
// --fast subset.
func (r *runner) pkgArgs() []string {
	if r.plan != nil {
		return r.plan.relDirs()
	}
	return []string{"./..."}
}
