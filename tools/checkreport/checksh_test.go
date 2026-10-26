package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/checksh golden files")

// The shims stand in for gofmt and go so check.sh's own output can be pinned
// without running the real (slow, networked) tools. They log every invocation,
// so the golden files also pin exactly which commands the script runs.
const goShim = `#!/bin/bash
echo "go $*" >> "$SHIM_LOG"
case "$1 $2" in
"vet "*) ;;
"run github.com/golangci/"*) echo "lint ran" ;;
"run docs/roadmap/gen.go") echo "roadmap ok" ;;
"test docs/roadmap/gen.go") [ -n "$SHIM_GEN_TEST_FAIL" ] && { echo "FAIL	command-line-arguments"; exit 1; }; echo "ok  	command-line-arguments	0.1s" ;;
"build ./..."*) ;;
"run golang.org/x/vuln/"*) echo "No vulnerabilities found." ;;
"test -race"*) echo "ok  	example.com/x	0.1s" ;;
"test ./internal/archtest"*) echo "ok  	example.com/x/internal/archtest	0.2s" ;;
"test -run"*) echo "bench output (discarded by the script)" ;;
"build -o"*) printf '#!/bin/bash\nprintf "%%b" "$FAKE_PLAN"\n' > "$3"; chmod +x "$3" ;;
"tool cover") printf 'x.go:1:\tF\t100.0%%\ntotal:\t(statements)\t%s\n' "${SHIM_COVERAGE:-85.9%}" ;;
"test -tags=integration"*) echo "ok  	example.com/integration	0.2s" ;;
*) echo "shim: unexpected go invocation: $*" >&2; exit 99 ;;
esac
`

const gofmtShim = `#!/bin/bash
echo "gofmt $*" >> "$SHIM_LOG"
[ -n "$SHIM_UNFORMATTED" ] && printf '%s\n' "$SHIM_UNFORMATTED"
exit 0
`

// checkScript is the script under test; CHECK_SH points it at another copy (used
// once to capture the golden files from the pre-change script).
func checkScript(t *testing.T) string {
	if p := os.Getenv("CHECK_SH"); p != "" {
		return p
	}
	abs, err := filepath.Abs("../../scripts/check.sh")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// sandboxScript copies the script into a throwaway repo root, because check.sh
// cds to its own repo root and writes coverage.product.out there. In the sandbox
// the run neither touches the real tree nor depends on whether the last full run
// left a coverage.out behind. The fuzz target list is fixed so the golden files
// do not change when a real target is added.
func sandboxScript(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	body, err := os.ReadFile(checkScript(t))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":                   "module example.com/x\n\ngo 1.24\n",
		"coverage.out":             "",
		"scripts/check.sh":         string(body),
		"scripts/check-secrets.sh": "#!/bin/bash\necho ok\n",
		"scripts/fuzz-targets.txt": "# sandbox list\nFuzzOne ./one\nFuzzTwo ./two\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "scripts", "check.sh")
}

func runCheckSh(t *testing.T, env []string, args ...string) string {
	t.Helper()
	shims := t.TempDir()
	for name, body := range map[string]string{"go": goShim, "gofmt": gofmtShim} {
		if err := os.WriteFile(filepath.Join(shims, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(t.TempDir(), "log")
	script := sandboxScript(t)
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append([]string{"PATH=" + shims + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "SHIM_LOG=" + logPath}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	log, _ := os.ReadFile(logPath)
	return fmt.Sprintf("exit: %d\n--- stdout ---\n%s--- stderr ---\n%s--- commands ---\n%s", code, stdout.String(), stderr.String(), log)
}

// TestCheckShHumanOutputUnchanged pins what scripts/check.sh printed, which
// streams it printed it on, its exit codes and the commands it ran, before the
// JSON flags existed. Without flags none of it may change.
func TestCheckShHumanOutputUnchanged(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		args []string
	}{
		{"pass", nil, nil},
		{"pass-integration", nil, []string{"--integration"}},
		{"unformatted", []string{"SHIM_UNFORMATTED=internal/x.go"}, nil},
		{"low-coverage", []string{"SHIM_COVERAGE=61.5%"}, nil},
		{"custom-min", []string{"SHIM_COVERAGE=61.5%", "COVERAGE_MIN=60"}, nil},
		{"unknown-arg", nil, []string{"--bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runCheckSh(t, tc.env, tc.args...)
			golden := filepath.Join("testdata", "checksh", tc.name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("check.sh output changed.\n--- want ---\n%s\n--- got ---\n%s", want, got)
			}
		})
	}
}

// TestCheckShBannersMatchRunnerStages keeps the plain script and the Go runner
// (used for --json, --json-out and --keep-going) in step: every banner the
// script prints must be a stage title the runner prints, in the same order.
func TestCheckShBannersMatchRunnerStages(t *testing.T) {
	b, err := os.ReadFile(checkScript(t))
	if err != nil {
		t.Fatal(err)
	}
	var script []string
	for _, m := range regexp.MustCompile(`(?m)^\s*banner "([^"]+)"`).FindAllStringSubmatch(string(b), -1) {
		title := m[1]
		if title == "all checks passed" {
			continue
		}
		title = strings.ReplaceAll(title, "${GOLANGCI_VERSION}", "v2.12.2")
		title = strings.ReplaceAll(title, "${GOVULNCHECK_VERSION}", "v1.5.0")
		title = strings.ReplaceAll(title, "${COVERAGE_MIN}", "70")
		title = strings.ReplaceAll(title, "${FUZZTIME}", "5s")
		script = append(script, title)
	}
	r := &runner{cfg: config{Integration: true, CoverageMin: 70, GolangciVersion: "v2.12.2", GovulncheckVersion: "v1.5.0"}}
	var runnerTitles []string
	for _, d := range r.stages() {
		runnerTitles = append(runnerTitles, d.title)
	}
	if strings.Join(script, "\n") != strings.Join(runnerTitles, "\n") {
		t.Errorf("scripts/check.sh stages and tools/checkreport stages differ.\nscript:\n  %s\nrunner:\n  %s",
			strings.Join(script, "\n  "), strings.Join(runnerTitles, "\n  "))
	}
}

// TestCheckShReportModePassesExactArguments pins the arguments check.sh hands to
// checkreport. Dropping one (say -coverage-min or -integration) would let report
// mode pass where plain mode fails, and no other test would notice.
func TestCheckShReportModePassesExactArguments(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"json", nil, []string{"--json"},
			"-coverage-min 70 -golangci-version v2.12.2 -govulncheck-version v1.5.0 -fuzz-time 5s -json"},
		{"json-integration-min", []string{"COVERAGE_MIN=81.5", "GOLANGCI_VERSION=v9.9.9", "GOVULNCHECK_VERSION=v8.8.8"},
			[]string{"--json", "--integration"},
			"-coverage-min 81.5 -golangci-version v9.9.9 -govulncheck-version v8.8.8 -fuzz-time 5s -integration -json"},
		{"keep-going-json-out", nil, []string{"--keep-going", "--json-out", "/tmp/r.json"},
			"-coverage-min 70 -golangci-version v2.12.2 -govulncheck-version v1.5.0 -fuzz-time 5s -keep-going -json-out /tmp/r.json"},
		{"fast", nil, []string{"--fast", "--json"},
			"-coverage-min 70 -golangci-version v2.12.2 -govulncheck-version v1.5.0 -fuzz-time 5s -fast -json"},
		{"list-stages", nil, []string{"--list-stages"},
			"-list-stages -golangci-version v2.12.2 -govulncheck-version v1.5.0 -fuzz-time 5s"},
		{"list-stages-integration-json", nil, []string{"--json", "--integration", "--list-stages"},
			"-list-stages -golangci-version v2.12.2 -govulncheck-version v1.5.0 -fuzz-time 5s -integration -json"},
		{"fuzztime-env", []string{"FUZZTIME=30s"}, []string{"--json"},
			"-coverage-min 70 -golangci-version v2.12.2 -govulncheck-version v1.5.0 -fuzz-time 30s -json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			argsLog := filepath.Join(dir, "args")
			// The stub stands in for the built checkreport binary.
			shim := "#!/bin/bash\nprintf '%s\\n' \"$*\" > \"$ARGS_LOG\"\n"
			goStub := "#!/bin/bash\n" +
				"if [ \"$1\" = build ]; then printf '%s' '" + strings.ReplaceAll(shim, "'", `'\''`) + "' > \"$3\"; chmod +x \"$3\"; exit 0; fi\n" +
				"exit 99\n"
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte(goStub), 0o755); err != nil {
				t.Fatal(err)
			}
			script := checkScript(t)
			cmd := exec.Command("bash", append([]string{script}, tc.args...)...)
			cmd.Env = append([]string{"PATH=" + dir + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "ARGS_LOG=" + argsLog}, tc.env...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("check.sh failed: %v\n%s", err, out)
			}
			got, err := os.ReadFile(argsLog)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(got)) != tc.want {
				t.Errorf("checkreport args\n got: %s\nwant: %s", strings.TrimSpace(string(got)), tc.want)
			}
		})
	}
}

// plan is what the stub planner prints for `checkreport -fast-plan`.
const (
	planTwoPkgs = `fast\torigin/main@abc123\nexample.com/x/internal/a\tinternal/a\tchanged: internal/a/a.go\nexample.com/x/internal/b\tinternal/b\timports internal/a\n`
	planNone    = `fast\torigin/main@abc123\n`
	planFull    = `full\torigin/main is not available (shallow clone or no remote); run git fetch origin main\n`
)

func bannersIn(out string) []string {
	var titles []string
	for _, m := range regexp.MustCompile(`(?m)^=== (.+) ===$`).FindAllStringSubmatch(out, -1) {
		if m[1] != "all checks passed" {
			titles = append(titles, m[1])
		}
	}
	return titles
}

func commandsIn(out string) []string {
	_, cmds, _ := strings.Cut(out, "--- commands ---\n")
	return strings.Split(strings.TrimSpace(cmds), "\n")
}

// --fast in plain mode checks exactly the planned packages and nothing that is
// not per-package.
func TestCheckShFastPlainMode(t *testing.T) {
	out := runCheckSh(t, []string{"FAKE_PLAN=" + planTwoPkgs}, "--fast")
	if !strings.HasPrefix(out, "exit: 0\n") {
		t.Fatalf("want exit 0:\n%s", out)
	}
	for _, want := range []string{
		"fast: 2 package(s) against origin/main@abc123",
		"./internal/a  (changed: internal/a/a.go)",
		"./internal/b  (imports internal/a)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	want := []string{
		"gofmt -l .",
		"go vet ./internal/a ./internal/b",
		"go test ./internal/archtest -run TestArchitecture",
		"go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run --config .golangci.arch.yml ./internal/a ./internal/b",
		"go test -race ./internal/a ./internal/b",
	}
	got := commandsIn(out)
	// The first logged command is the planner build; drop it.
	if len(got) == 0 || !strings.HasPrefix(got[0], "go build -o ") {
		t.Fatalf("commands = %v", got)
	}
	got = got[1:]
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands\n got: %v\nwant: %v", got, want)
	}
}

func TestCheckShFastPlainModeNoGoChange(t *testing.T) {
	out := runCheckSh(t, []string{"FAKE_PLAN=" + planNone}, "--fast")
	if !strings.HasPrefix(out, "exit: 0\n") || !strings.Contains(out, "no Go package changed") {
		t.Fatalf("output:\n%s", out)
	}
	if got := bannersIn(out); strings.Join(got, "|") != "format (gofmt)" {
		t.Errorf("banners = %v", got)
	}
	for _, c := range commandsIn(out) {
		if strings.HasPrefix(c, "go vet") || strings.HasPrefix(c, "go test") || strings.Contains(c, "golangci") {
			t.Errorf("ran %q with no package to check", c)
		}
	}
}

// With no origin/main the plan is "full": the whole gate runs, and says why.
func TestCheckShFastFallsBackToFullGate(t *testing.T) {
	out := runCheckSh(t, []string{"FAKE_PLAN=" + planFull}, "--fast")
	if !strings.HasPrefix(out, "exit: 0\n") || !strings.Contains(out, "fast: running the FULL gate: origin/main is not available") {
		t.Fatalf("output:\n%s", out)
	}
	all := strings.Join(commandsIn(out), "\n")
	for _, want := range []string{"govulncheck", "-coverprofile=coverage.out ./...", "-fuzz ^FuzzOne$", "-bench", "tool cover"} {
		if !strings.Contains(all, want) {
			t.Errorf("full-gate fallback did not run %q:\n%s", want, all)
		}
	}
}

func TestCheckShFastRejectsIntegration(t *testing.T) {
	out := runCheckSh(t, []string{"FAKE_PLAN=" + planTwoPkgs}, "--fast", "--integration")
	if !strings.HasPrefix(out, "exit: 2\n") || !strings.Contains(out, "--fast cannot be combined with --integration") {
		t.Fatalf("output:\n%s", out)
	}
}

// Plain mode and report mode must run the same stages for the same plan. The
// plain run's banners are compared with the stages tools/checkreport would run.
func TestCheckShFastStagesMatchRunner(t *testing.T) {
	for name, tc := range map[string]struct {
		plan string
		pkgs []FastPkg
	}{
		"packages":  {planTwoPkgs, []FastPkg{{Package: "a", Dir: "internal/a"}}},
		"no change": {planNone, nil},
	} {
		t.Run(name, func(t *testing.T) {
			out := runCheckSh(t, []string{"FAKE_PLAN=" + tc.plan}, "--fast")
			r := &runner{cfg: config{Integration: false, CoverageMin: 70, GolangciVersion: "v2.12.2", GovulncheckVersion: "v1.5.0"},
				plan: &FastPlan{Packages: tc.pkgs}}
			var want []string
			for _, d := range r.stages() {
				want = append(want, d.title)
			}
			if got := bannersIn(out); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("plain --fast stages differ from the report runner.\nplain:\n  %s\nrunner:\n  %s",
					strings.Join(got, "\n  "), strings.Join(want, "\n  "))
			}
		})
	}
}

// --list-stages runs nothing: it cannot be combined with the inner-loop plan.
func TestCheckShListStagesRejectsFast(t *testing.T) {
	out := runCheckSh(t, nil, "--list-stages", "--fast")
	if !strings.HasPrefix(out, "exit: 2\n") || !strings.Contains(out, "--list-stages cannot be combined with --fast") {
		t.Fatalf("output:\n%s", out)
	}
}

// TestCheckShFailsOnGeneratorTestFailure is the plain-mode half of the roadmap
// verdict (the --json half is TestRoadmapGeneratorTestFailureFailsStage): a
// failing docs/roadmap generator test must fail check.sh and stop it there.
func TestCheckShFailsOnGeneratorTestFailure(t *testing.T) {
	got := runCheckSh(t, []string{"SHIM_GEN_TEST_FAIL=1"})
	if !strings.HasPrefix(got, "exit: 1\n") {
		t.Fatalf("a failing generator test must fail check.sh:\n%s", got)
	}
	if strings.Contains(got, "go build ./...") {
		t.Errorf("check.sh must stop at the roadmap stage:\n%s", got)
	}
}
