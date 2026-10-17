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
"vet ./..."*) ;;
"run github.com/golangci/"*) echo "lint ran" ;;
"run docs/roadmap/gen.go") echo "roadmap ok" ;;
"build ./..."*) ;;
"run golang.org/x/vuln/"*) echo "No vulnerabilities found." ;;
"test -race"*) echo "ok  	example.com/x	0.1s" ;;
"test -run"*) echo "bench output (discarded by the script)" ;;
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

func runCheckSh(t *testing.T, env []string, args ...string) string {
	t.Helper()
	shims := t.TempDir()
	for name, body := range map[string]string{"go": goShim, "gofmt": gofmtShim} {
		if err := os.WriteFile(filepath.Join(shims, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(t.TempDir(), "log")
	script := checkScript(t)
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
			"-coverage-min 70 -golangci-version v2.12.2 -govulncheck-version v1.5.0 -json"},
		{"json-integration-min", []string{"COVERAGE_MIN=81.5", "GOLANGCI_VERSION=v9.9.9", "GOVULNCHECK_VERSION=v8.8.8"},
			[]string{"--json", "--integration"},
			"-coverage-min 81.5 -golangci-version v9.9.9 -govulncheck-version v8.8.8 -integration -json"},
		{"keep-going-json-out", nil, []string{"--keep-going", "--json-out", "/tmp/r.json"},
			"-coverage-min 70 -golangci-version v2.12.2 -govulncheck-version v1.5.0 -keep-going -json-out /tmp/r.json"},
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
