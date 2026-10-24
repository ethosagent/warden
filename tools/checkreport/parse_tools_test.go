package main

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLint(t *testing.T) {
	fs := parseLint(readTestdata(t, "lint.json"), gotestCtx())
	if len(fs) != 3 {
		t.Fatalf("want 3, got %+v", fs)
	}
	by := map[string]Finding{}
	for _, f := range fs {
		by[f.Rule] = f
	}
	e := by["errcheck"]
	if e.File != "lintbad/a.go" || e.Line != 9 || e.Col != 9 || !strings.Contains(e.Message, "os.Open") || !strings.Contains(e.Fix, "error") {
		t.Errorf("errcheck: %+v", e)
	}
	sa := by["staticcheck/SA1019"]
	if sa.Line != 10 || !strings.Contains(sa.Fix, "scoped exclusion") || !strings.HasPrefix(sa.Message, "strings.Title has been deprecated") {
		t.Errorf("SA1019: %+v", sa)
	}
	u := by["unused"]
	if u.Line != 13 || u.Fix == "" || u.Output != "func unusedFn() {}" {
		t.Errorf("unused: %+v", u)
	}
}

func TestParseLintTypecheckUsesEmbeddedLocation(t *testing.T) {
	in := `{"Issues":[{"FromLinter":"typecheck","Text":": # example.com/fx/lintbad\nlintbad/a.go:7:6: declared and not used: unused","Severity":"","SourceLines":["package lintbad"],"Pos":{"Filename":"lintbad/a.go","Offset":0,"Line":1,"Column":0}}],"Report":{}}`
	fs := parseLint([]byte(in), gotestCtx())
	if len(fs) != 1 || fs[0].Rule != "typecheck" || fs[0].Line != 7 || fs[0].Col != 6 || !strings.Contains(fs[0].Fix, "compile") {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseLintMalformed(t *testing.T) {
	fs := parseLint([]byte("not json"), gotestCtx())
	if len(fs) != 1 || fs[0].Rule != "stage/crashed" {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseVuln(t *testing.T) {
	fs := parseVuln(readTestdata(t, "govulncheck.json"), gotestCtx())
	if len(fs) != 9 {
		t.Fatalf("want 9 called vulnerabilities (module-level-only findings ignored), got %d: %+v", len(fs), fs)
	}
	var f Finding
	for _, x := range fs {
		if x.Rule == "GO-2026-5030" {
			f = x
		}
	}
	if f.File != "vuln/a.go" || f.Line != 6 || f.Col != 22 {
		t.Errorf("location should be the call site in our code: %+v", f)
	}
	if !strings.Contains(f.Fix, "golang.org/x/net") || !strings.Contains(f.Fix, "v0.55.0") || !strings.Contains(f.Fix, "go get") {
		t.Errorf("fix: %q", f.Fix)
	}
	if !strings.Contains(f.Message, "golang.org/x/net@v0.20.0") || !strings.Contains(f.Output, "html.Parse") {
		t.Errorf("message/output: %+v", f)
	}
	for _, x := range fs {
		if x.Fix == "" || x.Severity != "error" {
			t.Errorf("bad finding %+v", x)
		}
	}
}

func TestParseVulnNoFindings(t *testing.T) {
	in := `{"config":{"scanner_name":"govulncheck"}}` + "\n" + `{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1"}]}}` + "\n"
	if fs := parseVuln([]byte(in), gotestCtx()); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseVulnPicksHighestFixedVersion(t *testing.T) {
	in := `{"osv":{"id":"GO-9","summary":"s"}}
{"finding":{"osv":"GO-9","fixed_version":"v0.9.0","trace":[{"module":"m/x","version":"v0.1.0","package":"m/x","function":"A"},{"module":"example.com/fx","package":"example.com/fx/p","function":"F","position":{"filename":"p/p.go","line":3,"column":4}}]}}
{"finding":{"osv":"GO-9","fixed_version":"v0.10.0","trace":[{"module":"m/x","version":"v0.1.0","package":"m/x","function":"B"},{"module":"example.com/fx","package":"example.com/fx/p","function":"G","position":{"filename":"p/p.go","line":9,"column":4}}]}}
`
	fs := parseVuln([]byte(in), gotestCtx())
	if len(fs) != 1 || !strings.Contains(fs[0].Fix, "v0.10.0") || fs[0].Line != 3 {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseVulnStdlib(t *testing.T) {
	in := `{"osv":{"id":"GO-8","summary":"net/http bug"}}
{"finding":{"osv":"GO-8","fixed_version":"go1.26.10","trace":[{"module":"stdlib","version":"go1.26.9","package":"net/http","function":"Do"},{"module":"example.com/fx","package":"example.com/fx","function":"F","position":{"filename":"a.go","line":3,"column":4}}]}}
`
	fs := parseVuln([]byte(in), gotestCtx())
	if len(fs) != 1 || !strings.Contains(fs[0].Fix, "Go toolchain") || !strings.Contains(fs[0].Fix, "go1.26.10") {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseGofmtList(t *testing.T) {
	fs := parseGofmt(readTestdata(t, "gofmt_list.txt"), nil)
	if len(fs) != 1 || fs[0].Rule != "gofmt/unformatted" || fs[0].File != "fmtbad/a.go" || fs[0].Fix != "run `gofmt -w fmtbad/a.go`" {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseGofmtSyntaxError(t *testing.T) {
	fs := parseGofmt(nil, readTestdata(t, "gofmt_syntax.txt"))
	if len(fs) != 1 || fs[0].Rule != "gofmt/syntax-error" || fs[0].File != "fmtsyn/a.go" || fs[0].Line != 2 || fs[0].Col != 8 || fs[0].Fix == "" {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseGofmtSkipsVendor(t *testing.T) {
	if fs := parseGofmt([]byte("vendor/x/y.go\n"), nil); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestCoverageMatchesGoToolCover(t *testing.T) {
	pk, total, err := coverageByPackage(readTestdata(t, "coverage.out.txt"), "example.com/fx")
	if err != nil {
		t.Fatal(err)
	}
	if total != 22.2 { // the figure `go tool cover -func` prints for this profile (testdata/coverage_func.txt)
		t.Errorf("total = %v", total)
	}
	if !strings.Contains(string(readTestdata(t, "coverage_func.txt")), "22.2%") {
		t.Error("testdata drifted from go tool cover output")
	}
	if len(pk) != 2 || pk[0].Package != "cov/b" || pk[0].Percent != 0 || math.Abs(pk[1].Percent-33.3) > 0.05 {
		t.Errorf("packages not sorted lowest-first: %+v", pk)
	}
}

func TestCoverageStage(t *testing.T) {
	data := readTestdata(t, "coverage.out.txt")
	st := coverageStage(data, "example.com/fx", 70)
	if len(st.Findings) != 1 {
		t.Fatalf("got %+v", st)
	}
	f := st.Findings[0]
	if f.Rule != "coverage/below-minimum" || !strings.Contains(f.Message, "22.2%") || !strings.Contains(f.Message, "70%") || !strings.Contains(f.Fix, "cov/b") {
		t.Errorf("finding: %+v", f)
	}
	if st.Metrics["total"] != 22.2 || st.Metrics["min"] != 70.0 {
		t.Errorf("metrics: %+v", st.Metrics)
	}
	if low, ok := st.Metrics["lowest"].([]pkgCoverage); !ok || len(low) != 2 {
		t.Errorf("lowest: %+v", st.Metrics["lowest"])
	}
	if ok := coverageStage(data, "example.com/fx", 22.2); len(ok.Findings) != 0 {
		t.Errorf("equal to the minimum passes (gate is strict less-than): %+v", ok.Findings)
	}
}

func TestCoverageStageMissingProfile(t *testing.T) {
	st := coverageStage(nil, "example.com/fx", 70)
	if len(st.Findings) != 1 || st.Findings[0].Rule != "stage/crashed" {
		t.Fatalf("got %+v", st)
	}
}

func TestParseRoadmap(t *testing.T) {
	fs := parseRoadmap(readTestdata(t, "roadmap_stale.json"))
	if len(fs) != 1 || fs[0].Rule != "roadmap/stale" || fs[0].File != "docs/roadmap/README.md" || !strings.Contains(fs[0].Fix, "gen.go docs") {
		t.Fatalf("got %+v", fs)
	}
	fs = parseRoadmap(readTestdata(t, "roadmap_invalid.json"))
	if len(fs) != 1 || fs[0].Rule != "roadmap/invalid" || fs[0].File != "docs/roadmap/tickets.json" || !strings.Contains(fs[0].Message, "invalid character") {
		t.Fatalf("got %+v", fs)
	}
	if fs := parseRoadmap([]byte(`{"ok":true}`)); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
	if fs := parseRoadmap([]byte(`{"ok":false,"stale":["docs/roadmap/features/x.md (orphaned)"]}`)); len(fs) != 1 || fs[0].Rule != "roadmap/orphaned" || fs[0].File != "docs/roadmap/features/x.md" {
		t.Fatalf("orphan: %+v", fs)
	}
}

func TestParseLintEverySeverityIsAnError(t *testing.T) {
	// golangci-lint exits 1 on any issue, whatever its severity label.
	for _, sev := range []string{"", "error", "warning", "info"} {
		in := `{"Issues":[{"FromLinter":"unused","Text":"x is unused","Severity":"` + sev + `","Pos":{"Filename":"a.go","Line":1,"Column":1}}]}`
		fs := parseLint([]byte(in), gotestCtx())
		if len(fs) != 1 || fs[0].Severity != sevError {
			t.Errorf("severity %q: got %+v", sev, fs)
		}
	}
}

func TestCoverageExcludesTools(t *testing.T) {
	prof := []byte("mode: set\n" +
		"example.com/fx/internal/a/a.go:1.1,2.2 10 1\n" +
		"example.com/fx/internal/a/b.go:1.1,2.2 10 0\n" +
		"example.com/fx/tools/checkreport/main.go:1.1,2.2 100 1\n" +
		"example.com/fx/tools/other/x.go:1.1,2.2 100 1\n")
	pk, total, err := coverageByPackage(prof, "example.com/fx")
	if err != nil || total != 50 {
		t.Fatalf("total=%v err=%v, want 50 (product code only)", total, err)
	}
	for _, p := range pk {
		if strings.HasPrefix(p.Package, "tools") {
			t.Errorf("tools package listed: %+v", p)
		}
	}
	if st := coverageStage(prof, "example.com/fx", 60); len(st.Findings) != 1 {
		t.Errorf("tools coverage must not lift the gate: %+v", st)
	}
}

func TestParseSecrets(t *testing.T) {
	stderr := []byte("secrets: deploy/compose/dex/a.yaml:2: secret is a literal; use an env reference ($VAR or ${VAR:?})\n" +
		"noise line\n" +
		"secrets: deploy/compose/docker-compose.identity.yml:7: bindPW is a literal; use an env reference ($VAR or ${VAR:?})\n")
	fs := parseSecrets(stderr)
	if len(fs) != 2 {
		t.Fatalf("got %+v", fs)
	}
	if fs[0].Rule != "secrets/literal" || fs[0].File != "deploy/compose/dex/a.yaml" || fs[0].Line != 2 || !strings.Contains(fs[0].Message, "secret") {
		t.Errorf("first: %+v", fs[0])
	}
	if fs[1].File != "deploy/compose/docker-compose.identity.yml" || fs[1].Line != 7 {
		t.Errorf("second: %+v", fs[1])
	}
	if fs := parseSecrets([]byte("ok\n")); len(fs) != 0 {
		t.Errorf("clean output must give no findings: %+v", fs)
	}
}

// TestStageSecretsRealScript runs the real script so the stderr-to-findings
// wiring is covered end to end, not only parseSecrets on canned text.
func TestStageSecretsRealScript(t *testing.T) {
	root := t.TempDir()
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-secrets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "scripts/check-secrets.sh", string(script))
	writeFile(t, root, "deploy/compose/dex/config.yaml", "staticClients:\n  - id: x\n    secret: lit"+"eral\n")
	r := &runner{cfg: config{Root: root}, ctx: parseCtx{Root: root}, exec: osExec}
	st := r.stageSecrets()
	if st.OK || len(st.Findings) != 1 || st.Findings[0].File != "deploy/compose/dex/config.yaml" || st.Findings[0].Line != 3 {
		t.Fatalf("want one finding at config.yaml:3, got %+v", st)
	}
	if f := st.Findings[0]; strings.Contains(f.Message+f.Output+f.Fix, "hunter2x") {
		t.Errorf("finding leaked the value: %+v", f)
	}
}
