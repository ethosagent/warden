package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var versionFlags = []string{"-golangci-version", "v2.12.2", "-govulncheck-version", "v1.5.0", "-coverage-min", "70"}

func TestRealMainJSONPrintsExactlyOneDocumentToStdout(t *testing.T) {
	root := copyFixture(t, "clean")
	var stdout, stderr bytes.Buffer
	args := append([]string{"-root", root, "-json", "-stages", "format,vet,build,test,coverage"}, versionFlags...)
	code := realMain(args, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("clean fixture: exit %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	assertValidReport(t, stdout.Bytes())
	if !strings.Contains(stderr.String(), "=== format (gofmt) ===") || strings.Contains(stdout.String(), "===") {
		t.Errorf("human progress belongs on stderr only:\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}
}

func TestRealMainJSONOutKeepsHumanOutputOnStdout(t *testing.T) {
	root := copyFixture(t, "unformatted")
	path := filepath.Join(t.TempDir(), "check-report.json")
	var stdout, stderr bytes.Buffer
	args := append([]string{"-root", root, "-json-out", path, "-stages", "format"}, versionFlags...)
	if code := realMain(args, &stdout, &stderr, nil); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertValidReport(t, b)
	if !strings.Contains(stdout.String(), "gofmt -w a.go") || strings.Contains(stdout.String(), `"schema"`) {
		t.Errorf("human output expected on stdout: %q", stdout.String())
	}
}

func TestRealMainUnreadableRootStillYieldsValidReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := append([]string{"-root", t.TempDir(), "-json"}, versionFlags...)
	if code := realMain(args, &stdout, &stderr, nil); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	assertValidReport(t, stdout.Bytes())
	if !strings.Contains(stdout.String(), "stage/crashed") {
		t.Errorf("want a stage/crashed finding: %s", stdout.String())
	}
}

func TestRealMainRequiresPinnedVersions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := realMain([]string{"-json"}, &stdout, &stderr, nil); code != 2 || stdout.Len() != 0 {
		t.Fatalf("exit %d stdout %q", code, stdout.String())
	}
}

func TestRealMainUnwritableReportPathFails(t *testing.T) {
	root := copyFixture(t, "clean")
	var stdout, stderr bytes.Buffer
	args := append([]string{"-root", root, "-json-out", "/nonexistent-dir/r.json", "-stages", "format"}, versionFlags...)
	if code := realMain(args, &stdout, &stderr, nil); code == 0 || !strings.Contains(stderr.String(), "cannot write") {
		t.Fatalf("exit %d stderr %q", code, stderr.String())
	}
}

// listStages runs `checkreport -list-stages` on a clean fixture.
func listStages(t *testing.T, extra ...string) (string, int) {
	t.Helper()
	root := copyFixture(t, "clean")
	var stdout, stderr bytes.Buffer
	args := append([]string{"-root", root, "-list-stages"}, extra...)
	code := realMain(args, &stdout, &stderr, nil)
	return stdout.String(), code
}

func TestListStagesPlain(t *testing.T) {
	out, code := listStages(t)
	want := "format\nvet\narchtest\nlint\nroadmap\nbuild\nvulncheck\ntest\nfuzz\nbenchmark\ncoverage\n"
	if code != 0 || out != want {
		t.Fatalf("exit %d, stages:\n%s\nwant:\n%s", code, out, want)
	}
	// no version flags needed: listing runs nothing
	out, _ = listStages(t, "-integration")
	if !strings.HasSuffix(out, "coverage\nintegration\n") {
		t.Errorf("-integration adds the integration stage last:\n%s", out)
	}
}

func TestListStagesJSONIsAValidReport(t *testing.T) {
	out, code := listStages(t, "-json", "-integration")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	assertValidReport(t, []byte(out))
	for _, name := range []string{`"name": "format"`, `"name": "integration"`} {
		if !strings.Contains(out, name) {
			t.Errorf("report lacks %s:\n%s", name, out)
		}
	}
	if strings.Contains(out, `"ok": false`) {
		t.Errorf("listing is not a failure:\n%s", out)
	}
}

// The plain list is the stage name of every banner check.sh prints: the names
// gatecheck compares between base and head are the stages that really run.
func TestListStagesNamesMatchScriptBanners(t *testing.T) {
	b, err := os.ReadFile(checkScript(t))
	if err != nil {
		t.Fatal(err)
	}
	var banners []string
	for _, m := range regexp.MustCompile(`(?m)^\s*banner "(\S+)`).FindAllStringSubmatch(string(b), -1) {
		if m[1] != "all" {
			banners = append(banners, m[1])
		}
	}
	out, _ := listStages(t, "-integration")
	if got := strings.Fields(out); strings.Join(got, ",") != strings.Join(banners, ",") {
		t.Errorf("stage names differ from check.sh banners\nlist:    %v\nbanners: %v", got, banners)
	}
}
