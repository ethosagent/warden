package main

import (
	"bytes"
	"os"
	"path/filepath"
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
