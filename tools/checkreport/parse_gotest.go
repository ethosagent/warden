package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// testEvent is one `go test -json` event (test2json plus the build fields).
type testEvent struct {
	Action      string
	Package     string
	Test        string
	Output      string
	FailedBuild string
}

var (
	// testLoc is a "    file_test.go:12: message" line printed by t.Log/t.Error.
	testLoc = regexp.MustCompile(`^\s+(\S+\.go):(\d+): ?(.*)$`)
	// frameLoc is an absolute-path stack frame from a panic or a race report.
	frameLoc = regexp.MustCompile(`^\s+(/\S+\.go):(\d+)`)
)

type testBucket struct {
	pkg, test string
	out       []string
}

// parseGoTest parses `go test -json` output (the test, benchmark-smoke and
// integration stages). rulePrefix is the stage name, so rules read
// "test/failed", "integration/panic", and so on. It reports leaf failures only,
// classifies panics and data races, and leaves compile errors to buildFindings.
func parseGoTest(rulePrefix string, data []byte, c parseCtx) []Finding {
	buckets := map[string]*testBucket{}
	var bucketOrder []*testBucket
	var failed []*testBucket        // failed tests, in order
	failedPkgs := map[string]bool{} // packages with a package-level fail event
	var pkgOrder []string
	failedBuild := map[string]bool{}
	hasFailedTest := map[string]bool{}
	var garbage []string

	get := func(pkg, test string) *testBucket {
		k := pkg + "\x00" + test
		b := buckets[k]
		if b == nil {
			b = &testBucket{pkg: pkg, test: test}
			buckets[k] = b
			bucketOrder = append(bucketOrder, b)
		}
		return b
	}
	sc := newLineScanner(data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev testEvent
		if line[0] != '{' || json.Unmarshal([]byte(line), &ev) != nil {
			garbage = append(garbage, line)
			continue
		}
		switch ev.Action {
		case "output":
			if ev.Package != "" {
				b := get(ev.Package, ev.Test)
				b.out = append(b.out, ev.Output)
			}
		case "fail":
			if ev.Test != "" {
				failed = append(failed, get(ev.Package, ev.Test))
				hasFailedTest[ev.Package] = true
			} else {
				failedPkgs[ev.Package] = true
				pkgOrder = append(pkgOrder, ev.Package)
				if ev.FailedBuild != "" {
					failedBuild[ev.Package] = true
				}
			}
		}
	}

	out := buildFindings(data, c)
	haveBuild := len(out) > 0

	for _, b := range failed {
		if hasFailedChild(b, failed) {
			continue
		}
		out = append(out, testFinding(rulePrefix, b, c))
	}
	for _, p := range pkgOrder {
		if hasFailedTest[p] || (failedBuild[p] && haveBuild) {
			continue
		}
		// A panic or race outside a test's own goroutine kills the binary
		// before the test gets a fail event; the output is still attributed to it.
		if crashedTests := crashedBuckets(bucketOrder, p); len(crashedTests) > 0 {
			for _, b := range crashedTests {
				out = append(out, testFinding(rulePrefix, b, c))
			}
			continue
		}
		out = append(out, packageFinding(rulePrefix, get(p, ""), c, garbage))
	}
	if len(out) == 0 && len(garbage) > 0 && len(pkgOrder) == 0 && containsFailMarker(garbage) {
		out = append(out, Finding{
			Rule: rulePrefix + "/package-failed", Severity: sevError,
			Message: "go test reported a failure outside any package: " + garbage[len(garbage)-1],
			Fix:     "run `go test ./...` by hand and fix what it reports",
			Output:  strings.Join(garbage, "\n"),
		})
	}
	return out
}

// crashedBuckets returns the tests of pkg whose output shows a panic or race.
func crashedBuckets(all []*testBucket, pkg string) []*testBucket {
	var out []*testBucket
	for _, b := range all {
		if b.pkg != pkg || b.test == "" {
			continue
		}
		if kind, _ := classify(strings.Join(b.out, "")); kind != "failed" {
			out = append(out, b)
		}
	}
	return out
}

func containsFailMarker(lines []string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, "FAIL") {
			return true
		}
	}
	return false
}

func hasFailedChild(b *testBucket, failed []*testBucket) bool {
	for _, o := range failed {
		if o.pkg == b.pkg && strings.HasPrefix(o.test, b.test+"/") {
			return true
		}
	}
	return false
}

// classify decides what kind of failure the output shows.
func classify(out string) (kind, msg string) {
	switch {
	case strings.Contains(out, "WARNING: DATA RACE"):
		return "data-race", "data race detected"
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "panic: ") {
			return "panic", strings.TrimSpace(l)
		}
	}
	return "failed", ""
}

// frameInRepo returns the first stack frame that lies inside the repo.
func frameInRepo(out string, c parseCtx) (file string, line int) {
	for _, l := range strings.Split(out, "\n") {
		m := frameLoc.FindStringSubmatch(l)
		if m == nil || !c.inRepo(m[1]) {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		return c.relPath(m[1]), n
	}
	return "", 0
}

// lastTestLoc returns the last t.Log/t.Error style location, ignoring the
// testing package's own lines, plus its message.
func lastTestLoc(out string, dir string) (file string, line int, msg string) {
	for _, l := range strings.Split(out, "\n") {
		m := testLoc.FindStringSubmatch(l)
		if m == nil || m[1] == "testing.go" {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		file, line, msg = joinDir(dir, m[1]), n, m[3]
	}
	return file, line, msg
}

func rerunCmd(prefix, dir, test string) string {
	if prefix == "benchmark" {
		pat := "."
		if test != "" {
			pat = "^" + regexp.QuoteMeta(test) + "$"
		}
		return fmt.Sprintf("go test -run '^$' -bench '%s' -benchtime=1x ./%s", pat, dir)
	}
	args := "go test"
	if prefix == "test" {
		args += " -race"
	}
	if prefix == "integration" {
		args += " -tags=integration"
	}
	if test != "" {
		parts := strings.Split(test, "/")
		for i, p := range parts {
			parts[i] = "^" + regexp.QuoteMeta(p) + "$"
		}
		args += fmt.Sprintf(" -run '%s'", strings.Join(parts, "/"))
	}
	return fmt.Sprintf("%s ./%s", args, strings.TrimPrefix(dir, "./"))
}

func testFinding(prefix string, b *testBucket, c parseCtx) Finding {
	out := strings.Join(b.out, "")
	dir := c.pkgDir(b.pkg)
	kind, kmsg := classify(out)
	f := Finding{Rule: prefix + "/" + kind, Severity: sevError, Output: out}
	switch kind {
	case "data-race", "panic":
		f.File, f.Line = frameInRepo(out, c)
	}
	var tmsg string
	if kind == "failed" || f.File == "" {
		file, line, m := lastTestLoc(out, dir)
		if f.File == "" {
			f.File, f.Line = file, line
		}
		tmsg = m
	}
	rerun := rerunCmd(prefix, dir, b.test)
	where := ""
	if f.File != "" {
		where = fmt.Sprintf(" at `%s`", loc(f.File, f.Line))
	}
	switch kind {
	case "data-race":
		f.Message = fmt.Sprintf("%s: data race detected%s", b.test, where)
		f.Fix = fmt.Sprintf("`%s` has a data race%s; two goroutines touch the same variable without synchronisation. Guard it with a mutex, an atomic or a channel (see output for both stacks), then rerun `%s`", b.test, where, rerun)
	case "panic":
		f.Message = fmt.Sprintf("%s: %s", b.test, kmsg)
		f.Fix = fmt.Sprintf("`%s` panicked%s (%s); fix the cause shown in output, then rerun `%s`", b.test, where, strings.TrimPrefix(kmsg, "panic: "), rerun)
	default:
		f.Message = strings.TrimSpace(fmt.Sprintf("%s failed: %s", b.test, tmsg))
		f.Fix = fmt.Sprintf("`%s` failed%s; see output. Rerun with `%s`", b.test, where, rerun)
	}
	return f
}

func packageFinding(prefix string, b *testBucket, c parseCtx, garbage []string) Finding {
	out := strings.Join(b.out, "")
	dir := c.pkgDir(b.pkg)
	kind, kmsg := classify(out)
	if kind == "failed" {
		kind = "package-failed"
	}
	f := Finding{Rule: prefix + "/" + kind, Severity: sevError, Output: out}
	f.File, f.Line = frameInRepo(out, c)
	where := ""
	if f.File != "" {
		where = fmt.Sprintf(" at `%s`", loc(f.File, f.Line))
	}
	rerun := rerunCmd(prefix, dir, "")
	switch kind {
	case "data-race":
		f.Message = fmt.Sprintf("package %s: data race detected%s", dir, where)
		f.Fix = fmt.Sprintf("a data race outside a single test%s; synchronise the shared variable (see output), then rerun `%s`", where, rerun)
	case "panic":
		f.Message = fmt.Sprintf("package %s: %s", dir, kmsg)
		f.Fix = fmt.Sprintf("the test binary panicked%s (%s); fix the cause shown in output, then rerun `%s`", where, strings.TrimPrefix(kmsg, "panic: "), rerun)
	default:
		f.Message = fmt.Sprintf("package %s failed", dir)
		if len(garbage) > 0 {
			f.Output += strings.Join(garbage, "\n")
		}
		f.Fix = fmt.Sprintf("package `%s` failed without a failing test (setup, TestMain or exit); see output, then rerun `%s`", dir, rerun)
	}
	return f
}
