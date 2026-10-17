package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestReadFuzzTargets(t *testing.T) {
	got, err := readFuzzTargets(writeTargets(t, "# comment\n\nFuzzA ./a # trailing\nFuzzB   ./b/c\n"))
	if err != nil || len(got) != 2 || got[0] != (fuzzTarget{"FuzzA", "./a"}) || got[1] != (fuzzTarget{"FuzzB", "./b/c"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"FuzzA\n", "notfuzz ./a\n", "FuzzA ./a extra\n"} {
		if _, err := readFuzzTargets(writeTargets(t, bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestFuzzTargetsListIsComplete keeps scripts/fuzz-targets.txt honest: every
// Fuzz function in the repo is listed with the right package, and every listed
// target exists. Without it a new fuzz target would silently never run in the
// gate or the nightly job.
func TestFuzzTargetsListIsComplete(t *testing.T) {
	root := "../.."
	listed, err := readFuzzTargets(filepath.Join(root, "scripts/fuzz-targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{} // name -> package dir
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "vendor") {
			return fs.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Fuzz") {
				rel, _ := filepath.Rel(root, filepath.Dir(p))
				want[fn.Name.Name] = "./" + filepath.ToSlash(rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	for _, l := range listed {
		have[l.Name] = l.Pkg
	}
	var names []string
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if have[n] != want[n] {
			t.Errorf("%s (%s) must be listed in scripts/fuzz-targets.txt as \"%s %s\"; listed package: %q", n, want[n], n, want[n], have[n])
		}
	}
	for n := range have {
		if _, ok := want[n]; !ok {
			t.Errorf("scripts/fuzz-targets.txt lists %s, which no test file defines", n)
		}
	}
}

func fuzzFailOutput() []byte {
	var b bytes.Buffer
	for _, o := range []string{
		"fuzz: elapsed: 3s, execs: 1000 (333/sec), new interesting: 5 (total: 12)\n",
		"--- FAIL: FuzzPolicyMatch (3.01s)\n",
		"    --- FAIL: FuzzPolicyMatch (0.00s)\n",
		"        fuzz_test.go:61: Deny became Allow under pct-all variant\n",
		"    Failing input written to testdata/fuzz/FuzzPolicyMatch/a1b2c3\n",
		"    To re-run:\n",
		"    go test -run=FuzzPolicyMatch/a1b2c3\n",
	} {
		line, _ := json.Marshal(map[string]string{"Action": "output", "Package": "example.com/x/internal/policy", "Output": o})
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func TestParseFuzzCrash(t *testing.T) {
	tgt := fuzzTarget{"FuzzPolicyMatch", "./internal/policy"}
	fs := parseFuzz(tgt, execResult{Stdout: fuzzFailOutput(), Code: 1}, parseCtx{Root: "/r", Module: "example.com/x"})
	if len(fs) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	f := fs[0]
	if f.Rule != "fuzz/crash" || f.File != "internal/policy/testdata/fuzz/FuzzPolicyMatch/a1b2c3" {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Fix, "go test -run=FuzzPolicyMatch/a1b2c3 ./internal/policy") || !strings.Contains(f.Fix, "security") {
		t.Errorf("fix = %q", f.Fix)
	}
	if !strings.Contains(f.Output, "Deny became Allow") {
		t.Errorf("output excerpt lost the failure: %q", f.Output)
	}
	if got := parseFuzz(tgt, execResult{Code: 0}, parseCtx{}); got != nil {
		t.Errorf("a passing run produced %v", got)
	}
	if got := parseFuzz(tgt, execResult{Code: 1, Stdout: []byte("not json at all")}, parseCtx{}); len(got) != 1 || got[0].Rule != "fuzz/failed" {
		t.Errorf("unparseable failure must still be a finding, got %v", got)
	}
}

// The fuzz stage runs every target for the configured time and reports the budget.
func TestStageFuzz(t *testing.T) {
	var cmds []string
	r := &runner{
		cfg: config{Root: t.TempDir(), FuzzTime: "3s"},
		exec: func(dir, name string, args ...string) execResult {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			if strings.Contains(strings.Join(args, " "), "^FuzzB$") {
				return execResult{Code: 1, Stdout: fuzzFailOutput()}
			}
			return execResult{}
		},
	}
	r.cfg.FuzzTargets = writeTargets(t, "FuzzA ./a\nFuzzB ./b\n")
	st := r.stageFuzz()
	if len(cmds) != 2 || cmds[0] != "go test -run ^$ -fuzz ^FuzzA$ -fuzztime=3s -json ./a" {
		t.Fatalf("commands = %v", cmds)
	}
	if len(st.Findings) != 1 || st.Findings[0].Rule != "fuzz/crash" {
		t.Errorf("findings = %+v", st.Findings)
	}
	if st.Metrics["targets"] != 2 || st.Metrics["fuzzTimePerTarget"] != "3s" || st.Metrics["fuzzBudgetSeconds"] != 6.0 {
		t.Errorf("metrics = %v", st.Metrics)
	}
	r.cfg.FuzzTime = "nope"
	if st := r.stageFuzz(); len(st.Findings) != 1 || st.Findings[0].Rule != "stage/crashed" {
		t.Errorf("bad fuzz time: %+v", st.Findings)
	}
	r.cfg.FuzzTargets = filepath.Join(t.TempDir(), "missing.txt")
	if st := r.stageFuzz(); len(st.Findings) != 1 || st.Findings[0].Rule != "stage/crashed" {
		t.Errorf("missing list: %+v", st.Findings)
	}
}
