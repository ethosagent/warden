package main

import (
	"os"
	"strings"
	"testing"
)

const fxRoot = "/tmp/fx"

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gotestCtx() parseCtx { return parseCtx{Root: fxRoot, Module: "example.com/fx"} }

func TestParseGoTestFailure(t *testing.T) {
	fs := parseGoTest("test", readTestdata(t, "gotest_fail.json"), gotestCtx())
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %+v", fs)
	}
	f := fs[0]
	if f.Rule != "test/failed" || f.File != "tfail/a_test.go" || f.Line != 7 {
		t.Errorf("bad finding: %+v", f)
	}
	if !strings.Contains(f.Message, "TestFoo") || !strings.Contains(f.Message, "want 1 got 2") {
		t.Errorf("message should name the test and failure: %q", f.Message)
	}
	if !strings.Contains(f.Fix, "TestFoo") || !strings.Contains(f.Fix, "tfail/a_test.go:7") || !strings.Contains(f.Fix, "-run") {
		t.Errorf("fix should say how to rerun and where: %q", f.Fix)
	}
	if f.Severity != "error" || f.Output == "" {
		t.Errorf("want severity error and output excerpt: %+v", f)
	}
}

func TestParseGoTestPanic(t *testing.T) {
	fs := parseGoTest("test", readTestdata(t, "gotest_panic.json"), gotestCtx())
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %+v", fs)
	}
	f := fs[0]
	if f.Rule != "test/panic" || f.File != "tpanic/a_test.go" || f.Line != 7 {
		t.Errorf("bad finding: %+v", f)
	}
	if !strings.Contains(f.Message, "assignment to entry in nil map") {
		t.Errorf("message should carry the panic value: %q", f.Message)
	}
}

func TestParseGoTestDataRace(t *testing.T) {
	fs := parseGoTest("test", readTestdata(t, "gotest_race.json"), gotestCtx())
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %+v", fs)
	}
	f := fs[0]
	if f.Rule != "test/data-race" || f.File != "trace/a_test.go" || f.Line != 8 {
		t.Errorf("bad finding: %+v", f)
	}
	if !strings.Contains(f.Fix, "synchron") {
		t.Errorf("fix should advise synchronisation: %q", f.Fix)
	}
}

func TestParseGoTestBuildFailure(t *testing.T) {
	fs := parseGoTest("test", readTestdata(t, "gotest_buildfail.json"), gotestCtx())
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (no duplicate for the package FAIL), got %+v", fs)
	}
	f := fs[0]
	if f.Rule != "build/compile-error" || f.File != "tbuild/a_test.go" || f.Line != 3 || f.Col != 27 {
		t.Errorf("bad finding: %+v", f)
	}
	if !strings.Contains(f.Message, "undefined: undefinedFn") {
		t.Errorf("message: %q", f.Message)
	}
}

func TestParseGoTestPassingIsEmpty(t *testing.T) {
	in := `{"Action":"start","Package":"p"}
{"Action":"run","Package":"p","Test":"TestOk"}
{"Action":"pass","Package":"p","Test":"TestOk"}
{"Action":"pass","Package":"p"}
`
	if fs := parseGoTest("test", []byte(in), gotestCtx()); len(fs) != 0 {
		t.Fatalf("want none, got %+v", fs)
	}
}

func TestParseGoTestSubtestReportsLeafOnly(t *testing.T) {
	in := `{"Action":"run","Package":"example.com/fx/p","Test":"TestA"}
{"Action":"run","Package":"example.com/fx/p","Test":"TestA/sub"}
{"Action":"output","Package":"example.com/fx/p","Test":"TestA/sub","Output":"    x_test.go:9: boom\n"}
{"Action":"fail","Package":"example.com/fx/p","Test":"TestA/sub"}
{"Action":"fail","Package":"example.com/fx/p","Test":"TestA"}
{"Action":"fail","Package":"example.com/fx/p"}
`
	fs := parseGoTest("test", []byte(in), gotestCtx())
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "TestA/sub") || fs[0].File != "p/x_test.go" || fs[0].Line != 9 {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseGoTestPackageLevelFailureWithoutTest(t *testing.T) {
	in := `{"Action":"output","Package":"example.com/fx/p","Output":"panic: boom in TestMain\n"}
{"Action":"output","Package":"example.com/fx/p","Output":"\t/tmp/fx/p/main_test.go:12 +0x1\n"}
{"Action":"fail","Package":"example.com/fx/p"}
`
	fs := parseGoTest("integration", []byte(in), gotestCtx())
	if len(fs) != 1 || fs[0].Rule != "integration/panic" || fs[0].File != "p/main_test.go" || fs[0].Line != 12 {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseGoTestToleratesGarbageLines(t *testing.T) {
	in := "go: downloading x\n{not json\n" + `{"Action":"fail","Package":"example.com/fx/p"}` + "\n"
	fs := parseGoTest("test", []byte(in), gotestCtx())
	if len(fs) != 1 || fs[0].Rule != "test/package-failed" {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseGoTestPanicWithoutTestFailEvent(t *testing.T) {
	fs := parseGoTest("benchmark", readTestdata(t, "gotest_benchpanic.json"), parseCtx{Root: "/tmp/bp", Module: "example.com/fx"})
	if len(fs) != 1 {
		t.Fatalf("want 1, got %+v", fs)
	}
	f := fs[0]
	if f.Rule != "benchmark/panic" || f.File != "a_test.go" || f.Line != 7 || !strings.Contains(f.Fix, "-bench '^BenchmarkBoom$'") {
		t.Errorf("bad finding: %+v", f)
	}
}
