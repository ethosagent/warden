package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// jq renders s as a JSON string literal.
func jq(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// archtestJSON wraps one output line in the `go test -json` shape the
// architecture-gate stage runs.
func archtestJSON(lines ...string) []byte {
	var b strings.Builder
	b.WriteString(`{"Action":"start","Package":"example.com/x/internal/archtest"}` + "\n")
	b.WriteString(`{"Action":"run","Package":"example.com/x/internal/archtest","Test":"TestArchitecture"}` + "\n")
	for _, l := range lines {
		b.WriteString(`{"Action":"output","Package":"example.com/x/internal/archtest","Test":"TestArchitecture","Output":` +
			jq(l+"\n") + "}\n")
	}
	b.WriteString(`{"Action":"fail","Package":"example.com/x/internal/archtest","Test":"TestArchitecture"}` + "\n")
	b.WriteString(`{"Action":"fail","Package":"example.com/x/internal/archtest"}` + "\n")
	return []byte(b.String())
}

func TestParseArchtest(t *testing.T) {
	c := parseCtx{Root: "/repo", Module: "example.com/x"}

	t.Run("one finding per violation line", func(t *testing.T) {
		data := archtestJSON(
			"=== RUN   TestArchitecture",
			"    architecture_test.go:57: L4a  internal/proxy/proxy.go:88:  data-plane decision imports repository internal/repo  →  depend on the side-call port",
			"    architecture_test.go:58: baseline  architecture.baseline.yaml:5:  entry (L3, internal/config) matches no finding — the violation is fixed  →  remove the entry from architecture.baseline.yaml (the baseline only shrinks)",
		)
		fs := parseArchtest(data, c)
		if len(fs) != 2 {
			t.Fatalf("findings = %+v", fs)
		}
		if fs[0].Rule != "archtest/L4a" || fs[0].File != "internal/proxy/proxy.go" || fs[0].Line != 88 {
			t.Errorf("first = %+v", fs[0])
		}
		if fs[0].Message != "data-plane decision imports repository internal/repo" || fs[0].Fix != "depend on the side-call port" {
			t.Errorf("first text = %+v", fs[0])
		}
		if fs[1].Rule != "archtest/baseline" || fs[1].File != "architecture.baseline.yaml" || fs[1].Line != 5 {
			t.Errorf("second = %+v", fs[1])
		}
		for _, f := range fs {
			if f.Severity != sevError || f.Message == "" || f.Fix == "" {
				t.Errorf("incomplete finding: %+v", f)
			}
		}
	})

	t.Run("stale generated config", func(t *testing.T) {
		data := archtestJSON(
			"    architecture_test.go:70: .golangci.arch.yml is stale — run go run ./cmd/archgen",
		)
		fs := parseArchtest(data, c)
		if len(fs) != 1 || fs[0].Rule != "archtest/stale-config" || fs[0].File != ".golangci.arch.yml" {
			t.Fatalf("findings = %+v", fs)
		}
		if !strings.Contains(fs[0].Fix, "go run ./cmd/archgen") {
			t.Errorf("fix = %q", fs[0].Fix)
		}
	})

	t.Run("module not in the manifest", func(t *testing.T) {
		data := archtestJSON(
			`    architecture_test.go:88: module golang.org/x/net is required by go.mod but missing from the architecture.yaml module manifest (S3)`,
		)
		fs := parseArchtest(data, c)
		if len(fs) != 1 || fs[0].Rule != "archtest/module-manifest" || fs[0].File != "go.mod" || fs[0].Message == "" {
			t.Fatalf("findings = %+v", fs)
		}
	})

	t.Run("a failure the parser cannot classify still fails the stage", func(t *testing.T) {
		data := archtestJSON(
			"    engine_test.go:99: panic: something else went wrong",
		)
		fs := parseArchtest(data, c)
		if len(fs) != 1 || fs[0].Rule != "archtest/failed" || !strings.Contains(fs[0].Message, "panic") {
			t.Fatalf("findings = %+v", fs)
		}
	})

	t.Run("a passing run reports nothing", func(t *testing.T) {
		data := []byte(
			`{"Action":"start","Package":"example.com/x/internal/archtest"}` + "\n" +
				`{"Action":"pass","Package":"example.com/x/internal/archtest","Test":"TestArchitecture"}` + "\n" +
				`{"Action":"pass","Package":"example.com/x/internal/archtest"}` + "\n")
		if fs := parseArchtest(data, c); len(fs) != 0 {
			t.Fatalf("findings = %+v", fs)
		}
	})

	t.Run("compile errors of the gate itself are still build findings", func(t *testing.T) {
		data := []byte(
			`{"Action":"start","Package":"example.com/x/internal/archtest"}` + "\n" +
				`{"Action":"build-output","ImportPath":"example.com/x/internal/archtest","Output":"# example.com/x/internal/archtest\n"}` + "\n" +
				`{"Action":"build-output","ImportPath":"example.com/x/internal/archtest","Output":"engine.go:9:2: undefined: nope\n"}` + "\n" +
				`{"Action":"fail","Package":"example.com/x/internal/archtest","FailedBuild":"example.com/x/internal/archtest"}` + "\n")
		fs := parseArchtest(data, c)
		if len(fs) == 0 {
			t.Fatal("no findings for a broken gate")
		}
		bad := false
		for _, f := range fs {
			bad = bad || f.Rule == "build/compile-error"
		}
		if !bad {
			t.Errorf("no build/compile-error finding in %+v", fs)
		}
	})
}
