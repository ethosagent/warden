package main

import (
	"strings"
	"testing"
)

func TestParseVet(t *testing.T) {
	fs := parseVet(readTestdata(t, "vet.json"), gotestCtx())
	if len(fs) != 1 {
		t.Fatalf("want 1, got %+v", fs)
	}
	f := fs[0]
	if f.Rule != "vet/printf" || f.File != "vetbad/a.go" || f.Line != 6 || f.Col != 14 {
		t.Errorf("bad finding: %+v", f)
	}
	if !strings.Contains(f.Message, "wrong type string") || f.Fix == "" {
		t.Errorf("message/fix: %+v", f)
	}
}

func TestParseVetEmpty(t *testing.T) {
	if fs := parseVet(nil, gotestCtx()); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestParseBuild(t *testing.T) {
	fs := parseBuild(readTestdata(t, "build.json"), gotestCtx())
	if len(fs) != 3 {
		t.Fatalf("want 3, got %+v", fs)
	}
	f := fs[2]
	if f.Rule != "build/compile-error" || f.File != "buildbad/a.go" || f.Line != 5 || f.Col != 9 || f.Message != "undefined: y" {
		t.Errorf("bad finding: %+v", f)
	}
	if !strings.Contains(f.Fix, "undefined") || !strings.Contains(f.Fix, "buildbad/a.go:5") {
		t.Errorf("fix should be specific: %q", f.Fix)
	}
	for _, f := range fs {
		if f.Fix == "" {
			t.Errorf("empty fix: %+v", f)
		}
	}
}
