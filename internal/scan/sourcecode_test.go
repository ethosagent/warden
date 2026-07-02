package scan

import (
	"strings"
	"testing"
)

// hasCategory reports whether any detection has the given category.
func hasCategory(dets []Detection, category string) bool {
	for _, d := range dets {
		if d.Category == category {
			return true
		}
	}
	return false
}

// TestSourceCodeLanguages: real code in ~10 languages classifies as source_code
// with the expected per-language pattern (one detection per language family).
func TestSourceCodeLanguages(t *testing.T) {
	s := NewScanner()
	cases := []struct {
		lang string
		patt string
		code string
	}{
		{"go", "code_go", "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n"},
		{"python", "code_python", "def greet(name):\n    return \"hi \" + name\n"},
		{"javascript", "code_javascript", "export function add(a, b) {\n  return a + b\n}\n"},
		{"java", "code_java", "package com.example;\n\npublic class Foo {\n}\n"},
		{"c", "code_c", "#include <stdio.h>\nint main(void) {\n  return 0;\n}\n"},
		{"csharp", "code_csharp", "using System;\nnamespace App {\n}\n"},
		{"ruby", "code_ruby", "require 'json'\ndef run\n  puts 1\nend\n"},
		{"rust", "code_rust", "pub fn main() {\n    println!(\"hi\");\n}\n"},
		{"php", "code_php", "<?php\nfunction hello() {\n  echo 1;\n}\n"},
		{"shell", "code_shell", "if [ -f x ]; then\n  echo hi\nfi\n"},
	}
	for _, c := range cases {
		t.Run(c.lang, func(t *testing.T) {
			dets := s.ScanResponse([]byte(c.code))
			assertDetection(t, dets, "source_code", c.patt)
			if !hasClass(dets, c.patt, ClassSourceCode) {
				t.Fatalf("%s: %s must carry source_code class", c.lang, c.patt)
			}
		})
	}
}

// TestSourceCodeShebangAndVCS covers the non-language markers.
func TestSourceCodeShebangAndVCS(t *testing.T) {
	s := NewScanner()
	dets := s.ScanResponse([]byte("#!/usr/bin/env python3\nprint('x')\n"))
	assertDetection(t, dets, "source_code", "code_shebang")

	diff := "diff --git a/foo.go b/foo.go\n@@ -1,3 +1,4 @@\n-old\n+new\n"
	dets = s.ScanResponse([]byte(diff))
	assertDetection(t, dets, "source_code", "code_vcs")
}

// TestSourceCodeDensity: a multi-function body trips the density heuristic; JSON
// data and prose do NOT — the crucial false-positive guard.
func TestSourceCodeDensity(t *testing.T) {
	s := NewScanner()
	code := "func a() {}\nfunc b() {}\nfunc c() {}\nfunc d() {}\n"
	dets := s.ScanResponse([]byte(code))
	assertDetection(t, dets, "source_code", "code_density")

	// A JSON payload with many keys must not be classified as code (no defs).
	json := `{"function":"search","def":true,"class":"a","import":"b","fn":1,` +
		`"users":[{"name":"a","role":"admin"},{"name":"b","role":"user"}],` +
		`"count":42,"nested":{"k":"v","list":[1,2,3,4,5]}}`
	dets = s.ScanResponse([]byte(json))
	if hasCategory(dets, "source_code") {
		t.Fatalf("JSON data must NOT classify as source_code, got %+v", dets)
	}

	// Prose must not classify as code either.
	prose := "The quick brown fox jumps over the lazy dog. This paragraph is " +
		"ordinary prose describing a scene, with no function definitions, imports, " +
		"or code structure of any kind whatsoever in its sentences."
	dets = s.ScanResponse([]byte(prose))
	if hasCategory(dets, "source_code") {
		t.Fatalf("prose must NOT classify as source_code, got %+v", dets)
	}
}

// TestHealthOffByDefault: pii.health is DEFAULT OFF; a diagnosis string only
// detects when WithHealthPII(true) is set.
func TestHealthOffByDefault(t *testing.T) {
	body := []byte("patient diagnosed with hypertension, prescribed lisinopril 10mg daily")

	off := NewScanner().ScanResponse(body)
	for _, d := range off {
		if strings.HasPrefix(d.Pattern, "health_") {
			t.Fatalf("health detector fired without WithHealthPII: %+v", d)
		}
	}
	for _, d := range off {
		for _, c := range d.Classes {
			if c == ClassPIIHealth {
				t.Fatalf("pii.health class emitted while health detection is off: %+v", d)
			}
		}
	}

	on := NewScanner(WithHealthPII(true)).ScanResponse(body)
	if !hasClass(on, "health_diagnosis", ClassPIIHealth) && !hasCategory(on, "pii") {
		t.Fatalf("expected a health detection with WithHealthPII(true), got %+v", on)
	}
	var gotHealth bool
	for _, d := range on {
		if strings.HasPrefix(d.Pattern, "health_") {
			gotHealth = true
			if !containsClass(d.Classes, ClassPIIHealth) {
				t.Fatalf("health detection missing pii.health class: %+v", d)
			}
		}
	}
	if !gotHealth {
		t.Fatalf("WithHealthPII(true) produced no health_* detection: %+v", on)
	}
}

func containsClass(cs []DataClass, want DataClass) bool {
	for _, c := range cs {
		if c == want {
			return true
		}
	}
	return false
}
