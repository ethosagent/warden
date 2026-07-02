package scan

import "regexp"

// This file adds the source_code family. Unlike the exact matchers, these are
// CLASSIFIERS: they answer "does this body look like code of language X?" and
// emit ONE detection per language family (never per line). Severity is low/medium
// — code is sensitive but not a secret by itself. The design goal is that real
// code in the top-~10 languages trips a classifier while prose and plain JSON/
// config data do NOT: every language signal is anchored to a DEFINITION or
// language-specific declaration (func/def/fn/function/#include/<?php), none of
// which appear in JSON key/value data or ordinary sentences.

// buildSourceCodeClassifiers compiles the source-code classifiers once (per
// NewScanner call) and returns them as body classifiers. Order is irrelevant —
// dedup keys on Category|Pattern|Severity, and each classifier owns a distinct
// pattern name.
func buildSourceCodeClassifiers() []bodyClassifier {
	langs := []struct {
		pattern  string
		severity string
		signals  []*regexp.Regexp
	}{
		{"code_go", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*func\s+(?:\([^)\n]{1,60}\)\s*)?\w+\s*\(`),
			regexp.MustCompile(`(?m)^package\s+[a-z][a-zA-Z0-9_]*\s*$`),
		}},
		{"code_python", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*def\s+\w+\s*\([^)\n]*\)\s*:`),
			regexp.MustCompile(`(?m)^\s*class\s+\w+\s*(?:\([^)\n]*\))?\s*:`),
		}},
		{"code_javascript", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*\w+\s*\(`),
			regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:const|let)\s+\w+\s*=\s*(?:async\s+)?\([^)\n]*\)\s*=>`),
		}},
		{"code_java", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\].]+\s+\w+\s*\([^;\n]*\)\s*(?:throws [\w, .]+)?\{`),
			regexp.MustCompile(`(?m)^\s*package\s+[\w.]+;`),
		}},
		{"code_c", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*#include\s*[<"][\w./]+[>"]`),
			regexp.MustCompile(`(?m)^\s*(?:static\s+|inline\s+)*(?:void|int|char|short|long|float|double|unsigned|size_t|bool)\s+\**\w+\s*\([^;{]*\)\s*\{`),
		}},
		{"code_csharp", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*using\s+System(?:\.[\w.]+)?\s*;`),
			regexp.MustCompile(`(?m)^\s*namespace\s+[\w.]+\s*\{?`),
		}},
		{"code_ruby", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*require(?:_relative)?\s+['"][\w./]+['"]`),
			regexp.MustCompile(`(?m)^\s*def\s+[a-z_]\w*[!?=]?\s*(?:\([^)\n]*\))?\s*$`),
		}},
		{"code_rust", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*(?:<[^>\n]*>)?\s*\(`),
			regexp.MustCompile(`(?m)^\s*use\s+\w+(?:::\w+)+\s*;`),
		}},
		{"code_php", "low", []*regexp.Regexp{
			regexp.MustCompile(`<\?php\b`),
			regexp.MustCompile(`(?m)^\s*(?:public|private|protected)?\s*function\s+\w+\s*\([^)\n]*\)\s*\{`),
		}},
		{"code_shell", "low", []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*(?:if|elif|while|until)\b[^\n]*;\s*then\b`),
			regexp.MustCompile(`(?m)^\s*(?:for|while|until)\b[^\n]*;\s*do\b`),
			regexp.MustCompile(`(?m)^\s*case\s+.+\s+in\s*$`),
		}},
	}

	classifiers := make([]bodyClassifier, 0, len(langs)+3)
	for _, l := range langs {
		l := l
		classifiers = append(classifiers, func(data []byte) []Detection {
			for _, re := range l.signals {
				if re.Match(data) {
					return []Detection{{Category: "source_code", Pattern: l.pattern, Severity: l.severity}}
				}
			}
			return nil
		})
	}

	// Shebang: a real interpreter path at line start.
	shebangRe := regexp.MustCompile(`(?m)^#!\s*/\S+`)
	classifiers = append(classifiers, func(data []byte) []Detection {
		if shebangRe.Match(data) {
			return []Detection{{Category: "source_code", Pattern: "code_shebang", Severity: "low"}}
		}
		return nil
	})

	// VCS markers: unified-diff / git-patch structure.
	vcsRe := regexp.MustCompile(`(?m)^diff --git a/|^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@`)
	classifiers = append(classifiers, func(data []byte) []Detection {
		if vcsRe.Match(data) {
			return []Detection{{Category: "source_code", Pattern: "code_vcs", Severity: "low"}}
		}
		return nil
	})

	// Density heuristic: count definition-like lines across languages. JSON and
	// prose contain effectively zero of these, so the threshold cleanly separates
	// code from data. Requires BOTH an absolute floor (>= minDefs, so a lone
	// snippet does not trip) and a rate (>= defsPerKB per 1024 bytes, so a huge
	// data file with a couple of stray matches does not trip).
	classifiers = append(classifiers, densityClassifier)

	return classifiers
}

// defDensityRe matches a function/method definition in any of the supported
// languages — the signal counted by the density heuristic.
var defDensityRe = regexp.MustCompile(`(?m)^\s*(?:func\s+\w|def\s+\w|fn\s+\w|sub\s+\w|(?:export\s+)?(?:async\s+)?function\s*\*?\s*\w|(?:public|private|protected|internal)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\].]+\s+\w+\s*\()`)

const (
	densityMinDefs = 3 // absolute floor: a lone snippet must not trip
	densityDefsKB  = 3 // >= this many defs per 1024 bytes ⇒ code, not prose/JSON
)

// densityClassifier emits code_density when a body carries enough function-def
// lines, both absolutely and per KB. This catches code in languages outside the
// explicit top-10 (and unusually formatted code) without flagging data files.
func densityClassifier(data []byte) []Detection {
	n := len(defDensityRe.FindAll(data, -1))
	if n < densityMinDefs {
		return nil
	}
	if len(data) == 0 || n*1024 < densityDefsKB*len(data) {
		return nil
	}
	return []Detection{{Category: "source_code", Pattern: "code_density", Severity: "low"}}
}
