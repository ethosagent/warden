package main

import (
	"fmt"
	"sort"

	"github.com/ethosagent/warden/tools/approval"
	"github.com/ethosagent/warden/tools/report"
)

// kinds of weakening, the suffix of the finding rule gates/<kind>.
const (
	kindCoverage     = "coverage-lowered"
	kindStageRemoved = "stage-removed"
	kindStageSkipped = "stage-skipped"
	kindStageList    = "stage-list-failed"
	kindStageRenamed = "stage-renamed"
	kindStageCmd     = "stage-command-weakened"
	kindStageGuard   = "stage-guard-changed"
	kindStageDup     = "stage-banner-duplicated"
	kindCoverageCmd  = "coverage-check-changed"
	kindLintConfig   = "lint-config-changed"
	kindCIMissing    = "ci-gate-missing"
	kindCIIntegr     = "ci-integration-dropped"
	kindCIWeakened   = "ci-gate-weakened"
	kindTestDeleted  = "test-deleted"
	kindTestSkipped  = "test-skipped"
	kindLint         = "lint-loosened"
	kindNolint       = "nolint-added"
	kindArchRemoved  = "arch-rule-removed"
	kindArchDown     = "arch-rule-downgraded"
	kindArchLoosened = "arch-rule-loosened"
	kindBaseline     = "baseline-grew"
	kindTool         = "tool-downgraded"
	kindVuln         = "vuln-suppressed"
)

// finding builds one weakening finding. what says what weakened; undo says how
// to put it right instead. Every finding also says how to approve it if intended.
func finding(kind, file string, line int, what, undo string) report.Finding {
	if line < 1 {
		line = 1
	}
	return report.Finding{
		Rule:     "gates/" + kind,
		Severity: report.SevError,
		File:     file,
		Line:     line,
		Message:  fmt.Sprintf("%s:%d: %s", file, line, what),
		Fix:      fmt.Sprintf("%s; if this weakening is intended, a maintainer adds the %s label to the PR (docs/maintainer-setup.md)", undo, approval.Label),
	}
}

// diff holds both sides of a comparison.
type diff struct {
	base, head *view
}

// Compare reports every way head makes a check easier to pass than base. It
// returns nothing for a change that only adds tests or tightens a gate. The
// error is for failing to read a tree, never for a weakening.
func Compare(baseTree, headTree Tree) ([]report.Finding, error) {
	base, err := newView(baseTree)
	if err != nil {
		return nil, fmt.Errorf("read base: %w", err)
	}
	head, err := newView(headTree)
	if err != nil {
		return nil, fmt.Errorf("read head: %w", err)
	}
	d := &diff{base: base, head: head}
	var out []report.Finding
	for _, detect := range []func() []report.Finding{
		d.pins, d.assignments, d.stageList, d.stageCommands, d.scriptEdits, d.stageGuards, d.bannerDuplicates, d.swallowed, d.ci, d.e2e, d.testsDeleted, d.testsSkipped,
		d.lint, d.lintConfigs, d.nolintAdded, d.architecture, d.baseline, d.vuln,
	} {
		out = append(out, detect()...)
	}
	return dedupe(out), nil
}

func dedupe(in []report.Finding) []report.Finding {
	seen := map[string]bool{}
	var out []report.Finding
	for _, f := range in {
		k := fmt.Sprintf("%s|%s|%d|%s", f.Rule, f.File, f.Line, f.Message)
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
