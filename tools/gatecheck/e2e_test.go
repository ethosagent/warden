package main

import (
	"strings"
	"testing"
)

// The e2e job is a required check (#369): a PR must not be able to make it pass
// without running the suite. gatecheck runs from the base, so these hold the
// head's e2e.yml to what the real one on the base does.

const e2ePath = ".github/workflows/e2e.yml"

func e2eTrees(t *testing.T) (memTree, memTree) {
	t.Helper()
	real := mustRead(t, "../../"+e2ePath)
	return memTree{e2ePath: real}, memTree{e2ePath: real}
}

func TestE2EWorkflowUnchangedIsClean(t *testing.T) {
	base, head := e2eTrees(t)
	if fs := compare(t, base, head); len(fs) != 0 {
		t.Fatalf("the real e2e.yml compared with itself reported: %v", fs)
	}
}

func TestE2EWorkflowWeakeningsAreCaught(t *testing.T) {
	run := "run: go test -tags e2e -count=1 -timeout 12m ./test/e2e/ -json > e2e.jsonl"
	for _, tc := range []struct {
		name, old, new, kind, contains string
	}{
		{"|| true on the run step", run, run + " || true", "ci-gate-weakened", "ignores a failure"},
		{"|| : on the run step", run, "run: |\n          go test -tags e2e -count=1 ./test/e2e/ -json > e2e.jsonl || :\n          echo", "ci-gate-weakened", "ignores a failure"},
		{"|| exit 0 on the run step", run, run + " || exit 0", "ci-gate-weakened", "ignores a failure"},
		{"; true on the run step", run, run + "; true", "ci-gate-weakened", "ignores a failure"},
		{"set +e before the run", run, "run: |\n          set +e\n          go test -tags e2e -count=1 ./test/e2e/ -json > e2e.jsonl", "ci-gate-weakened", "ignores a failure"},
		{"continue-on-error on the step", "        env:\n          KEEP_STACK", "        continue-on-error: true\n        env:\n          KEEP_STACK", "ci-gate-weakened", "continue-on-error"},
		{"continue-on-error on the job", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    continue-on-error: true\n", "ci-gate-weakened", "continue-on-error"},
		{"step made conditional", "        env:\n          KEEP_STACK", "        if: github.actor != 'bot'\n        env:\n          KEEP_STACK", "ci-gate-weakened", "`if:"},
		{"run step removed", run, "run: echo skipped", "ci-gate-weakened", "no longer has a step"},
		{"timeout raised", "timeout-minutes: 15", "timeout-minutes: 60", "ci-gate-weakened", "timeout-minutes"},
		{"timeout removed", "    timeout-minutes: 15\n", "", "ci-gate-weakened", "no timeout"},
		{"job renamed", "  e2e:\n    name: e2e\n", "  suite:\n    name: e2e\n", "ci-gate-weakened", "job id"},
		{"job name changed", "    name: e2e\n", "    name: integration\n", "ci-gate-weakened", "name is no longer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, head := e2eTrees(t)
			head.replace(t, e2ePath, tc.old, tc.new)
			fs := compare(t, base, head)
			for _, f := range fs {
				if f.Rule == "gates/"+tc.kind && f.File == e2ePath && strings.Contains(f.Message, tc.contains) {
					return
				}
			}
			t.Fatalf("no gates/%s finding containing %q; got %v", tc.kind, tc.contains, fs)
		})
	}
}

func TestE2EWorkflowMakeTargetIsAccepted(t *testing.T) {
	base, head := e2eTrees(t)
	head.replace(t, e2ePath, "run: go test -tags e2e -count=1 -timeout 12m ./test/e2e/ -json > e2e.jsonl", "run: make e2e")
	if fs := compare(t, base, head); len(fs) != 0 {
		t.Fatalf("`make e2e` is the documented target, got %v", fs)
	}
}

func TestE2EWorkflowDeletedIsCaught(t *testing.T) {
	base, head := e2eTrees(t)
	delete(head, e2ePath)
	fs := compare(t, base, head)
	if len(fs) != 1 || fs[0].Rule != "gates/ci-gate-missing" {
		t.Fatalf("want one ci-gate-missing finding, got %v", fs)
	}
}

// The PR that adds e2e.yml has no base file to compare: nothing is reported.
func TestE2EWorkflowNewInThisPRIsNotCompared(t *testing.T) {
	_, head := e2eTrees(t)
	if fs := compare(t, memTree{}, head); len(fs) != 0 {
		t.Fatalf("no base e2e.yml, expected no findings, got %v", fs)
	}
}
