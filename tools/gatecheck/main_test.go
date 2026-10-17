package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/tools/approval"
	"github.com/ethosagent/warden/tools/report"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type fakeGH struct {
	pr       approval.PullRequest
	events   []approval.LabelEvent
	pushedAt time.Time
	perms    map[string]string
	err      error
}

func (f *fakeGH) PullRequest(context.Context, int) (approval.PullRequest, error) { return f.pr, f.err }
func (f *fakeGH) LabelEvents(context.Context, int, string) ([]approval.LabelEvent, error) {
	return f.events, f.err
}
func (f *fakeGH) HeadPushedAt(context.Context, int, string) (time.Time, error) {
	return f.pushedAt, f.err
}
func (f *fakeGH) Permission(_ context.Context, l string) (string, error) { return f.perms[l], f.err }

func user(l string) approval.Account { return approval.Account{Login: l, Type: "User"} }
func bot(l string) approval.Account  { return approval.Account{Login: l, Type: "Bot"} }

// botPR is a bot-opened PR with a label from a maintainer after the push.
func botPR() *fakeGH {
	return &fakeGH{
		pr:       approval.PullRequest{Author: bot("claude[bot]"), HeadSHA: "abc1234", Labels: []string{approval.Label}},
		events:   []approval.LabelEvent{{Added: true, Actor: user("mitesh"), At: t0.Add(time.Hour)}},
		pushedAt: t0,
		perms:    map[string]string{"mitesh": "maintain", "writer": "write"},
	}
}

func writeTree(t *testing.T, root string, files memTree) string {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type result struct {
	code     int
	out, err string
}

func (r result) doc(t *testing.T) (ok bool, rules []string, metrics map[string]any) {
	t.Helper()
	var d struct {
		OK     bool `json:"ok"`
		Stages []struct {
			Findings []struct{ Rule, Severity string }
			Metrics  map[string]any
		}
	}
	if err := json.Unmarshal([]byte(r.out), &d); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, r.out)
	}
	for _, f := range d.Stages[0].Findings {
		rules = append(rules, f.Severity+":"+f.Rule)
	}
	return d.OK, rules, d.Stages[0].Metrics
}

func run(args []string, gh *fakeGH, files []string) result {
	var out, errb bytes.Buffer
	d := deps{
		github: func(string) approval.GitHub { return gh },
		diff:   func(string, string, string) ([]string, error) { return files, nil },
	}
	code := realMain(args, &out, &errb, d)
	return result{code, out.String(), errb.String()}
}

// weakenedDirs checks out the good repo as base and head, with head lowering the coverage minimum.
func weakenedDirs(t *testing.T) (base, head string) {
	t.Helper()
	b := goodRepo()
	h := b.clone()
	h.replace(t, "scripts/check.sh", ":-70}", ":-60}")
	return writeTree(t, filepath.Join(t.TempDir(), "base"), b), writeTree(t, filepath.Join(t.TempDir(), "head"), h)
}

func TestWeakenedFailsWithoutApproval(t *testing.T) {
	base, head := weakenedDirs(t)
	// the risk map is read from the base checkout
	writeTree(t, base, memTree{".agents/risk.yaml": mustRead(t, "../../.agents/risk.yaml")})
	cases := []struct {
		name string
		args []string
		gh   *fakeGH
		code int
		rule string
	}{
		{"no PR given", []string{"weakened", "-base", base, "-head", head}, botPR(), 1, "error:gates/coverage-lowered"},
		{"valid label", []string{"weakened", "-base", base, "-head", head, "-pr", "7", "-repo", "o/r"}, botPR(), 0, "warning:gates/coverage-lowered"},
		{"label added by the bot", []string{"weakened", "-base", base, "-head", head, "-pr", "7", "-repo", "o/r"}, func() *fakeGH {
			g := botPR()
			g.events[0].Actor = bot("claude[bot]")
			return g
		}(), 1, "error:gates/coverage-lowered"},
		{"label before the push", []string{"weakened", "-base", base, "-head", head, "-pr", "7", "-repo", "o/r"}, func() *fakeGH {
			g := botPR()
			g.pushedAt = t0.Add(5 * time.Hour)
			return g
		}(), 1, "error:gates/coverage-lowered"},
		{"label from a writer", []string{"weakened", "-base", base, "-head", head, "-pr", "7", "-repo", "o/r"}, func() *fakeGH {
			g := botPR()
			g.events[0].Actor = user("writer")
			return g
		}(), 1, "error:gates/coverage-lowered"},
		{"no label", []string{"weakened", "-base", base, "-head", head, "-pr", "7", "-repo", "o/r"}, func() *fakeGH {
			g := botPR()
			g.pr.Labels = nil
			return g
		}(), 1, "error:gates/coverage-lowered"},
		{"GitHub unreachable fails closed", []string{"weakened", "-base", base, "-head", head, "-pr", "7", "-repo", "o/r"}, func() *fakeGH {
			g := botPR()
			g.err = os.ErrDeadlineExceeded
			return g
		}(), 1, "error:approval/unverifiable"},
	}
	for _, c := range cases {
		r := run(c.args, c.gh, nil)
		ok, rules, _ := r.doc(t)
		if r.code != c.code || ok != (c.code == 0) || !contains(rules, c.rule) {
			t.Errorf("%s: code=%d ok=%v rules=%v, want code %d with %s\n%s", c.name, r.code, ok, rules, c.code, c.rule, r.err)
		}
	}
}

func TestWeakenedPassesWhenNothingWeakens(t *testing.T) {
	b := goodRepo()
	h := b.clone()
	h.replace(t, "scripts/check.sh", ":-70}", ":-75}")
	base := writeTree(t, filepath.Join(t.TempDir(), "b"), b)
	head := writeTree(t, filepath.Join(t.TempDir(), "h"), h)
	r := run([]string{"weakened", "-base", base, "-head", head}, botPR(), nil)
	if ok, rules, _ := r.doc(t); r.code != 0 || !ok || len(rules) != 0 {
		t.Fatalf("a tightening must pass: code=%d rules=%v\n%s", r.code, rules, r.err)
	}
}

func TestWeakenedUsage(t *testing.T) {
	for _, args := range [][]string{
		{}, {"bogus"}, {"weakened"}, {"weakened", "-base", "a", "-head", "b", "-pr", "3"}, {"protected-paths"},
	} {
		if r := run(args, botPR(), nil); r.code != 2 {
			t.Errorf("%v: code = %d, want 2", args, r.code)
		}
	}
}

func riskPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../.agents/risk.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProtectedPaths(t *testing.T) {
	protected := []string{"internal/dlp/dlp.go", "scripts/check.sh"}
	args := func(extra ...string) []string {
		return append([]string{"protected-paths", "-risk", riskPath(t), "-base-sha", "b", "-head-sha", "h", "-pr", "7", "-repo", "o/r"}, extra...)
	}
	cases := []struct {
		name  string
		gh    *fakeGH
		files []string
		code  int
		rule  string
	}{
		{"bot touches check.sh without a label", func() *fakeGH { g := botPR(); g.pr.Labels = nil; return g }(), protected, 1, "error:protected-paths/touched"},
		{"bot touches check.sh, label from a maintainer after the push", botPR(), protected, 0, ""},
		{"bot touches check.sh, label added by the bot itself", func() *fakeGH {
			g := botPR()
			g.events[0].Actor = bot("claude[bot]")
			return g
		}(), protected, 1, "error:protected-paths/touched"},
		{"bot touches check.sh, label before the latest push", func() *fakeGH {
			g := botPR()
			g.pushedAt = t0.Add(2 * time.Hour)
			return g
		}(), protected, 1, "error:protected-paths/touched"},
		{"bot touches .github", func() *fakeGH { g := botPR(); g.pr.Labels = nil; return g }(), []string{".github/workflows/ci.yml"}, 1, "error:protected-paths/touched"},
		{"bot touches only ordinary files", func() *fakeGH { g := botPR(); g.pr.Labels = nil; return g }(), []string{"internal/dlp/dlp.go", "docs/x.md"}, 0, ""},
		{"human maintainer touches check.sh", func() *fakeGH {
			g := botPR()
			g.pr.Author = user("mitesh")
			g.pr.Labels = nil
			return g
		}(), protected, 0, ""},
		{"GitHub unreachable", func() *fakeGH { g := botPR(); g.err = os.ErrDeadlineExceeded; return g }(), protected, 1, "error:approval/unverifiable"},
	}
	for _, c := range cases {
		r := run(args(), c.gh, c.files)
		ok, rules, _ := r.doc(t)
		if r.code != c.code || ok != (c.code == 0) || (c.rule != "" && !contains(rules, c.rule)) || (c.rule == "" && len(rules) != 0) {
			t.Errorf("%s: code=%d ok=%v rules=%v, want code %d %q\n%s", c.name, r.code, ok, rules, c.code, c.rule, r.err)
		}
	}
	// the finding names each protected file and how to get approval
	g := botPR()
	g.pr.Labels = nil
	r := run(args(), g, protected)
	if !strings.Contains(r.out, `"file": "scripts/check.sh"`) || !strings.Contains(r.out, approval.Label) || strings.Contains(r.out, `"file": "internal/dlp/dlp.go"`) {
		t.Errorf("findings should name scripts/check.sh only and the label:\n%s", r.out)
	}
}

func TestProtectedPathsAgentAccountList(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "risk.yaml")
	doc := strings.Replace(mustRead(t, "../../.agents/risk.yaml"), "agent-accounts: []", "agent-accounts: [Helper-Agent]", 1)
	if err := os.WriteFile(rp, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	g := botPR()
	g.pr.Author = user("helper-agent") // type User, but listed
	g.pr.Labels = nil
	r := run([]string{"protected-paths", "-risk", rp, "-base-sha", "b", "-head-sha", "h", "-pr", "7", "-repo", "o/r"}, g, []string{"scripts/check.sh"})
	if r.code != 1 {
		t.Fatalf("a listed agent account must be held to the label: %d\n%s", r.code, r.out)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestDirTreeSkipsGitAndReadsFiles(t *testing.T) {
	root := writeTree(t, t.TempDir(), memTree{"a/b.go": "x", ".git/config": "y", "c.txt": "z"})
	files, err := (dirTree{root}).Files()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(files, ",") != "a/b.go,c.txt" {
		t.Fatalf("files = %v", files)
	}
	if b, err := (dirTree{root}).Read("a/b.go"); err != nil || string(b) != "x" {
		t.Fatalf("read = %q, %v", b, err)
	}
}

func TestStageListProblems(t *testing.T) {
	base := goodRepo()
	head := base.clone()
	delete(head, "scripts/check.sh")
	f, err := Compare(base, head)
	if err != nil || !hasRule(f, "gates/stage-list-failed") {
		t.Fatalf("a head without check.sh must fail closed: %v %v", f, err)
	}
	// no script on base: nothing to hold head to
	noScript := base.clone()
	delete(noScript, "scripts/check.sh")
	if f, _ := Compare(noScript, base); hasRule(f, "gates/stage-list-failed") || hasRule(f, "gates/stage-removed") {
		t.Fatalf("expected no stage comparison without a base script: %v", f)
	}
}

func hasRule(fs []report.Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
