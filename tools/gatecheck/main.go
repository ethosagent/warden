// Command gatecheck guards the rules that decide what "green" means (#354).
//
//	gatecheck weakened -base DIR -head DIR [-pr N -repo OWNER/NAME]
//	gatecheck protected-paths -dir DIR -base-sha SHA -head-sha SHA -pr N -repo OWNER/NAME
//
// weakened compares the base and head checkouts of a PR and reports every way
// head makes a check easier to pass: a lower coverage minimum, a removed or
// skipped check.sh stage, CI that stops running the gate, a deleted or skipped
// test, loosened lint, loosened architecture rules, a growing baseline, a
// downgraded tool, a hidden vulnerability. protected-paths fails a bot- or
// agent-opened PR that touches a path of the gates tier of .agents/risk.yaml.
// Both pass when the PR carries a valid gates-change-approved label (package
// approval), and both write a warden.check.v1 report on stdout.
//
// Run it from a checkout of the BASE branch: a PR must not be able to change
// the code that judges it. It never executes anything from the head checkout,
// not even its check.sh: the head tree is only read as text (the token it holds
// must never meet code the PR author wrote).
//
// This is developer tooling: no Warden package may import it, and it is not
// part of the shipped binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethosagent/warden/tools/approval"
	"github.com/ethosagent/warden/tools/report"
	"github.com/ethosagent/warden/tools/risk"
)

// deps are the parts of gatecheck that touch the outside world.
type deps struct {
	github func(repo string) approval.GitHub
	diff   func(dir, base, head string) ([]string, error)
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr, productionDeps()))
}

func productionDeps() deps {
	return deps{
		github: func(repo string) approval.GitHub {
			api := os.Getenv("GITHUB_API_URL")
			if api == "" {
				api = "https://api.github.com"
			}
			return &approval.Client{BaseURL: strings.TrimRight(api, "/"), Repo: repo, Token: os.Getenv("GITHUB_TOKEN"), Doer: approval.TransportDoer{RT: transport()}}
		},
		diff: risk.DiffNames,
	}
}

func realMain(args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: gatecheck weakened|protected-paths [flags]")
		return 2
	}
	switch args[0] {
	case "weakened":
		return runWeakened(args[1:], stdout, stderr, d)
	case "protected-paths":
		return runProtected(args[1:], stdout, stderr, d)
	}
	fmt.Fprintf(stderr, "gatecheck: unknown command %q\n", args[0])
	return 2
}

const approvalTimeout = 90 * time.Second

func runWeakened(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("weakened", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseDir := fs.String("base", "", "checkout of the base commit")
	headDir := fs.String("head", "", "checkout of the head commit")
	riskPath := fs.String("risk", "", "risk map (default <base>/.agents/risk.yaml)")
	pr := fs.Int("pr", 0, "pull request number, to look for a gates-change-approved label")
	repo := fs.String("repo", "", "owner/name of the repository")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *baseDir == "" || *headDir == "" || (*pr != 0) != (*repo != "") {
		fmt.Fprintln(stderr, "gatecheck weakened: -base and -head are required, and -pr goes with -repo")
		return 2
	}
	findings, err := Compare(dirTree{*baseDir}, dirTree{*headDir})
	if err != nil {
		fmt.Fprintln(stderr, "gatecheck:", err)
		return 1
	}
	metrics := map[string]any{"findings": len(findings)}
	if len(findings) > 0 {
		rp := *riskPath
		if rp == "" {
			rp = *baseDir + "/.agents/risk.yaml"
		}
		findings = applyApproval(findings, metrics, rp, *pr, *repo, d)
	}
	return emit(stdout, stderr, "gates-not-weakened", findings, metrics)
}

func runProtected(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("protected-paths", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "git checkout containing both commits")
	baseSHA := fs.String("base-sha", "", "base commit")
	headSHA := fs.String("head-sha", "", "head commit")
	riskPath := fs.String("risk", ".agents/risk.yaml", "risk map; take it from the base branch")
	pr := fs.Int("pr", 0, "pull request number")
	repo := fs.String("repo", "", "owner/name of the repository")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *baseSHA == "" || *headSHA == "" || *pr == 0 || *repo == "" {
		fmt.Fprintln(stderr, "gatecheck protected-paths: -base-sha, -head-sha, -pr and -repo are required")
		return 2
	}
	raw, err := os.ReadFile(*riskPath)
	if err != nil {
		fmt.Fprintln(stderr, "gatecheck:", err)
		return 1
	}
	m, err := risk.Parse(raw)
	if err != nil {
		fmt.Fprintln(stderr, "gatecheck:", err)
		return 1
	}
	files, err := d.diff(*dir, *baseSHA, *headSHA)
	if err != nil {
		fmt.Fprintln(stderr, "gatecheck: git diff:", err)
		return 1
	}
	protected := m.Classify(files).Protected()
	metrics := map[string]any{"protected": protected}
	if len(protected) == 0 {
		return emit(stdout, stderr, "protected-paths", nil, metrics)
	}
	ctx, cancel := context.WithTimeout(context.Background(), approvalTimeout)
	defer cancel()
	gh := d.github(*repo)
	p, err := gh.PullRequest(ctx, *pr)
	if err != nil {
		return emit(stdout, stderr, "protected-paths", []report.Finding{unverifiable(err)}, metrics)
	}
	agent := m.IsAgent(p.Author.Login, p.Author.Type)
	metrics["author"], metrics["agent"] = p.Author.Login, agent
	if !agent {
		return emit(stdout, stderr, "protected-paths", nil, metrics) // the gates-not-weakened check still applies
	}
	v, err := approval.Verify(ctx, gh, *pr, m.IsAgent)
	if err != nil {
		return emit(stdout, stderr, "protected-paths", []report.Finding{unverifiable(err)}, metrics)
	}
	metrics["approval"] = v.Reason
	if v.Approved {
		return emit(stdout, stderr, "protected-paths", nil, metrics)
	}
	var findings []report.Finding
	for _, f := range protected {
		findings = append(findings, report.Finding{
			Rule:     "protected-paths/touched",
			Severity: report.SevError,
			File:     f,
			Message:  fmt.Sprintf("%s is a protected gate path and this PR was opened by %s, a bot or agent account; %s", f, p.Author.Login, v.Reason),
			Fix: fmt.Sprintf("an agent must not change gates: stop and ask. If the change is intended, a maintainer (maintain or admin, not a bot) adds the %s label after the latest push (docs/maintainer-setup.md)",
				approval.Label),
		})
	}
	return emit(stdout, stderr, "protected-paths", findings, metrics)
}

func unverifiable(err error) report.Finding {
	return report.Finding{
		Rule:     "approval/unverifiable",
		Severity: report.SevError,
		Message:  fmt.Sprintf("could not verify the %s label with the GitHub API: %v", approval.Label, err),
		Fix:      "re-run the check; if it keeps failing, see the token permissions in docs/maintainer-setup.md",
	}
}

// applyApproval lets a valid gates-change-approved label turn the findings into
// warnings. Without -pr, with an unverifiable label or with an invalid one the
// findings stay errors.
func applyApproval(findings []report.Finding, metrics map[string]any, riskPath string, pr int, repo string, d deps) []report.Finding {
	if pr == 0 {
		metrics["approval"] = "no pull request given, so no label can approve"
		return findings
	}
	raw, err := os.ReadFile(riskPath)
	if err != nil {
		return append(findings, unverifiable(err))
	}
	m, err := risk.Parse(raw)
	if err != nil {
		return append(findings, unverifiable(err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), approvalTimeout)
	defer cancel()
	v, err := approval.Verify(ctx, d.github(repo), pr, m.IsAgent)
	if err != nil {
		return append(findings, unverifiable(err))
	}
	metrics["approval"] = v.Reason
	if !v.Approved {
		return findings
	}
	metrics["approvedBy"] = v.By
	for i := range findings {
		findings[i].Severity = report.SevWarning
		findings[i].Message += fmt.Sprintf(" [approved by %s]", v.By)
	}
	return findings
}

func emit(stdout, stderr io.Writer, name string, findings []report.Finding, metrics map[string]any) int {
	rep := report.New(name, "tools/gatecheck", findings, metrics)
	if err := rep.Write(stdout); err != nil {
		fmt.Fprintln(stderr, "gatecheck:", err)
		return 1
	}
	for _, f := range findings {
		fmt.Fprintf(stderr, "%s: %s: %s\n  fix: %s\n", f.Severity, f.Rule, f.Message, f.Fix)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

// transport is the HTTP transport for GitHub API calls. The tool talks only to
// the GitHub API, so it uses the transport directly (X4: no bare http.Client).
func transport() http.RoundTripper { return http.DefaultTransport }
