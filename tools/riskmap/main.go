// Command riskmap prints the risk tier of a pull request as a warden.check.v1
// document (docs/check-report.schema.json): the highest tier any changed file
// hits in .agents/risk.yaml wins; a path that matches nothing is normal, never
// low (#354). CI turns the tier into a risk:<tier> label and makes the L2 e2e
// job required when it is critical.
//
// This is developer tooling: no Warden package may import it, and it is not
// part of the shipped binary.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ethosagent/warden/tools/report"
	"github.com/ethosagent/warden/tools/risk"
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr, func(base, head string) ([]string, error) { return risk.DiffNames(".", base, head) }))
}

type diffFunc func(base, head string) ([]string, error)

func realMain(args []string, stdout, stderr io.Writer, diff diffFunc) int {
	fs := flag.NewFlagSet("riskmap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	riskPath := fs.String("risk", ".agents/risk.yaml", "risk map file")
	base := fs.String("base", "", "base ref or sha (git diff --name-only <base>...<head>)")
	head := fs.String("head", "", "head ref or sha")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *base == "" || *head == "" {
		fmt.Fprintln(stderr, "riskmap: -base and -head are required")
		return 2
	}
	b, err := os.ReadFile(*riskPath)
	if err != nil {
		fmt.Fprintln(stderr, "riskmap:", err)
		return 1
	}
	m, err := risk.Parse(b)
	if err != nil {
		fmt.Fprintln(stderr, "riskmap:", err)
		return 1
	}
	files, err := diff(*base, *head)
	if err != nil {
		fmt.Fprintln(stderr, "riskmap: git diff:", err)
		return 1
	}
	res := m.Classify(files)
	metrics := map[string]any{
		"tier":        string(res.Tier),
		"label":       res.Tier.Label(),
		"e2eRequired": res.Tier == risk.Critical,
		"files":       res.Files,
	}
	if err := report.New("riskmap", "tools/riskmap", nil, metrics).Write(stdout); err != nil {
		fmt.Fprintln(stderr, "riskmap:", err)
		return 1
	}
	return 0
}
