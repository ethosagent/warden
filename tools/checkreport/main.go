package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr, os.Environ())) }

// realMain is main without the process globals, so it can be tested. Whatever
// happens inside, a requested report is always written and is always valid.
func realMain(args []string, stdout, stderr io.Writer, environ []string) (code int) {
	fs := flag.NewFlagSet("checkreport", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg config
	var asJSON bool
	var jsonOut, only string
	var planOnly, listOnly bool
	fs.StringVar(&cfg.Root, "root", ".", "repository root to check")
	fs.BoolVar(&cfg.Integration, "integration", false, "also run the integration stage")
	fs.BoolVar(&cfg.KeepGoing, "keep-going", false, "run every stage after a failure")
	fs.BoolVar(&asJSON, "json", false, "write the report to stdout; human progress goes to stderr")
	fs.StringVar(&jsonOut, "json-out", "", "also write the report to this `path`")
	fs.Float64Var(&cfg.CoverageMin, "coverage-min", 0, "minimum total coverage percent")
	fs.StringVar(&cfg.GolangciVersion, "golangci-version", "", "pinned golangci-lint version")
	fs.StringVar(&cfg.GovulncheckVersion, "govulncheck-version", "", "pinned govulncheck version")
	fs.BoolVar(&cfg.Fast, "fast", false, "check only packages changed since origin/main plus their importers; skip whole-repo stages")
	fs.BoolVar(&planOnly, "fast-plan", false, "print the --fast package plan for scripts/check.sh and exit")
	fs.BoolVar(&listOnly, "list-stages", false, "print the names of the stages the gate runs (one per line, or a report with -json) and exit; runs nothing")
	fs.StringVar(&cfg.FuzzTime, "fuzz-time", defaultFuzzTime, "-fuzztime for each fuzz target")
	fs.StringVar(&cfg.FuzzTargets, "fuzz-targets", "scripts/fuzz-targets.txt", "file listing the fuzz targets, relative to -root")
	fs.StringVar(&only, "stages", "", "comma-separated stages to run (default: all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !planOnly && !listOnly && (cfg.GolangciVersion == "" || cfg.GovulncheckVersion == "") {
		fmt.Fprintln(stderr, "checkreport: -golangci-version and -govulncheck-version are required (scripts/check.sh passes them)")
		return 2
	}
	if only != "" {
		cfg.Only = strings.Split(only, ",")
	}
	if asJSON {
		cfg.KeepGoing = true
	}
	human := stdout
	if asJSON {
		human = stderr
	}

	sc := NewScrubber(environ)
	var rep *Report
	defer func() {
		// Last resort: a panic outside any stage still yields a valid report.
		if p := recover(); p != nil {
			rep = &Report{Stages: []Stage{{Name: "runner", Tool: "checkreport", Findings: []Finding{crashed("runner", fmt.Sprint("checkreport panicked: ", p))}}}}
			rep.Finalize(sc)
			code = 1
		}
		if rep != nil {
			if werr := emit(rep, asJSON, jsonOut, stdout); werr != nil {
				fmt.Fprintln(stderr, "checkreport:", werr)
				if code == 0 {
					code = 1
				}
			}
		}
	}()

	module, err := readModule(cfg.Root)
	if err != nil {
		rep = &Report{Stages: []Stage{{Name: "setup", Tool: "checkreport", Findings: []Finding{crashed("setup", "cannot read go.mod: "+err.Error())}}}}
		rep.Finalize(sc)
		return 1
	}
	r := &runner{cfg: cfg, ctx: parseCtx{Root: absRoot(cfg.Root), Module: module}, exec: osExec, human: human}
	r.cfg.Root = r.ctx.Root
	if planOnly {
		// Not a report: the plain-mode script reads this to scope its own commands.
		return writeFastPlan(stdout, r.fastPlan())
	}
	if listOnly {
		return writeStageList(stdout, r, asJSON, jsonOut, sc)
	}
	r.goVer = goVersion(r.cfg.Root)
	rep, code = r.Run(sc)
	return code
}

// writeFastPlan prints the plan in the line format scripts/check.sh reads:
// "full<TAB>why", or "fast<TAB>base" followed by "package<TAB>dir<TAB>reason".
func writeFastPlan(w io.Writer, p FastPlan) int {
	if p.Full {
		fmt.Fprintf(w, "full\t%s\n", p.Why)
		return 0
	}
	fmt.Fprintf(w, "fast\t%s\n", p.Base)
	for _, pk := range p.Packages {
		fmt.Fprintf(w, "%s\t%s\t%s\n", pk.Package, pk.Dir, pk.Reason)
	}
	return 0
}

// writeStageList prints the stages the gate would run for this configuration:
// one name per line, or (with -json) a warden.check.v1 report with one passing
// stage per name. gatecheck compares the lists of a PR's base and head to find a
// removed stage.
func writeStageList(w io.Writer, r *runner, asJSON bool, jsonOut string, sc *Scrubber) int {
	defs := r.stages()
	if !asJSON && jsonOut == "" {
		for _, d := range defs {
			fmt.Fprintln(w, d.name)
		}
		return 0
	}
	r.goVer = goVersion(r.cfg.Root)
	rep := &Report{}
	for _, d := range defs {
		rep.Stages = append(rep.Stages, Stage{Name: d.name, Tool: d.tool(r), Metrics: map[string]any{"listed": true}})
	}
	rep.Finalize(sc)
	if err := emit(rep, asJSON, jsonOut, w); err != nil {
		return 1
	}
	return 0
}

func absRoot(root string) string {
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

func goVersion(dir string) string {
	res := osExec(dir, "go", "env", "GOVERSION")
	if v := strings.TrimSpace(string(res.Stdout)); res.Err == nil && v != "" {
		return v
	}
	return "unknown"
}

// emit writes the report where it was asked for.
func emit(rep *Report, toStdout bool, path string, stdout io.Writer) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode report: %w", err)
	}
	b = append(b, '\n')
	if toStdout {
		if _, err := stdout.Write(b); err != nil {
			return err
		}
	}
	if path != "" {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return fmt.Errorf("cannot write %s: %w", path, err)
		}
	}
	return nil
}
