package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type vulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position"`
}

type vulnMessage struct {
	OSV *struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
	} `json:"osv"`
	Finding *struct {
		OSV          string      `json:"osv"`
		FixedVersion string      `json:"fixed_version"`
		Trace        []vulnFrame `json:"trace"`
	} `json:"finding"`
}

// vulnAgg collects the called-symbol findings of one (vulnerability, module).
type vulnAgg struct {
	osv, module, version, fixed string
	trace                       []vulnFrame
}

// parseVuln parses `govulncheck -format json`. Only findings whose trace reaches
// a vulnerable *function* are reported: that is what the text mode (and so the
// existing gate) fails on. Module- and package-level matches are noise there.
func parseVuln(data []byte, c parseCtx) []Finding {
	summary := map[string]string{}
	aggs := map[string]*vulnAgg{}
	var order []string
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for dec.More() {
		var m vulnMessage
		if err := dec.Decode(&m); err != nil {
			return []Finding{crashed("vulncheck", "unreadable govulncheck JSON: "+err.Error())}
		}
		if m.OSV != nil {
			summary[m.OSV.ID] = m.OSV.Summary
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 || m.Finding.Trace[0].Function == "" {
			continue
		}
		v := m.Finding.Trace[0]
		key := m.Finding.OSV + "|" + v.Module
		a := aggs[key]
		if a == nil {
			a = &vulnAgg{osv: m.Finding.OSV, module: v.Module, version: v.Version, trace: m.Finding.Trace}
			aggs[key] = a
			order = append(order, key)
		}
		if semverLess(a.fixed, m.Finding.FixedVersion) {
			a.fixed = m.Finding.FixedVersion
		}
	}
	sort.Strings(order)
	var out []Finding
	for _, k := range order {
		out = append(out, vulnFinding(aggs[k], summary[aggs[k].osv], c))
	}
	return out
}

func vulnFinding(a *vulnAgg, summary string, c parseCtx) Finding {
	f := Finding{
		Rule: a.osv, Severity: sevError,
		Message: fmt.Sprintf("%s: %s (%s@%s)", a.osv, summary, a.module, a.version),
	}
	if last := a.trace[len(a.trace)-1]; last.Position != nil {
		f.File, f.Line, f.Col = c.relPath(last.Position.Filename), last.Position.Line, last.Position.Column
	}
	var tr []string
	for _, fr := range a.trace {
		name := fr.Package
		if fr.Function != "" {
			name += "." + fr.Function
		}
		if fr.Position != nil {
			name += fmt.Sprintf(" (%s:%d)", c.relPath(fr.Position.Filename), fr.Position.Line)
		}
		tr = append(tr, name)
	}
	f.Output = "call trace (vulnerable symbol first):\n  " + strings.Join(tr, "\n  ")
	switch {
	case a.module == "stdlib":
		f.Fix = fmt.Sprintf("upgrade the Go toolchain to %s or later (go.mod `go` line, Dockerfile builder image, setup-go)", orUnknown(a.fixed))
	case a.fixed != "":
		f.Fix = fmt.Sprintf("bump `%s` to %s: `go get %s@%s && go mod tidy`", a.module, a.fixed, a.module, a.fixed)
	default:
		f.Fix = fmt.Sprintf("no fixed version of `%s` is published; see https://pkg.go.dev/vuln/%s, then replace the dependency or stop calling the vulnerable symbol", a.module, a.osv)
	}
	return f
}

func orUnknown(s string) string {
	if s == "" {
		return "a fixed release"
	}
	return s
}

// semverLess reports whether a < b for versions like v0.9.0, v0.10.0 or go1.26.10.
// An empty a is less than anything.
func semverLess(a, b string) bool {
	if a == "" {
		return b != ""
	}
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func versionParts(v string) []int {
	v = strings.TrimLeft(v, "vgo")
	v, _, _ = strings.Cut(v, "-")
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}
