package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
)

var posnRe = regexp.MustCompile(`^(.*):(\d+):(\d+)$`)

type vetDiag struct {
	Posn    string `json:"posn"`
	Message string `json:"message"`
}

// vetFix gives analyzer-specific advice; others get the generic wording.
var vetFix = map[string]string{
	"printf":       "make the format verbs and arguments agree",
	"copylocks":    "pass the value containing the lock by pointer",
	"lostcancel":   "call the cancel function (defer cancel()) on every path",
	"structtag":    "correct the struct tag syntax",
	"unusedresult": "use the returned value or drop the call",
	"loopclosure":  "copy the loop variable into the closure or pass it as an argument",
	"nilness":      "guard the nil case before the dereference",
}

// parseVet parses `go vet -json` output: a stream of {package:{analyzer:[diag]}}
// objects. Note `go vet -json` exits 0 even with findings, so findings, not the
// exit code, decide whether the stage failed.
func parseVet(data []byte, c parseCtx) []Finding {
	var out []Finding
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var doc map[string]map[string]json.RawMessage
		if err := dec.Decode(&doc); err != nil {
			if err != io.EOF {
				out = append(out, crashed("vet", "unreadable go vet -json output: "+err.Error()))
			}
			return out
		}
		pkgs := make([]string, 0, len(doc))
		for p := range doc {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		for _, p := range pkgs {
			analyzers := make([]string, 0, len(doc[p]))
			for a := range doc[p] {
				analyzers = append(analyzers, a)
			}
			slices.Sort(analyzers)
			for _, a := range analyzers {
				out = append(out, vetFindings(p, a, doc[p][a], c)...)
			}
		}
	}
}

func vetFindings(pkg, analyzer string, raw json.RawMessage, c parseCtx) []Finding {
	var diags []vetDiag
	if err := json.Unmarshal(raw, &diags); err != nil {
		// Analyzer-level failure: {"error": "..."}.
		var e struct{ Error string }
		_ = json.Unmarshal(raw, &e)
		return []Finding{{
			Rule: "vet/" + analyzer, Severity: sevError, Message: fmt.Sprintf("%s: %s", pkg, e.Error),
			Fix: fmt.Sprintf("run `go vet %s` and fix what it reports", "./"+c.pkgDir(pkg)),
		}}
	}
	var out []Finding
	for _, d := range diags {
		f := Finding{Rule: "vet/" + analyzer, Severity: sevError, Message: d.Message}
		if m := posnRe.FindStringSubmatch(d.Posn); m != nil {
			f.File = c.relPath(m[1])
			f.Line, _ = strconv.Atoi(m[2])
			f.Col, _ = strconv.Atoi(m[3])
		} else {
			f.File = d.Posn
		}
		advice, ok := vetFix[analyzer]
		if !ok {
			advice = fmt.Sprintf("fix the `%s` vet finding", analyzer)
		}
		f.Fix = fmt.Sprintf("%s at `%s`, then rerun `go vet ./%s`", advice, loc(f.File, f.Line), c.pkgDir(pkg))
		out = append(out, f)
	}
	return out
}
