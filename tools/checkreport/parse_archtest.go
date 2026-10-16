package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// The architecture gate (internal/archtest, run by the archtest stage) prints
// one violation per line in the Finding.String shape of that package:
//
//	RULE  file:line:  what is wrong  →  how to fix
//
// parseArchtest turns each of those lines into a finding. Everything else the
// run may print — a stale generated config, a go.mod module outside the
// architecture.yaml manifest, a compile error or a panic in the gate itself —
// is classified separately, so a failing gate never fails silently.

// archLine matches one violation line after the "file.go:12: " test-location
// prefix is stripped. The message part is greedy, so an arrow inside a message
// leaves the fix as the text after the last one.
var archLine = regexp.MustCompile(`^(baseline|[A-Z][0-9][ab]?)  (\S+):(\d+):  (.*)  →  (.*)$`)

var (
	archStaleConfig = regexp.MustCompile(`\.golangci\.arch\.yml is (?:stale|missing)`)
	archManifest    = regexp.MustCompile(`^module (\S+) is required by go\.mod but missing from the architecture\.yaml module manifest`)
	// archLoc is the location prefix t.Errorf puts on a message.
	archLoc = regexp.MustCompile(`^\s+\S+\.go:\d+: `)
)

func parseArchtest(data []byte, c parseCtx) []Finding {
	out := buildFindings(data, c)
	var lines []string
	failed := false
	sc := newLineScanner(data)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev testEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		switch ev.Action {
		case "output":
			lines = append(lines, ev.Output)
		case "fail":
			failed = true
		}
	}
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\n")
		switch {
		case archStaleConfig.MatchString(line):
			out = append(out, Finding{
				Rule: "archtest/stale-config", Severity: sevError, File: ".golangci.arch.yml",
				Message: strings.TrimSpace(archLoc.ReplaceAllString(line, "")),
				Fix:     "run go run ./cmd/archgen to regenerate .golangci.arch.yml from architecture.yaml",
			})
		default:
			body := archLoc.ReplaceAllString(line, "")
			if m := archManifest.FindStringSubmatch(body); m != nil {
				out = append(out, Finding{
					Rule: "archtest/module-manifest", Severity: sevError, File: "go.mod",
					Message: strings.TrimSpace(body),
					Fix:     "add module " + m[1] + " to the architecture.yaml module manifest (S3)",
				})
				continue
			}
			m := archLine.FindStringSubmatch(body)
			if m == nil {
				continue
			}
			lineNo, _ := strconv.Atoi(m[3])
			out = append(out, Finding{
				Rule: "archtest/" + m[1], Severity: sevError,
				File: c.relPath(m[2]), Line: lineNo,
				Message: m[4], Fix: m[5],
			})
		}
	}
	if failed && !hasError(out) {
		last := ""
		for _, l := range lines {
			if t := strings.TrimSpace(l); t != "" {
				last = t
			}
		}
		out = append(out, Finding{
			Rule: "archtest/failed", Severity: sevError,
			Message: "the architecture gate failed without a parseable finding: " + last,
			Fix:     "run go test ./internal/archtest -run TestArchitecture by hand and fix what it reports",
			Output:  strings.Join(lines, ""),
		})
	}
	return out
}
