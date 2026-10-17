package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type lintReport struct {
	Issues []struct {
		FromLinter  string
		Text        string
		Severity    string
		SourceLines []string
		Pos         struct {
			Filename string
			Line     int
			Column   int
		}
	}
}

// staticcheckCode matches the "SA1019: " prefix staticcheck puts on its messages.
var staticcheckCode = regexp.MustCompile(`^([A-Z]+[0-9]+): (.*)$`)

// lintFix gives linter-specific advice. The repo convention for a justified
// exception is a scoped rule in .golangci.yml with a reason, so say that.
func lintFix(linter, code string) string {
	switch {
	case linter == "staticcheck" && code == "SA1019":
		return "use the replacement named in the message, or add a scoped exclusion with a reason in .golangci.yml"
	case linter == "errcheck":
		return "handle the returned error (or assign it to `_` with a comment saying why it is safe to ignore)"
	case linter == "unused":
		return "delete the unused identifier, or use it"
	case linter == "ineffassign":
		return "remove the assignment whose value is never read, or use the value"
	case linter == "misspell":
		return "fix the spelling named in the message"
	case linter == "gofmt":
		return "run `gofmt -w` on the file"
	case linter == "typecheck":
		return "fix the compile error first (`go build ./...`); lint cannot analyse code that does not compile"
	}
	return fmt.Sprintf("fix the %s finding, or add a scoped exclusion with a reason in .golangci.yml", linter)
}

// parseLint parses golangci-lint's --output.json.path file.
func parseLint(data []byte, c parseCtx) []Finding {
	var rep lintReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return []Finding{crashed("lint", "unreadable golangci-lint JSON: "+err.Error())}
	}
	var out []Finding
	// Every issue is an error whatever its severity label: golangci-lint exits
	// 1 on any issue, and the report must agree with that exit code.
	for _, is := range rep.Issues {
		rule, msg := is.FromLinter, is.Text
		code := ""
		if m := staticcheckCode.FindStringSubmatch(msg); m != nil {
			code, msg = m[1], m[2]
			rule += "/" + code
		}
		f := Finding{
			Rule: rule, Severity: sevError, Message: msg,
			File: c.relPath(is.Pos.Filename), Line: is.Pos.Line, Col: is.Pos.Column,
			Fix:    lintFix(is.FromLinter, code),
			Output: strings.Join(is.SourceLines, "\n"),
		}
		if is.FromLinter == "typecheck" {
			// The issue position is the package's first line; the real
			// location is inside the message.
			if cf := parseCompileLines(is.Text, c); len(cf) > 0 {
				f.File, f.Line, f.Col, f.Message = cf[0].File, cf[0].Line, cf[0].Col, cf[0].Message
			}
		}
		out = append(out, f)
	}
	return out
}
