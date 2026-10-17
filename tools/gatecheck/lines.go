package main

import (
	"regexp"
	"strings"
)

// lineRef is a line of a file with its 1-based number.
type lineRef struct {
	n    int
	text string // trimmed
}

func splitLines(s string) []lineRef {
	var out []lineRef
	for i, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, lineRef{i + 1, t})
		}
	}
	return out
}

// added returns the lines of head that base does not have, comparing trimmed
// lines as a multiset: a line moved within a file is not new, a second copy of
// an existing line is.
func added(base, head string) []lineRef { return surplus(splitLines(head), splitLines(base)) }

// removed returns the lines of base that head no longer has.
func removed(base, head string) []lineRef { return surplus(splitLines(base), splitLines(head)) }

func surplus(have, other []lineRef) []lineRef {
	count := map[string]int{}
	for _, l := range other {
		count[l.text]++
	}
	var out []lineRef
	for _, l := range have {
		if count[l.text] > 0 {
			count[l.text]--
			continue
		}
		out = append(out, l)
	}
	return out
}

// isComment reports whether a script or YAML line is only a comment.
func isComment(t string) bool { return strings.HasPrefix(t, "#") }

// addedMatching returns added non-comment lines matching re.
func addedMatching(base, head string, re *regexp.Regexp) []lineRef {
	var out []lineRef
	for _, l := range added(base, head) {
		if !isComment(l.text) && re.MatchString(l.text) {
			out = append(out, l)
		}
	}
	return out
}
