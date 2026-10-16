package policy

import "strings"

// matchPath reports whether a raw (percent-encoded) request path matches one
// allowlist `paths` pattern (#371). The dialect mirrors the domain dialect's
// minimalism:
//
//   - trailing "/*"  — segment-aligned prefix: the pattern's path itself and
//     everything under it ("/acme/app/*" matches "/acme/app" and
//     "/acme/app/x/y", not "/acme/appx");
//   - "*" elsewhere  — a within-segment wildcard ("/acme/*/x", "/v1*.json");
//   - anything else  — an exact byte match, case-sensitive.
//
// Both sides are the RAW forms: the pattern is never decoded, and the request
// path is the percent-encoded form that goes upstream (URL.EscapedPath() for
// HTTP/1.1, the :path pseudo-header for HTTP/2). No URL decoding happens on
// either side, so "/acme%2Fapp" and "/acme/app" are different paths.
func matchPath(pattern, path string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2]
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	if strings.Contains(pattern, "*") {
		// Segment-wise glob: split both sides on "/" so a "*" never crosses a
		// segment boundary, and each non-wildcard segment must match exactly.
		pp := strings.Split(pattern, "/")
		sp := strings.Split(path, "/")
		if len(pp) != len(sp) {
			return false
		}
		for i := range pp {
			if !globMatch(pp[i], sp[i]) {
				return false
			}
		}
		return true
	}
	return pattern == path
}

// globMatch reports whether s matches pattern where '*' stands for any run of
// bytes within one path segment. Segments are short, so plain recursion.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if globMatch(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	}
	if s == "" || pattern[0] != s[0] {
		return false
	}
	return globMatch(pattern[1:], s[1:])
}

// isCanonicalPath reports whether a raw request path is free of the encodings
// and dot-segments upstream could normalize differently than the bytes this
// package string-matches (#371). When an entry constrains paths, a
// non-canonical path is DENIED even if it string-matches a pattern: the bytes
// we matched and the resource the origin serves must be the same thing.
//
// Checked on the raw form, never a decoded one — decoding is exactly the
// confusion this closes:
//   - dot segments ("/a/../b", "/a/./b", "/..", trailing "/." "/.."),
//   - encoded dots, slashes and backslashes in any case ("%2e", "%2f", "%5c"),
//   - raw backslashes,
//   - matrix parameters (";params", raw or "%3b"/"%3B"): Java servers (Tomcat,
//     Jetty, Spring) strip them per segment, so "/v1/..;/admin" is "/admin"
//     upstream — traversal through a path that string-matches a pattern,
//   - empty segments ("//", which some servers treat as path collapse).
func isCanonicalPath(path string) bool {
	// One lowercased probe covers every case mix of the percent escapes.
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") ||
		strings.Contains(lower, "%5c") || strings.Contains(lower, "%3b") {
		return false
	}
	if strings.ContainsAny(path, "\\;") || strings.Contains(path, "//") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
