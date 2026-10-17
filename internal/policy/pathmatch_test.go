package policy

import "testing"

// TestMatchPath pins the paths-pattern dialect: a trailing "/*" matches the
// path itself and everything under it, a "*" elsewhere matches within one path
// segment, and anything else is an exact byte match. Patterns are compared
// against the RAW (percent-encoded) request path — no decoding on either side.
func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// Exact.
		{"/v1/chat", "/v1/chat", true},
		{"/v1/chat", "/v1/chatted", false},
		{"/v1/chat", "/v1/chat/extra", false},
		{"/v1/chat", "/v1/CHAT", false}, // paths are case-sensitive bytes
		{"/", "/", true},
		{"/", "/x", false},

		// Trailing "/*": the path itself and everything under it.
		{"/acme/app/*", "/acme/app", true},
		{"/acme/app/*", "/acme/app/", true},
		{"/acme/app/*", "/acme/app/x", true},
		{"/acme/app/*", "/acme/app/x/y", true},
		{"/acme/app/*", "/acme/appx", false},    // prefix must be segment-aligned
		{"/acme/app/*", "/acme/app.git", false}, // .git repo is a separate entry
		{"/acme/app/*", "/acme", false},

		// Segment "*" elsewhere: matches within exactly one segment.
		{"/acme/*/x", "/acme/foo/x", true},
		{"/acme/*/x", "/acme/x", false},     // the star matches one segment, not zero
		{"/acme/*/x", "/acme/a/b/x", false}, // ...and not two
		{"/acme/*/x", "/acme/foo/bar", false},
		{"/v1*.json", "/v2.json", false},
		{"/v1*.json", "/v10.json", true},
		{"/a*b/c", "/axxxb/c", true},

		// "/*" alone: any canonical path.
		{"/*", "/", true},
		{"/*", "/anything/here", true},
	}
	for _, c := range cases {
		if got := matchPath(c.pattern, c.path); got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// TestIsCanonicalPath pins the path-confusion deny list (#371 owner decision):
// when an entry constrains paths, a raw request path that upstream could
// normalize differently than the string we matched must be denied. Every form
// here matched a `paths` pattern as a plain string at some point in review —
// none may be treated as canonical.
func TestIsCanonicalPath(t *testing.T) {
	canonical := []string{
		"/",
		"/acme/app/x",
		"/acme/app/",    // trailing slash is a real, distinct path
		"/acme/app/x?q", // a query is not part of the path component anyway
		"/file.tar.gz",
		"/%41", // encoded form is preserved as-is (byte-literal matching)
	}
	for _, p := range canonical {
		if !isCanonicalPath(p) {
			t.Errorf("isCanonicalPath(%q) = false, want true", p)
		}
	}

	nonCanonical := []string{
		// Dot segments, raw.
		"/acme/app/../evil/x",
		"/./x",
		"/a/./b",
		"/a/..",
		"/a/.",
		"/..",
		"/.",
		// Encoded dot segments (any case mix).
		"/%2e%2e/x",
		"/a/%2E%2E/b",
		"/a/%2e/b",
		"/x%2e%2e",
		// Encoded slash / backslash (any case mix).
		"/a%2fb",
		"/a%2Fb",
		"/a%5cb",
		"/a%5Cb",
		// Raw backslash.
		"/a\\b",
		"\\a",
		// Matrix parameters (";params"): Java servers (Tomcat, Jetty, Spring)
		// strip them per segment, so "/v1/..;/admin" is "/admin" upstream —
		// traversal through a path that string-matches a pattern (#371 review).
		"/v1/..;/admin",
		"/v1/.;/admin",
		"/v1/some;x",
		"/v1/a;b/c",
		// Encoded ";" (any case mix).
		"/v1/x%3b",
		"/v1/x%3B",
		"/v1/..%3b/y",
		// Empty segment ("//").
		"/a//b",
		"//a",
	}
	for _, p := range nonCanonical {
		if isCanonicalPath(p) {
			t.Errorf("isCanonicalPath(%q) = true, want false", p)
		}
	}
}
