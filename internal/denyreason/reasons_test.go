package denyreason

import (
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestDeclaredSetIsWellFormed pins the set's invariants: every reason is
// non-empty, snake_case, and unique — they become metric labels, so any drift
// here is a cardinality/contract bug.
func TestDeclaredSetIsWellFormed(t *testing.T) {
	seen := make(map[Reason]bool, len(declared))
	re := regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	for _, r := range Declared() {
		if r == "" {
			t.Fatal("declared set contains an empty reason")
		}
		if !re.MatchString(string(r)) {
			t.Errorf("reason %q is not snake_case", r)
		}
		if seen[r] {
			t.Errorf("reason %q declared twice", r)
		}
		seen[r] = true
	}
	if len(seen) != len(declared) {
		t.Fatalf("Declared() returned %d reasons, declared slice has %d", len(seen), len(declared))
	}
}

// TestRequiredReasonsDeclared pins the values downstream consumers key on: the
// #409 policy reasons and its two fallbacks (mcp_gateway_deny, unspecified),
// the #371 constraints, the #388/#389/#396 edge denies and the #391
// sibling-branch SSRF reasons.
func TestRequiredReasonsDeclared(t *testing.T) {
	for _, r := range []Reason{
		PolicyNoMatch, PolicyDenylist, RateLimited, TimeWindow,
		PathNotCanonical, MethodNotAllowed, PathNotAllowed,
		H2RequestTrailersUnsupported, H2ExtendedConnectUnsupported,
		TransformNeedsBufferedBody, HostMismatch,
		RequestTrailersUnsupported,
		GRPCBodyPlaceholder, GRPCFrameTooLarge, GRPCFrameMalformed, GRPCFrameCompressed,
		SecretEcho, SecretEchoUnscannable,
		SSRFBlocked, SSRFDeniedHostname,
		TransparentNoSNI, TransparentBadClientHello,
		TransparentH2PriorKnowledge, TransparentLoopGuard,
		MalformedRequest,
		MCPGatewayDeny, Unspecified,
	} {
		if !r.Declared() {
			t.Errorf("required reason %q is not declared", r)
		}
	}
	if (Reason("not_a_reason")).Declared() {
		t.Error("undeclared reason reported as declared")
	}
}

// TestNoReasonLiteralsOutsideTheDeclaredSet is the grep-style guard for rule X6
// (#349): a declared reason value must never be written as a code string
// literal outside the declaration file. It tokenizes every production
// (non-_test.go) Go file in the packages that WRITE reasons — internal/proxy
// and internal/policy — with go/scanner and inspects only string-literal
// tokens, so comments, struct tags and unrelated identifiers that merely
// contain a value's substring (e.g. a yaml section named "judge") never trip
// it. reasons.go in this package is the one file allowed to declare the values.
// Test files are exempt: tests assert the exact wire values on purpose.
func TestNoReasonLiteralsOutsideTheDeclaredSet(t *testing.T) {
	dirs := []string{
		filepath.Join("..", "..", "internal", "proxy"),
		filepath.Join("..", "..", "internal", "policy"),
	}
	values := make(map[string]Reason, len(declared))
	for _, r := range Declared() {
		values[string(r)] = r
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, ent := range entries {
			name := ent.Name()
			if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, lit := range stringLiterals(t, src) {
				if r, ok := values[lit]; ok {
					t.Errorf("%s: declared reason %q written as a literal; use denyreason.%s (rule X6, #349)",
						path, r, r)
				}
			}
		}
	}
}

// stringLiterals returns every interpreted/raw string-literal VALUE in a Go
// source file via go/scanner, so comments and non-string tokens are excluded.
func stringLiterals(t *testing.T, src []byte) []string {
	t.Helper()
	var s scanner.Scanner
	fset := token.NewFileSet()
	file := fset.AddFile("src.go", fset.Base(), len(src))
	s.Init(file, src, nil, 0)
	var out []string
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}
		if tok != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit)
		if err != nil {
			// A malformed literal is a syntax error the compiler will report;
			// skip it here.
			continue
		}
		out = append(out, v)
	}
}
