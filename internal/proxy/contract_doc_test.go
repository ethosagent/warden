package proxy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// contractDocPath is the harness-builder contract (W-P1-IDC-01). The tests in
// this file pin it to the code: a renamed status, reason, mode, header, event
// field or limit fails here until the doc is updated with it.
const contractDocPath = "../../docs/identity-contract.md"

func readContractDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(contractDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractDocPath, err)
	}
	return string(b)
}

// docTableKeys returns the first-column values of the first Markdown table
// after the line heading, each written as `value`. It fails when the heading
// or the table is missing, so a restructured doc cannot pass vacuously.
func docTableKeys(t *testing.T, doc, heading string) []string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := slices.Index(lines, heading)
	if start < 0 {
		t.Fatalf("contract doc has no %q heading", heading)
	}
	var keys []string
	inTable := false
	for _, l := range lines[start+1:] {
		if strings.HasPrefix(l, "#") {
			break
		}
		if !strings.HasPrefix(l, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cell := strings.TrimSpace(strings.Split(l, "|")[1])
		if strings.HasPrefix(cell, "`") && strings.HasSuffix(cell, "`") && len(cell) > 2 {
			keys = append(keys, strings.Trim(cell, "`"))
		}
	}
	if len(keys) == 0 {
		t.Fatalf("contract doc has no table of `values` under %q", heading)
	}
	sort.Strings(keys)
	return keys
}

// typedConsts parses the Go files of dir and returns the string values of
// every constant declared with the named type. Reading the source (not a
// hand-kept list) means a status added to internal/identity must also be
// documented.
func typedConsts(t *testing.T, dir, typeName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				id, ok := vs.Type.(*ast.Ident)
				if !ok || id.Name != typeName {
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: a %s constant is not a string literal", path, typeName)
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					out = append(out, s)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s constants found in %s", typeName, dir)
	}
	sort.Strings(out)
	return out
}

func sortedStrings[S ~string](in ...S) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	sort.Strings(out)
	return out
}

// TestContractDocMatchesConstants keeps docs/identity-contract.md in line with
// the statuses and reasons of internal/identity, the modes of internal/config
// and internal/proxy, the header names of internal/proxy, the identity event
// fields of internal/analytics and the enforced limits.
func TestContractDocMatchesConstants(t *testing.T) {
	doc := readContractDoc(t)

	t.Run("contract version", func(t *testing.T) {
		if !strings.Contains(doc, "Contract v1") {
			t.Error("contract doc lost its `Contract v1` version marker")
		}
	})

	t.Run("statuses", func(t *testing.T) {
		// The named constants make a rename a compile error here; their values
		// must match the source-wide set, so a new Status cannot be missed.
		named := sortedStrings(identity.StatusOff, identity.StatusNone, identity.StatusValid,
			identity.StatusInvalid, identity.StatusExpired, identity.StatusUnverified, identity.StatusConflict)
		all := typedConsts(t, "../identity", "Status")
		if !slices.Equal(named, all) {
			t.Fatalf("internal/identity Status constants %v differ from the named set %v: update this test and the doc", all, named)
		}
		if got := docTableKeys(t, doc, "### Statuses"); !slices.Equal(got, all) {
			t.Errorf("doc statuses = %v, want exactly %v", got, all)
		}
	})

	t.Run("reasons", func(t *testing.T) {
		want := sortedStrings(identity.Reasons()...)
		if all := typedConsts(t, "../identity", "Reason"); !slices.Equal(all, want) {
			t.Fatalf("identity.Reasons() %v is not every Reason constant %v", want, all)
		}
		if got := docTableKeys(t, doc, "### Reasons"); !slices.Equal(got, want) {
			t.Errorf("doc reasons = %v, want exactly %v", got, want)
		}
	})

	t.Run("modes", func(t *testing.T) {
		cfgModes := sortedStrings(config.IdentityModeOff, config.IdentityModeAttribute, config.IdentityModeChallenge)
		if px := sortedStrings(IdentityModeOff, IdentityModeAttribute, IdentityModeChallenge); !slices.Equal(px, cfgModes) {
			t.Fatalf("proxy modes %v differ from config modes %v", px, cfgModes)
		}
		got := docTableKeys(t, doc, "### Modes")
		if !slices.Equal(got, cfgModes) {
			t.Errorf("doc modes = %v, want exactly %v", got, cfgModes)
		}
		// Every documented mode must pass config validation, and require (the
		// Phase 2 mode the doc says is rejected) must not.
		for _, m := range got {
			if err := loadIdentityMode(t, m); err != nil {
				t.Errorf("documented mode %q is rejected by config validation: %v", m, err)
			}
		}
		if loadIdentityMode(t, "require") == nil {
			t.Error("config accepts require; the doc says it is rejected until Phase 2")
		}
		if !strings.Contains(doc, "`require` is rejected") {
			t.Error("doc no longer says `require` is rejected")
		}
	})

	// The challenge 407 (#558): the body's keys, the reason values, the sign-in
	// errors and the three deny reasons are the ones the code writes.
	t.Run("challenge", func(t *testing.T) {
		section := doc[strings.Index(doc, "### Challenge mode"):]
		section = section[:strings.Index(section, "\n## ")]
		var want []string
		for _, f := range []any{SignInOffer{}} {
			rt := reflect.TypeOf(f)
			for i := 0; i < rt.NumField(); i++ {
				name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
				want = append(want, `"`+name+`"`)
			}
		}
		want = append(want, `"error"`, `"reason"`, `"sign_in"`, `"sign_in_error"`)
		for _, w := range want {
			if !strings.Contains(section, w) {
				t.Errorf("the challenge section does not show the body key %s", w)
			}
		}
		for _, w := range []string{
			string(identity.StatusNone), string(identity.StatusExpired), string(identity.StatusInvalid), string(identity.StatusUnverified),
			string(SignInStarted), string(SignInReused), string(SignInRateLimited), string(SignInIssuerUnreachable),
			string(denyreason.IdentityRequired), string(denyreason.IdentityExpired), string(denyreason.IdentityConflict),
			"Proxy-Authenticate: Basic realm=\"warden\"", "Cache-Control: no-store", "Connection: close",
			"WARDEN_SIGNIN_URL", "WARDEN_SIGNIN_CODE", "device_code", "untrusted_offer",
		} {
			if !strings.Contains(section, "`"+w+"`") && !strings.Contains(section, w) {
				t.Errorf("the challenge section does not mention %q", w)
			}
		}
		if got := challengeReason(identity.StatusConflict); got != string(identity.StatusInvalid) {
			t.Errorf("challengeReason maps an unexpected status to %q, want invalid", got)
		}
	})

	t.Run("headers", func(t *testing.T) {
		for _, want := range []string{
			proxyAuthorizationHeader + `: Basic base64("` + ProxyAuthUsername + `:"+token)`,
			proxyAuthorizationHeader + ": Bearer <token>",
			"http://" + ProxyAuthUsername + ":<token>@<worker>:8080",
			IdentityHeader + ": Bearer <token>",
			"user name is `" + ProxyAuthUsername + "` (case-sensitive)",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("contract doc does not show %q", want)
			}
		}
		// Both identity headers are proxy-only: the doc promises they are
		// stripped before forwarding.
		for _, h := range []string{proxyAuthorizationHeader, IdentityHeader} {
			if !slices.Contains(proxyOnlyHeaders, h) {
				t.Errorf("%s is not in proxyOnlyHeaders, but the doc says it is stripped", h)
			}
		}
	})

	t.Run("event fields", func(t *testing.T) {
		var want []string
		et := reflect.TypeOf(analytics.Event{})
		for i := 0; i < et.NumField(); i++ {
			name, _, _ := strings.Cut(et.Field(i).Tag.Get("json"), ",")
			if strings.HasPrefix(name, "user_") || strings.HasPrefix(name, "identity_") {
				want = append(want, name)
			}
		}
		sort.Strings(want)
		if got := docTableKeys(t, doc, "## Observability"); !slices.Equal(got, want) {
			t.Errorf("doc event fields = %v, want exactly %v", got, want)
		}
	})

	t.Run("limits", func(t *testing.T) {
		kib := func(n int) string { return fmt.Sprintf("%d KiB", n>>10) }
		secs := func(d time.Duration) string { return fmt.Sprintf("%d s", int(d/time.Second)) }
		for _, want := range []string{
			"| Raw token size | " + kib(identity.MaxTokenBytes) + " |",
			"| CONNECT request line | " + kib(maxConnectLineBytes) + " |",
			"| " + kib(maxConnectHeaderBytes) + " |",
			"| Time to deliver the CONNECT preamble | " + secs(connectPreambleTimeout) + " |",
			"| One token verification | " + secs(identityVerifyTimeout) + " |",
			"| " + secs(identity.DefaultClockSkew) + " (default) |",
			fmt.Sprintf("| %d h (default) |", int(identity.DefaultMaxTokenTTL/time.Hour)),
			fmt.Sprintf("at most %d groups of at most %d bytes", identity.MaxGroups, identity.MaxGroupBytes),
			fmt.Sprintf("at most %d)", int(config.MaxIdentityClockSkewSeconds)),
			"deny reason `" + string(denyreason.MalformedConnect) + "`",
			"reason `" + string(denyreason.UnsupportedProtocol) + "`",
			"`" + identity.DefaultGroupsClaim + "`",
			"transparent",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("contract doc does not state %q", want)
			}
		}
	})
}

// loadIdentityMode reports whether a config with identity.defaultMode mode
// passes config validation.
func loadIdentityMode(t *testing.T, mode string) error {
	t.Helper()
	body := "policy:\n  allowlist:\n    - domain: api.example.com\n" +
		"identity:\n  defaultMode: " + mode + "\n  issuer: https://idp.example.com\n  audience: warden\n"
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.NewLocalYAMLProvider(p)
	return err
}
