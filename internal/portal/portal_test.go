package portal

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/webauth"
)

type blocks map[string]bool

func (b blocks) IsBlocked(sub, email string) bool { return b[sub] || b[strings.ToLower(email)] }

func TestPortalAdmission(t *testing.T) {
	bl := blocks{"bad-sub": true, "bad@example.com": true}
	ok := Candidate{Sub: "pat", Email: "pat@example.com", Groups: []string{"employees"}, HasRefreshToken: true}
	for _, c := range []struct {
		name string
		adm  Admission
		c    Candidate
		want string
	}{
		{"admitted", Admission{Blocks: bl}, ok, ""},
		{"nil block list", Admission{}, Candidate{Sub: "bad-sub"}, ""},
		{"blocked sub", Admission{Blocks: bl}, Candidate{Sub: "bad-sub", Email: "x@example.com"}, CodeBlocked},
		{"blocked email", Admission{Blocks: bl}, Candidate{Sub: "x", Email: "BAD@example.com"}, CodeBlocked},
		{"blocked beats groups", Admission{Blocks: bl, AllowedGroups: []string{"employees"}}, Candidate{Sub: "bad-sub"}, CodeBlocked},
		{"outside allowedGroups", Admission{AllowedGroups: []string{"admins"}}, ok, CodeNotAllowed},
		{"no groups", Admission{AllowedGroups: []string{"employees"}}, Candidate{Sub: "pat"}, CodeNotAllowed},
		{"in allowedGroups", Admission{AllowedGroups: []string{"admins", "employees"}}, ok, ""},
		{"empty allowedGroups admits all", Admission{AllowedGroups: nil}, Candidate{Sub: "pat"}, ""},
		{"no refresh token", Admission{RequireRefreshToken: true}, Candidate{Sub: "pat"}, CodeOfflineAccessNotGranted},
		{"refresh token present", Admission{RequireRefreshToken: true}, ok, ""},
		{"not_allowed before offline_access", Admission{AllowedGroups: []string{"admins"}, RequireRefreshToken: true}, Candidate{Sub: "pat"}, CodeNotAllowed},
	} {
		if got := c.adm.Admit(c.c); got != c.want {
			t.Errorf("%s: Admit = %q, want %q", c.name, got, c.want)
		}
	}
	// Only the first MaxGroups groups count.
	many := make([]string, MaxGroups+1)
	for i := range many {
		many[i] = fmt.Sprintf("g%d", i)
	}
	adm := Admission{AllowedGroups: []string{many[MaxGroups]}}
	if got := adm.Admit(Candidate{Sub: "pat", Groups: many}); got != CodeNotAllowed {
		t.Errorf("group past the cap admitted: %q", got)
	}
	if len(CapGroups(many)) != MaxGroups || len(CapGroups(many[:3])) != 3 {
		t.Error("CapGroups does not cap at MaxGroups")
	}
}

// TestPortalNextRedirect pins the post-login path rule: only same-origin paths
// under /portal/ or /connect/ survive webauth.SafeNext with NextPrefixes.
func TestPortalNextRedirect(t *testing.T) {
	keep := []string{"/portal/connect/abc", "/connect/github", "/portal/x?y=1"}
	drop := []string{"https://evil.example", "//evil.example", "/dashboard/", "/portal", "/portalx/",
		"/connect", `/portal/\evil`, "/portal/../dashboard/", "/portal/%2e%2e/dashboard", "/portal//evil.example", ""}
	for _, n := range keep {
		if !webauth.SafeNext(n, NextPrefixes()...) {
			t.Errorf("next %q dropped, want kept", n)
		}
	}
	for _, n := range drop {
		if webauth.SafeNext(n, NextPrefixes()...) {
			t.Errorf("next %q kept, want %s", n, Home)
		}
	}
	p := NextPrefixes()
	p[0] = "/"
	if NextPrefixes()[0] != "/portal/" {
		t.Error("NextPrefixes returns a shared slice")
	}
}

func TestPortalScopes(t *testing.T) {
	if got := strings.Join(Scopes(false), " "); got != "openid email profile groups" {
		t.Errorf("Scopes(false) = %q", got)
	}
	if got := strings.Join(Scopes(true), " "); got != "openid email profile groups offline_access" {
		t.Errorf("Scopes(true) = %q", got)
	}
}

type consoleKey struct{}

func TestPortalPrincipalContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := PrincipalFrom(ctx); ok {
		t.Fatal("principal in an empty context")
	}
	// A value of the same shape under another key is not a portal principal.
	if _, ok := PrincipalFrom(context.WithValue(ctx, consoleKey{}, Principal{Sub: "x"})); ok {
		t.Fatal("principal read from a foreign key")
	}
	p := Principal{Iss: "https://idp", Sub: "pat", Email: "pat@example.com", Groups: []string{"g"}, SessionHash: "abc"}
	got, ok := PrincipalFrom(WithPrincipal(ctx, p))
	if !ok || got.Sub != "pat" || got.Iss != "https://idp" || got.SessionHash != "abc" {
		t.Fatalf("PrincipalFrom = %+v %v", got, ok)
	}
}

func TestPortalLinkNeverPrintsToken(t *testing.T) {
	const tok = "rt-secret-value"
	l := Link{Iss: "https://idp", Sub: "pat", Email: "pat@example.com", RefreshToken: tok}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "link", l)
	for _, s := range []string{l.String(), fmt.Sprint(l), fmt.Sprintf("%+v", l), fmt.Sprintf("%#v", l), buf.String()} {
		if strings.Contains(s, tok) {
			t.Errorf("token printed: %s", s)
		}
	}
	if !strings.Contains(buf.String(), `"sub":"pat"`) {
		t.Errorf("log value lost the sub: %s", buf.String())
	}
}
