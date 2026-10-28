package dashboard

import (
	"strings"
	"testing"
)

// TestIndexBreakGlassBanner pins the break-glass banner (W-P1-OPS1-09) in the
// served page: a hidden red element, shown only when /auth/me says the session
// is a break-glass one, with the expiry written through textContent.
func TestIndexBreakGlassBanner(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{
		`id="breakglass-banner"`,
		`m.authMethod!=='breakglass'`,
		`'Break-glass session, expires at '`,
		`applyBreakGlassBanner(me);`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("served page has no %s", want)
		}
	}
	if !strings.Contains(html, `id="breakglass-banner" role="alert" style="display:none"`) {
		t.Error("the banner is not hidden by default")
	}
	a := strings.Index(html, "function applyBreakGlassBanner")
	if a < 0 {
		t.Fatal("no applyBreakGlassBanner function")
	}
	end := strings.Index(html[a:], "\n}\n")
	if end < 0 {
		t.Fatal("applyBreakGlassBanner has no end")
	}
	fn := html[a : a+end]
	if !strings.Contains(fn, "el.textContent=") && !strings.Contains(fn, "esc(") {
		t.Error("the expiry is not set through textContent or esc()")
	}
	if strings.Contains(fn, "innerHTML") {
		t.Error("the banner is written with innerHTML")
	}
}
