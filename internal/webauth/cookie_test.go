package webauth_test

import (
	"net/http"
	"testing"

	"github.com/ethosagent/warden/internal/webauth"
)

func TestCookieNames(t *testing.T) {
	c, err := webauth.NewCookie("https://cp.example:443/portal/callback", "warden_portal")
	if err != nil || c.Name != "__Host-warden_portal" || !c.Secure || c.Origin() != "https://cp.example" {
		t.Fatalf("https cookie = %+v %v", c, err)
	}
	if l := c.Named("warden_portal_login"); l.Name != "__Host-warden_portal_login" || !l.Secure || l.Origin() != c.Origin() {
		t.Fatalf("https login cookie = %+v", l)
	}
	p, err := webauth.NewCookie("http://127.0.0.1:7070/portal/callback", "warden_portal")
	if err != nil || p.Name != "warden_portal" || p.Secure || p.Origin() != "http://127.0.0.1:7070" {
		t.Fatalf("loopback cookie = %+v %v", p, err)
	}
	if l := p.Named("warden_portal_login"); l.Name != "warden_portal_login" || l.Secure {
		t.Fatalf("loopback login cookie = %+v", l)
	}
	if _, err := webauth.NewCookie("http://cp.example/portal/callback", "warden_portal"); err == nil {
		t.Fatal("an http redirect URL on a public host was accepted")
	}
	ck := c.New("v", 0)
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		t.Fatalf("cookie flags = %+v", ck)
	}
}
