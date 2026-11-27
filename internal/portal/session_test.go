package portal

import "testing"

func TestPortalRedirectToLogin(t *testing.T) {
	for next, want := range map[string]string{
		"/portal/connect/abc":     "/portal/login?next=%2Fportal%2Fconnect%2Fabc",
		"/connect/start?x=1":      "/portal/login?next=%2Fconnect%2Fstart%3Fx%3D1",
		"":                        LoginPath,
		"/dashboard/":             LoginPath,
		"//evil.example/portal/":  LoginPath,
		"/portal/\\evil":          LoginPath,
		"https://evil.example/x":  LoginPath,
		"/portal/x?u=https://a.b": LoginPath,
	} {
		if got := LoginURL(next); got != want {
			t.Errorf("LoginURL(%q) = %q, want %q", next, got, want)
		}
	}
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/portal/connect/abc", true},
		{"HEAD", "/portal/connect/abc", true},
		{"GET", "/connect/start", true},
		{"GET", MePath, false},
		{"GET", "/portal/api/connections", false},
		{"POST", "/portal/connect/abc", false},
		{"POST", LogoutPath, false},
	} {
		if got := SignedOutRedirects(tc.method, tc.path); got != tc.want {
			t.Errorf("SignedOutRedirects(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestPortalCSRF pins the portal's CSRF label apart from the console's
// ("warden-csrf"): HMAC tokens under different labels are unrelated, so a
// console token never validates on the portal. The HTTP check is tested in
// internal/controlplane (TestPortalCSRF).
func TestPortalCSRF(t *testing.T) {
	if CSRFLabel != "warden-portal-csrf" || CSRFLabel == "warden-csrf" || CSRFFormField != "csrf" {
		t.Fatalf("CSRFLabel = %q, CSRFFormField = %q", CSRFLabel, CSRFFormField)
	}
	if MePath[:len(APIPrefix)] != APIPrefix {
		t.Fatal("MePath is outside the API tree: a signed-out call would be redirected")
	}
}
