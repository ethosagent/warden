package identity_test

import (
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/identity"
)

func TestCheckIssuer(t *testing.T) {
	cases := []struct {
		name     string
		issuer   string
		internal string
		ok       bool
	}{
		{"https no internal", "https://idp.example.com", "", true},
		{"https with internal", "https://idp.example.com", "http://dex:5556", true},
		{"http no internal", "http://localhost:5556/dex", "", false},
		{"http with internal", "http://localhost:5556/dex", "http://dex:5556", true},
		{"internal with trailing slash", "http://localhost:5556/dex", "http://dex:5556/", true},
		{"internal with path", "http://localhost:5556/dex", "http://dex:5556/dex", false},
		{"internal with query", "http://localhost:5556/dex", "http://dex:5556?a=1", false},
		{"internal with userinfo", "http://localhost:5556/dex", "http://u:p@dex:5556", false},
		{"internal ftp", "http://localhost:5556/dex", "ftp://dex:5556", false},
		{"internal without issuer", "", "http://dex:5556", false},
		{"empty issuer", "", "", false},
		{"issuer query", "https://h/?q", "", false},
		{"issuer force-query", "https://h/?", "", false},
		{"issuer fragment", "https://h/#f", "", false},
		{"issuer userinfo", "https://u:p@h", "", false},
		{"issuer relative", "/relative", "", false},
		{"issuer no scheme", "idp.example.com", "", false},
		{"issuer no host", "https://", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := identity.CheckIssuer(tc.issuer, tc.internal)
			if tc.ok && err != nil {
				t.Fatalf("want ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want error, got nil")
			}
			if err != nil && strings.Contains(err.Error(), "p@") {
				t.Fatalf("error leaks userinfo: %v", err)
			}
		})
	}
}

func TestCheckIssuerHTTPErrorNamesKey(t *testing.T) {
	err := identity.CheckIssuer("http://localhost:5556/dex", "")
	if err == nil || !strings.Contains(err.Error(), "internalIssuerURL") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("error must name internalIssuerURL and https, got %v", err)
	}
}

func TestCheckClientIssuer(t *testing.T) {
	cases := []struct {
		issuer string
		ok     bool
	}{
		{"https://idp.example.com", true},
		{"https://idp.example.com/realms/x", true},
		{"http://localhost:5556/dex", true},
		{"http://LOCALHOST:5556/dex", true},
		{"http://127.0.0.1:5556/dex", true},
		{"http://127.9.9.9/dex", true},
		{"http://[::1]:5556/dex", true},
		{"http://dex:5556", false},
		{"http://10.0.0.1", false},
		{"http://idp.example.com", false},
		{"http://localhost.evil.example", false},
		{"", false},
		{"https://h/?q", false},
		{"https://h/#f", false},
		{"https://u:p@h", false},
		{"ftp://localhost", false},
	}
	for _, tc := range cases {
		err := identity.CheckClientIssuer(tc.issuer)
		if tc.ok != (err == nil) {
			t.Errorf("CheckClientIssuer(%q) err=%v, want ok=%v", tc.issuer, err, tc.ok)
		}
		if err != nil && tc.issuer != "" && strings.Contains(err.Error(), "p@h") {
			t.Errorf("error leaks userinfo: %v", err)
		}
	}
}
