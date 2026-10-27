package config

import "testing"

func TestDiffKey(t *testing.T) {
	allow := []struct {
		e    AllowlistEntry
		want string
	}{
		{AllowlistEntry{Domain: "api.example.com", Port: 443}, "api.example.com|443"},
		{AllowlistEntry{Domain: "api.example.com"}, "api.example.com|0"},
		// Compared attributes never change the key.
		{AllowlistEntry{Domain: "api.example.com", Port: 443, RateLimit: "10/m", TimeWindow: "09:00-17:00", Methods: []string{"GET"}, Paths: []string{"/v1/*"}}, "api.example.com|443"},
		{AllowlistEntry{Domain: "*.example.com", Port: 8443}, "*.example.com|8443"},
	}
	for _, c := range allow {
		if got := c.e.DiffKey(); got != c.want {
			t.Errorf("AllowlistEntry%+v.DiffKey() = %q, want %q", c.e, got, c.want)
		}
	}
	deny := []struct {
		e    DenylistEntry
		want string
	}{
		{DenylistEntry{Domain: "evil.example.com", Port: 25}, "evil.example.com|25"},
		{DenylistEntry{Domain: "evil.example.com"}, "evil.example.com|0"},
	}
	for _, c := range deny {
		if got := c.e.DiffKey(); got != c.want {
			t.Errorf("DenylistEntry%+v.DiffKey() = %q, want %q", c.e, got, c.want)
		}
	}
	// Allow and deny entries on the same destination share a key shape.
	if (AllowlistEntry{Domain: "x.example.com", Port: 1}).DiffKey() != (DenylistEntry{Domain: "x.example.com", Port: 1}).DiffKey() {
		t.Error("allow and deny DiffKey shapes differ for the same domain|port")
	}
}
