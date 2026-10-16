package config

import (
	"strings"
	"testing"
)

// TestDNS_Parsed covers the `dns:` block: a configured upstreamResolver is
// carried on the policy for the worker to build its resolver from.
func TestDNS_Parsed(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dns:
  upstreamResolver: "10.20.30.2:53"
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.DNS.UpstreamResolver != "10.20.30.2:53" {
		t.Fatalf("dns.upstreamResolver = %q, want 10.20.30.2:53", pol.DNS.UpstreamResolver)
	}
}

// TestDNS_AbsentDefaultsToZero verifies the back-compat contract: no dns block
// means the zero DNSConfig, i.e. Go's default resolver and byte-identical
// behavior to a warden without this feature.
func TestDNS_AbsentDefaultsToZero(t *testing.T) {
	p, err := NewLocalYAMLProvider(writeTemp(t, goodYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.DNS != (DNSConfig{}) {
		t.Fatalf("absent dns block = %+v, want zero", pol.DNS)
	}
}

// TestDNS_UnknownFieldRejected proves a typo'd key inside the dns block fails
// at load (strict decoding) instead of silently no-oping.
func TestDNS_UnknownFieldRejected(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dns:
  upstreamReslover: "10.20.30.2:53"
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
		t.Fatal("expected unknown-field error for a misspelled dns key")
	}
}

// TestValidateDNS covers the "<host>:<port>" shape check: valid addresses pass,
// everything else fails with a clear, field-named error.
func TestValidateDNS(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr string // "" = valid
	}{
		{"empty_is_default", "", ""},
		{"ipv4_port", "10.20.30.2:53", ""},
		{"hostname_port", "dns.corp.internal:5353", ""},
		{"ipv6_bracketed", "[2001:db8::1]:53", ""},
		{"missing_port", "10.20.30.2", `must be <host>:<port>`},
		{"bare_ipv6", "2001:db8::1", `must be <host>:<port>`},
		{"missing_host", ":53", "missing the host"},
		{"port_zero", "10.20.30.2:0", "invalid port"},
		{"port_too_large", "10.20.30.2:99999", "invalid port"},
		{"port_not_numeric", "10.20.30.2:domain", "invalid port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDNS(DNSConfig{UpstreamResolver: tc.addr})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestDNS_InvalidRejectedAtLoad proves the shape check runs from parse(), so a
// malformed resolver fails at startup with a clear message instead of turning
// into per-request dial failures at runtime.
func TestDNS_InvalidRejectedAtLoad(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dns:
  upstreamResolver: "10.20.30.2"
`
	_, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err == nil || !strings.Contains(err.Error(), "dns.upstreamResolver") {
		t.Fatalf("want load error naming dns.upstreamResolver, got %v", err)
	}
}
