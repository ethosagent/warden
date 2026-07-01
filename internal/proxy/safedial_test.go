package proxy

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestIsPrivateIP_Loopback(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("127.0.0.1")) {
		t.Error("127.0.0.1 should be blocked")
	}
}

func TestIsPrivateIP_Private10(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 should be blocked")
	}
}

func TestIsPrivateIP_Private192(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should be blocked")
	}
}

func TestIsPrivateIP_CloudMetadata(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("169.254.169.254")) {
		t.Error("169.254.169.254 should be blocked")
	}
}

func TestIsPrivateIP_IPv4MappedIPv6(t *testing.T) {
	// ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address; after To4() unwrap it
	// should match the 127.0.0.0/8 blocklist entry.
	ip := net.ParseIP("::ffff:127.0.0.1")
	if ip == nil {
		t.Fatal("failed to parse ::ffff:127.0.0.1")
	}
	if !IsPrivateIP(ip) {
		t.Error("::ffff:127.0.0.1 should be blocked")
	}
}

func TestIsPrivateIP_PublicIP(t *testing.T) {
	if IsPrivateIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should not be blocked")
	}
}

func TestSafeDialer_AllowPrivateException(t *testing.T) {
	d, err := NewSafeDialer(5*time.Second, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	ip := net.ParseIP("127.0.0.1")
	if d.isBlocked(ip) {
		t.Error("127.0.0.1 should not be blocked when 127.0.0.0/8 is in allowPrivate")
	}
}

func TestSafeDialer_BlocksAll_Error(t *testing.T) {
	d, err := NewSafeDialer(2*time.Second, nil)
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	// Attempt to dial a private IP directly. The dialer should refuse before
	// even attempting a TCP connection.
	_, err = d.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error when all resolved IPs are blocked")
	}
	if !strings.Contains(err.Error(), "blocked (SSRF protection)") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- SSRF bypass hardening tests ---

// parseObfuscatedIPv4 must decode non-dotted-decimal IPv4 encodings that
// net.ParseIP rejects, so the blocklist check sees the canonical address.
func TestParseObfuscatedIPv4(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // canonical dotted-decimal, "" means should not decode
	}{
		// Decimal (single 32-bit integer): 2130706433 == 127.0.0.1
		{"decimal_loopback", "2130706433", "127.0.0.1"},
		{"decimal_metadata", "2852039166", "169.254.169.254"},
		{"decimal_public", "134744072", "8.8.8.8"},
		// Octal: leading-zero octets.
		{"octal_loopback", "0177.0.0.1", "127.0.0.1"},
		{"octal_full", "0300.0250.0001.0001", "192.168.1.1"},
		// Hex: 0x-prefixed octets or single 32-bit hex.
		{"hex_dotted_loopback", "0x7f.0.0.1", "127.0.0.1"},
		{"hex_single_loopback", "0x7f000001", "127.0.0.1"},
		{"hex_single_metadata", "0xa9fea9fe", "169.254.169.254"},
		// Mixed / short forms: 3-part (a.b.c => c is 16-bit), 2-part (a.b => b is 24-bit).
		{"short_2part_loopback", "127.1", "127.0.0.1"},
		{"short_3part", "192.168.257", "192.168.1.1"},
		{"mixed_octal_hex", "0177.0x0.0.01", "127.0.0.1"},
		// Plain dotted-decimal already handled by ParseIP but must still decode here.
		{"plain_dotted", "10.0.0.1", "10.0.0.1"},
		// Non-numeric hostnames must NOT decode.
		{"hostname", "example.com", ""},
		{"empty", "", ""},
		// Out-of-range octet must fail closed (not decode to something wrong).
		{"octet_overflow", "256.1.1.1", ""},
		{"decimal_overflow", "4294967296", ""},
		// Bad octal digit.
		{"bad_octal", "08.0.0.1", ""},
		// Too many parts.
		{"too_many_parts", "1.2.3.4.5", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseObfuscatedIPv4(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("parseObfuscatedIPv4(%q) = %v, want nil", tc.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseObfuscatedIPv4(%q) = nil, want %s", tc.in, tc.want)
			}
			if got.String() != tc.want {
				t.Fatalf("parseObfuscatedIPv4(%q) = %s, want %s", tc.in, got.String(), tc.want)
			}
		})
	}
}

// Encoding-normalization bypass: obfuscated IPv4 forms that decode to a blocked
// range must be blocked before reaching the OS resolver.
func TestSafeDialer_ObfuscatedIPv4_Blocked(t *testing.T) {
	d, err := NewSafeDialer(2*time.Second, nil)
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	blocked := []string{
		"2130706433",          // decimal 127.0.0.1
		"0177.0.0.1",          // octal 127.0.0.1
		"0300.0250.0001.0001", // octal 192.168.1.1
		"0x7f.0.0.1",          // hex-dotted 127.0.0.1
		"0x7f000001",          // hex single 127.0.0.1
		"2852039166",          // decimal 169.254.169.254 (metadata)
		"0xa9fea9fe",          // hex 169.254.169.254 (metadata)
		"127.1",               // short form 127.0.0.1
	}
	for _, host := range blocked {
		t.Run(host, func(t *testing.T) {
			_, err := d.Dial("tcp", net.JoinHostPort(host, "80"))
			if err == nil {
				t.Fatalf("expected %q to be blocked", host)
			}
			if !strings.Contains(err.Error(), "blocked (SSRF protection)") {
				t.Fatalf("host %q: unexpected error: %v", host, err)
			}
		})
	}
}

// A public IP given in decimal form must still be ALLOWED to be dialed (it may
// fail to connect, but must not be rejected by the SSRF blocklist).
func TestSafeDialer_ObfuscatedIPv4_PublicAllowed(t *testing.T) {
	d, err := NewSafeDialer(1*time.Second, nil)
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	// 134744072 == 8.8.8.8 (public). Dial to a closed port so it fails fast on
	// connection, NOT on SSRF policy.
	_, err = d.Dial("tcp", net.JoinHostPort("134744072", "9"))
	if err != nil && strings.Contains(err.Error(), "blocked (SSRF protection)") {
		t.Fatalf("public decimal IP 134744072 (8.8.8.8) must not be SSRF-blocked: %v", err)
	}
}

// URL userinfo bypass: a host carrying user:pass@ must be rejected so the real
// host after @ cannot be smuggled past the check.
func TestSafeDialer_UserinfoRejected(t *testing.T) {
	d, err := NewSafeDialer(2*time.Second, nil)
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	hosts := []string{
		"user:pass@10.0.0.1",
		"evil.com@169.254.169.254",
		"foo@127.0.0.1",
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			_, err := d.Dial("tcp", net.JoinHostPort(host, "80"))
			if err == nil {
				t.Fatalf("expected userinfo host %q to be rejected", host)
			}
		})
	}
}

// Cloud-metadata hostname bypass: known metadata hostnames must be blocked
// explicitly, including the trailing-dot form.
func TestSafeDialer_MetadataHostnameBlocked(t *testing.T) {
	d, err := NewSafeDialer(2*time.Second, nil)
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	hosts := []string{
		"metadata.google.internal",
		"metadata.google.internal.",
		"METADATA.GOOGLE.INTERNAL", // case-insensitive
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			_, err := d.Dial("tcp", net.JoinHostPort(host, "80"))
			if err == nil {
				t.Fatalf("expected metadata hostname %q to be blocked", host)
			}
			if !strings.Contains(err.Error(), "blocked (SSRF protection)") {
				t.Fatalf("host %q: unexpected error: %v", host, err)
			}
		})
	}
}

// canonicalizeHost strips userinfo and normalizes obfuscated IPv4 literals.
func TestCanonicalizeHost(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain_host", "example.com", "example.com", false},
		{"plain_ip", "8.8.8.8", "8.8.8.8", false},
		{"decimal_ip", "2130706433", "127.0.0.1", false},
		{"userinfo", "user:pass@10.0.0.1", "", true},
		{"userinfo_at_only", "foo@bar", "", true},
		{"trailing_dot_kept", "example.com.", "example.com.", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeHost(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("canonicalizeHost(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalizeHost(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("canonicalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
