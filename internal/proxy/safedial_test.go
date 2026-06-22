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
