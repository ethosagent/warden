package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// blockedNets is the hardcoded list of private/reserved IP ranges that the
// SafeDialer blocks by default to prevent SSRF attacks.
var blockedNets []net.IPNet

func init() {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.168.0.0/16",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		// IPv6
		"::1/128",
		"::/128",
		"::ffff:0:0/96",
		"64:ff9b::/96",
		"2002::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("safedial: bad CIDR %q: %v", cidr, err))
		}
		blockedNets = append(blockedNets, *ipNet)
	}
}

// IsPrivateIP reports whether ip falls within any of the hardcoded
// private/reserved IP ranges. It does NOT consider SafeDialer.allowPrivate
// exceptions.
func IsPrivateIP(ip net.IP) bool {
	// Unwrap IPv4-mapped IPv6 addresses so the IPv4 blocklist entries match.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	ipLen := len(ip)
	for i := range blockedNets {
		// Only check against CIDRs of matching address family. Go's
		// net.IPNet.Contains normalises lengths, which causes the
		// ::ffff:0:0/96 (16-byte) CIDR to match all 4-byte IPv4
		// addresses. By comparing mask length we restrict IPv4 IPs to
		// IPv4 CIDRs and IPv6 IPs to IPv6 CIDRs.
		if len(blockedNets[i].Mask) != ipLen {
			continue
		}
		if blockedNets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// SafeDialer wraps Go's net.Dialer with DNS-pinning and private-IP blocking
// to prevent SSRF and TOCTOU DNS-rebinding attacks. It resolves DNS once,
// validates the resolved IP against a blocklist, and connects directly to the
// pinned IP.
type SafeDialer struct {
	allowPrivate []net.IPNet
	timeout      time.Duration
}

// NewSafeDialer creates a SafeDialer. allowPrivate is an optional list of CIDR
// strings that should be exempted from the private-IP blocklist (e.g.
// "10.0.0.0/8" for a known-good internal service).
func NewSafeDialer(timeout time.Duration, allowPrivate []string) (*SafeDialer, error) {
	d := &SafeDialer{timeout: timeout}
	for _, cidr := range allowPrivate {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("safedial: bad allowPrivate CIDR %q: %w", cidr, err)
		}
		d.allowPrivate = append(d.allowPrivate, *ipNet)
	}
	return d, nil
}

// isBlocked reports whether ip is in the hardcoded blocklist AND not covered
// by any allowPrivate exception.
func (d *SafeDialer) isBlocked(ip net.IP) bool {
	// Unwrap IPv4-mapped IPv6 first.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !IsPrivateIP(ip) {
		return false
	}
	// Check allowPrivate exceptions.
	for i := range d.allowPrivate {
		if d.allowPrivate[i].Contains(ip) {
			return false
		}
	}
	return true
}

// resolve performs DNS lookup with a timeout and returns the resolved IPs.
func (d *SafeDialer) resolve(host string) ([]net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	// If host is already an IP literal, skip DNS.
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// Dial resolves addr, validates the resolved IPs against the blocklist, and
// tries each allowed IP in order until one connects. This prevents TOCTOU
// DNS-rebinding by connecting to the pinned IP rather than the hostname.
func (d *SafeDialer) Dial(network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safedial: %w", err)
	}

	ips, err := d.resolve(host)
	if err != nil {
		return nil, fmt.Errorf("safedial: resolve %q: %w", host, err)
	}

	// Collect all non-blocked IPs.
	var allowed []net.IP
	for _, ipAddr := range ips {
		if !d.isBlocked(ipAddr.IP) {
			allowed = append(allowed, ipAddr.IP)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("proxy: all resolved IPs for %q are blocked (SSRF protection)", host)
	}

	// Try each allowed IP in order.
	var lastErr error
	for _, ip := range allowed {
		target := net.JoinHostPort(ip.String(), port)
		conn, dialErr := (&net.Dialer{Timeout: d.timeout}).Dial(network, target)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("proxy: all allowed IPs for %q failed: %w", host, lastErr)
}

// DialTLS resolves addr, validates the resolved IPs, and performs a TLS
// handshake with SNI set to the original hostname. It tries each allowed IP
// in order until one connects.
func (d *SafeDialer) DialTLS(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safedial: %w", err)
	}

	ips, err := d.resolve(host)
	if err != nil {
		return nil, fmt.Errorf("safedial: resolve %q: %w", host, err)
	}

	// Collect all non-blocked IPs.
	var allowed []net.IP
	for _, ipAddr := range ips {
		if !d.isBlocked(ipAddr.IP) {
			allowed = append(allowed, ipAddr.IP)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("proxy: all resolved IPs for %q are blocked (SSRF protection)", host)
	}

	// Clone or create TLS config with SNI set to the original hostname.
	var tlsCfg *tls.Config
	if cfg != nil {
		tlsCfg = cfg.Clone()
	} else {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}

	// Try each allowed IP in order.
	var lastErr error
	for _, ip := range allowed {
		target := net.JoinHostPort(ip.String(), port)
		conn, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: d.timeout}, network, target, tlsCfg)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("proxy: all allowed IPs for %q failed: %w", host, lastErr)
}
