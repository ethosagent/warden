package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// blockedNets is the hardcoded list of private/reserved IP ranges that the
// SafeDialer blocks by default to prevent SSRF attacks.
var blockedNets []net.IPNet

// deniedHostnames is a set of hostnames that must never be dialed regardless of
// what they resolve to. Cloud-metadata endpoints commonly expose IMDS via a
// hostname as well as the 169.254.169.254 link-local IP (already covered by
// 169.254.0.0/16). Keys are lower-cased and stripped of any trailing dot; see
// canonicalizeHost. The allowPrivate exception mechanism does NOT apply here:
// these hostnames are hard-denied.
var deniedHostnames = map[string]struct{}{
	"metadata.google.internal": {},
}

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

// parseObfuscatedIPv4 decodes non-dotted-decimal IPv4 encodings that
// net.ParseIP rejects (returning nil), so an attacker cannot smuggle a blocked
// address past the IP-literal blocklist by encoding it in a form the OS
// resolver understands but net.ParseIP does not. It returns the canonical
// 4-byte IPv4 address, or nil if host is not an obfuscated IPv4 literal (e.g. a
// real hostname, an IPv6 literal, or an unparseable/out-of-range form).
//
// It is deliberately fail-closed: any ambiguity (overflow, bad digit, too many
// parts) returns nil, which leaves the value to be treated as a hostname and
// resolved+re-checked, never silently allowed as a decoded IP.
//
// Encodings handled (per the classic inet_aton / glibc semantics that resolvers
// and browsers accept):
//   - Decimal:  a single 32-bit integer, e.g. "2130706433" -> 127.0.0.1
//   - Octal:    octets with a leading 0, e.g. "0177.0.0.1" -> 127.0.0.1
//   - Hex:      octets with 0x prefix, e.g. "0x7f.0.0.1" or "0x7f000001"
//   - Short:    fewer than 4 parts where the final part is a wide field:
//     "a.b.c" (c is 16-bit), "a.b" (b is 24-bit), "a" (32-bit)
//   - Mixed:    each part may independently be decimal/octal/hex
func parseObfuscatedIPv4(host string) net.IP {
	if host == "" {
		return nil
	}
	// An IPv6 literal (contains ':') is never an obfuscated IPv4 form.
	if strings.ContainsRune(host, ':') {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return nil
	}

	// Parse each part as an unsigned integer honoring octal/hex prefixes.
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseIPv4Part(p)
		if !ok {
			return nil
		}
		vals[i] = v
	}

	// Combine parts into a single 32-bit value following inet_aton rules. The
	// last part is a "wide" field filling all remaining low-order bytes; every
	// preceding part must fit in a single byte.
	var addr uint64
	last := len(vals) - 1
	for i := 0; i < last; i++ {
		if vals[i] > 0xff {
			return nil // non-final octet out of range -> fail closed
		}
		addr |= vals[i] << (8 * (3 - uint(i)))
	}
	// The final part fills the remaining (4-last) low bytes.
	remainingBytes := 4 - last
	maxLast := (uint64(1) << (8 * uint(remainingBytes))) - 1
	if vals[last] > maxLast {
		return nil // final field out of range -> fail closed
	}
	addr |= vals[last]

	return net.IPv4(
		byte(addr>>24),
		byte(addr>>16),
		byte(addr>>8),
		byte(addr),
	).To4()
}

// parseIPv4Part parses one segment of an obfuscated IPv4 literal, honoring the
// C-style base prefixes that resolvers accept: "0x"/"0X" for hex, a leading "0"
// for octal, otherwise decimal. It returns ok=false on any malformed input so
// callers fail closed. It intentionally rejects negative signs and whitespace.
func parseIPv4Part(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	// Reject anything with sign/whitespace that ParseUint might otherwise
	// tolerate for some bases; keep the grammar strict.
	base := 10
	digits := p
	switch {
	case len(p) >= 2 && (p[0:2] == "0x" || p[0:2] == "0X"):
		base = 16
		digits = p[2:]
		if digits == "" {
			return 0, false
		}
	case len(p) >= 2 && p[0] == '0':
		// Leading zero with more digits -> octal (e.g. "0177"). A lone "0" is
		// decimal zero and handled by the default branch below.
		base = 8
		digits = p[1:]
	}
	v, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// canonicalizeHost prepares a host (as extracted from an address) for the SSRF
// checks. It:
//   - rejects any host carrying URL userinfo ("user:pass@host" / "user@host"),
//     which could otherwise smuggle a different real host past the blocklist;
//   - normalizes obfuscated IPv4 literals (decimal/octal/hex/short forms) to
//     canonical dotted-decimal so the blocklist sees the true address.
//
// It returns the canonical host to use for resolution and blocklist checks. A
// non-nil error means the host must be rejected (fail closed).
func canonicalizeHost(host string) (string, error) {
	// Reject userinfo. A '@' in a host position is never legitimate for a
	// dial target; net.SplitHostPort does not strip it, so evil.com@evil-ip
	// would otherwise be resolved as the whole string (and could match a real
	// host). Fail closed rather than guess which side is the real host.
	if strings.ContainsRune(host, '@') {
		return "", fmt.Errorf("proxy: host %q contains userinfo (SSRF protection)", host)
	}
	// Normalize obfuscated IPv4 encodings to canonical dotted-decimal.
	if ip := parseObfuscatedIPv4(host); ip != nil {
		return ip.String(), nil
	}
	return host, nil
}

// isDeniedHostname reports whether host is on the hard-deny hostname list
// (e.g. cloud-metadata endpoints). Comparison is case-insensitive and ignores a
// single trailing dot (the DNS root form).
func isDeniedHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	_, denied := deniedHostnames[h]
	return denied
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

// safeHostAndIPs canonicalizes host (stripping userinfo and normalizing
// obfuscated IPv4 encodings), rejects hard-denied hostnames, resolves the host,
// and returns the canonical host together with the resolved IPs that survive
// the blocklist. It centralizes the SSRF pre-flight so Dial and DialTLS cannot
// diverge. A "blocked (SSRF protection)" error is returned when nothing is
// allowed, matching the existing contract.
func (d *SafeDialer) safeHostAndIPs(host string) (string, []net.IP, error) {
	canonHost, err := canonicalizeHost(host)
	if err != nil {
		return "", nil, err
	}
	// Hard-deny known metadata hostnames before any resolution.
	if isDeniedHostname(canonHost) {
		return "", nil, fmt.Errorf("proxy: host %q is blocked (SSRF protection)", canonHost)
	}

	ips, err := d.resolve(canonHost)
	if err != nil {
		return "", nil, fmt.Errorf("safedial: resolve %q: %w", canonHost, err)
	}

	var allowed []net.IP
	for _, ipAddr := range ips {
		if !d.isBlocked(ipAddr.IP) {
			allowed = append(allowed, ipAddr.IP)
		}
	}
	if len(allowed) == 0 {
		return "", nil, fmt.Errorf("proxy: all resolved IPs for %q are blocked (SSRF protection)", canonHost)
	}
	return canonHost, allowed, nil
}

// Dial resolves addr, validates the resolved IPs against the blocklist, and
// tries each allowed IP in order until one connects. This prevents TOCTOU
// DNS-rebinding by connecting to the pinned IP rather than the hostname.
func (d *SafeDialer) Dial(network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safedial: %w", err)
	}

	_, allowed, err := d.safeHostAndIPs(host)
	if err != nil {
		return nil, err
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

	canonHost, allowed, err := d.safeHostAndIPs(host)
	if err != nil {
		return nil, err
	}

	// Clone or create TLS config with SNI set to the canonical hostname.
	var tlsCfg *tls.Config
	if cfg != nil {
		tlsCfg = cfg.Clone()
	} else {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = canonHost
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
