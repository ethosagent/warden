package config

import (
	"fmt"
	"net"
)

// UpstreamConfig is LOCAL-ONLY upstream-dial wiring: exceptions to the SSRF
// private-IP blocklist the SafeDialer enforces (internal/proxy/safedial.go).
//
// allowPrivateCIDRs exists for lab/test networks where the allowlisted upstream
// legitimately lives on a private range (the L2 container harness dials a fake
// upstream across a Docker bridge network). It is a SECURITY exception — it
// punches a hole in SSRF protection — so it travels nowhere: Policy.Upstream is
// json:"-" (like DNS and the listen/CA paths), which keeps a control-plane
// policy from ever setting or widening it, and it is never projected onto the
// worker-served settings wire. Validate hard at startup (validateUpstream) and
// treat every deployment that sets it as lab-only.
type UpstreamConfig struct {
	// AllowPrivateCIDRs is the list of CIDR ranges exempted from the
	// private-IP blocklist. Empty (the default) = no exceptions, byte-identical
	// to the behavior before this block existed.
	AllowPrivateCIDRs []string
}

// rawUpstream mirrors the on-disk `upstream:` block. Pointer so absence is
// distinct from an empty block; both map to the zero UpstreamConfig.
type rawUpstream struct {
	AllowPrivateCIDRs []string `yaml:"allowPrivateCIDRs"`
}

// parseUpstream converts the raw upstream block into a typed UpstreamConfig. An
// absent block (nil) yields the zero value. Validation of the entries lives in
// validateUpstream so both the YAML and CP-served paths share one gate.
func parseUpstream(r *rawUpstream) UpstreamConfig {
	if r == nil {
		return UpstreamConfig{}
	}
	return UpstreamConfig{AllowPrivateCIDRs: r.AllowPrivateCIDRs}
}

// forbiddenUpstreamRanges are the ranges allowPrivateCIDRs may never exempt:
// loopback (the DNS-rebind target — after a rebinding answer a name resolves to
// 127.0.0.1, and the blocklist must keep refusing it), link-local and the other
// cloud-metadata endpoints (169.254.169.254, Alibaba's 100.100.100.200, AWS's
// IPv6 fd00:ec2::254, the reserved 192.0.0.192), multicast (never an upstream),
// and the unspecified addresses.
var forbiddenUpstreamRanges = []struct {
	cidr string
	why  string
}{
	{"127.0.0.0/8", "loopback"},
	{"::1/128", "loopback"},
	{"169.254.0.0/16", "link-local / cloud metadata"},
	{"fe80::/10", "link-local / cloud metadata"},
	{"100.100.100.200/32", "cloud metadata"},
	{"fd00:ec2::254/128", "cloud metadata"},
	{"192.0.0.192/32", "cloud metadata"},
	{"224.0.0.0/4", "multicast"},
	{"ff00::/8", "multicast"},
	{"0.0.0.0/8", "the unspecified range"},
	{"::/128", "the unspecified range"},
}

// validateUpstream enforces, at LOAD, that every allowPrivateCIDRs entry is a
// parseable CIDR that (a) is not an IPv4-mapped IPv6 range, (b) does not touch
// a protected range, and (c) is narrow enough to be a real exception rather
// than a blocklist bypass. Failing closed here means a typo or an over-wide
// entry stops the process instead of quietly re-opening private addresses at
// dial time.
func validateUpstream(c UpstreamConfig) error {
	for i, raw := range c.AllowPrivateCIDRs {
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("config: upstream.allowPrivateCIDRs[%d] %q is not a valid CIDR: %v", i, raw, err)
		}
		if err := checkUpstreamV4Mapped(i, raw, ipNet); err != nil {
			return err
		}
		if err := checkUpstreamRange(i, raw, ipNet); err != nil {
			return err
		}
		if err := checkUpstreamPrefix(i, raw, ipNet); err != nil {
			return err
		}
	}
	return nil
}

// checkUpstreamV4Mapped rejects IPv4-mapped IPv6 entries (::ffff:0:0/96 and
// anything inside it). The SafeDialer sees dial addrs in their plain IPv4 form
// (net.IP.To4 normalizes before the blocklist runs), so such an entry exempts
// nothing — it is inert and purely misleading, so it is rejected outright
// instead of being silently accepted as a no-op. This runs BEFORE the range
// check: a mapped entry's parsed network degenerates under v4 normalization
// (a /96 becomes an effective /0), which would produce a confusing overlap
// error instead of this one. Detected structurally: a v6-sized network whose
// address has a To4 form lies inside ::ffff:0:0/96 by construction.
func checkUpstreamV4Mapped(i int, raw string, entry *net.IPNet) error {
	ones, bits := entry.Mask.Size()
	if bits == 128 && entry.IP.To4() != nil {
		return fmt.Errorf("config: upstream.allowPrivateCIDRs[%d] %q is an IPv4-mapped IPv6 range (inside ::ffff:0:0/96); such entries are inert under the SafeDialer and misleading — list the plain IPv4 CIDR instead (entry is /%d)", i, raw, ones)
	}
	return nil
}

// checkUpstreamRange rejects an entry whose range intersects a protected one.
// Two CIDRs intersect exactly when the wider one contains the narrower one's
// network address, so testing membership in both directions covers containment
// in either direction (equality included).
func checkUpstreamRange(i int, raw string, entry *net.IPNet) error {
	for _, forbidden := range forbiddenUpstreamRanges {
		_, fNet, err := net.ParseCIDR(forbidden.cidr)
		if err != nil {
			panic(fmt.Sprintf("config: bad forbidden upstream range %q: %v", forbidden.cidr, err))
		}
		if fNet.Contains(entry.IP) || entry.Contains(fNet.IP) {
			return fmt.Errorf("config: upstream.allowPrivateCIDRs[%d] %q overlaps %s %s; %s is never exempt from SSRF protection",
				i, raw, forbidden.why, forbidden.cidr, forbidden.why)
		}
	}
	return nil
}

// checkUpstreamPrefix enforces the prefix-length floor: an exception wide
// enough to swallow whole swaths of private address space (IPv4 wider than /8,
// IPv6 wider than /16) defeats the blocklist it is exempting from.
func checkUpstreamPrefix(i int, raw string, entry *net.IPNet) error {
	ones, bits := entry.Mask.Size()
	switch bits {
	case 32:
		if ones < 8 {
			return fmt.Errorf("config: upstream.allowPrivateCIDRs[%d] %q must be at least /8 for IPv4 (got /%d)", i, raw, ones)
		}
	case 128:
		if ones < 16 {
			return fmt.Errorf("config: upstream.allowPrivateCIDRs[%d] %q must be at least /16 for IPv6 (got /%d)", i, raw, ones)
		}
	default:
		return fmt.Errorf("config: upstream.allowPrivateCIDRs[%d] %q has an unsupported mask size (%d bits)", i, raw, bits)
	}
	return nil
}
