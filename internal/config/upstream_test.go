package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// upstreamYAML wraps a minimal valid config around an `upstream:` block. The
// allowlist entry is required because a config with no allowlist and no
// control-plane endpoint is rejected before validateUpstream ever runs.
func upstreamYAML(block string) string {
	return `
policy:
  allowlist:
    - domain: api.example.test
` + block
}

// TestParse_UpstreamAllowPrivateCIDRs proves the local-only SSRF exception list
// loads when well-formed and stays empty (default-off) when the block is absent.
func TestParse_UpstreamAllowPrivateCIDRs(t *testing.T) {
	t.Run("absent block means empty (default off)", func(t *testing.T) {
		p, err := parse([]byte(upstreamYAML("")))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		pol, _ := p.GetPolicy()
		if got := pol.Upstream.AllowPrivateCIDRs; len(got) != 0 {
			t.Errorf("Upstream.AllowPrivateCIDRs = %v, want empty (default off)", got)
		}
	})

	t.Run("valid CIDRs load", func(t *testing.T) {
		y := upstreamYAML(`
upstream:
  allowPrivateCIDRs:
    - "10.200.0.0/24"
    - "2001:db8:abcd::/48"
`)
		p, err := parse([]byte(y))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		pol, _ := p.GetPolicy()
		want := []string{"10.200.0.0/24", "2001:db8:abcd::/48"}
		if len(pol.Upstream.AllowPrivateCIDRs) != len(want) {
			t.Fatalf("Upstream.AllowPrivateCIDRs = %v, want %v", pol.Upstream.AllowPrivateCIDRs, want)
		}
		for i := range want {
			if pol.Upstream.AllowPrivateCIDRs[i] != want[i] {
				t.Errorf("AllowPrivateCIDRs[%d] = %q, want %q", i, pol.Upstream.AllowPrivateCIDRs[i], want[i])
			}
		}
	})

	t.Run("empty list loads as empty", func(t *testing.T) {
		p, err := parse([]byte(upstreamYAML("upstream:\n  allowPrivateCIDRs: []\n")))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		pol, _ := p.GetPolicy()
		if got := pol.Upstream.AllowPrivateCIDRs; len(got) != 0 {
			t.Errorf("Upstream.AllowPrivateCIDRs = %v, want empty", got)
		}
	})
}

// TestValidate_UpstreamAllowPrivateCIDRs_Rejections pins every rejected shape:
// a value that is not a CIDR, entries that touch protected ranges, and prefixes
// so wide they would re-open the whole private internet.
func TestValidate_UpstreamAllowPrivateCIDRs_Rejections(t *testing.T) {
	cases := []struct {
		name    string
		cidr    string
		wantErr string // substring that must appear in the error
	}{
		{"not a cidr", "not-a-cidr", "not-a-cidr"},
		{"not a cidr with key named", "10.0.0.0", "upstream.allowPrivateCIDRs"},
		// Loopback must never be excepted (the /_rebind demo relies on this).
		{"loopback v4", "127.0.0.0/8", "loopback"},
		{"loopback v4 narrow", "127.0.0.0/16", "loopback"},
		{"loopback v6", "::1/128", "loopback"},
		// Link-local / cloud metadata.
		{"link-local v4", "169.254.0.0/16", "link-local"},
		{"link-local v4 wider entry containing it", "169.254.0.0/15", "link-local"},
		{"link-local v6", "fe80::/10", "link-local"},
		{"link-local v6 narrow", "fe80::/16", "link-local"},
		// Cloud metadata endpoints off the link-local range: Alibaba's IMDS
		// (100.100.100.200), AWS's IPv6 IMDS (fd00:ec2::254, inside the ULA
		// range — a plain "unique local" exemption would expose it), and the
		// 192.0.0.0/24 IETF-reserved block the metadata gateways sit behind.
		{"cloud metadata v4", "100.100.100.200/32", "cloud metadata"},
		{"cloud metadata v4 wider entry containing it", "100.100.0.0/16", "cloud metadata"},
		{"cloud metadata v6", "fd00:ec2::254/128", "cloud metadata"},
		{"cloud metadata v6 wider entry containing it", "fd00:ec2::/32", "cloud metadata"},
		{"cloud metadata reserved v4", "192.0.0.192/32", "cloud metadata"},
		// Multicast is never an upstream.
		{"multicast v4", "224.0.0.0/4", "multicast"},
		{"multicast v4 narrow", "239.255.255.250/32", "multicast"},
		{"multicast v6", "ff00::/8", "multicast"},
		{"multicast v6 narrow", "ff02::1/128", "multicast"},
		// IPv4-mapped IPv6 entries are inert (dial addrs are normalized to
		// plain IPv4 before the blocklist sees them) and misleading — reject
		// outright with the dedicated message.
		{"ipv4-mapped ipv6 range", "::ffff:0:0/96", "IPv4-mapped"},
		{"ipv4-mapped ipv6 inside the range", "::ffff:10.0.0.0/104", "IPv4-mapped"},
		{"ipv4-mapped ipv6 loopback literal", "::ffff:127.0.0.1/128", "IPv4-mapped"},
		// Unspecified addresses.
		{"unspecified v4", "0.0.0.0/8", "unspecified"},
		{"unspecified v6", "::/128", "unspecified"},
		// Prefixes so wide they defeat the blocklist. 0.0.0.0/0 trips the
		// overlap check first (it contains everything, loopback included) — the
		// rejection is what matters, whichever guard fires.
		{"ipv4 shorter than /8", "10.0.0.0/7", "at least /8"},
		{"ipv4 default route", "0.0.0.0/0", "overlaps"},
		{"ipv6 shorter than /16", "2001:db8::/15", "at least /16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := upstreamYAML("upstream:\n  allowPrivateCIDRs: [\"" + tc.cidr + "\"]\n")
			_, err := parse([]byte(y))
			if err == nil {
				t.Fatalf("parse with allowPrivateCIDRs %q: got nil error, want rejection", tc.cidr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestParse_Upstream_AllowsBoundaryPrefixes checks the prefix-length floor does
// not reject legitimate, narrow-enough entries.
func TestParse_Upstream_AllowsBoundaryPrefixes(t *testing.T) {
	y := upstreamYAML(`
upstream:
  allowPrivateCIDRs:
    - "10.0.0.0/8"
    - "2001:db8::/16"
`)
	if _, err := parse([]byte(y)); err != nil {
		t.Fatalf("parse with /8 (v4) and /16 (v6) entries: %v", err)
	}
}

// TestRemotePolicy_CannotSetAllowPrivateCIDRs is the SEC-9 guard: the SSRF
// exception list is LOCAL-only wiring, so a control-plane-served policy must not
// be able to set it (it would let a compromised CP widen a worker's egress).
// Policy.Upstream is json:"-", so a JSON body carrying the key must leave the
// field untouched, and marshalling a policy that HAS the value must not emit it.
func TestRemotePolicy_CannotSetAllowPrivateCIDRs(t *testing.T) {
	t.Run("CP json body cannot set it", func(t *testing.T) {
		body := `{
			"allowlist": [{"domain": "api.example.test"}],
			"upstream": {"allowPrivateCIDRs": ["10.0.0.0/8"]},
			"allowPrivateCIDRs": ["10.0.0.0/8"]
		}`
		p, _, err := parseRemotePolicy([]byte(body))
		if err != nil {
			t.Fatalf("parseRemotePolicy: %v", err)
		}
		if got := p.Upstream.AllowPrivateCIDRs; len(got) != 0 {
			t.Errorf("CP-served policy set Upstream.AllowPrivateCIDRs = %v; it must stay local-only", got)
		}
	})

	t.Run("marshalled policy never emits it", func(t *testing.T) {
		p := Policy{Upstream: UpstreamConfig{AllowPrivateCIDRs: []string{"10.0.0.0/8"}}}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if s := string(b); strings.Contains(s, "allowPrivateCIDRs") || strings.Contains(s, "upstream") {
			t.Errorf("marshalled policy leaks the local-only key: %s", s)
		}
	})
}

// TestDeepCopy_UpstreamAllowPrivateCIDRs keeps DeepCopy honest for the new
// slice: mutating the copy must not touch the original (GetPolicy hands out
// deep copies so a hot-reload applier cannot corrupt the served policy).
func TestDeepCopy_UpstreamAllowPrivateCIDRs(t *testing.T) {
	p := Policy{Upstream: UpstreamConfig{AllowPrivateCIDRs: []string{"10.200.0.0/24"}}}
	cp := p.DeepCopy()
	cp.Upstream.AllowPrivateCIDRs[0] = "mutated"
	if p.Upstream.AllowPrivateCIDRs[0] != "10.200.0.0/24" {
		t.Fatalf("DeepCopy aliases Upstream.AllowPrivateCIDRs: original is now %q", p.Upstream.AllowPrivateCIDRs[0])
	}
}
