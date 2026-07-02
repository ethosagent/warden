package scan

import (
	"net"
	"regexp"
)

// This file adds the infrastructure detector family: private/link-local IPs,
// internal-TLD hostnames, cloud resource identifiers, and the k8s-manifest
// co-occurrence classifier. IPs carry a validator (parse octets AND confirm the
// RFC1918/link-local range) so 999.999.999.999 and public addresses never flag.

// buildInfraPatterns returns the single-regex infrastructure detectors. The k8s
// manifest marker is a CLASSIFIER (co-occurrence, not a single span) and is added
// separately via k8sManifestClassifier.
func buildInfraPatterns() []compiledPattern {
	return []compiledPattern{
		{
			// Any dotted quad; the validator restricts to RFC1918 + link-local and
			// rejects invalid octets (so 999.999.999.999 never matches).
			name:     "private_ip",
			re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			severity: "low",
			category: "infrastructure",
			validate: validPrivateIP,
		},
		{
			// Internal-only TLDs / cluster DNS.
			name:     "internal_hostname",
			re:       regexp.MustCompile(`(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|corp)\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.svc\.cluster\.local\b`),
			severity: "low",
			category: "infrastructure",
		},
		{
			// AWS ARN.
			name:     "aws_arn",
			re:       regexp.MustCompile(`\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:[^\s"']+`),
			severity: "medium",
			category: "infrastructure",
		},
		{
			// AWS resource IDs: i-/vpc-/subnet-/sg- + 8 or 17 hex chars.
			name:     "aws_resource_id",
			re:       regexp.MustCompile(`\b(?:i|vpc|subnet|sg)-(?:[0-9a-f]{8}|[0-9a-f]{17})\b`),
			severity: "low",
			category: "infrastructure",
		},
	}
}

// validPrivateIP reports whether match is a syntactically valid IPv4 address in a
// private (10/8, 172.16/12, 192.168/16) or link-local (169.254/16) range.
// net.ParseIP rejects out-of-range octets, so "999.999.999.999" fails here.
func validPrivateIP(match string) bool {
	ip := net.ParseIP(match)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4.IsPrivate() || v4.IsLinkLocalUnicast()
}

// k8sManifestRe matches the two markers a Kubernetes manifest always carries.
var (
	k8sAPIVersionRe = regexp.MustCompile(`(?m)^\s*apiVersion:\s*\S`)
	k8sKindRe       = regexp.MustCompile(`(?m)^\s*kind:\s*\S`)
)

// k8sManifestClassifier emits a single infrastructure detection when a body
// carries BOTH `apiVersion:` and `kind:` as YAML keys — the co-occurrence that
// marks a Kubernetes manifest. A lone `kind:` (common in ordinary config/prose)
// does NOT trigger, which is the whole point of requiring both.
func k8sManifestClassifier(data []byte) []Detection {
	if k8sAPIVersionRe.Match(data) && k8sKindRe.Match(data) {
		return []Detection{{
			Category: "infrastructure",
			Pattern:  "k8s_manifest",
			Severity: "low",
		}}
	}
	return nil
}
