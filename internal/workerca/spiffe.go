package workerca

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// workerPathPrefix is the SPIFFE path every worker identity lives under.
const workerPathPrefix = "/warden/worker/"

var (
	workerIDRe     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	trustDomainRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	maxTrustDomain = 253
)

// ValidWorkerID reports whether id matches the P1 proxy_id rule.
// "." and ".." match the character class but are path segments SPIFFE forbids.
func ValidWorkerID(id string) bool {
	return id != "." && id != ".." && workerIDRe.MatchString(id)
}

// ValidTrustDomain reports whether td is a lowercase DNS-style host.
func ValidTrustDomain(td string) bool {
	return len(td) <= maxTrustDomain && trustDomainRe.MatchString(td)
}

// SPIFFEID returns spiffe://<trustDomain>/warden/worker/<workerID>.
func SPIFFEID(trustDomain, workerID string) (*url.URL, error) {
	if !ValidTrustDomain(trustDomain) {
		return nil, ErrInvalidTrustDomain
	}
	if !ValidWorkerID(workerID) {
		return nil, ErrInvalidWorkerID
	}
	return &url.URL{Scheme: "spiffe", Host: trustDomain, Path: workerPathPrefix + workerID}, nil
}

// WorkerIDFromCert returns the worker id a certificate carries, and only when
// it has exactly one URI SAN with scheme spiffe, host trustDomain and a path
// of /warden/worker/<id>, and no other SAN. Anything else is ErrNotWorkerCert.
func WorkerIDFromCert(cert *x509.Certificate, trustDomain string) (string, error) {
	if cert == nil || !ValidTrustDomain(trustDomain) {
		return "", ErrNotWorkerCert
	}
	if len(cert.URIs) != 1 || len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 {
		return "", ErrNotWorkerCert
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != trustDomain || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, workerPathPrefix) {
		return "", ErrNotWorkerCert
	}
	id := strings.TrimPrefix(u.Path, workerPathPrefix)
	if !ValidWorkerID(id) {
		return "", fmt.Errorf("%w: bad worker id", ErrNotWorkerCert)
	}
	return id, nil
}
