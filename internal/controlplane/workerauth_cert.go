package controlplane

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/workerca"
)

// Certificate authentication (W-P2-WCA-04). The TLS listener only requests a
// client certificate (tls.RequestClientCert): the handshake proves the client
// holds the private key but verifies nothing else, so a bad certificate is a
// uniform HTTP 401 here, keep-alive connections see expiry and revocation on
// the next request, and the pinned intermediates can be swapped without
// restarting the listener.

// maxCertCache bounds the verified-certificate cache. The keys are hashes of
// certificates the pinned intermediates signed, so it holds at most the fleet;
// at the cap it is dropped and refilled.
const maxCertCache = 8192

// presentedCert returns the leaf certificate the client presented in the TLS
// handshake, or nil. Only the leaf is used: anything else the client sends is
// ignored, so no chain is ever built through client-supplied certificates.
func presentedCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// verifiedCert is what a successful verification established about a leaf.
type verifiedCert struct {
	v                   *workerca.Verifier // the pool it verified against
	workerID, serial    string
	spiffeID            string
	notBefore, notAfter time.Time
}

// certCache remembers verified certificates by the sha256 of their DER, so the
// per-request path is a hash and a map read instead of a chain verification.
// An entry is valid only for the verifier that produced it and only inside the
// certificate's validity window; revocation is never cached (certIndex).
type certCache struct {
	mu sync.RWMutex
	m  map[[sha256.Size]byte]verifiedCert
}

func (c *certCache) get(k [sha256.Size]byte) (verifiedCert, bool) {
	c.mu.RLock()
	e, ok := c.m[k]
	c.mu.RUnlock()
	return e, ok
}

func (c *certCache) put(k [sha256.Size]byte, e verifiedCert) {
	c.mu.Lock()
	if c.m == nil || len(c.m) >= maxCertCache {
		c.m = make(map[[sha256.Size]byte]verifiedCert, 64)
	}
	c.m[k] = e
	c.mu.Unlock()
}

func (c *certCache) reset() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}

// resolveCert authenticates a presented client certificate. Every failure is
// ErrUnauthorized with a reason for the rate-limited log (bad_chain, bad_eku,
// bad_san, expired, revoked, or the unavailable-store reasons) except a header
// naming another worker, which is a 403 like a mismatched token binding.
func (a *WorkerAuthenticator) resolveCert(r *http.Request, v *workerca.Verifier, leaf *x509.Certificate) (p WorkerPrincipal, reason, tokenID string, err error) {
	p.Kind = KindCert
	if a.certs == nil {
		return p, "no_cert_store", "", ErrUnauthorized
	}
	key := sha256.Sum256(leaf.Raw)
	now := a.clk.Now()
	ent, ok := a.certCache.get(key)
	if !ok || ent.v != v || now.Before(ent.notBefore) || !now.Before(ent.notAfter) {
		id, verr := v.Verify(leaf)
		if verr != nil {
			p.CertSerial = leaf.SerialNumber.Text(16)
			return p, classifyCertError(verr), "", ErrUnauthorized
		}
		ent = verifiedCert{
			v: v, workerID: id, serial: leaf.SerialNumber.Text(16), spiffeID: leaf.URIs[0].String(),
			notBefore: leaf.NotBefore, notAfter: leaf.NotAfter,
		}
		a.certCache.put(key, ent)
	}
	p.CertSerial = ent.serial
	entry, revoked, loaded := a.certs.Entry(ent.serial)
	switch {
	case !loaded:
		return p, "revocation_unavailable", "", ErrUnauthorized
	case revoked:
		if entry.Reason == RevokeReasonSuperseded && a.onSuperseded != nil {
			a.onSuperseded(ent.workerID, ent.serial, remoteHost(r))
		}
		return p, "revoked", "", ErrUnauthorized
	}
	// The certificate's id is authoritative: a header that differs in any way is
	// refused, so one worker cannot speak as another.
	for _, h := range r.Header.Values(analytics.ProxyIDHeader) {
		if h != "" && h != ent.workerID {
			return p, "proxy_id_mismatch", "", ErrProxyIDMismatch
		}
	}
	return WorkerPrincipal{
		Kind: KindCert, ProxyID: ent.workerID, CertSerial: ent.serial, SpiffeID: ent.spiffeID, NotAfter: ent.notAfter,
	}, "", "", nil
}

// classifyCertError names why a certificate failed verification, from the
// closed set bad_chain, bad_eku, bad_san and expired.
func classifyCertError(err error) string {
	var invalid x509.CertificateInvalidError
	switch {
	case errors.Is(err, workerca.ErrNotWorkerCert):
		return "bad_san"
	case errors.As(err, &invalid):
		switch invalid.Reason {
		case x509.Expired:
			return "expired"
		case x509.IncompatibleUsage:
			return "bad_eku"
		}
	}
	return "bad_chain"
}

// AuthenticateCert authenticates a request that must carry a worker
// certificate (POST /control/renew): no bearer, shared token or anonymous
// caller is accepted whatever the auth mode, and a request without a verifier
// (workerCA off) or without a presented certificate is a 401 like any other.
func (a *WorkerAuthenticator) AuthenticateCert(r *http.Request) (WorkerPrincipal, error) {
	if a.verifier.Load() == nil || presentedCert(r) == nil {
		a.count(KindNone, "unauthorized")
		a.logRejected("cert_required", "", "", r)
		return WorkerPrincipal{}, ErrUnauthorized
	}
	return a.Authenticate(r)
}

// hasWorkerCert reports whether the request presented a client certificate on a
// control plane that requests them. The human routes refuse such a request
// when it carries no credential of its own: a worker certificate is never an
// admin credential.
func (a *WorkerAuthenticator) hasWorkerCert(r *http.Request) bool {
	return a.verifier.Load() != nil && presentedCert(r) != nil
}
