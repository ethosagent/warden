package signer_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

func TestIntermediateIsConstrainedToTheTrustDomain(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	root, rootKey, err := signer.NewRoot(now)
	if err != nil {
		t.Fatal(err)
	}
	ik, _ := signer.GenerateKey()
	inter, err := signer.NewIntermediate(root, rootKey, &ik.PublicKey, "warden.local", now)
	if err != nil {
		t.Fatal(err)
	}
	if !inter.IsCA || inter.MaxPathLen != 0 || !inter.MaxPathLenZero || inter.KeyUsage != x509.KeyUsageCertSign {
		t.Fatalf("intermediate shape: %+v", inter)
	}
	if root.MaxPathLen != 1 || inter.NotAfter.After(root.NotAfter) {
		t.Fatalf("root shape / validity")
	}
	leafKey, _ := signer.GenerateKey()
	issue := func(uri string) *x509.Certificate {
		u, _ := url.Parse(uri)
		der, err := signer.CreateCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(7), Subject: pkix.Name{}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs: []*url.URL{u},
		}, inter, &leafKey.PublicKey, ik)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	pool := x509.NewCertPool()
	pool.AddCert(inter)
	opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}
	if _, err := issue("spiffe://warden.local/warden/worker/a").Verify(opts); err != nil {
		t.Fatalf("in-domain: %v", err)
	}
	// The intermediate itself is the trust anchor here, so its own constraint is
	// checked when the root is the anchor instead.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	ip := x509.NewCertPool()
	ip.AddCert(inter)
	ro := x509.VerifyOptions{Roots: rootPool, Intermediates: ip, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}
	if _, err := issue("spiffe://warden.local/warden/worker/a").Verify(ro); err != nil {
		t.Fatalf("via root: %v", err)
	}
	if _, err := issue("spiffe://other.local/warden/worker/a").Verify(ro); err == nil {
		t.Fatal("out-of-domain URI verified under the name constraint")
	}
	der, err := signer.NewCSR(ik)
	if err != nil {
		t.Fatal(err)
	}
	if csr, err := x509.ParseCertificateRequest(der); err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
}
