package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWorkerCertsInsertRefusesEmptyIssuer(t *testing.T) {
	e := newEnrollEnv(t)
	_, csr, _ := newKeyCSR(t)
	cert, err := e.ca.Issue(csr, "worker-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// An intermediate with no key id and no issuer to hash is an error, never a
	// blank issuer_kid.
	cert.AuthorityKeyId = nil
	rec := RecordFor(cert, nil, "worker-1", CertIssuedViaRenew, e.clk.Now())
	if rec.IssuerKID != "" {
		t.Fatalf("issuer kid %q from nothing", rec.IssuerKID)
	}
	if err := e.store.RecordCert(context.Background(), rec); !errors.Is(err, ErrCertNoIssuer) {
		t.Fatalf("RecordCert with no issuer kid = %v, want ErrCertNoIssuer", err)
	}
	// With the issuer passed, the kid is the intermediate's SPKI hash.
	if kid := RecordFor(cert, e.ca.Intermediate(), "worker-1", CertIssuedViaRenew, e.clk.Now()).IssuerKID; len(kid) != 64 {
		t.Fatalf("fallback issuer kid %q", kid)
	}
}

func TestWorkerCertsRevokeWorker(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	b := c.issue(t, "worker-1")
	other := c.issue(t, "worker-2")
	ctx := context.Background()
	idTok, _ := c.create(t, EnrollCreateOpts{Name: "id-bound", WorkerID: "worker-1"})
	pfxTok, _ := c.create(t, EnrollCreateOpts{Name: "prefix", WorkerIDPrefix: "worker-", MaxUses: 3})
	if _, err := c.store.RevokeWorker(ctx, "nobody", "admin", "test"); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("unknown worker: %v", err)
	}
	if _, err := c.store.RevokeWorker(ctx, "worker-1", "", "test"); err == nil {
		t.Fatal("an empty actor was accepted")
	}
	serials, err := c.store.RevokeWorker(ctx, "worker-1", "admin", "test")
	if err != nil || len(serials) != 2 {
		t.Fatalf("RevokeWorker = %v, %v", serials, err)
	}
	for _, w := range []workerCert{a, b} {
		row, err := c.store.Cert(ctx, w.serial())
		if err != nil || row.RevokedAt.IsZero() || row.RevokedBy != "admin" || row.RevokeReason != "test" {
			t.Fatalf("row %+v, %v", row, err)
		}
	}
	if row, _ := c.store.Cert(ctx, other.serial()); !row.RevokedAt.IsZero() {
		t.Fatal("another worker's certificate was revoked")
	}
	// The unused id-bound token is revoked; a prefix token is not an id-bound one.
	if _, err := c.store.Peek(idTok); !errors.Is(err, ErrEnrollRevoked) {
		t.Errorf("id-bound token after RevokeWorker: %v", err)
	}
	if _, err := c.store.Peek(pfxTok); err != nil {
		t.Errorf("prefix token after RevokeWorker: %v", err)
	}
	// Idempotent: nothing left to revoke, the first revocation stays.
	again, err := c.store.RevokeWorker(ctx, "worker-1", "other-admin", "later")
	if err != nil || len(again) != 0 {
		t.Fatalf("second RevokeWorker = %v, %v", again, err)
	}
	if row, _ := c.store.Cert(ctx, a.serial()); row.RevokedBy != "admin" || row.RevokeReason != "test" {
		t.Fatalf("the first revocation was overwritten: %+v", row)
	}
	// Expired certificates are not listed as revoked: they cannot authenticate anyway.
	list, err := c.store.RevokedCerts(ctx, c.clk.Now())
	if err != nil || len(list) != 2 {
		t.Fatalf("RevokedCerts = %v, %v", list, err)
	}
	list, _ = c.store.RevokedCerts(ctx, c.clk.Now().Add(48*time.Hour))
	if len(list) != 0 {
		t.Fatalf("expired serials still listed: %v", list)
	}
}

func TestWorkerCertsIndexRebuildReportsFreshRevocations(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	var got []string
	c.srv.certIdx.onRevoked = func(serial string) { got = append(got, serial) }
	c.revoke(t, a.serial())
	if len(got) != 1 || got[0] != a.serial() {
		t.Fatalf("onRevoked calls = %v", got)
	}
	if err := c.srv.certIdx.Rebuild(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("a rebuild with nothing new called onRevoked again: %v %v", got, err)
	}
	if c.srv.certIdx.Len() != 1 {
		t.Fatalf("index length %d", c.srv.certIdx.Len())
	}
}

func TestValidateWorkerAuthRequireCerts(t *testing.T) {
	ok := Params{RequireWorkerCerts: true, StateDir: "/s", CACert: "c", CAKey: "k"}
	if _, err := validateWorkerAuth(ok); err != nil {
		t.Fatalf("valid combination: %v", err)
	}
	cases := map[string]struct {
		mut  func(*Params)
		want string
	}{
		"with tokens":    {func(p *Params) { p.RequireWorkerTokens = true }, "--require-worker-tokens"},
		"with legacy":    {func(p *Params) { p.LegacyTokenEnv = "L" }, "--legacy-token-env"},
		"with alias":     {func(p *Params) { p.TokenEnv = "L" }, "--legacy-token-env"},
		"no state dir":   {func(p *Params) { p.StateDir = "" }, "--state-dir"},
		"no TLS":         {func(p *Params) { p.CACert, p.CAKey = "", "" }, "TLS"},
		"insecure flag":  {func(p *Params) { p.CACert, p.CAKey, p.AllowInsecureWorkerAuth = "", "", true }, "TLS"},
		"only a ca cert": {func(p *Params) { p.CAKey = "" }, "TLS"},
	}
	for name, c := range cases {
		p := ok
		c.mut(&p)
		if _, err := validateWorkerAuth(p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, c.want)
		}
	}
}
