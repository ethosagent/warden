package security

import (
	"crypto"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/workerca"
)

// The enrollment and renewal attacks of W-P2-SECT-06: /control/enroll and
// /control/renew must never mint a certificate for a worker the token or the
// presented certificate does not name, never revive a revoked worker, and never
// say why a token was refused. Every refused request is proved to have reached
// the check under test: the case pins the CP's rejection reason in the log
// window of the case and the outcome counter, not only the status.

// unauthorizedBody is the one 401 body of /control/enroll: an unknown,
// used-up, expired or revoked token is not told apart.
const unauthorizedBody = "unauthorized\n"

// fresh opens a new rate-limit and log window: the CP rate limits its rejection
// log lines (one per reason and address a minute) and its per-address budget on
// the shared fake clock, so a case that asserts a log line or a budget starts
// a minute after the previous one. The clock is moved only here, never to wait
// for anything.
func fresh(s *Stack) { s.Clock.Advance(61 * time.Second) }

// expectDelta fails tb when the CP state moved by anything but want.
func expectDelta(tb testing.TB, before, after, want State) {
	tb.Helper()
	got := State{
		Certs: after.Certs - before.Certs, RevokedCerts: after.RevokedCerts - before.RevokedCerts,
		TokenUses: after.TokenUses - before.TokenUses, TokensRevoked: after.TokensRevoked - before.TokensRevoked,
		Audit: after.Audit - before.Audit,
	}
	if got != want {
		tb.Errorf("CP state moved by %+v (certs issued, certs revoked, token uses, tokens revoked, audit rows), want %+v", got, want)
	}
}

// expectCount fails tb when counter moved by anything but want while run ran.
func expectCount(tb testing.TB, name string, counter func() int64, want int64, run func()) {
	tb.Helper()
	before := counter()
	run()
	if d := counter() - before; d != want {
		tb.Errorf("%s moved by %d, want %d", name, d, want)
	}
}

// assertIssuedCert is the certificate the CA must issue whatever the CSR asked
// for: exactly one URI SAN for workerID, client authentication only, not a CA,
// no subject, no other SAN, the CSR's key, and a chain to the CP's roots.
func assertIssuedCert(tb testing.TB, s *Stack, r issued, cert *x509.Certificate, workerID string, key crypto.Signer) {
	tb.Helper()
	want, err := workerca.SPIFFEID(TrustDomain, workerID)
	if err != nil {
		tb.Fatalf("security: spiffe id for %q: %v", workerID, err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != want.String() {
		tb.Errorf("URI SANs = %v, want exactly [%s]", cert.URIs, want)
	}
	if id, err := workerca.WorkerIDFromCert(cert, TrustDomain); err != nil || id != workerID {
		tb.Errorf("WorkerIDFromCert = %q, %v, want %q", id, err, workerID)
	}
	if r.WorkerID != workerID || r.SpiffeID != want.String() {
		tb.Errorf("response names worker %q spiffe %q, want %q %q", r.WorkerID, r.SpiffeID, workerID, want)
	}
	if len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 {
		tb.Errorf("certificate carries dns %v email %v ip %v, want no other SAN", cert.DNSNames, cert.EmailAddresses, cert.IPAddresses)
	}
	if cert.Subject.String() != "" {
		tb.Errorf("certificate subject = %q, want empty (the CSR subject is ignored)", cert.Subject)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 {
		tb.Errorf("ExtKeyUsage = %v %v, want [ClientAuth] only", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature {
		tb.Errorf("IsCA = %t KeyUsage = %v, want a leaf with digitalSignature only", cert.IsCA, cert.KeyUsage)
	}
	if !samePublicKey(cert, key) {
		tb.Error("the certificate does not carry the CSR's public key")
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	for i, pemChain := range r.Chain {
		certs, err := workerca.ParseCertsPEM([]byte(pemChain))
		if err != nil || len(certs) == 0 {
			tb.Errorf("chain[%d] does not parse: %v", i, err)
			continue
		}
		if i == len(r.Chain)-1 {
			roots.AddCert(certs[0])
		} else {
			inters.AddCert(certs[0])
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: s.Clock.Now(),
	}); err != nil {
		tb.Errorf("the certificate does not verify against the chain the CP returned: %v", err)
	}
}

func samePublicKey(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := key.Public().(equaler)
	return ok && pub.Equal(cert.PublicKey)
}

// hostile is the CSR of an attacker: it asks for another worker's identity, a
// subject, DNS, e-mail and IP SANs, and a CA certificate.
func (s *Stack) hostile(tb testing.TB, victim string) (crypto.Signer, string) {
	tb.Helper()
	spiffe, err := workerca.SPIFFEID(TrustDomain, victim)
	if err != nil {
		tb.Fatalf("security: spiffe id: %v", err)
	}
	return s.NewCSR(tb, CSROptions{
		CommonName: victim, DNSNames: []string{"warden.example", "*.example.com"},
		Emails: []string{"admin@example.com"}, IPs: []net.IP{net.ParseIP("10.0.0.1")}, URIs: []*url.URL{spiffe, {Scheme: "https", Host: "evil.example"}},
		CA: true,
	})
}

// enrollFixtures are the tokens the enrollment cases spend, minted before the
// first case so no case's audit window holds the admin's own writes.
type enrollFixtures struct {
	sans, rsa, badCSR, reused, expired, revoked, prefix, rate string
	reusedKey                                                 crypto.Signer
	// bad is the first 401 reply any bad_token case saw: the rest must equal
	// it byte for byte.
	bad *Reply
}

func newEnrollFixtures(tb testing.TB, s *Stack) *enrollFixtures {
	tb.Helper()
	adm := s.AdminSession(tb)
	mk := func(req map[string]any) string { return adm.CreateEnrollmentTokenWith(tb, req) }
	fx := &enrollFixtures{
		sans:    mk(map[string]any{"name": "sec-sans", "workerId": "sec-sans"}),
		rsa:     mk(map[string]any{"name": "sec-rsa", "workerId": "sec-rsa"}),
		badCSR:  mk(map[string]any{"name": "sec-badcsr", "workerId": "sec-badcsr"}),
		reused:  mk(map[string]any{"name": "sec-reused", "workerId": "sec-reused"}),
		expired: mk(map[string]any{"name": "sec-expired", "workerId": "sec-expired", "expiresIn": "1m"}),
		revoked: mk(map[string]any{"name": "sec-revoked", "workerId": "sec-revoked"}),
		prefix:  mk(map[string]any{"name": "sec-prefix", "workerIdPrefix": "pool-", "maxUses": 3}),
		rate:    mk(map[string]any{"name": "sec-rate", "workerId": "sec-rate"}),
	}
	// A used-up token: redeem it once, honestly.
	key, csr := s.NewCSR(tb, CSROptions{})
	s.ParseIssued(tb, s.Enroll(tb, fx.reused, csr, ""), key)
	// A revoked one: through the console API, as an operator does.
	id := s.EnrollRowByName(tb, "sec-revoked").ID
	if r := adm.Do(tb, http.MethodDelete, enrollmentsPath+"/"+id, nil); r.Status != http.StatusNoContent && r.Status != http.StatusOK {
		tb.Fatalf("security: revoke the enrollment token: %d %s", r.Status, r.Body)
	}
	return fx
}

// badToken is the case of a token the CP must refuse with the one 401.
func badToken(fx *enrollFixtures, name, reason string, token func(fx *enrollFixtures) string, prep func(tb testing.TB, s *Stack)) Case {
	return Case{
		Name: name,
		Path: PathEnroll,
		Attack: func(t testing.TB, s *Stack) Observed {
			if prep != nil {
				prep(t, s)
			}
			fresh(s)
			_, csr := s.NewCSR(t, CSROptions{})
			before := s.State(t)
			var r Reply
			expectCount(t, "warden_cp_worker_enroll_total{outcome=bad_token}", func() int64 { return s.Server().EnrollCount(controlplane.EnrollOutcomeBadToken) }, 1, func() {
				r = s.Enroll(t, token(fx), csr, "")
			})
			expectDelta(t, before, s.State(t), State{})
			if fx.bad == nil {
				fx.bad = &r
			} else if r.Status != fx.bad.Status || r.Body != fx.bad.Body || r.Header.Get("Content-Type") != fx.bad.Header.Get("Content-Type") ||
				r.Header.Get("Www-Authenticate") != fx.bad.Header.Get("Www-Authenticate") {
				t.Errorf("the 401 differs between bad tokens: %d %q (%v) vs %d %q (%v)", r.Status, r.Body, r.Header, fx.bad.Status, fx.bad.Body, fx.bad.Header)
			}
			return SeenReply(r)
		},
		WantStatus: http.StatusUnauthorized,
		WantBody:   unauthorizedBody,
		WantLog:    `"reason":"` + reason + `"`,
	}
}

// enrollCases are the attacks on POST /control/enroll.
func enrollCases(fx *enrollFixtures) []Case {
	return []Case{{
		// A CSR that asks for another worker, a CN, extra SANs and CA:true gets
		// the worker id of the token and nothing else of what it asked.
		Name:   "csr_sans_ignored",
		Path:   PathEnroll,
		Covers: []string{CoverRoute("/control/enroll")},
		Attack: func(t testing.TB, s *Stack) Observed {
			fresh(s)
			key, csr := s.hostile(t, "agent-a")
			before, mark := s.State(t), s.AuditMark(t)
			// The suffix is for prefix tokens: an id-bound token ignores it.
			r := s.Enroll(t, fx.sans, csr, "agent-a")
			leaf, body := s.ParseIssued(t, r, key)
			assertIssuedCert(t, s, body, leaf.Cert, "sec-sans", key)
			expectDelta(t, before, s.State(t), State{Certs: 1, TokenUses: 1, Audit: 1})
			s.ExpectAudit(t, mark, "ok", "worker.enrolled")
			if rows := s.CertRows(t, "sec-sans"); len(rows) != 1 || rows[0].Via != "enroll" || rows[0].Revoked {
				t.Errorf("worker_certs rows of sec-sans = %+v, want one live enroll row", rows)
			}
			if rows := s.CertRows(t, "agent-a"); len(rows) != 0 {
				t.Errorf("a certificate row exists for agent-a: %+v", rows)
			}
			return SeenReply(r)
		},
		WantStatus: http.StatusCreated,
		WantLog:    `"msg":"worker enrolled"`,
	}, badToken(fx, "bad_token_reused", "exhausted", func(fx *enrollFixtures) string { return fx.reused }, nil),
		badToken(fx, "bad_token_expired", "expired", func(fx *enrollFixtures) string { return fx.expired },
			func(t testing.TB, s *Stack) { s.Clock.Advance(2 * time.Minute) }),
		badToken(fx, "bad_token_revoked", "revoked", func(fx *enrollFixtures) string { return fx.revoked }, nil),
		badToken(fx, "bad_token_unknown", "unknown_token", func(*enrollFixtures) string {
			return "wet_" + strings.Repeat("a", 52)
		}, nil),
		badToken(fx, "bad_token_malformed", "unknown_token", func(*enrollFixtures) string { return "not-a-token" }, nil),
		{
			// An RSA key is refused before the token is read, so the token
			// stays unspent and a good CSR still redeems it.
			Name:   "rsa_csr",
			Path:   PathEnroll,
			Covers: []string{CoverRoute("/control/enroll")},
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				before := s.State(t)
				var r Reply
				expectCount(t, "warden_cp_worker_enroll_total{outcome=bad_csr}", func() int64 { return s.Server().EnrollCount(controlplane.EnrollOutcomeBadCSR) }, 1, func() {
					r = s.Enroll(t, fx.rsa, s.RSACSR(t), "")
				})
				expectDelta(t, before, s.State(t), State{})
				if row := s.EnrollRowByName(t, "sec-rsa"); row.Uses != 0 || row.Revoked {
					t.Errorf("the token after an RSA CSR: %+v, want unused and not revoked", row)
				}
				return SeenReply(r)
			},
			WantStatus: http.StatusBadRequest,
			WantBody:   `"error":"bad_csr"`,
			WantLog:    `"reason":"bad_csr"`,
		}, {
			// The same token, a minute later, with a good CSR: the refusal above
			// really left it redeemable.
			Name: "rsa_csr_leaves_token_redeemable",
			Path: PathEnroll,
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				key, csr := s.NewCSR(t, CSROptions{})
				mark := s.AuditMark(t)
				r := s.Enroll(t, fx.rsa, csr, "")
				leaf, body := s.ParseIssued(t, r, key)
				assertIssuedCert(t, s, body, leaf.Cert, "sec-rsa", key)
				s.ExpectAudit(t, mark, "ok", "worker.enrolled")
				return SeenReply(r)
			},
			WantStatus: http.StatusCreated,
		}, {
			Name: "malformed_csr_keeps_token",
			Path: PathEnroll,
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				before := s.State(t)
				r := s.Enroll(t, fx.badCSR, "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", "")
				expectDelta(t, before, s.State(t), State{})
				if row := s.EnrollRowByName(t, "sec-badcsr"); row.Uses != 0 {
					t.Errorf("the token after a malformed CSR: %+v, want unused", row)
				}
				return SeenReply(r)
			},
			WantStatus: http.StatusBadRequest,
			WantBody:   `"error":"bad_csr"`,
			WantLog:    `"reason":"bad_csr"`,
		}, {
			// A prefix token cannot be steered out of its prefix, and a refused
			// suffix spends no use.
			Name: "bad_worker_id",
			Path: PathEnroll,
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				_, csr := s.NewCSR(t, CSROptions{})
				before := s.State(t)
				var r Reply
				expectCount(t, "warden_cp_worker_enroll_total{outcome=bad_csr}", func() int64 { return s.Server().EnrollCount(controlplane.EnrollOutcomeBadCSR) }, 1, func() {
					r = s.Enroll(t, fx.prefix, csr, "../worker/agent-a")
				})
				expectDelta(t, before, s.State(t), State{})
				if row := s.EnrollRowByName(t, "sec-prefix"); row.Uses != 0 {
					t.Errorf("the prefix token after a bad suffix: %+v, want unused", row)
				}
				return SeenReply(r)
			},
			WantStatus: http.StatusBadRequest,
			WantBody:   `"error":"bad_worker_id"`,
			WantLog:    `"reason":"bad_worker_id"`,
		}, {
			// A prefix token mints only worker ids under its prefix.
			Name: "prefix_token_stays_in_prefix",
			Path: PathEnroll,
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				key, csr := s.hostile(t, "agent-b")
				r := s.Enroll(t, fx.prefix, csr, "agent-b")
				leaf, body := s.ParseIssued(t, r, key)
				assertIssuedCert(t, s, body, leaf.Cert, "pool-agent-b", key)
				if rows := s.CertRows(t, "agent-b"); len(rows) != 0 {
					t.Errorf("a certificate row exists for agent-b: %+v", rows)
				}
				return SeenReply(r)
			},
			WantStatus: http.StatusCreated,
		}, {
			// The 11th request in a minute from one address is refused before
			// anything is read; the ten before it were answered (400, for want
			// of a CSR), so the limit and not the body decided.
			Name:   "rate_limited_addr",
			Path:   PathEnroll,
			Covers: []string{CoverRoute("/control/enroll")},
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				before := s.State(t)
				var last Reply
				expectCount(t, "warden_cp_worker_enroll_total{outcome=rate_limited}", func() int64 { return s.Server().EnrollCount(controlplane.EnrollOutcomeRateLimited) }, 1, func() {
					for i := 1; i <= 11; i++ {
						last = s.Enroll(t, fx.rate, "", "")
						if want := map[bool]int{true: http.StatusTooManyRequests, false: http.StatusBadRequest}[i == 11]; last.Status != want {
							t.Fatalf("request %d of 11 = %d, want %d", i, last.Status, want)
						}
					}
				})
				expectDelta(t, before, s.State(t), State{})
				if row := s.EnrollRowByName(t, "sec-rate"); row.Uses != 0 {
					t.Errorf("the token after a flood: %+v, want unused", row)
				}
				return SeenReply(last)
			},
			WantStatus: http.StatusTooManyRequests,
			WantBody:   `"error":"rate_limited"`,
			WantHeader: map[string]string{"Retry-After": "*"},
			WantLog:    `"reason":"rate_limited_addr"`,
		},
	}
}

// TestEnroll attacks POST /control/enroll.
func TestEnroll(t *testing.T) {
	s := StartStack(t, StackOptions{})
	s.PositiveControl(t, "enroll", func(t *testing.T) {
		// An honest enrollment: a token for one worker, a P-256 CSR, a 201 with
		// the certificate of that worker, accepted by the CP on /policy.
		leaf := s.NewLeaf(t, "sec-control")
		if leaf.ID != "sec-control" {
			t.Fatalf("enrolled worker id = %q, want sec-control", leaf.ID)
		}
		cert := leaf.TLS()
		if r := s.Send(t, s.CPClient(t, &cert), http.MethodGet, "/policy", http.Header{"Accept": {controlplane.BundleMediaType}}, nil); r.Status != http.StatusOK {
			t.Fatalf("GET /policy with the enrolled certificate = %d, want 200", r.Status)
		}
	})
	Run(t, s, "enroll", enrollCases(newEnrollFixtures(t, s)))
}

// renewFixtures are the certificates the renewal cases present.
type renewFixtures struct {
	ok, sans, revoked, same, rsa Leaf
}

// renewOnce renews l with a fresh key and requires the 201.
func renewOnce(tb testing.TB, s *Stack, l Leaf) Leaf {
	tb.Helper()
	key, csr := s.NewCSR(tb, CSROptions{})
	next, _ := s.ParseIssued(tb, s.Renew(tb, l, csr), key)
	return next
}

func newRenewFixtures(tb testing.TB, s *Stack) *renewFixtures {
	tb.Helper()
	fx := &renewFixtures{
		ok: s.NewLeaf(tb, "sec-ren-ok"), sans: s.NewLeaf(tb, "sec-ren-sans"), revoked: s.NewLeaf(tb, "sec-ren-rev"),
		same: s.NewLeaf(tb, "sec-ren-same"), rsa: s.NewLeaf(tb, "sec-ren-rsa"),
	}
	// An operator revokes a worker through the console API.
	if r := s.AdminSession(tb).Do(tb, http.MethodPost, "/dashboard/api/workers/sec-ren-rev/revoke", map[string]any{}); r.Status != http.StatusOK {
		tb.Fatalf("security: revoke worker sec-ren-rev: %d %s", r.Status, r.Body)
	}
	return fx
}

// refusedRenew is a renewal the CP must refuse without issuing or revoking
// anything more than want.
func refusedRenew(fx *renewFixtures, name string, covers bool, leaf func(*renewFixtures) Leaf, csr func(tb testing.TB, s *Stack, l Leaf) string, wantState State, outcome string, c Case) Case {
	c.Name, c.Path = name, PathEnroll
	if covers {
		c.Covers = []string{CoverRoute("/control/renew")}
	}
	c.Attack = func(t testing.TB, s *Stack) Observed {
		l := leaf(fx)
		fresh(s)
		body := csr(t, s, l)
		before := s.State(t)
		var r Reply
		expectCount(t, "warden_cp_worker_renew_total{outcome="+outcome+"}", func() int64 { return s.Server().RenewCount(outcome) }, 1, func() {
			r = s.Renew(t, l, body)
		})
		expectDelta(t, before, s.State(t), wantState)
		return SeenReply(r)
	}
	return c
}

func freshKeyCSR(tb testing.TB, s *Stack, _ Leaf) string {
	_, csr := s.NewCSR(tb, CSROptions{})
	return csr
}

// renewCases are the attacks on POST /control/renew.
func renewCases(fx *renewFixtures) []Case {
	return []Case{{
		// A renewal keeps the worker id whatever the CSR asks for.
		Name:   "worker_id_preserved",
		Path:   PathEnroll,
		Covers: []string{CoverRoute("/control/renew")},
		Attack: func(t testing.TB, s *Stack) Observed {
			fresh(s)
			key, csr := s.hostile(t, "agent-b")
			before := s.State(t)
			r := s.Renew(t, fx.sans, csr)
			next, body := s.ParseIssued(t, r, key)
			assertIssuedCert(t, s, body, next.Cert, "sec-ren-sans", key)
			if body.PrevSerial != fx.sans.Serial() || next.Serial() == fx.sans.Serial() {
				t.Errorf("renewal lineage: prevSerial %q serial %q, want prev %q and a new serial", body.PrevSerial, next.Serial(), fx.sans.Serial())
			}
			// Renewals are logged and counted, not admin-audited.
			expectDelta(t, before, s.State(t), State{Certs: 1})
			if rows := s.CertRows(t, "agent-b"); len(rows) != 0 {
				t.Errorf("a certificate row exists for agent-b: %+v", rows)
			}
			return SeenReply(r)
		},
		WantStatus: http.StatusCreated,
		WantLog:    `"msg":"worker certificate renewed"`,
	},
		refusedRenew(fx, "revoked", true, func(fx *renewFixtures) Leaf { return fx.revoked }, freshKeyCSR,
			State{}, controlplane.RenewOutcomeUnauthorized, Case{
				WantStatus: http.StatusUnauthorized,
				WantBody:   unauthorizedBody,
				WantHeader: map[string]string{"Www-Authenticate": "Bearer"},
				WantLog:    `"reason":"revoked"`,
			}),
		refusedRenew(fx, "same_spki", true, func(fx *renewFixtures) Leaf { return fx.same },
			func(tb testing.TB, s *Stack, l Leaf) string {
				_, csr := s.NewCSR(tb, CSROptions{Key: l.Key})
				return csr
			}, State{}, controlplane.RenewOutcomeBadCSR, Case{
				WantStatus: http.StatusBadRequest,
				WantBody:   `"error":"same_key"`,
				WantLog:    `"reason":"same_key"`,
			}),
		refusedRenew(fx, "rsa_csr", false, func(fx *renewFixtures) Leaf { return fx.rsa },
			func(tb testing.TB, s *Stack, _ Leaf) string { return s.RSACSR(tb) },
			State{}, controlplane.RenewOutcomeBadCSR, Case{
				WantStatus: http.StatusBadRequest,
				WantBody:   `"error":"bad_csr"`,
				WantLog:    `"reason":"bad_csr"`,
			}),
		{
			// Two holders of one key: the presented certificate is no longer
			// the lineage head and the 10 minute grace has passed, so the CP
			// revokes the whole worker and records the conflict. The worker is
			// made inside the case, so the grace is measured from its renewal.
			Name:   "lineage_conflict",
			Path:   PathEnroll,
			Covers: []string{CoverRoute("/control/renew")},
			Attack: func(t testing.TB, s *Stack) Observed {
				old := s.NewLeaf(t, "sec-ren-lin")
				head := renewOnce(t, s, old)
				s.Clock.Advance(11 * time.Minute)
				fresh(s)
				_, csr := s.NewCSR(t, CSROptions{})
				before, mark, issued := s.State(t), s.AuditMark(t), len(s.CertRows(t, "sec-ren-lin"))
				var r Reply
				expectCount(t, "warden_cp_worker_renew_total{outcome=lineage_conflict}", func() int64 { return s.Server().RenewCount(controlplane.RenewOutcomeLineageConflict) }, 1, func() {
					r = s.Renew(t, old, csr)
				})
				// Nothing issued; both certificates of the worker revoked.
				expectDelta(t, before, s.State(t), State{RevokedCerts: 2, Audit: 1})
				rows := s.CertRows(t, "sec-ren-lin")
				if len(rows) != issued {
					t.Errorf("worker_certs rows of sec-ren-lin = %d, want %d (no certificate issued)", len(rows), issued)
				}
				for _, row := range rows {
					if !row.Revoked {
						t.Errorf("certificate %s of the conflicting worker is still live", row.Serial)
					}
				}
				// The successor the worker legitimately holds is dead too.
				cert := head.TLS()
				if got := s.Send(t, s.CPClient(t, &cert), http.MethodGet, "/policy", http.Header{"Accept": {controlplane.BundleMediaType}}, nil); got.Status != http.StatusUnauthorized {
					t.Errorf("GET /policy with the revoked worker's successor certificate = %d, want 401", got.Status)
				}
				audit := s.ExpectAudit(t, mark, "denied", "worker.cert_lineage_conflict")
				if len(audit) == 1 && (audit[0].TargetRef != "worker:sec-ren-lin" || audit[0].HTTPStatus != http.StatusUnauthorized) {
					t.Errorf("lineage conflict audit row = %+v, want target worker:sec-ren-lin and status 401", audit[0])
				}
				return SeenReply(r)
			},
			WantStatus: http.StatusUnauthorized,
			WantBody:   unauthorizedBody,
			WantHeader: map[string]string{"Www-Authenticate": "Bearer"},
			WantLog:    `"reason":"lineage_conflict"`,
		}, {
			// The control of the case above: the same renewal from the
			// predecessor inside the window is a lost-response retry and is
			// served, and the unused successor is revoked as superseded.
			Name: "lineage_inside_window",
			Path: PathEnroll,
			Attack: func(t testing.TB, s *Stack) Observed {
				old := s.NewLeaf(t, "sec-ren-grace")
				head := renewOnce(t, s, old)
				fresh(s)
				key, csr := s.NewCSR(t, CSROptions{})
				mark := s.AuditMark(t)
				r := s.Renew(t, old, csr)
				next, body := s.ParseIssued(t, r, key)
				assertIssuedCert(t, s, body, next.Cert, "sec-ren-grace", key)
				s.ExpectAudit(t, mark, "")
				var superseded bool
				for _, row := range s.CertRows(t, "sec-ren-grace") {
					if row.Serial == head.Serial() {
						superseded = row.Revoked && row.RevokeReason == "superseded"
					}
				}
				if !superseded {
					t.Error("the unused successor was not revoked as superseded")
				}
				return SeenReply(r)
			},
			WantStatus: http.StatusCreated,
			WantLog:    `"msg":"worker certificate renewed"`,
		}, {
			// No certificate: no bearer, token or anonymous caller renews.
			Name:   "no_certificate",
			Path:   PathEnroll,
			Covers: []string{CoverRoute("/control/renew")},
			Attack: func(t testing.TB, s *Stack) Observed {
				fresh(s)
				_, csr := s.NewCSR(t, CSROptions{})
				before := s.State(t)
				r := s.postJSON(t, s.CPClient(t, nil), renewRoute, map[string]string{"csr": csr})
				expectDelta(t, before, s.State(t), State{})
				return SeenReply(r)
			},
			WantStatus: http.StatusUnauthorized,
			WantBody:   unauthorizedBody,
			WantLog:    `"reason":"cert_required"`,
		},
	}
}

// TestRenew attacks POST /control/renew.
func TestRenew(t *testing.T) {
	s := StartStack(t, StackOptions{})
	fx := newRenewFixtures(t, s)
	s.PositiveControl(t, "renew", func(t *testing.T) {
		// An honest renewal: the certificate of a worker, a fresh key, a 201 for
		// the same worker whose new certificate the CP then accepts.
		key, csr := s.NewCSR(t, CSROptions{})
		next, body := s.ParseIssued(t, s.Renew(t, fx.ok, csr), key)
		assertIssuedCert(t, s, body, next.Cert, "sec-ren-ok", key)
		cert := next.TLS()
		if r := s.Send(t, s.CPClient(t, &cert), http.MethodGet, "/policy", http.Header{"Accept": {controlplane.BundleMediaType}}, nil); r.Status != http.StatusOK {
			t.Fatalf("GET /policy with the renewed certificate = %d, want 200", r.Status)
		}
	})
	Run(t, s, "renew", renewCases(fx))
}
