package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/harness"
)

// Worker certificate attacks (W-P2-SECT-04). The control plane runs with
// --require-worker-certs: only a valid, unrevoked certificate of the worker CA
// reaches /policy, /control/heartbeat and /central/ingest. Every case attacks
// all three routes and the control plane's rate-limited rejection log names
// the reason.

// workerRoutes are the worker plane routes a certificate opens.
var workerRoutes = []struct {
	method, path, body string
	ok                 int
	hdr                http.Header
}{
	{http.MethodGet, "/policy", "", http.StatusOK, http.Header{"Accept": {controlplane.BundleMediaType}}},
	{http.MethodPost, "/control/heartbeat", `{"policyETag":"x"}`, http.StatusNoContent, nil},
	{http.MethodPost, "/central/ingest", `{"events":[{"type":"allow","host":"api.example.com"}]}`, http.StatusNoContent, nil},
}

var workerRouteCovers = []string{CoverRoute("/policy"), CoverRoute("/control/heartbeat"), CoverRoute("/central/ingest")}

// hitRoutes sends every worker route through cl with extra headers and returns
// the replies, failing the test when one is not want (want < 0: the route's own
// success status).
func hitRoutes(t testing.TB, s *Stack, cl *http.Client, extra http.Header, want int) Observed {
	t.Helper()
	var obs Observed
	for i, rt := range workerRoutes {
		hdr := http.Header{}
		for k, v := range rt.hdr {
			hdr[k] = v
		}
		for k, v := range extra {
			hdr[k] = v
		}
		r := s.Send(t, cl, rt.method, rt.path, hdr, []byte(rt.body))
		wantStatus := want
		if want < 0 {
			wantStatus = rt.ok
		}
		if r.Status != wantStatus {
			t.Errorf("%s %s = %d, want %d", rt.method, rt.path, r.Status, wantStatus)
		}
		if i == 0 {
			obs.Status, obs.Header, obs.Body = r.Status, r.Header, r.Body
		}
		obs.Replies = append(obs.Replies, r)
	}
	return obs
}

// pastRejectWindow moves the shared clock beyond the control plane's one
// rejection log line per reason and host per minute, so the next rejection of a
// reason logs again.
func (s *Stack) pastRejectWindow() { s.Clock.Advance(61 * time.Second) }

// certCase is a case that presents a hostile credential to all three routes.
func certCase(name, wantLog string, status int, creds func(t testing.TB, s *Stack) (cert *tls.Certificate, hdr http.Header)) Case {
	return Case{
		Name:   name,
		Path:   PathCPRoute,
		Covers: workerRouteCovers,
		Attack: func(t testing.TB, s *Stack) Observed {
			s.pastRejectWindow()
			cert, hdr := creds(t, s)
			return hitRoutes(t, s, s.CPClient(t, cert), hdr, status)
		},
		WantStatus: status,
		WantLog:    wantLog,
	}
}

// workerLeaf mints a leaf signed by the stack's worker CA intermediate.
func (s *Stack) workerLeaf(t testing.TB, spec harness.WorkerLeafSpec) *tls.Certificate {
	t.Helper()
	if spec.TrustDomain == "" {
		spec.TrustDomain = TrustDomain
	}
	if spec.WorkerID == "" {
		spec.WorkerID = "worker-a"
	}
	leaf := harness.MintWorkerLeaf(t, s.wcaInter, s.wcaKey, spec)
	c := leaf.TLS()
	return &c
}

// certCases are the certificate attacks of the table.
func certCases() []Case {
	return []Case{
		certCase("no cert", "worker_cert_required", http.StatusUnauthorized,
			func(testing.TB, *Stack) (*tls.Certificate, http.Header) { return nil, nil }),
		certCase("foreign ca", "bad_chain", http.StatusUnauthorized,
			func(t testing.TB, s *Stack) (*tls.Certificate, http.Header) {
				ca := harness.NewTestCA(t, "foreign-worker-ca")
				s.Track("key PEM", string(ca.KeyPEM()))
				now := s.Clock.Now()
				leaf := ca.Leaf(harness.LeafSpec{
					CommonName: "worker-a", URIs: []string{harness.SPIFFEURI(TrustDomain, "worker-a")},
					NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				})
				c := leaf.TLS()
				return &c, nil
			}),
		certCase("expired", "expired", http.StatusUnauthorized,
			func(t testing.TB, s *Stack) (*tls.Certificate, http.Header) {
				now := s.Clock.Now()
				// Minted with a past NotAfter: no clock waits.
				return s.workerLeaf(t, harness.WorkerLeafSpec{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Minute)}), nil
			}),
		certCase("bad eku", "bad_eku", http.StatusUnauthorized,
			func(t testing.TB, s *Stack) (*tls.Certificate, http.Header) {
				now := s.Clock.Now()
				return s.workerLeaf(t, harness.WorkerLeafSpec{
					NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
					EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}), nil
			}),
		certCase("multi san", "bad_san", http.StatusUnauthorized,
			func(t testing.TB, s *Stack) (*tls.Certificate, http.Header) {
				now := s.Clock.Now()
				return s.workerLeaf(t, harness.WorkerLeafSpec{
					NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
					URIs: []string{harness.SPIFFEURI(TrustDomain, "worker-a"), harness.SPIFFEURI(TrustDomain, "worker-b")},
				}), nil
			}),
		certCase("worker token", "worker_cert_required", http.StatusUnauthorized,
			func(t testing.TB, s *Stack) (*tls.Certificate, http.Header) {
				tok := s.MintWorkerToken(t, "worker-a")
				return nil, http.Header{"Authorization": {"Bearer " + tok}}
			}),
		certCase("cert of another worker", "proxy_id_mismatch", http.StatusForbidden,
			func(t testing.TB, s *Stack) (*tls.Certificate, http.Header) {
				// worker-b's genuine certificate, speaking as worker-a.
				c := s.Credential(t, s.Worker("agent-b"))
				return &c, http.Header{"X-Warden-Proxy-Id": {"worker-a"}}
			}),
	}
}

// MintWorkerToken creates a wwt_ worker token through the admin API, the
// credential strict-certs mode must refuse.
func (s *Stack) MintWorkerToken(t testing.TB, proxyID string) string {
	t.Helper()
	r := s.AdminSession(t).Do(t, http.MethodPost, "/dashboard/api/worker-tokens", map[string]any{"name": "sec-token", "proxyID": proxyID})
	var out struct {
		Token string `json:"token"`
	}
	if r.Status != http.StatusCreated || !decodeJSON(r.Body, &out) || !strings.HasPrefix(out.Token, "wwt_") {
		t.Fatalf("security: POST /dashboard/api/worker-tokens = %d (no wwt_ token)", r.Status)
	}
	s.Track("worker token", out.Token)
	return out.Token
}

// TestWorkerCert is the certificate table: a valid certificate opens the three
// worker routes, and every forged, expired, wrong-purpose, ambiguous,
// foreign-worker, token and (last) revoked credential is refused with the
// pinned status and a rate-limited CP log line naming the reason.
func TestWorkerCert(t *testing.T) {
	s := StartStack(t, StackOptions{CPEndpoint: tamperAgentA})
	for _, id := range []string{"agent-a", "agent-b"} {
		agentSetup(t, s, id)
	}
	s.PositiveControl(t, "cp-route", func(t *testing.T) {
		cert := s.Credential(t, s.Worker("agent-a"))
		hitRoutes(t, s, s.CPClient(t, &cert), nil, -1)
	})
	Run(t, s, "cp-route", certCases())
	Run(t, s, "cp-route", []Case{serverCertCase})
	Run(t, s, "cp-route", []Case{revokedCase})
}

// revokedCase revokes worker-b through the console and proves the revocation
// cuts a held long-poll, the next request on the same connection, a heartbeat
// and the fleet view, leaves one worker.revoked audit row, and that the worker
// keeps enforcing its last-known-good policy.
var revokedCase = Case{
	Name:   "revoked",
	Path:   PathCPRoute,
	Covers: workerRouteCovers,
	Attack: func(t testing.TB, s *Stack) Observed {
		w := s.Worker("agent-b")
		cert := s.Credential(t, w)
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("security: parse %s certificate: %v", w.Name, err)
		}
		serial := leaf.SerialNumber.Text(16)
		cl := s.CPClient(t, &cert)
		first := s.Send(t, cl, http.MethodGet, "/policy", http.Header{"Accept": {controlplane.BundleMediaType}}, nil)
		etag := first.Header.Get("ETag")
		if first.Status != http.StatusOK || etag == "" {
			t.Fatalf("security: GET /policy before the revoke = %d (ETag %q)", first.Status, etag)
		}
		parked := s.Server().ParkedWorkerPolls(serial)
		type result struct {
			status int
			err    error
		}
		held := make(chan result, 1)
		go func() {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.CP.URL+"/policy?wait=30s", nil)
			if err != nil {
				held <- result{err: err}
				return
			}
			req.Header.Set("Accept", controlplane.BundleMediaType)
			req.Header.Set("If-None-Match", etag)
			resp, err := cl.Do(req)
			if err != nil {
				held <- result{err: err}
				return
			}
			_ = resp.Body.Close()
			held <- result{status: resp.StatusCode}
		}()
		s.Eventually("the direct long-poll to park at the control plane", func() bool {
			return s.Server().ParkedWorkerPolls(serial) > parked
		})

		start := time.Now()
		if r := s.AdminSession(t).Do(t, http.MethodPost, "/dashboard/api/workers/"+w.Name+"/revoke", nil); r.Status != http.StatusOK {
			t.Fatalf("security: revoke %s = %d %s", w.Name, r.Status, r.Body)
		}
		select {
		case got := <-held:
			if got.err != nil || got.status != http.StatusUnauthorized {
				t.Errorf("held /policy long-poll after the revoke = %d, %v; want 401", got.status, got.err)
			}
			// The ticket says within 1s; the bound is loose enough for a loaded
			// -race machine, and the poll is cut by the revoke, not by a timer.
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("the held long-poll took %s to end after the revoke, want about immediately", d.Round(time.Millisecond))
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("security: the held long-poll was not cut within 10s of the revoke")
		}
		// The next requests on the same keep-alive client are refused.
		obs := hitRoutes(t, s, cl, nil, http.StatusUnauthorized)
		s.EventuallyAdvance("the fleet view to show "+w.Name+" revoked", time.Second, func() bool {
			v, ok := s.FleetWorker(t, w)
			return ok && v.CertRevoked
		})

		// The worker keeps enforcing its last-known-good policy.
		tok := s.FreshToken(t, "agent-b")
		if got := s.ConnectStatus(t, w, UpstreamHost, tok); got != http.StatusOK {
			t.Errorf("a host the last-known-good policy allows = %d after the revoke, want 200", got)
		}
		if got := s.ConnectStatus(t, w, EvilHost, tok); got == http.StatusOK {
			t.Errorf("a host no policy allows = %d after the revoke, want a denial", got)
		}
		return obs
	},
	WantStatus: http.StatusUnauthorized,
	WantAudit:  "worker.revoked",
}

// tamperAgentA puts a TamperProxy between agent-a's worker and the CP.
func tamperAgentA(s *Stack, w *Worker) string {
	if w.AgentID != "agent-a" {
		return ""
	}
	return NewTamperProxy(s, w).Addr
}

// serverCertCase has the "control plane" present a certificate no CA the worker
// trusts signed (a stub CP minted by a foreign TestCA), while it offers a
// validly signed bundle that would be applied if the worker did not check the
// server certificate. The worker must refuse the connection and keep its
// last-known-good policy.
var serverCertCase = Case{
	Name:   "cp server cert outside caCert",
	Path:   PathCPRoute,
	Covers: workerRouteCovers,
	Attack: func(t testing.TB, s *Stack) Observed {
		w := s.Worker("agent-a")
		tp := w.Tamper
		seq := s.WorkerSeq(t, w)
		base := s.DecodeBundle(t, tp.Latest())
		hostile := base
		hostile.Seq = base.Seq + 1000
		hostile.Policy = PolicyAllowing(t, base.Policy, EvilHost, nil)
		stub := harness.NewTestCA(t, "stub-cp-ca")
		s.Track("key PEM", string(stub.KeyPEM()))
		failures := tp.HandshakeFailures()
		tp.UseServerCert(stub.ServerCert("127.0.0.1"))
		tp.Replace(Plan{Body: Sign(t, hostile, nil, s.BundleSigner(t))})
		s.EventuallyAdvance("the worker to refuse the stub control plane's certificate", time.Second, func() bool {
			return tp.HandshakeFailures() > failures
		})
		if tp.Served() != 0 {
			t.Errorf("the stub control plane delivered %d bundles to a worker that must not trust it", tp.Served())
		}
		tp.RestoreServerCert()
		tp.Disarm()
		// Back on the real control plane the worker still holds its policy.
		if got := s.WorkerSeq(t, w); got != seq {
			t.Errorf("warden_bundle_seq = %v after the refused connection, want %v", got, seq)
		}
		tok := s.FreshToken(t, "agent-a")
		if got := s.ConnectStatus(t, w, EvilHost, tok); got == http.StatusOK {
			t.Errorf("a host only the stub control plane's bundle allows = %d, want a denial", got)
		}
		return Observed{Status: s.ConnectStatus(t, w, UpstreamHost, tok)}
	},
	WantStatus: http.StatusOK,
}
