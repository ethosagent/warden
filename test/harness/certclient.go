package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/workerca/adapters/cpclient"
)

// The worker-side certificate client (W-P2-WCA-03), pointed at the harness
// control plane: the real cpclient Enroller and Renewer on the harness clock,
// and a client whose TLS handshake presents the certificate in the Source, the
// way the worker's shared control-plane client does.

// CertClient is a worker's enrolled certificate and the client that presents it.
type CertClient struct {
	h *H
	// Source holds the certificate in use.
	Source *cpclient.Source
	// HTTP presents Source's certificate (an empty one once it has expired).
	HTTP      *http.Client
	transport *http.Transport
	stateDir  string
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	outcomes  []string
	mu        sync.Mutex
}

func (c *CPClient) enrollEndpoints() (enroll, renew string) {
	return "https://" + c.addr + "/control/enroll", "https://" + c.addr + "/control/renew"
}

func (h *H) newEnroller(stateDir, token, suffix string) *cpclient.Enroller {
	enroll, _ := h.CP().enrollEndpoints()
	plain := &http.Client{Transport: h.CP().cl.Transport.(*http.Transport).Clone(), Timeout: 30 * time.Second}
	h.tb.Cleanup(plain.CloseIdleConnections)
	return &cpclient.Enroller{Endpoint: enroll, HTTP: plain, StateDir: stateDir, Token: token, Suffix: suffix, Now: h.fake.Now}
}

// TryEnrollCertClient runs the Enroller once: it loads the certificate persisted
// in stateDir or trades token for a new one. It returns the error as is, for a
// scenario that expects a refusal.
func (h *H) TryEnrollCertClient(stateDir, token, suffix string) (*CertClient, error) {
	h.tb.Helper()
	cred, err := h.newEnroller(stateDir, token, suffix).LoadOrEnroll(context.Background())
	if err != nil {
		return nil, err
	}
	return h.certClient(stateDir, cred), nil
}

// EnrollCertClient is TryEnrollCertClient for a token minted offline: the
// control plane loads it on its 2 s data_version poll (on the harness clock), so
// each refused try advances the clock until it is accepted.
func (h *H) EnrollCertClient(stateDir, token, suffix string) *CertClient {
	h.tb.Helper()
	var out *CertClient
	h.Eventually("the control plane to load the enrollment token for the worker client", func() bool {
		cc, err := h.TryEnrollCertClient(stateDir, token, suffix)
		if err == nil {
			out = cc
			return true
		}
		if !cpclient.IsPermanent(err) {
			h.tb.Fatalf("harness: worker client enrollment: %v", err)
		}
		h.fake.Advance(6 * time.Second)
		return false
	})
	return out
}

func (h *H) certClient(stateDir string, cred *cpclient.Credential) *CertClient {
	cc := &CertClient{h: h, Source: cpclient.NewSource(cred), stateDir: stateDir}
	tr := h.CP().cl.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c := cc.Source.Current()
		if c == nil || c.Expired(h.fake.Now()) {
			return &tls.Certificate{}, nil
		}
		return &tls.Certificate{Certificate: c.DER(), PrivateKey: c.Key, Leaf: c.Leaf}, nil
	}
	cc.transport = tr
	cc.HTTP = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	h.tb.Cleanup(func() { cc.Stop(); tr.CloseIdleConnections() })
	return cc
}

// StartRenewer runs the real Renewer on the harness clock with no jitter, until
// Stop (or the end of the test). Each attempt's outcome is kept for Outcomes.
func (cc *CertClient) StartRenewer() {
	cc.h.tb.Helper()
	_, renew := cc.h.CP().enrollEndpoints()
	ctx, cancel := context.WithCancel(context.Background())
	cc.cancel = cancel
	r := &cpclient.Renewer{
		Endpoint: renew, HTTP: cc.HTTP, Source: cc.Source, StateDir: cc.stateDir, Clock: cc.h.fake,
		Jitter: func() float64 { return 0 }, CloseIdle: cc.transport.CloseIdleConnections,
		OnRenew: func(o string) {
			cc.mu.Lock()
			cc.outcomes = append(cc.outcomes, o)
			cc.mu.Unlock()
		},
	}
	cc.wg.Add(1)
	go func() { defer cc.wg.Done(); r.Run(ctx) }()
}

// Stop ends the renewer started by StartRenewer and waits for it.
func (cc *CertClient) Stop() {
	if cc.cancel != nil {
		cc.cancel()
		cc.wg.Wait()
		cc.cancel = nil
	}
}

// Outcomes are the renewal outcomes seen so far, oldest first.
func (cc *CertClient) Outcomes() []string {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return append([]string(nil), cc.outcomes...)
}

// Do sends one request with the certificate and NO Authorization header and
// returns the status.
func (cc *CertClient) Do(method, path, body string) int {
	cc.h.tb.Helper()
	req, err := http.NewRequest(method, "https://"+cc.h.CP().addr+path, bytes.NewReader([]byte(body)))
	if err != nil {
		cc.h.tb.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cc.HTTP.Do(req)
	if err != nil {
		cc.h.tb.Fatalf("harness: %s %s with the worker client certificate: %v", method, path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// EnrollCount and RenewCount are the in-process control plane's counters of
// /control/enroll and /control/renew outcomes.
func (c *CPClient) EnrollCount(outcome string) int64 {
	c.h.tb.Helper()
	s := c.h.cpSrv.Load()
	if s == nil {
		c.h.tb.Fatal("harness: EnrollCount needs the in-process control plane")
	}
	return s.EnrollCount(outcome)
}

// RenewCount: see EnrollCount.
func (c *CPClient) RenewCount(outcome string) int64 {
	c.h.tb.Helper()
	s := c.h.cpSrv.Load()
	if s == nil {
		c.h.tb.Fatal("harness: RenewCount needs the in-process control plane")
	}
	return s.RenewCount(outcome)
}
