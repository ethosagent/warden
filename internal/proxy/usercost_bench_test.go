package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// benchCostProxy starts a TLS-terminating proxy that allows api.openai.com
// with the cost estimator and the per-user cost ledger wired, as the worker
// wires them, and the given per-user limits.
func benchCostProxy(b *testing.B, pol config.Policy) (*Proxy, []byte) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(b)
	backendLn, _ := startBackend(b, caCert, caKey)
	pol.Allowlist = []config.AllowlistEntry{{Domain: costHost, Port: 443}}
	dir := b.TempDir()
	certFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0o600); err != nil {
		b.Fatal(err)
	}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(pol),
		Secrets:    &fakes.FakeSecretProvider{},
		Analytics:  &syncStore{},
		CACertPath: certFile,
		CAKeyPath:  keyFile,
		AgentID:    "agent",
		Cost:       cost.NewEstimator(),
		UserCost:   cost.NewLedger(nil),
	})
	if err != nil {
		b.Fatal(err)
	}
	p.dialTLS = func(string, string, *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 100 && p.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		b.Fatal("proxy did not start")
	}
	return p, caCertPEM
}

func benchCostLoop(b *testing.B, p *Proxy, caCertPEM []byte) {
	tlsClient := dialProxyAndConnect(b, p.Addr().String(), costHost, caCertPEM)
	br := bufio.NewReader(tlsClient)
	req, err := http.NewRequest(http.MethodGet, "https://"+costHost+"/v1/chat", nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := req.Write(tlsClient); err != nil {
			b.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			b.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status = %d", resp.StatusCode)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Fatalf("drain body: %v", err)
		}
		_ = resp.Body.Close()
	}
}

// BenchmarkHandleHTTPUserCostOff is a tracked destination with the ledger
// wired and no limits configured (the production default): the cost check is
// the estimator's domain lookup and one evaluator read lock.
func BenchmarkHandleHTTPUserCostOff(b *testing.B) {
	p, ca := benchCostProxy(b, config.Policy{})
	benchCostLoop(b, p, ca)
}

// BenchmarkHandleHTTPUserCostOn charges every request to an anonymous rule
// with a cap high enough never to refuse: two rule matches, a ledger read
// before the request and a ledger add after it.
func BenchmarkHandleHTTPUserCostOn(b *testing.B) {
	p, ca := benchCostProxy(b, config.Policy{AnonymousLimit: &config.UserLimit{DailyCostUSD: config.MaxUserLimitDailyCostUSD}})
	benchCostLoop(b, p, ca)
}
