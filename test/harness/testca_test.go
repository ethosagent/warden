package harness

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/fakes"
)

func TestTestCALeaves(t *testing.T) {
	ca := NewTestCA(t, "root")
	other := NewTestCA(t, "other")
	now := time.Now()

	good := ca.Leaf(LeafSpec{URIs: []string{SPIFFEURI("example.test", "w1")}})
	foreign := other.Leaf(LeafSpec{URIs: []string{SPIFFEURI("example.test", "w1")}})
	expired := ca.Leaf(LeafSpec{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
	wrongEKU := ca.Leaf(LeafSpec{EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	multi := ca.Leaf(LeafSpec{URIs: []string{SPIFFEURI("example.test", "w1"), SPIFFEURI("example.test", "w2")}})

	verify := func(l Leaf, eku x509.ExtKeyUsage) error {
		_, err := l.Cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{eku}})
		return err
	}
	if err := verify(good, x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("good leaf: %v", err)
	}
	if got := good.Cert.URIs[0].String(); got != "spiffe://example.test/warden/worker/w1" {
		t.Errorf("SPIFFE SAN = %s", got)
	}
	for name, l := range map[string]Leaf{"foreign CA": foreign, "expired": expired} {
		if verify(l, x509.ExtKeyUsageClientAuth) == nil {
			t.Errorf("%s leaf verified under the root", name)
		}
	}
	if verify(wrongEKU, x509.ExtKeyUsageClientAuth) == nil {
		t.Error("a server-auth-only leaf verified as a client certificate")
	}
	if len(multi.Cert.URIs) != 2 {
		t.Errorf("multi-SAN leaf has %d URI SANs, want 2", len(multi.Cert.URIs))
	}
	if good.Serial() == "" || good.TLS().PrivateKey == nil {
		t.Error("Leaf.Serial/TLS are empty")
	}
	reuse := ca.Leaf(LeafSpec{PublicKey: &good.Key.PublicKey})
	if reuse.Key != nil || !reuse.Cert.PublicKey.(*ecdsa.PublicKey).Equal(&good.Key.PublicKey) {
		t.Error("PublicKey spec must certify the supplied key and return no key")
	}
	cert, key := ca.WriteFiles(t.TempDir(), "ca")
	if cert == "" || key == "" || len(ca.KeyPEM()) == 0 {
		t.Error("WriteFiles/KeyPEM returned nothing")
	}
}

func TestUpstreamCountsAndRecords(t *testing.T) {
	ca := NewTestCA(t, "root")
	up := fakes.NewUpstream(t, ca.ServerCert("api.example.test"))
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "api.example.test", MinVersion: tls.VersionTLS12}}}
	t.Cleanup(cl.CloseIdleConnections)

	if up.Hits() != 0 {
		t.Fatalf("hits before any request = %d", up.Hits())
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+up.Addr()+"/v1/x?q=1", strings.NewReader(`{"jsonrpc":"2.0","id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer swapped")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "jsonrpc") {
		t.Errorf("default reply = %d %s, want 200 with a JSON-RPC result", resp.StatusCode, body)
	}
	got := up.Requests()
	if up.Hits() != 1 || len(got) != 1 || got[0].Path != "/v1/x?q=1" || got[0].Header.Get("Authorization") != "Bearer swapped" ||
		!strings.Contains(string(got[0].Body), "jsonrpc") {
		t.Errorf("recorded = %+v hits %d", got, up.Hits())
	}
	up.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	resp, err = cl.Get("https://" + up.Addr() + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || up.Hits() != 2 {
		t.Errorf("custom handler = %d hits %d", resp.StatusCode, up.Hits())
	}
}
