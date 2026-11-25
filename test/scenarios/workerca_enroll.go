package scenarios

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/workerca"
	"github.com/ethosagent/warden/test/harness"
)

// Worker enrollment (W-P2-WCA-02). A worker trades a one-time wet_ token and a
// CSR for a worker certificate at POST /control/enroll, with no other
// credential. The scenario drives it the way operators and workers do: the token
// is minted by the offline enroll-token opener on the running control plane's
// state dir, and the request goes over the control plane's TLS listener.

func workerCAEnrollOpts() []harness.Option {
	return []harness.Option{harness.WithWorkerCA(), harness.WithAdminAudit()}
}

func scenarioCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type enrollReply struct {
	WorkerID    string   `json:"workerId"`
	SpiffeID    string   `json:"spiffeId"`
	Certificate string   `json:"certificate"`
	Chain       []string `json:"chain"`
	Serial      string   `json:"serial"`
	NotAfter    string   `json:"notAfter"`
}

// enrollOK enrolls and requires a 201.
func enrollOK(t *testing.T, h *harness.H, token, suffix string) enrollReply {
	t.Helper()
	status, body := h.CP().Enroll(token, scenarioCSR(t), suffix)
	if status != http.StatusCreated {
		t.Fatalf("POST /control/enroll = %d %s, want 201", status, body)
	}
	var out enrollReply
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode the enroll response: %v", err)
	}
	return out
}

// enrollUntilLoaded posts until the control plane has loaded a token minted
// offline: the 2s data_version poll runs on the harness clock, so each try
// advances it (6s, a whole rate-limit token) until the 401 turns into a 201.
func enrollUntilLoaded(t *testing.T, h *harness.H, token, suffix string) enrollReply {
	t.Helper()
	var out enrollReply
	h.Eventually("the control plane to load the offline-created enrollment token", func() bool {
		status, body := h.CP().Enroll(token, scenarioCSR(t), suffix)
		if status == http.StatusCreated {
			if err := json.Unmarshal([]byte(body), &out); err != nil {
				t.Fatalf("decode the enroll response: %v", err)
			}
			return true
		}
		if status != http.StatusUnauthorized {
			t.Fatalf("POST /control/enroll = %d %s while waiting for the token", status, body)
		}
		h.Clock().Advance(6 * time.Second)
		return false
	})
	return out
}

func workerCAEnroll(t *testing.T, h *harness.H) {
	// A degraded CA answers 503 before a token is touched.
	token := h.CreateEnrollToken("worker-1", "", 0, 0)
	status, body := h.CP().Enroll(token, scenarioCSR(t), "")
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "ca_unavailable") {
		t.Fatalf("degraded enroll = %d %s, want 503 ca_unavailable", status, body)
	}

	workerCAMakeReady(t, h)

	// The same token now enrolls: 201, a SPIFFE URI SAN, a verifying chain.
	out := enrollUntilLoaded(t, h, token, "")
	block, _ := pem.Decode([]byte(out.Certificate))
	if block == nil {
		t.Fatal("the certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wantID := "spiffe://" + harness.WorkerCATrustDomain + "/warden/worker/worker-1"
	if out.WorkerID != "worker-1" || out.SpiffeID != wantID || len(cert.URIs) != 1 || cert.URIs[0].String() != wantID {
		t.Fatalf("identity: %+v, SAN %v", out, cert.URIs)
	}
	if len(out.Chain) != 2 {
		t.Fatalf("chain has %d certificates, want intermediate and root", len(out.Chain))
	}
	var chain []*x509.Certificate
	for _, p := range out.Chain {
		cs, err := workerca.ParseCertsPEM([]byte(p))
		if err != nil || len(cs) != 1 {
			t.Fatalf("chain entry: %v", err)
		}
		chain = append(chain, cs[0])
	}
	if chain[0].CheckSignatureFrom(chain[1]) != nil || cert.CheckSignatureFrom(chain[0]) != nil {
		t.Fatal("the chain does not link: chain[1] must sign chain[0], which must sign the certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(chain[0])
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: h.Clock().Now()}); err != nil {
		t.Fatalf("the issued certificate does not verify against the intermediate: %v", err)
	}

	// Single use: the same token is a plain 401, whatever the reason.
	h.Clock().Advance(time.Minute)
	status, body = h.CP().Enroll(token, scenarioCSR(t), "")
	if status != http.StatusUnauthorized || strings.TrimSpace(body) != "unauthorized" {
		t.Fatalf("reused token = %d %q, want 401 unauthorized", status, body)
	}

	// A bad CSR is a 400 and leaves the token usable.
	token2 := h.CreateEnrollToken("worker-2", "", 0, time.Hour)
	if status, body := h.CP().Enroll(token2, "not a csr", ""); status != http.StatusBadRequest {
		t.Fatalf("bad CSR = %d %s, want 400", status, body)
	}
	if got := enrollUntilLoaded(t, h, token2, ""); got.WorkerID != "worker-2" {
		t.Fatalf("second worker: %+v", got)
	}

	// A prefix token enrolls a pool, then is used up; a hostile suffix is a 400.
	pool3 := h.CreateEnrollToken("", "pool-a-", 3, 0)
	if got := enrollUntilLoaded(t, h, pool3, "h1"); got.WorkerID != "pool-a-h1" {
		t.Fatalf("pool member 1: %+v", got)
	}
	h.Clock().Advance(time.Minute)
	if status, body := h.CP().Enroll(pool3, scenarioCSR(t), "../x"); status != http.StatusBadRequest {
		t.Fatalf("suffix ../x = %d %s, want 400", status, body)
	}
	for _, s := range []string{"h2", "h3"} {
		if got := enrollOK(t, h, pool3, s); got.WorkerID != "pool-a-"+s {
			t.Fatalf("pool member %s: %+v", s, got)
		}
	}
	h.Clock().Advance(time.Minute)
	if status, _ := h.CP().Enroll(pool3, scenarioCSR(t), "h4"); status != http.StatusUnauthorized {
		t.Fatalf("fourth pool member = %d, want 401", status)
	}

	// An expired token is the same 401.
	short := h.CreateEnrollToken("worker-3", "", 0, time.Hour)
	h.Clock().Advance(6 * time.Second) // the control plane loads it
	h.Clock().Advance(2 * time.Hour)
	status, body = h.CP().Enroll(short, scenarioCSR(t), "")
	if status != http.StatusUnauthorized || strings.TrimSpace(body) != "unauthorized" {
		t.Fatalf("expired token = %d %q", status, body)
	}

	workerCAEnrollAuditAndSecrets(t, h, []string{token, token2, pool3, short}, 5)
}

// workerCAEnrollAuditAndSecrets checks what the control plane stored and
// logged: one worker.enrolled row per certificate (and the cli rows for the
// tokens), and no plaintext token, hash or PEM request anywhere.
func workerCAEnrollAuditAndSecrets(t *testing.T, h *harness.H, tokens []string, wantEnrolled int) {
	t.Helper()
	enrolled := 0
	for _, r := range h.AdminAuditRows() {
		if r.Action != "worker.enrolled" {
			continue
		}
		enrolled++
		var d map[string]string
		if err := json.Unmarshal([]byte(r.Details), &d); err != nil {
			t.Fatalf("details: %v", err)
		}
		if !strings.HasPrefix(r.Sub, "enroll:et_") || r.Target != "worker_certs" || !strings.HasPrefix(r.TargetRef, "worker:") ||
			d["token_id"] == "" || d["serial"] == "" || r.Outcome != "ok" {
			t.Errorf("worker.enrolled row: %+v", r)
		}
	}
	if enrolled != wantEnrolled {
		t.Errorf("worker.enrolled rows = %d, want %d", enrolled, wantEnrolled)
	}
	var all bytes.Buffer
	for _, name := range []string{"warden-cp.db", "warden-cp.db-wal"} {
		if b, err := os.ReadFile(filepath.Join(h.WorkerCAStateDir(), name)); err == nil {
			all.Write(b)
		}
	}
	for _, r := range h.AdminAuditRows() {
		all.WriteString(r.Details + r.TargetRef + r.Sub)
	}
	all.WriteString(h.Logs())
	for _, tok := range tokens {
		sum := sha256.Sum256([]byte(tok))
		if bytes.Contains(all.Bytes(), []byte(tok)) {
			t.Errorf("a plaintext enrollment token appears in the database, audit rows or logs")
		}
		if bytes.Contains(all.Bytes(), []byte(hex.EncodeToString(sum[:]))) {
			t.Errorf("a token's hex sha256 appears in the database, audit rows or logs")
		}
	}
	if bytes.Contains([]byte(h.Logs()), []byte("CERTIFICATE REQUEST")) {
		t.Errorf("the control plane log carries a CSR")
	}
}

// workerCAEnrollOff: without workerCA.enabled the route does not exist.
func workerCAEnrollOff(t *testing.T, h *harness.H) {
	status, _ := h.CP().Enroll("wet_"+strings.Repeat("a", 52), scenarioCSR(t), "")
	if status != http.StatusNotFound {
		t.Fatalf("POST /control/enroll without workerCA = %d, want 404", status)
	}
}
