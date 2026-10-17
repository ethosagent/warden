// The fakeupstream tests run the server IN-PROCESS against loopback ports: no
// Docker, no container network, no external network — so they run in the plain
// `go test ./...` gate. The container-level behavior (ports, DNS routing,
// certs on the compose network) is exercised by the L2 harness in part 2.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/websocket"
)

// scenarioNames are the DNS names the fake upstream answers by default — the
// same list the compose override aliases onto the egress network.
var scenarioNames = []string{"api.example.test", "llm.example.test", "mcp.example.test", "evil.example.test"}

const scenarioIP = "10.200.0.10"

// genCerts creates a throwaway CA plus a leaf covering every scenario alias
// (the same SAN set gen.sh produces for the container), returning the leaf
// tls.Certificate and a pool trusting the CA.
func genCerts(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2e-fake-upstream-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "api.example.test"},
		DNSNames:     append([]string{"fakeupstream", "localhost"}, scenarioNames...),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}, pool
}

// testStack is one fake upstream wired to loopback ports: the TLS app server,
// its plain-HTTP twin, the plain-HTTP control API, and the DNS responder.
type testStack struct {
	tlsAddr     string // host:port of the TLS app server
	plainAddr   string // host:port of the plain-HTTP app twin
	controlAddr string // host:port of the control API
	dns         *dnsServer
	cert        tls.Certificate
	pool        *x509.CertPool
}

func startTestStack(t *testing.T) *testStack {
	t.Helper()
	cert, pool := genCerts(t)
	rec := newRecorder()
	rb := newRebinds()

	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	t.Cleanup(func() { _ = tlsLn.Close() })
	appSrv := &http.Server{
		Handler: newApp(rec),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			// h2 first: the app must negotiate HTTP/2 when a client offers it
			// (the worker's gRPC path requires it).
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	go func() { _ = appSrv.ServeTLS(tlsLn, "", "") }()

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen plain http: %v", err)
	}
	t.Cleanup(func() { _ = plainLn.Close() })
	plainSrv := &http.Server{Handler: newApp(rec)}
	go func() { _ = plainSrv.Serve(plainLn) }()

	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen control: %v", err)
	}
	t.Cleanup(func() { _ = controlLn.Close() })
	controlSrv := &http.Server{Handler: newControl(rec, rb)}
	go func() { _ = controlSrv.Serve(controlLn) }()

	dns := startTestDNS(t, scenarioIP, scenarioNames, rb)

	return &testStack{
		tlsAddr:     tlsLn.Addr().String(),
		plainAddr:   plainLn.Addr().String(),
		controlAddr: controlLn.Addr().String(),
		dns:         dns,
		cert:        cert,
		pool:        pool,
	}
}

func startTestDNS(t *testing.T, ip string, names []string, rb *rebinds) *dnsServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &dnsServer{ip: ip, names: names, rebinds: rb, conn: conn}
	go s.serveUDP()
	return s
}

// hostClient returns an HTTP client that dials the stack's TLS listener with
// SNI and Host set to host, trusting the test CA — the same shape a proxied
// request arrives with through the worker.
func (s *testStack) hostClient(host string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				raw, err := d.DialContext(ctx, "tcp", s.tlsAddr)
				if err != nil {
					return nil, err
				}
				cfg := &tls.Config{ServerName: host, RootCAs: s.pool, MinVersion: tls.VersionTLS12}
				return tls.Client(raw, cfg), nil
			},
		},
	}
}

// controlGet issues a plain-HTTP request against the control API.
func (s *testStack) control(t *testing.T, method, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+s.controlAddr+path, nil)
	if err != nil {
		t.Fatalf("build control request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("control %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read control body: %v", err)
	}
	return resp, string(body)
}

// recorded decodes GET /_recorded's envelope into the record slice.
func (s *testStack) recorded(t *testing.T) []record {
	t.Helper()
	recs, _ := s.recordedWithDropped(t)
	return recs
}

// recordedWithDropped decodes GET /_recorded's envelope: the kept records plus
// the running count of records already evicted (oldest dropped) by the cap.
func (s *testStack) recordedWithDropped(t *testing.T) ([]record, int) {
	t.Helper()
	resp, body := s.control(t, http.MethodGet, "/_recorded")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_recorded status = %d", resp.StatusCode)
	}
	var env struct {
		Records []record `json:"records"`
		Dropped int      `json:"dropped"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode /_recorded body %q: %v", body, err)
	}
	return env.Records, env.Dropped
}

// TestRecorder_CapsOldestAndCountsDropped pins the recorder cap: once full,
// the OLDEST record is evicted for each new one and /_recorded exposes the
// running dropped count. A long scenario run cannot balloon the container, and
// the runner can tell when it has lost the head of its recording.
func TestRecorder_CapsOldestAndCountsDropped(t *testing.T) {
	s := startTestStack(t)

	// Under the cap: nothing dropped, records intact.
	for i := 0; i < 3; i++ {
		resp, err := s.hostClient("api.example.test").Get(fmt.Sprintf("https://api.example.test/%d", i))
		if err != nil {
			t.Fatalf("GET /%d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	recs, dropped := s.recordedWithDropped(t)
	if len(recs) != 3 || dropped != 0 {
		t.Fatalf("under cap: %d records, dropped=%d; want 3/0", len(recs), dropped)
	}

	// Overflow through the default cap via a small, direct recorder: the same
	// middleware the app serves through, driven by httptest. cap+2 records in
	// → cap records out, the two OLDEST gone, dropped counted.
	rec := newRecorderWithCap(4)
	h := rec.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://api.example.test/n"+fmt.Sprint(i), nil)
		req.Host = "api.example.test"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	kept := rec.snapshot()
	if len(kept) != 4 {
		t.Fatalf("kept %d records, want the cap 4", len(kept))
	}
	if kept[0].Path != "/n2" || kept[3].Path != "/n5" {
		t.Fatalf("kept paths = %v, want the NEWEST four (/n2../n5)", []string{kept[0].Path, kept[1].Path, kept[2].Path, kept[3].Path})
	}
	if got := rec.droppedCount(); got != 2 {
		t.Fatalf("dropped = %d, want 2", got)
	}

	// And the control API reports that count (wired through the same stack).
	if _, body := s.control(t, http.MethodGet, "/_recorded"); !strings.Contains(body, `"dropped"`) {
		t.Fatalf("/_recorded body %q does not carry the dropped counter", body)
	}
}

// TestEndpoints_RecordOneEach calls every app endpoint once and asserts
// /_recorded lists exactly those calls with the right host, path — and the
// Authorization header intact (the canary oracle the L2 suite asserts on).
func TestEndpoints_RecordOneEach(t *testing.T) {
	s := startTestStack(t)

	// Plain allowed call, like agent-1's first curl.
	resp, err := s.hostClient("api.example.test").Get("https://api.example.test/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}

	// /echo reflects request headers.
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.test/echo", nil)
	req.Header.Set("Authorization", "Bearer CANARY-e2e-0123456789abcdef")
	req.Header.Set("X-E2E-Probe", "echo-me")
	resp, err = s.hostClient("api.example.test").Do(req)
	if err != nil {
		t.Fatalf("GET /echo: %v", err)
	}
	var echo struct {
		Method string              `json:"method"`
		Host   string              `json:"host"`
		Path   string              `json:"path"`
		Header map[string][]string `json:"header"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode /echo: %v", err)
	}
	_ = resp.Body.Close()
	if echo.Host != "api.example.test" || echo.Path != "/echo" {
		t.Errorf("echo host/path = %q/%q, want api.example.test//echo", echo.Host, echo.Path)
	}
	if got := echo.Header["Authorization"]; len(got) != 1 || got[0] != "Bearer CANARY-e2e-0123456789abcdef" {
		t.Errorf("echo Authorization = %v, want the header reflected", echo.Header["Authorization"])
	}

	// LLM stub.
	chatBody := `{"model":"e2e-model","messages":[{"role":"user","content":"hi from the agent"}]}`
	resp, err = s.hostClient("llm.example.test").Post("https://llm.example.test/v1/chat/completions", "application/json", strings.NewReader(chatBody))
	if err != nil {
		t.Fatalf("POST /v1/chat/completions: %v", err)
	}
	var chat struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chat); err != nil {
		t.Fatalf("decode chat completion: %v", err)
	}
	_ = resp.Body.Close()
	if chat.Model != "e2e-model" || len(chat.Choices) != 1 {
		t.Fatalf("chat completion shape = %+v, want one choice for e2e-model", chat)
	}
	if !strings.Contains(chat.Choices[0].Message.Content, "hi from the agent") {
		t.Errorf("completion content %q does not echo the user message", chat.Choices[0].Message.Content)
	}

	// Poisoned MCP server (mounted at mcp.example.test).
	mcpBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	resp, err = s.hostClient("mcp.example.test").Post("https://mcp.example.test/", "application/json", strings.NewReader(mcpBody))
	if err != nil {
		t.Fatalf("POST tools/list: %v", err)
	}
	mcpRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read tools/list: %v", err)
	}
	_ = resp.Body.Close()
	if !strings.Contains(string(mcpRaw), "ignore all previous instructions") {
		t.Errorf("tools/list response is missing the poisoned description: %s", mcpRaw)
	}

	// One record per call, right host and path, in call order.
	recs := s.recorded(t)
	want := []struct{ host, path string }{
		{"api.example.test", "/"},
		{"api.example.test", "/echo"},
		{"llm.example.test", "/v1/chat/completions"},
		{"mcp.example.test", "/"},
	}
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(recs), len(want), recs)
	}
	for i, w := range want {
		if recs[i].Host != w.host || recs[i].Path != w.path {
			t.Errorf("record[%d] = %s%s, want %s%s", i, recs[i].Host, recs[i].Path, w.host, w.path)
		}
	}
	if got := recs[1].Header.Get("Authorization"); got != "Bearer CANARY-e2e-0123456789abcdef" {
		t.Errorf("recorded Authorization = %q, want the canary (the recorder is the oracle)", got)
	}
	if recs[2].Body == "" || !strings.Contains(recs[2].Body, "hi from the agent") {
		t.Errorf("recorded body = %q, want the chat request body", recs[2].Body)
	}
}

// TestPlainHTTPTwinServesAndRecords: the plain-HTTP app (#376) serves the same
// recorder-backed mux as the TLS app — the shape a transparent :80 upstream hop
// reaches. Host and headers must land in the recorder identically.
func TestPlainHTTPTwinServesAndRecords(t *testing.T) {
	s := startTestStack(t)

	req, err := http.NewRequest(http.MethodGet, "http://"+s.plainAddr+"/echo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.example.test"
	req.Header.Set("Authorization", "Bearer CANARY-e2e-0123456789abcdef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("plain GET /echo: %v", err)
	}
	var echo struct {
		Host   string `json:"host"`
		Path   string `json:"path"`
		Proto  string `json:"proto"`
		Header map[string][]string
	}
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode plain /echo: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || echo.Host != "api.example.test" || echo.Path != "/echo" {
		t.Fatalf("plain /echo = %d %+v, want 200 from api.example.test", resp.StatusCode, echo)
	}

	recs := s.recorded(t)
	if len(recs) != 1 || recs[0].Host != "api.example.test" || recs[0].Path != "/echo" {
		t.Fatalf("records = %+v, want one api.example.test /echo", recs)
	}
	if got := recs[0].Header.Get("Authorization"); got != "Bearer CANARY-e2e-0123456789abcdef" {
		t.Errorf("recorded Authorization = %q, want the canary", got)
	}
}

// TestControlReset_ClearsRecordsAndRebinds: POST /_reset empties the recorder
// and disarms any armed rebinding.
func TestControlReset_ClearsRecordsAndRebinds(t *testing.T) {
	s := startTestStack(t)

	resp, err := s.hostClient("api.example.test").Get("https://api.example.test/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	if got := s.recorded(t); len(got) != 1 {
		t.Fatalf("records before reset = %d, want 1", len(got))
	}

	s.dns.rebinds.arm("api.example.test")
	if !s.dns.rebinds.armedFor("api.example.test") {
		t.Fatal("rebind not armed")
	}

	respReset, body := s.control(t, http.MethodPost, "/_reset")
	if respReset.StatusCode != http.StatusOK {
		t.Fatalf("/_reset status = %d body %s", respReset.StatusCode, body)
	}
	if got := s.recorded(t); len(got) != 0 {
		t.Fatalf("records after reset = %d, want 0", len(got))
	}
	if s.dns.rebinds.armedFor("api.example.test") {
		t.Fatal("/_reset must disarm rebinding")
	}
}

// TestControlRebind_ArmsDisarmsAndAnswersLoopback drives the red-team control:
// arm a host, see its next DNS answer point at 127.0.0.1, disarm via the
// control API and see the real answer restored.
func TestControlRebind_ArmsDisarmsAndAnswersLoopback(t *testing.T) {
	s := startTestStack(t)

	if got := dnsA(t, s, "api.example.test"); got != scenarioIP {
		t.Fatalf("A before rebind = %q, want %q", got, scenarioIP)
	}

	resp, body := s.control(t, http.MethodPost, "/_rebind?host=api.example.test")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_rebind status = %d body %s", resp.StatusCode, body)
	}
	if got := dnsA(t, s, "api.example.test"); got != "127.0.0.1" {
		t.Fatalf("A after rebind = %q, want 127.0.0.1", got)
	}
	// Other names are untouched.
	if got := dnsA(t, s, "llm.example.test"); got != scenarioIP {
		t.Fatalf("A for un-rebound name = %q, want %q", got, scenarioIP)
	}

	resp, body = s.control(t, http.MethodDelete, "/_rebind?host=api.example.test")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /_rebind status = %d body %s", resp.StatusCode, body)
	}
	if got := dnsA(t, s, "api.example.test"); got != scenarioIP {
		t.Fatalf("A after disarm = %q, want %q", got, scenarioIP)
	}

	// A rebind without a host is a bad request, not a silent no-op.
	if resp, _ = s.control(t, http.MethodPost, "/_rebind"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("/_rebind without host status = %d, want 400", resp.StatusCode)
	}
}

// TestDNS_UnknownNameIsNXDOMAIN keeps the hermetic default: names outside the
// scenario list do not resolve at all.
func TestDNS_UnknownNameIsNXDOMAIN(t *testing.T) {
	s := startTestStack(t)
	if rc := dnsRCode(t, s, "real-internet.example"); rc != dnsmessage.RCodeNameError {
		t.Fatalf("rcode for unknown name = %v, want NameError", rc)
	}
	if rc := dnsRCode(t, s, "api.example.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode for known name = %v, want Success", rc)
	}
}

// TestDNS_TCPAnswersToo covers the truncation-fallback transport: the same
// answer, length-prefixed, over TCP.
func TestDNS_TCPAnswersToo(t *testing.T) {
	s := startTestStack(t)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer func() { _ = tcpLn.Close() }()
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		serveDNSConn(s.dns, conn)
	}()

	query := mustDNSQuery(t, "api.example.test", dnsmessage.TypeA)
	conn, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp dns: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var lenPrefix [2]byte
	lenPrefix[0], lenPrefix[1] = byte(len(query)>>8), byte(len(query))
	if _, err := conn.Write(append(lenPrefix[:], query...)); err != nil {
		t.Fatalf("write tcp query: %v", err)
	}
	if _, err := io.ReadFull(conn, lenPrefix[:]); err != nil {
		t.Fatalf("read tcp length: %v", err)
	}
	resp := make([]byte, int(lenPrefix[0])<<8|int(lenPrefix[1]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read tcp response: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("unpack tcp response: %v", err)
	}
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 200, 0, 10} {
		t.Fatalf("tcp answers = %+v, want one A 10.200.0.10", m.Answers)
	}
}

// dnsA resolves name over the stack's UDP DNS and returns the single A record.
func dnsA(t *testing.T, s *testStack, name string) string {
	t.Helper()
	var m = dnsMessage(t, s, name, dnsmessage.TypeA)
	if len(m.Answers) != 1 {
		t.Fatalf("answers for %s = %+v, want one", name, m.Answers)
	}
	a, ok := m.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer type = %T, want AResource", m.Answers[0].Body)
	}
	return net.IP(a.A[:]).String()
}

func dnsRCode(t *testing.T, s *testStack, name string) dnsmessage.RCode {
	t.Helper()
	return dnsMessage(t, s, name, dnsmessage.TypeA).RCode // embedded Header
}

func dnsMessage(t *testing.T, s *testStack, name string, qtype dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial("udp", s.dns.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial udp dns: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(mustDNSQuery(t, name, qtype)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read dns response: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack dns response: %v", err)
	}
	return m
}

func mustDNSQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	buf := make([]byte, 2, 512)
	b := dnsmessage.NewBuilder(buf, dnsmessage.Header{ID: 42, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("builder questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name + "."),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("builder question: %v", err)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatalf("builder finish: %v", err)
	}
	return q[2:]
}

// TestHTTP2AndHTTP1_NegotiatedOverALPN pins the transport mix the ticket
// promises: h2 and http/1.1 both negotiable on the same port.
func TestHTTP2AndHTTP1_NegotiatedOverALPN(t *testing.T) {
	s := startTestStack(t)

	dialWith := func(next []string) string {
		raw, err := net.Dial("tcp", s.tlsAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = raw.Close() }()
		conn := tls.Client(raw, &tls.Config{ServerName: "api.example.test", RootCAs: s.pool, NextProtos: next})
		defer func() { _ = conn.Close() }()
		if err := conn.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("handshake with %v: %v", next, err)
		}
		return conn.ConnectionState().NegotiatedProtocol
	}
	if got := dialWith([]string{"h2", "http/1.1"}); got != "h2" {
		t.Errorf("negotiated protocol = %q, want h2", got)
	}
	if got := dialWith([]string{"http/1.1"}); got != "http/1.1" {
		t.Errorf("negotiated protocol = %q, want http/1.1", got)
	}
}

// TestWebSocketEcho drives /ws with a real RFC 6455 client: one text frame in,
// the same text frame out.
func TestWebSocketEcho(t *testing.T) {
	s := startTestStack(t)

	// x/net/websocket dials the URL host literally, so point the URL at the
	// loopback listener and pin SNI + CA trust in TlsConfig — the server mux
	// routes /ws by path, not Host, so this exercises the real handshake.
	cfg, err := websocket.NewConfig("wss://"+s.tlsAddr+"/ws", "https://api.example.test/")
	if err != nil {
		t.Fatalf("websocket config: %v", err)
	}
	cfg.TlsConfig = &tls.Config{ServerName: "api.example.test", RootCAs: s.pool, MinVersion: tls.VersionTLS12}
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	const msg = "hello over the tunnel"
	if err := websocket.Message.Send(ws, msg); err != nil {
		t.Fatalf("ws send: %v", err)
	}
	var got []byte
	if err := websocket.Message.Receive(ws, &got); err != nil {
		t.Fatalf("ws receive: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("ws echo = %q, want %q", got, msg)
	}
}

// TestControlHealth serves the compose healthcheck.
func TestControlHealth(t *testing.T) {
	s := startTestStack(t)
	resp, body := s.control(t, http.MethodGet, "/_health")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "ok") {
		t.Fatalf("/_health = %d %q, want 200 ok", resp.StatusCode, body)
	}
}

// TestGRPCEcho_UnaryOverH2 drives a real gRPC-shaped unary call over a
// negotiated-h2 connection: POST /e2e.Echo/Echo with an application/grpc
// length-prefixed protobuf frame in, the echo as message field 1 out, and a
// grpc-status: 0 trailer — the transport the worker's gRPC inspection sees.
func TestGRPCEcho_UnaryOverH2(t *testing.T) {
	s := startTestStack(t)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{ServerName: "api.example.test", RootCAs: s.pool},
			ForceAttemptHTTP2:   true, // ALPN h2 — gRPC requires it
			DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return dialContextAddr(ctx, s.tlsAddr) },
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	// One gRPC data frame: 1-byte compressed flag, 4-byte big-endian length,
	// then a protobuf message with field 1 (length-delimited) = the payload.
	payload := []byte("ping over the tunnel")
	msg := append([]byte{0x0A, byte(len(payload))}, payload...)
	frame := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)

	req, err := http.NewRequest(http.MethodPost, "https://api.example.test/e2e.Echo/Echo", bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("build grpc request: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("grpc call: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("grpc negotiated %q, want HTTP/2.0", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read grpc body: %v", err)
	}
	if st := resp.Trailer.Get("Grpc-Status"); st != "0" {
		t.Fatalf("grpc-status = %q, want 0 (body %q)", st, body)
	}
	if len(body) < 5 {
		t.Fatalf("grpc response frame too short: %x", body)
	}
	msgLen := int(body[1])<<24 | int(body[2])<<16 | int(body[3])<<8 | int(body[4])
	if int(body[0]) != 0 || msgLen != len(body)-5 {
		t.Fatalf("malformed grpc response frame: flag=%d len=%d have=%d", body[0], msgLen, len(body)-5)
	}
	// Echoed protobuf: field 1, wire type 2, containing "echo: " + payload.
	out := body[5:]
	if len(out) < 2 || out[0] != 0x0A {
		t.Fatalf("response message = %x, want field-1 string", out)
	}
	if string(out[2:]) != "echo: "+string(payload) {
		t.Fatalf("echoed message = %q, want %q", out[2:], "echo: "+string(payload))
	}
}

// dialContextAddr dials a fixed host:port, ignoring the caller's addr — used
// to point an http2-capable transport at the stack's TLS listener.
func dialContextAddr(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// TestCertWritingRoundTrip sanity-checks genCerts: the PEM write path used by
// nothing in-process, but pinned so a regression in the leaf SAN list (the
// thing the workers' TLS verification depends on) cannot land silently. The
// bytes must parse and carry every scenario alias.
func TestCertWritingRoundTrip(t *testing.T) {
	cert, pool := genCerts(t)
	if len(cert.Certificate) == 0 {
		t.Fatal("leaf has no DER")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	for _, name := range scenarioNames {
		found := false
		for _, dns := range leaf.DNSNames {
			if dns == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("leaf SANs %v missing %q", leaf.DNSNames, name)
		}
	}
	if pool == nil {
		t.Fatal("nil CA pool")
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	if !strings.Contains(buf.String(), "CERTIFICATE") {
		t.Fatal("PEM round trip lost the block")
	}
	if _, err := os.Stat(filepath.Join(t.TempDir(), "unused")); err == nil {
		t.Fatal("temp dir unexpectedly non-empty")
	}
}
