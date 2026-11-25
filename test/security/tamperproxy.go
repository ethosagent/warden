package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethosagent/warden/internal/controlplane"
)

// TamperProxy sits between one worker and the control plane and can replace,
// replay or mutate the signed bundle the worker is about to receive on
// GET /policy, so the worker's real RemoteProvider and bundle.Verify are what
// reject it. Every other request (heartbeat, ingest, enrollment, renewal) is
// relayed unchanged.
//
// The worker authenticates to the CP with its client certificate, which a TLS
// terminating proxy cannot pass through, so the proxy presents the worker's own
// certificate (read from its state dir on every new upstream connection) to the
// CP. That is test code reading a test worker's files; it is not a production
// seam, and no production code knows the proxy exists.
//
// It serves one armed response and then relays again: an attack that must
// raise warden_bundle_rejected_total by exactly one is served exactly once. An
// armed response answers a held long-poll at once (the forwarded request is
// cancelled), so a case does not wait out the CP's long-poll window.
type TamperProxy struct {
	// Addr is host:port, what the worker dials.
	Addr string

	s   *Stack
	w   *Worker
	srv *httptest.Server
	rp  *httputil.ReverseProxy

	cert atomic.Pointer[tls.Certificate]

	mu   sync.Mutex
	plan *Plan
	wake chan struct{}
	seen []Relayed
	reqs []ProxiedRequest

	served    atomic.Int64
	etagSeq   atomic.Int64
	handshake atomic.Int64
	relayed   atomic.Int64
}

// ProxiedRequest is what a worker sent the control plane through the proxy: no
// header value, only whether an Authorization header was present, and the
// SHA-256 (hex) of the client certificate the worker presented in its own
// handshake with the proxy ("" when it presented none).
type ProxiedRequest struct {
	Method, Path  string
	Authorization bool
	ClientCert    string
	// Status is what the proxy answered the worker (the control plane's own
	// status for a relayed request; 0 when the request was abandoned).
	Status int
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps streaming replies (a held long-poll) flushable through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Requests returns every request the worker sent through the proxy, oldest
// first.
func (p *TamperProxy) Requests() []ProxiedRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ProxiedRequest(nil), p.reqs...)
}

// Plan is one response the proxy serves in place of the CP's answer to a
// bundle request. Zero fields default to a 200 bundle envelope.
type Plan struct {
	Status      int
	ContentType string
	Body        []byte
}

// Relayed is one real envelope the proxy relayed from the CP.
type Relayed struct {
	Seq  int64
	ETag string
	Body []byte
}

// NewTamperProxy starts a proxy in front of the CP for worker w and registers
// it on the worker. Call it from StackOptions.CPEndpoint and return its Addr.
func NewTamperProxy(s *Stack, w *Worker) *TamperProxy {
	s.tb.Helper()
	p := &TamperProxy{s: s, w: w, wake: make(chan struct{})}
	cert := s.CPCA.ServerCert("127.0.0.1")
	p.cert.Store(&cert)
	target, err := url.Parse(s.CP.URL)
	if err != nil {
		s.tb.Fatalf("security: parse the CP url: %v", err)
	}
	// No keep-alive: the transport picks the client certificate once per
	// connection, so a connection opened before the worker enrolled (with no
	// certificate) would be reused for /policy and answered 401 forever.
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		RootCAs: s.CPCA.Pool(), MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c, err := p.workerCredential(); err == nil {
				return c, nil
			}
			return &tls.Certificate{}, nil
		},
	}}
	s.tb.Cleanup(tr.CloseIdleConnections)
	p.rp = &httputil.ReverseProxy{
		Transport: tr,
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(target) },
		ErrorLog:  log.New(io.Discard, "", 0),
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(p.handle))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// httptest adds its own certificate to a config without one, and Go
		// uses that for a client that sends no SNI (an IP address), so the
		// certificate is chosen per handshake through GetConfigForClient.
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			// The worker's certificate is requested, not verified here (the CP
			// verifies the one the proxy relays): it is how Requests can say
			// which certificate the worker itself presented.
			return &tls.Config{Certificates: []tls.Certificate{*p.cert.Load()}, MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}, nil
		},
	}
	// A client that refuses the proxy's certificate shows up as a handshake
	// error in the server's error log: that is how a case proves the worker
	// attempted the connection and walked away.
	srv.Config.ErrorLog = log.New(handshakeCounter{&p.handshake}, "", 0)
	srv.StartTLS()
	s.tb.Cleanup(srv.Close)
	p.srv = srv
	p.Addr = strings.TrimPrefix(srv.URL, "https://")
	w.Tamper = p
	return p
}

type handshakeCounter struct{ n *atomic.Int64 }

func (h handshakeCounter) Write(b []byte) (int, error) {
	if strings.Contains(string(b), "TLS handshake error") {
		h.n.Add(1)
	}
	return len(b), nil
}

// workerCredential is the worker's enrolled certificate, or an error before it
// has enrolled.
func (p *TamperProxy) workerCredential() (*tls.Certificate, error) {
	dir := filepath.Join(p.w.StateDir, "cert")
	c, err := os.ReadFile(filepath.Join(dir, "worker-cert.pem"))
	if err != nil {
		return nil, err
	}
	k, err := os.ReadFile(filepath.Join(dir, "worker-key.pem"))
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func (p *TamperProxy) isBundleRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == "/policy" &&
		strings.Contains(r.Header.Get("Accept"), controlplane.BundleMediaType)
}

func (p *TamperProxy) handle(w http.ResponseWriter, r *http.Request) {
	rec := &statusWriter{ResponseWriter: w}
	pr := ProxiedRequest{Method: r.Method, Path: r.URL.Path, Authorization: len(r.Header.Values("Authorization")) > 0}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		pr.ClientCert = hex.EncodeToString(sum[:])
	}
	defer func() {
		pr.Status = rec.status
		p.mu.Lock()
		p.reqs = append(p.reqs, pr)
		p.mu.Unlock()
	}()
	w = rec
	// Only enrollment may reach the CP without the worker's certificate: the
	// CP requires certs, and a cert-less relay would be a false 401.
	if r.URL.Path != "/control/enroll" {
		if _, err := p.workerCredential(); err != nil {
			http.Error(w, "tamper proxy: worker has no certificate yet", http.StatusBadGateway)
			return
		}
	}
	if !p.isBundleRequest(r) {
		p.rp.ServeHTTP(w, r)
		return
	}
	for {
		p.mu.Lock()
		plan, wake := p.plan, p.wake
		p.plan = nil
		p.mu.Unlock()
		if plan != nil {
			p.write(w, plan)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			p.rp.ServeHTTP(rec, r.WithContext(ctx))
		}()
		select {
		case <-done:
			cancel()
			p.relay(w, rec)
			return
		case <-wake:
			cancel()
			<-done
		case <-r.Context().Done():
			cancel()
			<-done
			return
		}
	}
}

// relay writes the CP's buffered answer to the worker and records a real
// envelope.
func (p *TamperProxy) relay(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode == http.StatusOK && res.Header.Get("Content-Type") == controlplane.BundleMediaType {
		p.record(res.Header.Get("ETag"), body)
	}
	for k, vs := range res.Header {
		w.Header()[k] = vs
	}
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(body)
	p.relayed.Add(1)
}

func (p *TamperProxy) record(etag string, body []byte) {
	var env struct {
		Payload string `json:"payload"`
	}
	var head struct {
		Seq int64 `json:"seq"`
	}
	if json.Unmarshal(body, &env) == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(env.Payload); err == nil {
			_ = json.Unmarshal(raw, &head)
		}
	}
	p.mu.Lock()
	p.seen = append(p.seen, Relayed{Seq: head.Seq, ETag: etag, Body: append([]byte(nil), body...)})
	p.mu.Unlock()
}

// write serves plan. Its ETag is unique, so the worker never mistakes it for
// the real bundle and asks the CP for the current one on its next poll.
func (p *TamperProxy) write(w http.ResponseWriter, plan *Plan) {
	status, ct := plan.Status, plan.ContentType
	if status == 0 {
		status = http.StatusOK
	}
	if ct == "" {
		ct = controlplane.BundleMediaType
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("ETag", `"tamper-`+strconv.FormatInt(p.etagSeq.Add(1), 10)+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(plan.Body)))
	w.WriteHeader(status)
	_, _ = w.Write(plan.Body)
	p.served.Add(1)
}

// Replace arms plan: the next bundle request, held or new, gets it instead of
// the CP's answer, once.
func (p *TamperProxy) Replace(plan Plan) {
	p.mu.Lock()
	cp := plan
	p.plan = &cp
	close(p.wake)
	p.wake = make(chan struct{})
	p.mu.Unlock()
}

// Disarm drops an armed response nobody has taken yet.
func (p *TamperProxy) Disarm() {
	p.mu.Lock()
	p.plan = nil
	p.mu.Unlock()
}

// Replay arms the recorded envelope at index i (see Relayed) as it was relayed.
func (p *TamperProxy) Replay(i int) {
	p.s.tb.Helper()
	seen := p.Relayed()
	if i < 0 || i >= len(seen) {
		p.s.tb.Fatalf("security: replay %d of %d recorded envelopes", i, len(seen))
	}
	p.Replace(Plan{Body: seen[i].Body})
}

// Mutate arms the newest real envelope after fn changed it.
func (p *TamperProxy) Mutate(fn func(raw []byte) []byte) {
	p.s.tb.Helper()
	seen := p.Relayed()
	if len(seen) == 0 {
		p.s.tb.Fatal("security: the proxy relayed no envelope yet")
	}
	p.Replace(Plan{Body: fn(append([]byte(nil), seen[len(seen)-1].Body...))})
}

// Relayed returns the real envelopes relayed so far, oldest first.
func (p *TamperProxy) Relayed() []Relayed {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Relayed(nil), p.seen...)
}

// Latest is the newest real envelope relayed.
func (p *TamperProxy) Latest() []byte {
	p.s.tb.Helper()
	seen := p.Relayed()
	if len(seen) == 0 {
		p.s.tb.Fatal("security: the proxy relayed no envelope yet")
	}
	return seen[len(seen)-1].Body
}

// Served is how many armed responses the proxy has delivered.
func (p *TamperProxy) Served() int64 { return p.served.Load() }

// HandshakeFailures is how many TLS handshakes a client abandoned.
func (p *TamperProxy) HandshakeFailures() int64 { return p.handshake.Load() }

// UseServerCert makes the proxy present cert (a certificate no CA the worker
// trusts signed) and drops every open connection, so the worker's next request
// must handshake again. RestoreServerCert undoes it.
func (p *TamperProxy) UseServerCert(cert tls.Certificate) {
	p.cert.Store(&cert)
	p.srv.CloseClientConnections()
}

// RestoreServerCert presents the CP CA's certificate again.
func (p *TamperProxy) RestoreServerCert() {
	cert := p.s.CPCA.ServerCert("127.0.0.1")
	p.cert.Store(&cert)
	p.srv.CloseClientConnections()
}

// mutateEnvelope is a helper for Mutate funcs: it decodes raw into a map of
// raw members, applies fn and re-encodes.
func mutateEnvelope(raw []byte, fn func(m map[string]json.RawMessage)) []byte {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(fmt.Sprintf("security: not an envelope: %v", err))
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		panic(fmt.Sprintf("security: encode an envelope: %v", err))
	}
	return out
}
