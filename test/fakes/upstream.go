package fakes

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// UpstreamBodyLimit bounds how much of a request body the recorder keeps.
const UpstreamBodyLimit = 1 << 20

// UpstreamRequest is one request the upstream received, exactly as it arrived
// after the worker's pipeline (secret swaps applied).
type UpstreamRequest struct {
	Method string
	Host   string
	Path   string
	Header http.Header
	Body   []byte
}

// Upstream is a TLS server standing in for a destination the worker egresses
// to. It counts every request that reaches it and records headers and bodies,
// so a security case can assert "nothing reached the upstream" and "the swapped
// secret and no identity header arrived". Safe for concurrent use.
type Upstream struct {
	srv  *httptest.Server
	hits atomic.Int64

	mu   sync.Mutex
	reqs []UpstreamRequest
	next http.Handler
}

// NewUpstream starts a TLS upstream serving cert (a certificate for the host
// the worker dials, issued by a CA the worker's upstream pool trusts).
// It answers 200 with a small JSON body (a JSON-RPC result when the body is a
// JSON-RPC request) until SetHandler says otherwise, and stops at cleanup.
func NewUpstream(tb testing.TB, cert tls.Certificate) *Upstream {
	tb.Helper()
	u := &Upstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(u.serve))
	u.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	u.srv.StartTLS()
	tb.Cleanup(u.srv.Close)
	return u
}

func (u *Upstream) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, UpstreamBodyLimit))
	u.hits.Add(1)
	u.mu.Lock()
	u.reqs = append(u.reqs, UpstreamRequest{
		Method: r.Method, Host: r.Host, Path: r.URL.RequestURI(),
		Header: r.Header.Clone(), Body: body,
	})
	next := u.next
	u.mu.Unlock()
	if next != nil {
		next.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(body) > 0 && body[0] == '{' && containsJSONRPC(body) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func containsJSONRPC(b []byte) bool {
	const m = `"jsonrpc"`
	for i := 0; i+len(m) <= len(b); i++ {
		if string(b[i:i+len(m)]) == m {
			return true
		}
	}
	return false
}

// Addr is the loopback host:port the server listens on.
func (u *Upstream) Addr() string { return u.srv.Listener.Addr().String() }

// Hits is how many requests have reached the upstream.
func (u *Upstream) Hits() int { return int(u.hits.Load()) }

// Requests returns a copy of every recorded request, oldest first.
func (u *Upstream) Requests() []UpstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]UpstreamRequest, len(u.reqs))
	copy(out, u.reqs)
	return out
}

// SetHandler replaces the response handler (nil restores the default). The
// recorder always runs first.
func (u *Upstream) SetHandler(h http.Handler) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.next = h
}
