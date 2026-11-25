package security

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// Tunnel is a CONNECT tunnel the test holds open across a cut: the agent that
// opened it with a good token and keeps sending requests on it. Stack.Do opens
// a tunnel per request and closes it; the lifetime cases need the same tunnel
// to outlive a key rotation, a block or a disable, and to see whether the next
// request on it is served, refused or the connection closed.
type Tunnel struct {
	// Open is the CONNECT reply: Status 200 when the tunnel is open.
	Open Response

	conn net.Conn
	tc   *tls.Conn
	r    *bufio.Reader
	host string
	// hdr is the X-Warden-Identity token sent with every request ("" = none).
	hdr string
	raw bool
}

// OpenTunnel opens a CONNECT tunnel through w carrying token on
// Proxy-Authorization and, over TransportTerminated, on X-Warden-Identity of
// every request. It does not fail on a refusal: Tunnel.Open holds the reply.
// With StackOptions.NoCA the tunnel is raw and the client speaks TLS to the
// upstream itself. The tunnel closes with the test.
func (s *Stack) OpenTunnel(tb testing.TB, w *Worker, tr Transport, token string) *Tunnel {
	tb.Helper()
	conn, err := net.DialTimeout("tcp", w.ProxyAddr, 10*time.Second)
	if err != nil {
		tb.Fatalf("security: dial %s: %v", w.Name, err)
	}
	t := &Tunnel{conn: conn, host: UpstreamHost, raw: s.opts.NoCA}
	tb.Cleanup(func() { _ = conn.Close() })
	if tr == TransportTerminated {
		t.hdr = token
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	pre := "CONNECT " + UpstreamHost + ":443 HTTP/1.1\r\nHost: " + UpstreamHost + ":443\r\n"
	if token != "" {
		pre += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+token)) + "\r\n"
	}
	if _, err := io.WriteString(conn, pre+"\r\n"); err != nil {
		tb.Fatalf("security: write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		tb.Fatalf("security: read the CONNECT reply: %v", err)
	}
	t.Open = Response{Status: resp.StatusCode, Header: resp.Header, ConnectStatus: resp.StatusCode, ConnectHeader: resp.Header}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		t.Open.Body, t.Open.ConnectBody = string(b), string(b)
		return t
	}
	pool := s.ProxyCA.Pool()
	if t.raw {
		pool = s.UpstreamCA.Pool()
	}
	t.tc = tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: UpstreamHost, MinVersion: tls.VersionTLS12})
	if err := t.tc.Handshake(); err != nil {
		tb.Fatalf("security: the handshake through the tunnel failed: %v", err)
	}
	t.r = bufio.NewReader(t.tc)
	return t
}

// Get sends one keep-alive GET on the tunnel and returns the reply. A non-nil
// error means the tunnel is closed or the reply never came.
func (t *Tunnel) Get(tb testing.TB) (Response, error) {
	tb.Helper()
	if t.tc == nil {
		return Response{}, errors.New("the tunnel never opened")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+t.host+"/", nil)
	if err != nil {
		tb.Fatalf("security: build the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+SwappedPlaceholder)
	if t.hdr != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+t.hdr)
	}
	_ = t.conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := req.Write(t.tc); err != nil {
		return Response{}, err
	}
	resp, err := http.ReadResponse(t.r, req)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}, nil
}

// MustGet is Get that fails the test when the tunnel is closed.
func (t *Tunnel) MustGet(tb testing.TB) Response {
	tb.Helper()
	r, err := t.Get(tb)
	if err != nil {
		tb.Fatalf("security: a request on the open tunnel failed: %v", err)
	}
	return r
}

// Closed reports whether the worker has closed the tunnel: it reads with a
// short deadline, so an open idle tunnel answers false and a closed one (EOF,
// reset) true. It consumes nothing an idle tunnel would send.
func (t *Tunnel) Closed() bool {
	if t.tc == nil {
		return true
	}
	_ = t.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := t.r.Peek(1)
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return true
}
