package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// hopByHopGRPCHeaders is the set of hop-by-hop headers that must not be
// forwarded across the proxy boundary (they describe a single transport hop, not
// end-to-end semantics). Matched case-insensitively via http.Header canonical
// keys, which is why they are stored in canonical form.
var hopByHopGRPCHeaders = map[string]struct{}{
	"Connection":        {},
	"Proxy-Connection":  {},
	"Keep-Alive":        {},
	"Transfer-Encoding": {},
	"Upgrade":           {},
}

// flushWriter wraps an io.Writer and flushes after every Write, so gRPC
// streaming frames (which arrive incrementally and must reach the client
// promptly) are not buffered by the HTTP/2 server's write path.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

// handleGRPC terminates HTTP/2 on the (already TLS-terminated) client
// connection and reverse-proxies each stream upstream over HTTP/2. Each stream
// runs the shared request-stage pipeline (see serveGRPCStream), so it gets the
// same controls as an HTTP/1.1 request, including the per-request judge when
// needsJudge (a NoMatch destination).
//
// One *http2.Transport is built per client connection so all of that
// connection's streams multiplex over a single upstream HTTP/2 connection.
func (p *Proxy) handleGRPC(clientConn net.Conn, domain string, port int, needsJudge bool) {
	// DialTLSContext ignores the addr the transport would derive from the request
	// URL and always dials the CONNECT-gated destination through the SSRF-safe
	// dialer, negotiating ALPN h2 (required for the upstream to speak HTTP/2).
	rt := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return p.dialTLS(network, net.JoinHostPort(domain, strconv.Itoa(port)), &tls.Config{
				ServerName: domain,
				NextProtos: []string{"h2"},
			})
		},
	}
	defer rt.CloseIdleConnections()

	// ServeConn blocks until the client connection closes and dispatches each
	// HTTP/2 stream concurrently to the handler.
	(&http2.Server{}).ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serveGRPCStream(w, r, rt, domain, port, needsJudge)
		}),
	})
}

// serveGRPCStream handles a single HTTP/2 stream by running it through the SAME
// runRequestStages pipeline as an HTTP/1.1 request (#388): host recheck, the #371
// method/path constraints (still the first policy decision, before any swap or
// upstream write), judge, MCP scan, DLP, secret swap, transforms, forward, and
// response scan. Only the client-leg framing (h2Sink) and the upstream hop
// (forwardH2) differ; a stage added to the pipeline applies to both protocols.
//
// proto is "grpc" when the Content-Type marks a gRPC call, else "http2". A gRPC
// body is streamed verbatim (streamBody): no buffering, no body swap, DLP records
// it partial — exactly how h1 treats a non-text body — and protobuf field swap
// stays deferred.
func (p *Proxy) serveGRPCStream(w http.ResponseWriter, r *http.Request, rt *http2.Transport, domain string, port int, needsJudge bool) {
	isGRPC := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	proto := "http2"
	if isGRPC {
		proto = "grpc"
	}
	s := &requestScope{
		out:        h2Sink{w: w},
		rt:         rt,
		proto:      proto,
		streamBody: isGRPC,
		domain:     domain,
		port:       port,
		needsJudge: needsJudge,
		req:        r,
		reqStart:   time.Now(),
		gw:         p.mcpGateway(),
		liveJudge:  p.judge(),
	}
	defer s.cleanup()
	_ = p.runRequestStages(s)
	if s.abortStream {
		// The echo guard cut a stream whose headers already went out: reset it
		// (RST_STREAM) instead of ending it cleanly.
		panic(http.ErrAbortHandler)
	}
}

// forwardH2 is forward's HTTP/2 leg: it sends the (stage-mutated) request over
// the per-connection http2.Transport and installs the response on the scope. An
// upstream failure is not a policy decision: like the h1 path it is a 502 with no
// analytics event.
func (p *Proxy) forwardH2(s *requestScope) (endSession bool) {
	outURL := &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(s.domain, strconv.Itoa(s.port)),
		Path:     s.req.URL.Path,
		RawPath:  s.req.URL.RawPath,
		RawQuery: s.req.URL.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(s.req.Context(), s.req.Method, outURL.String(), s.req.Body)
	if err != nil {
		return p.badGateway(s)
	}
	copyGRPCHeaders(outReq.Header, s.req.Header)
	// A stage that buffered or rewrote the body left an exact length; otherwise the
	// client body streams full-duplex with unknown length.
	outReq.ContentLength = s.req.ContentLength
	if s.req.Body == nil || s.req.Body == http.NoBody {
		outReq.Body = http.NoBody
	}
	outReq.Host = s.domain

	resp, err := s.rt.RoundTrip(outReq)
	if err != nil {
		return p.badGateway(s)
	}
	s.resp = resp
	return false
}

// copyGRPCHeaders copies every header from src to dst except the hop-by-hop set,
// which describes a single transport hop and must not cross the proxy boundary.
func copyGRPCHeaders(dst, src http.Header) {
	for key, vals := range src {
		if _, hop := hopByHopGRPCHeaders[http.CanonicalHeaderKey(key)]; hop {
			continue
		}
		for _, v := range vals {
			dst.Add(key, v)
		}
	}
}
