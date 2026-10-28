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
// deferJudge (a NoMatch destination).
//
// One *http2.Transport is built per client connection so all of that
// connection's streams multiplex over a single upstream HTTP/2 connection.
func (p *Proxy) handleGRPC(clientConn net.Conn, domain string, port int, d deferred, ci connIdentity) {
	// DialTLSContext ignores the addr the transport would derive from the request
	// URL and always dials the CONNECT-gated destination through the SSRF-safe
	// dialer. The tls.Config comes from upstreamTLSConfig so the assembly-only
	// UpstreamRootCAs override applies here like on every other upstream TLS
	// dial, plus ALPN h2 (required for the upstream to speak HTTP/2).
	rt := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			upstreamCfg := p.upstreamTLSConfig(domain)
			upstreamCfg.NextProtos = []string{"h2"}
			return p.dialTLS(network, net.JoinHostPort(domain, strconv.Itoa(port)), upstreamCfg)
		},
	}
	defer rt.CloseIdleConnections()

	// ServeConn blocks until the client connection closes and dispatches each
	// HTTP/2 stream concurrently to the handler.
	(&http2.Server{}).ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serveGRPCStream(w, r, rt, domain, port, d, ci)
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
// body is never swapped (protobuf field swap is out of scope: credentials ride
// metadata, which is). With a placeholder in scope for the destination it is
// inspected message by message (guardGRPCBody, #418) and relayed as the
// messages arrive; DLP records it partial, exactly how h1 treats a non-text
// body. The scope's quiescence-tracker slot is entered/exited by the shared
// pipeline (runRequestStages), so an h2 stream is tracked exactly like an h1
// request: one unit from stream start until its terminal bookkeeping.
func (p *Proxy) serveGRPCStream(w http.ResponseWriter, r *http.Request, rt *http2.Transport, domain string, port int, d deferred, ci connIdentity) {
	isGRPC := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	proto := "http2"
	path := PathH2
	if isGRPC {
		proto = "grpc"
		path = PathGRPC
	}
	p.reach(path)

	s := &requestScope{
		out:        h2Sink{w: w},
		rt:         rt,
		proto:      proto,
		streamBody: isGRPC,
		domain:     domain,
		port:       port,
		deferred:   d,
		req:        r,
		reqStart:   time.Now(),
		gw:         p.mcpGateway(),
		liveJudge:  p.judge(),
		ci:         ci,
	}
	defer s.cleanup()
	if isGRPC {
		p.guardGRPCBody(s)
	}
	_ = p.runRequestStages(s)
	if ref, ok := s.grpcGuard.Refusal(); ok && !s.grpcGuard.markAnswered() {
		// The refusal came after the response was already streaming (a bidi or
		// client-streaming call): the headers are out, so end the stream with the
		// refusal status as trailers.
		setGRPCStatus(w.Header(), http.TrailerPrefix, ref)
	}
	if s.abortStream {
		// The echo guard cut a stream whose headers already went out: reset it
		// (RST_STREAM) instead of ending it cleanly.
		panic(http.ErrAbortHandler)
	}
}

// guardGRPCBody wraps a gRPC request body so every message is inspected before
// it is forwarded (#418): a message carrying a placeholder in scope for this
// destination is refused, never relayed, and so is one that cannot be
// inspected (oversize, compressed, malformed). Messages without one are
// released as they arrive. The placeholder set and the scoping are the secret
// swap's own (PlaceholderNames, placeholderInScope); the swap itself still
// handles metadata only. With no placeholder in scope there is nothing to
// protect and the body streams verbatim.
func (p *Proxy) guardGRPCBody(s *requestScope) {
	if s.req.Body == nil || s.req.Body == http.NoBody {
		return
	}
	var phs [][]byte
	for _, name := range p.cfg.PlaceholderNames {
		if name != "" && p.placeholderInScope(name, s.domain) {
			phs = append(phs, []byte(name))
		}
	}
	if len(phs) == 0 {
		return
	}
	maxFrame := p.grpcMaxFrame
	if maxFrame <= 0 {
		maxFrame = maxGRPCFrameBytes
	}
	s.grpcGuard = newGRPCFrameGuard(s.req.Body, phs, maxFrame, func(r grpcRefusal) {
		// Runs on the transport goroutine that reads the body, before the read
		// error is returned, so the deny is recorded before the stream is reset.
		p.emitDeny(s, r.reason, denyExtra{LatencyMs: s.latencyMs(), SwappedRefs: s.swappedNames})
	})
	s.req.Body = s.grpcGuard
}

// setGRPCStatus sets grpc-status and grpc-message on h (prefix is
// http.TrailerPrefix to send them as trailers after the headers went out). The
// message is fixed ASCII text, never request content.
func setGRPCStatus(h http.Header, prefix string, r grpcRefusal) {
	h.Set(prefix+"Grpc-Status", strconv.Itoa(r.code))
	h.Set(prefix+"Grpc-Message", r.message)
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
	// Inspect the call's first message before any byte goes upstream: a refused
	// call then reaches the upstream not at all (see grpcFirstFrameWait).
	s.grpcGuard.Prime(grpcFirstFrameWait)
	if ref, ok := s.grpcGuard.Refusal(); ok {
		return p.answerGRPCRefusal(s, ref)
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
		if ref, ok := s.grpcGuard.Refusal(); ok {
			return p.answerGRPCRefusal(s, ref)
		}
		// The transport surfaces the DialTLSContext error unwrapped, so a dial
		// the SSRF-safe dialer refused is audited here (#391); ordinary
		// failures remain a plain 502 with no event.
		p.recordSSRFDeny(s, err)
		return p.badGateway(s)
	}
	s.resp = resp
	return false
}

// answerGRPCRefusal ends a call the body guard refused before any response
// started: a trailers-only gRPC status, not a 502. The deny is already recorded
// (the guard reports it when it refuses).
func (p *Proxy) answerGRPCRefusal(s *requestScope, ref grpcRefusal) (endSession bool) {
	s.grpcGuard.markAnswered()
	if sink, isH2 := s.out.(h2Sink); isH2 {
		sink.grpcStatus(ref)
	}
	return true
}

// copyGRPCHeaders copies every header from src to dst except the strip set shared
// with the h1 stage (strippedRequestHeaders) and the headers src's Connection
// names: they describe one transport hop, or Warden, and must not cross the proxy
// boundary. "TE: trailers" (gRPC) is kept.
func copyGRPCHeaders(dst, src http.Header) {
	named := make(map[string]struct{})
	for _, k := range connectionTokens(src) {
		named[http.CanonicalHeaderKey(k)] = struct{}{}
	}
	for key, vals := range src {
		ck := http.CanonicalHeaderKey(key)
		if _, hop := strippedRequestHeaders[ck]; hop {
			continue
		}
		if _, hop := named[ck]; hop {
			continue
		}
		for _, v := range vals {
			dst.Add(key, v)
		}
	}
	if isTETrailers(src) {
		dst.Set("TE", "trailers")
	}
}
