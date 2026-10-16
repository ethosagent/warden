package proxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

// proxyOnlyHeaders are addressed to Warden, never to the destination (#396).
// Warden reads any value it needs from them before stripHopHeaders runs.
var proxyOnlyHeaders = []string{
	"Proxy-Authorization",
	"Proxy-Connection",
	"X-Warden-Identity",
}

// hopByHopRequestHeaders are the RFC 9110 §7.6.1 hop-by-hop fields (plus the
// legacy Keep-Alive); each describes one transport hop, not the request.
var hopByHopRequestHeaders = []string{
	"Connection",
	"Keep-Alive",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Proxy-Authenticate",
}

// strippedRequestHeaders is the one authoritative strip set (canonical keys),
// shared by the h1 stage and the h2 request leg (copyGRPCHeaders).
var strippedRequestHeaders = func() map[string]struct{} {
	m := make(map[string]struct{}, len(proxyOnlyHeaders)+len(hopByHopRequestHeaders))
	for _, k := range proxyOnlyHeaders {
		m[http.CanonicalHeaderKey(k)] = struct{}{}
	}
	for _, k := range hopByHopRequestHeaders {
		m[http.CanonicalHeaderKey(k)] = struct{}{}
	}
	return m
}()

// connectionTokens returns every token of every Connection header line.
func connectionTokens(h http.Header) []string {
	var toks []string
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				toks = append(toks, tok)
			}
		}
	}
	return toks
}

// isTETrailers reports the only TE value HTTP/2 permits ("TE: trailers", gRPC).
func isTETrailers(h http.Header) bool {
	return strings.EqualFold(strings.TrimSpace(h.Get("TE")), "trailers")
}

// stripHopHeaders removes proxy-only and hop-by-hop headers from the request,
// plus every header named in its Connection header, so none reaches the upstream.
// It runs once, before any stage that rewrites headers (so a placeholder inside
// Proxy-Authorization is never swapped into a real secret) and before forward on
// both protocols. Two things the upstream hop genuinely needs survive:
//   - a WebSocket handshake keeps "Upgrade: websocket" and "Connection: Upgrade";
//   - on HTTP/2, "TE: trailers" (gRPC), the only TE value h2 permits.
//
// The body framing is untouched: Transfer-Encoding lives on req.TransferEncoding
// and req.Close carries Connection: close, and the h1 writer re-derives both.
//
// On h1 it also arms the trailer guard (see trailerGuard): request trailers are
// denied for parity with h2, so none can carry a proxy-only header past this stage.
func (p *Proxy) stripHopHeaders(s *requestScope) (endSession bool) {
	h := s.req.Header
	wsUpgrade := s.rt == nil && isWebSocketUpgrade(h)
	h2Trailers := s.rt != nil && isTETrailers(h)

	// Collect the Connection-named headers before Connection itself is removed.
	for _, k := range connectionTokens(h) {
		h.Del(k)
	}
	for k := range strippedRequestHeaders {
		h.Del(k)
	}
	if wsUpgrade {
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", "websocket")
	}
	if h2Trailers {
		h.Set("TE", "trailers")
	}
	if s.rt == nil && s.req.Body != nil && s.req.Body != http.NoBody {
		// Drop the declared trailer keys now: req.Write would re-emit them as a
		// Trailer: header. net/http still collects the sent values into a fresh map.
		s.req.Trailer = nil
		s.denyTrailers = func() { p.denyTrailers(s) }
		s.req.Body = &trailerGuard{s: s, rc: s.req.Body}
	}
	return false
}

// isWebSocketUpgrade reports an h1 WebSocket handshake: "websocket" among the
// Upgrade tokens (case-insensitive; "websocket, h2c" counts).
func isWebSocketUpgrade(h http.Header) bool {
	for _, v := range h.Values("Upgrade") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "websocket") {
				return true
			}
		}
	}
	return false
}

// errRequestTrailers is what trailerGuard returns instead of EOF when the chunked
// body ended with trailer fields.
var errRequestTrailers = errors.New("request trailers unsupported")

// trailerGuard wraps an h1 request body. net/http fills req.Trailer only once the
// body hits EOF, and req.Write would re-emit those values (undeclared ones too)
// without any stage seeing them, so a Proxy-Authorization or X-Warden-Identity
// trailer would reach the upstream and skip swap, DLP and the MCP scan. At EOF the
// guard checks for trailer values: if any, it marks the scope, clears req.Trailer
// (so nothing can be re-synthesised) and fails the read instead of returning EOF,
// so the terminating chunk is never written. forward / ensureBody turn that into
// the 400 deny. It covers both the buffered (ensureBody) and the streamed body.
type trailerGuard struct {
	s  *requestScope
	rc io.ReadCloser
}

func (g *trailerGuard) Read(b []byte) (int, error) {
	n, err := g.rc.Read(b)
	if err == io.EOF {
		trailers := hasTrailerValues(g.s.req.Trailer)
		g.s.req.Trailer = nil
		if trailers {
			g.s.trailerDenied = true
			return n, errRequestTrailers
		}
	}
	return n, err
}

func (g *trailerGuard) Close() error { return g.rc.Close() }

// hasTrailerValues reports whether any trailer field carries a value; a declared
// but never-sent trailer (key present, no values) is not a trailer.
func hasTrailerValues(t http.Header) bool {
	for _, v := range t {
		if len(v) > 0 {
			return true
		}
	}
	return false
}

// denyTrailers records the request_trailers_unsupported deny and answers 400.
func (p *Proxy) denyTrailers(s *requestScope) {
	p.recordDeny(s, "request_trailers_unsupported")
	s.out.errorResponse(http.StatusBadRequest, "Bad Request")
}
