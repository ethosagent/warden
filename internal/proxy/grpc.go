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

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/secrets"
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
// connection and reverse-proxies each stream upstream over HTTP/2. It is only
// reached for destinations that are STATICALLY allowed (needsJudge == false):
// HTTP/2 carries no HTTP/1 request the inline judge can inspect, so a NoMatch
// destination fails closed before ever reaching here (see handleTLS). CONNECT
// admission only could-matched the destination; each stream re-evaluates the
// per-request method/path constraints (#371) in serveGRPCStream.
//
// Secret placeholders are swapped in request METADATA (headers) only. gRPC
// message bodies are streamed verbatim — protobuf message-field swap is
// explicitly deferred (see plan/Feat-gRPC-Support.md: "Phase first on
// metadata-level secret swap; protobuf body field swap is more involved").
//
// One *http2.Transport is built per client connection so all of that
// connection's streams multiplex over a single upstream HTTP/2 connection.
func (p *Proxy) handleGRPC(clientConn net.Conn, domain string, port int) {
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
			p.serveGRPCStream(w, r, rt, domain, port)
		}),
	})
}

// serveGRPCStream handles a single HTTP/2 stream: the #371 method/path
// constraint check, metadata secret-swap, upstream round-trip, and response +
// trailer forwarding. proto is "grpc" when the Content-Type marks a gRPC call,
// else "http2" (a plain HTTP/2 request).
func (p *Proxy) serveGRPCStream(w http.ResponseWriter, r *http.Request, rt *http2.Transport, domain string, port int) {
	isGRPC := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	proto := "http2"
	if isGRPC {
		proto = "grpc"
	}

	// #371: the per-request constraint check on the HTTP/2 path, before the
	// metadata swap and before any upstream write — the same enforcement-point
	// contract as the HTTP/1.1 constraintGate (CONNECT admission only
	// could-matched the constraints; this evaluation is authoritative and counts
	// the request exactly once). The matched values are the pseudo-headers as
	// sent: r.Method (:method, case-sensitive) and r.URL.EscapedPath() — the
	// http2 server parses the raw :path with url.ParseRequestURI, so
	// EscapedPath() is the exact percent-encoded path that goes upstream, never
	// a decoded one. A NoMatch cannot occur here (the destination was statically
	// allowed at CONNECT) but falls through fail-closed-safe either way.
	verdict := p.cfg.Policy.EvaluateRequest(domain, port, policy.SchemeHTTPS, r.Method, r.URL.EscapedPath())
	if verdict.Decision == policy.Deny {
		reason := verdict.Reason
		if reason == "" {
			reason = "policy"
		}
		fullURL := "https://" + domain + r.URL.RequestURI()
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  proto,
			Method:    r.Method,
			URL:       fullURL,
			Decision:  "deny",
			Reason:    reason,
		})
		p.cfg.Metrics.RecordRequest("deny", proto)
		p.cfg.Metrics.RecordBlocked(reason)
		p.logDecision(decisionLog{
			Domain: domain, Port: port, Protocol: proto,
			Method: r.Method, URL: fullURL, Decision: "deny",
			Reason: reason,
		})
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Swap secret placeholders in request headers (metadata) only. Snapshot the
	// live secret provider once so a concurrent cache.ttl swap can't change it
	// mid-substitution. The body is never read or modified (streamed verbatim).
	var refs []secrets.Reference
	var swappedNames []string
	if len(p.cfg.PlaceholderNames) > 0 {
		secretsProvider := p.secrets()
		var outOfScope []string
		for _, placeholder := range p.cfg.PlaceholderNames {
			// Destination scoping (#373): see swapSecrets in http.go. domain is the
			// CONNECT/SNI host, never the request's :authority.
			if !p.placeholderInScope(placeholder, domain) {
				if headerCarriesPlaceholder(r.Header, placeholder) {
					outOfScope = append(outOfScope, placeholder)
				}
				continue
			}
			realValue, err := secretsProvider.GetSecret(placeholder)
			if err != nil {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			swapped := false
			for key, vals := range r.Header {
				for i, v := range vals {
					replaced := strings.ReplaceAll(v, placeholder, realValue)
					// Basic auth (git over HTTPS): see swapSecrets in http.go.
					// Authorization only; never Proxy-Authorization.
					if replaced == v && key == "Authorization" {
						replaced, _ = swapBasicAuth(v, placeholder, realValue)
					}
					if replaced != v {
						r.Header[key][i] = replaced
						swapped = true
					}
				}
			}
			if swapped {
				refs = append(refs, secrets.Ref(realValue))
				// placeholder is the configured NAME (bounded, log-safe), never
				// the secret value.
				swappedNames = append(swappedNames, placeholder)
			}
		}
		if len(outOfScope) > 0 {
			p.recordOutOfScope(domain, port, proto, r.Method, r.URL.RequestURI(), outOfScope)
		}
	}

	// Build the upstream request, streaming the client body full-duplex.
	outURL := &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(domain, strconv.Itoa(port)),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	copyGRPCHeaders(outReq.Header, r.Header)
	outReq.ContentLength = -1 // streaming; length unknown
	outReq.Host = domain

	resp, err := rt.RoundTrip(outReq)
	if err != nil {
		// Upstream failure is not a policy decision: mirror the HTTP path, which
		// writes a 502 and emits NO analytics event on an upstream dial/round-trip
		// failure.
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Forward response headers, pre-declaring announced trailers so the HTTP/2
	// server sends them as trailers rather than as (illegally late) headers.
	copyGRPCHeaders(w.Header(), resp.Header)
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the body through a flushing writer so streaming gRPC frames are not
	// buffered.
	fw := &flushWriter{w: w}
	if f, ok := w.(http.Flusher); ok {
		fw.f = f
	}
	_, _ = io.Copy(fw, resp.Body)

	// Emit trailers that arrived after the body (grpc-status, grpc-message, etc.).
	// http.TrailerPrefix keys set on the header map after WriteHeader are sent as
	// trailers.
	for k, vals := range resp.Trailer {
		for _, v := range vals {
			w.Header().Set(http.TrailerPrefix+k, v)
		}
	}

	// Log ALLOW exactly like the HTTP success path.
	var refStrs []string
	for _, ref := range refs {
		refStrs = append(refStrs, ref.String())
	}
	secretRef := strings.Join(refStrs, ",")
	fullURL := "https://" + domain + r.URL.RequestURI()
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp:      time.Now(),
		Domain:         domain,
		Port:           port,
		Protocol:       proto,
		Method:         r.Method,
		URL:            fullURL,
		Decision:       "allow",
		ResponseStatus: resp.StatusCode,
		SecretRef:      secretRef,
	})
	p.cfg.Metrics.RecordRequest("allow", proto)
	for _, name := range swappedNames {
		p.cfg.Metrics.RecordSecretSwap(name)
	}
	p.logDecision(decisionLog{
		Domain: domain, Port: port, Protocol: proto,
		Method: r.Method, URL: fullURL, Decision: "allow",
		ResponseStatus: resp.StatusCode, SecretRef: secretRef,
	})
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
