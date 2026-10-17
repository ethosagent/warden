package proxy

import (
	"fmt"
	"io"
	"net/http"
)

// responseSink is the seam between the shared per-request stage pipeline
// (runRequestStages) and the wire protocol of the CLIENT leg. The stages decide
// WHAT to say to the agent (a terminal error, a relayed upstream response, an
// incrementally scanned stream); the sink owns HOW it is framed: raw HTTP/1.1
// bytes on the TLS conn for h1, an http.ResponseWriter for h2. One pipeline,
// two framings — a stage added to runRequestStages applies to both protocols.
type responseSink interface {
	// errorResponse writes a terminal status + one-line text body.
	errorResponse(status int, text string)
	// relay writes the whole upstream response (status, headers, body, and any
	// trailers) to the client. A non-nil error means the client leg is broken.
	relay(resp *http.Response) error
	// stream writes only the status line and headers of resp and returns the
	// writer the caller tees the (incrementally scanned) body into.
	stream(resp *http.Response) (io.Writer, error)
}

// connSink frames responses as HTTP/1.1 bytes on the MITM-terminated TLS conn.
type connSink struct{ w io.Writer }

func (c connSink) errorResponse(status int, text string) { writeErrorResponse(c.w, status, text) }

func (c connSink) relay(resp *http.Response) error { return resp.Write(c.w) }

func (c connSink) stream(resp *http.Response) (io.Writer, error) {
	// resp.Write cannot be used because the body is teed through a scanner. This
	// preserves Content-Type, Transfer-Encoding, Cache-Control, etc.
	statusLine := fmt.Sprintf("HTTP/%d.%d %03d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))
	if _, err := io.WriteString(c.w, statusLine); err != nil {
		return nil, err
	}
	if err := resp.Header.Write(c.w); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(c.w, "\r\n"); err != nil {
		return nil, err
	}
	return c.w, nil
}

// h2Sink frames responses on an HTTP/2 stream's http.ResponseWriter. Bodies are
// always written through a flushing writer so streaming responses (gRPC server
// streams, SSE) reach the client promptly instead of sitting in the h2 write
// buffer.
type h2Sink struct{ w http.ResponseWriter }

func (h h2Sink) errorResponse(status int, text string) { http.Error(h.w, text, status) }

func (h h2Sink) flushing() *flushWriter {
	fw := &flushWriter{w: h.w}
	if f, ok := h.w.(http.Flusher); ok {
		fw.f = f
	}
	return fw
}

func (h h2Sink) writeHeader(resp *http.Response) {
	copyGRPCHeaders(h.w.Header(), resp.Header)
	// Pre-declare announced trailers so the HTTP/2 server sends them as trailers
	// rather than as (illegally late) headers.
	for k := range resp.Trailer {
		h.w.Header().Add("Trailer", k)
	}
	h.w.WriteHeader(resp.StatusCode)
}

func (h h2Sink) relay(resp *http.Response) error {
	h.writeHeader(resp)
	_, err := io.Copy(h.flushing(), resp.Body)
	// Trailers that arrived after the body (grpc-status, grpc-message, ...).
	// http.TrailerPrefix keys set after WriteHeader are sent as trailers.
	for k, vals := range resp.Trailer {
		for _, v := range vals {
			h.w.Header().Set(http.TrailerPrefix+k, v)
		}
	}
	return err
}

func (h h2Sink) stream(resp *http.Response) (io.Writer, error) {
	h.writeHeader(resp)
	return h.flushing(), nil
}
