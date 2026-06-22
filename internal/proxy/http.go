package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/secrets"
)

const maxBodySwapSize = 10 << 20 // 10 MB

func (p *Proxy) handleHTTP(tlsConn *tls.Conn, br *bufio.Reader, domain string, port int) {
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		// Host header recheck (defense in depth)
		hostOnly := req.Host
		if h, _, err := net.SplitHostPort(req.Host); err == nil {
			hostOnly = h
		}
		if !strings.EqualFold(hostOnly, domain) {
			_ = req.Body.Close()
			return
		}

		var refs []secrets.Reference
		needBodySwap := len(p.cfg.PlaceholderNames) > 0 &&
			req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0

		if len(p.cfg.PlaceholderNames) > 0 {
			// Read body if needed
			var bodyStr string
			if needBodySwap {
				bodyBytes, readErr := io.ReadAll(io.LimitReader(req.Body, maxBodySwapSize+1))
				if readErr != nil {
					writeErrorResponse(tlsConn, 502, "Bad Gateway")
					_ = req.Body.Close()
					return
				}
				if int64(len(bodyBytes)) > maxBodySwapSize {
					writeErrorResponse(tlsConn, 413, "Request body too large for secret substitution")
					_ = req.Body.Close()
					return
				}
				bodyStr = string(bodyBytes)
			}

			// Swap in headers, query, and body
			for _, placeholder := range p.cfg.PlaceholderNames {
				realValue, err := p.cfg.Secrets.GetSecret(placeholder)
				if err != nil {
					writeErrorResponse(tlsConn, 503, "Service Unavailable")
					_ = req.Body.Close()
					return
				}
				swapped := false

				// Header values
				for key, vals := range req.Header {
					for i, v := range vals {
						replaced := strings.ReplaceAll(v, placeholder, realValue)
						if replaced != v {
							req.Header[key][i] = replaced
							swapped = true
						}
					}
				}

				// URL query
				if req.URL.RawQuery != "" {
					params := req.URL.Query()
					changed := false
					for key, vals := range params {
						for i, v := range vals {
							replaced := strings.ReplaceAll(v, placeholder, realValue)
							if replaced != v {
								params[key][i] = replaced
								changed = true
							}
						}
					}
					if changed {
						req.URL.RawQuery = params.Encode()
						swapped = true
					}
				}

				// Body
				if needBodySwap && bodyStr != "" {
					replaced := strings.ReplaceAll(bodyStr, placeholder, realValue)
					if replaced != bodyStr {
						bodyStr = replaced
						swapped = true
					}
				}

				if swapped {
					refs = append(refs, secrets.Ref(realValue))
				}
			}

			// Set swapped body back
			if needBodySwap && bodyStr != "" {
				req.Body = io.NopCloser(strings.NewReader(bodyStr))
				req.ContentLength = int64(len(bodyStr))
			}
		}

		// Apply auth transforms
		for _, mt := range p.cfg.Transformers {
			if mt.Matches(domain) {
				if err := mt.Transformer.Transform(req); err != nil {
					writeErrorResponse(tlsConn, 502, "Bad Gateway")
					_ = req.Body.Close()
					return
				}
			}
		}

		// Forward to upstream
		upstream, err := p.dialTLS("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)), &tls.Config{ServerName: domain})
		if err != nil {
			writeErrorResponse(tlsConn, 502, "Bad Gateway")
			_ = req.Body.Close()
			return
		}

		if err := req.Write(upstream); err != nil {
			_ = upstream.Close()
			writeErrorResponse(tlsConn, 502, "Bad Gateway")
			_ = req.Body.Close()
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
		if err != nil {
			_ = upstream.Close()
			writeErrorResponse(tlsConn, 502, "Bad Gateway")
			_ = req.Body.Close()
			return
		}

		closeAfter := req.Close || resp.Close

		writeErr := resp.Write(tlsConn)

		// Log the decision
		var refStrs []string
		for _, r := range refs {
			refStrs = append(refStrs, r.String())
		}
		_ = p.cfg.Analytics.StoreEvent(analytics.Event{
			Timestamp:      time.Now(),
			Domain:         domain,
			Port:           port,
			Protocol:       "https",
			Method:         req.Method,
			URL:            "https://" + domain + req.URL.RequestURI(),
			Decision:       "allow",
			ResponseStatus: resp.StatusCode,
			SecretRef:      strings.Join(refStrs, ","),
		})

		// Cleanup
		_ = req.Body.Close()
		_ = resp.Body.Close()
		_ = upstream.Close()

		if writeErr != nil || closeAfter {
			return
		}
	}
}

func writeErrorResponse(w io.Writer, statusCode int, statusText string) {
	resp := &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, statusText),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(statusText + "\n")),
		ContentLength: int64(len(statusText) + 1),
	}
	_ = resp.Write(w)
}
