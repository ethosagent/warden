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

func (p *Proxy) handleHTTP(tlsConn *tls.Conn, br *bufio.Reader, domain string, port int, needsJudge bool) {
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

		// Inline judge: only for requests that matched no static rule. The judge
		// is never consulted for statically allowed/denied requests (static rules
		// always win). It receives auth *presence* only, never the auth value,
		// and fails closed (deny) on any error. A judge "allow" is still subject
		// to every remaining check (secret swap, transforms, forwarding). On
		// allow, the reason is carried onto the single forwarding event below so
		// there is exactly one audit event per request (no double-counting); on
		// deny the request terminates here, so it logs its own event.
		var judgeReason string
		if needsJudge {
			fullURL := "https://" + domain + req.URL.RequestURI()
			_, hasAuth := req.Header["Authorization"]
			verdict := p.cfg.Judge.Evaluate(
				p.cfg.AgentID, req.Method, fullURL, domain,
				req.Header.Get("Content-Type"), hasAuth,
			)
			if verdict.Decision != "allow" {
				_ = p.cfg.Analytics.StoreEvent(analytics.Event{
					Timestamp:   time.Now(),
					Domain:      domain,
					Port:        port,
					Protocol:    "https",
					Method:      req.Method,
					URL:         fullURL,
					Decision:    "deny",
					JudgeReason: verdict.Reason,
				})
				p.cfg.Metrics.RecordRequest("deny", "https")
				p.cfg.Metrics.RecordBlocked("judge")
				p.cfg.Metrics.RecordJudge("deny")
				p.logDecision(decisionLog{
					Domain: domain, Port: port, Protocol: "https",
					Method: req.Method, URL: fullURL, Decision: "deny",
					JudgeReason: verdict.Reason,
				})
				writeErrorResponse(tlsConn, 403, "Forbidden")
				_ = req.Body.Close()
				return
			}
			judgeReason = verdict.Reason
			p.cfg.Metrics.RecordJudge("allow")
		}

		var refs []secrets.Reference
		var swappedNames []string
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
					// placeholder is the configured NAME (bounded, log-safe),
					// never the secret value.
					swappedNames = append(swappedNames, placeholder)
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
		fullURL := "https://" + domain + req.URL.RequestURI()
		secretRef := strings.Join(refStrs, ",")
		_ = p.cfg.Analytics.StoreEvent(analytics.Event{
			Timestamp:      time.Now(),
			Domain:         domain,
			Port:           port,
			Protocol:       "https",
			Method:         req.Method,
			URL:            fullURL,
			Decision:       "allow",
			ResponseStatus: resp.StatusCode,
			SecretRef:      secretRef,
			JudgeReason:    judgeReason, // empty unless a judge allowed this request
		})
		p.cfg.Metrics.RecordRequest("allow", "https")
		for _, name := range swappedNames {
			p.cfg.Metrics.RecordSecretSwap(name)
		}
		p.logDecision(decisionLog{
			Domain: domain, Port: port, Protocol: "https",
			Method: req.Method, URL: fullURL, Decision: "allow",
			ResponseStatus: resp.StatusCode, SecretRef: secretRef,
			JudgeReason: judgeReason,
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
