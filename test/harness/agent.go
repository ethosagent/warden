package harness

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"time"
)

// agentBodyLimit bounds how much of each response body the recording
// transport keeps for the canary oracle.
const agentBodyLimit = 1 << 20

// defaultAgentTimeout is the agent client's per-request budget. It exists so a
// scenario bug fails fast: a Delay fault whose Advance never comes would
// otherwise hang the request until the test binary's own 10-minute timeout. It
// is deliberately generous (a parked request waits for the scenario to notice,
// and -race runs under load) — a healthy scenario never comes near it.
const defaultAgentTimeout = 30 * time.Second

// RecordedResponse is one response the harness agent received, as the agent
// saw it — the "what did the protected workload actually get back" oracle the
// canary sweeps.
type RecordedResponse struct {
	URL    string
	Status int
	Header http.Header
	Body   []byte
	Err    string // non-empty when the transport failed (leak checks still scan)
}

// Agent returns an HTTP client configured the way a protected agent is: its
// requests ride the worker's proxy, and it trusts the worker's MITM CA
// (RootCAs = the harness proxy CA — the same trust a deployment distributes
// to its agents). The client is cached; every scenario shares one agent, so
// AgentResponses() is the full transcript.
//
// Time still belongs to the harness fake clock (a Delay fault holds a request
// until h.Clock().Advance), but the client carries a generous wall-clock
// request timeout (defaultAgentTimeout, 30s) as a FAIL-FAST backstop: a
// scenario that forgets the Advance fails in seconds with a transport error
// instead of hanging until the test binary's 10-minute timeout. Pair Delay
// with Upstream.WaitParked(n) to synchronize deterministically.
func (h *H) Agent() *http.Client {
	h.tb.Helper()
	h.agentOnce.Do(func() {
		base := &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://" + h.ProxyAddr()) },
			TLSClientConfig: &tls.Config{
				RootCAs:    h.proxyCA.pool(),
				MinVersion: tls.VersionTLS12,
			},
		}
		h.agentCl = &http.Client{
			Timeout:   defaultAgentTimeout,
			Transport: &recordingTransport{base: base, h: h},
		}
	})
	return h.agentCl
}

// AgentTLSConfig returns a fresh TLS config trusting the worker's MITM CA — the
// trust a deployment distributes to its agents. Scenarios that speak a protocol
// the plain Agent client cannot (a WebSocket upgrade through a CONNECT tunnel)
// build their connection with it, so they trust exactly what the agent trusts.
func (h *H) AgentTLSConfig() *tls.Config {
	return &tls.Config{RootCAs: h.proxyCA.pool(), MinVersion: tls.VersionTLS12}
}

// AgentH2 is Agent with HTTP/2 negotiated end to end: same proxy, same trust,
// ALPN h2 on the MITM leg. It shares the agent transcript, so
// AssertCanaryNeverLeaked sweeps its responses too. Use it for the h2 and gRPC
// paths, which the worker handles separately from HTTP/1.1.
func (h *H) AgentH2() *http.Client {
	h.tb.Helper()
	h.h2Once.Do(func() {
		base := &http.Transport{
			Proxy:             func(*http.Request) (*url.URL, error) { return url.Parse("http://" + h.ProxyAddr()) },
			ForceAttemptHTTP2: true,
			TLSClientConfig:   h.AgentTLSConfig(),
		}
		h.agentH2Cl = &http.Client{
			Timeout:   defaultAgentTimeout,
			Transport: &recordingTransport{base: base, h: h},
		}
	})
	return h.agentH2Cl
}

// AgentResponses returns a copy of every response the agent has received
// through h.Agent(), in order.
func (h *H) AgentResponses() []RecordedResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]RecordedResponse, len(h.agentRecs))
	copy(out, h.agentRecs)
	return out
}

// recordingTransport wraps the agent's transport and keeps a copy of every
// response (status, headers, bounded body) for the oracles. Recording never
// changes what the agent sees: the body is restored as a fresh reader before
// the response continues.
type recordingTransport struct {
	base http.RoundTripper
	h    *H
}

// CloseIdleConnections forwards to the wrapped transport — without this,
// Client.CloseIdleConnections is a no-op on a custom RoundTripper and the
// agent's idle CONNECT tunnels keep the worker's session goroutines alive
// past cleanup.
func (t *recordingTransport) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }
	if ci, ok := t.base.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		t.h.mu.Lock()
		t.h.agentRecs = append(t.h.agentRecs, RecordedResponse{
			URL: req.URL.String(),
			Err: fmtError(err),
		})
		t.h.mu.Unlock()
		return resp, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, agentBodyLimit+1))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))

	t.h.mu.Lock()
	t.h.agentRecs = append(t.h.agentRecs, RecordedResponse{
		URL:    req.URL.String(),
		Status: resp.StatusCode,
		Header: resp.Header.Clone(),
		Body:   body,
	})
	t.h.mu.Unlock()
	return resp, nil
}

// fmtError renders a transport error's message (nil-safe) for the transcript.
func fmtError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
