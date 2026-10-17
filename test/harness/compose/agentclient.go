//go:build e2e

package compose

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The agent seam (harness.AgentClients): the protected agent is the agent-1
// CONTAINER, not this process, so h.Agent()'s requests must leave from inside
// it — same network namespace, same proxy env (HTTPS_PROXY=worker-1:8080), same
// trust store — or the scenario would be testing a route the agent does not
// have. The transport below makes one *http.Client request BE one `curl` run
// inside that container (AgentCurlArgs builds the argv, AgentRunStdin feeds the
// body, ParseCurlResponse reads the reply back).

// requestBodyLimit bounds how much of a request body the transport reads into
// the curl stdin (scenario bodies are kilobytes; the bound is against a
// runaway, not a diet).
const requestBodyLimit = 4 << 20

// AgentClient returns agent-1's HTTP client. h2 selects the HTTP/2 flavor: curl
// negotiates h2 with the worker's MITM endpoint over the tunnel (the AgentH2
// client's ALPN lever).
func (t *Target) AgentClient(h2 bool) (*http.Client, error) {
	return &http.Client{Transport: &agentTransport{h2: h2}}, nil
}

// agentTransport is one RoundTrip = one curl run inside the agent container.
type agentTransport struct {
	h2 bool
}

// RoundTrip runs the request through the agent container and parses curl's
// reply. A curl that never got a response (a refused tunnel above all) is a
// TRANSPORT error, exactly as the in-process client reports one — with -i,
// curl prints the proxy's CONNECT reply headers, so the error carries the
// proxy's own words ("403 Forbidden") a scenario may assert on.
func (tr *agentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, fmt.Errorf("compose: the agent transport speaks https through the worker's tunnel, not %v", req.URL)
	}
	var body []byte
	if req.Body != nil { // nil for a bodyless GET; the stdlib transport reads it the same way
		b, err := io.ReadAll(io.LimitReader(req.Body, requestBodyLimit+1))
		if err != nil {
			return nil, fmt.Errorf("compose: read the request body: %w", err)
		}
		_ = req.Body.Close()
		if len(b) > requestBodyLimit {
			return nil, fmt.Errorf("compose: request body exceeds %d bytes", requestBodyLimit)
		}
		body = b
	}
	args, err := AgentCurlArgs(req, body, tr.h2)
	if err != nil {
		return nil, err
	}
	res, err := AgentRunStdin(SvcAgent1, body, args...)
	if err != nil {
		return nil, err
	}
	if res.Exit != 0 {
		return nil, fmt.Errorf("compose: agent curl exited %d for %s: %s%s",
			res.Exit, req.URL, strings.TrimSpace(res.Stdout), strings.TrimSpace(res.Stderr))
	}
	return ParseCurlResponse([]byte(res.Stdout), req)
}
