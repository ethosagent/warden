// Package scenarios is Warden's catalog of behavioural scenarios, written once
// as DATA against the L1 harness (test/harness). Each Scenario is a named
// function over *harness.H; TestScenarios runs every entry of All in-process,
// and #351 runs the same slice against a compose stack through the harness
// Target seam — a scenario body never knows which.
//
// Scenario bodies live in ordinary (non-_test) files precisely so another
// package can import All.
package scenarios

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// Scenario is one named behaviour check.
type Scenario struct {
	Name string
	// L2 marks the scenarios #351 also runs on the compose stack: they use only
	// the harness's Target-level surface (addresses, oracles, faults on the
	// control plane), never the in-process-only levers.
	L2 bool
	// Opts boots the harness this scenario needs (secrets, extra allowed
	// domains, topology). TestScenarios prepends harness.Local(), so a scenario
	// that needs another topology simply lists it.
	Opts []harness.Option
	Run  func(t *testing.T, h *harness.H)
}

// connectStatus sends a CONNECT for hostPort straight to the worker's proxy and
// returns the status code of its reply: the policy decision itself, before any
// client library turns a refusal into an opaque transport error.
func connectStatus(t *testing.T, h *harness.H, hostPort string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort); err != nil {
		t.Fatalf("send CONNECT %s: %v", hostPort, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the CONNECT %s reply: %v", hostPort, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// adminDo calls the worker's admin listener (healthz, refresh-secrets,
// dashboard API) and returns the status and body.
func adminDo(t *testing.T, h *harness.H, method, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+h.AdminAddr()+path, nil)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	// A private transport: the shared default would leave idle connections (and
	// their goroutines) behind the harness's leak check.
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s on the admin listener: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s body: %v", method, path, err)
	}
	return resp.StatusCode, body
}

// get issues a GET through the harness agent and returns status and body,
// closing the response (an unclosed one outlives the harness's leak check).
func get(t *testing.T, h *harness.H, url string, hdr map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", url, err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET %s through the worker: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// eventsFor returns the recorded events for domain with the given decision.
func eventsFor(evs []analytics.Event, domain, decision string) []analytics.Event {
	var out []analytics.Event
	for _, e := range evs {
		if e.Domain == domain && e.Decision == decision {
			out = append(out, e)
		}
	}
	return out
}

// lastRequest is the most recent request an upstream recorded.
func lastRequest(t *testing.T, u *harness.Upstream) harness.RecordedRequest {
	t.Helper()
	reqs := u.Requests()
	if len(reqs) == 0 {
		t.Fatal("the upstream recorded no request; the traffic never reached it")
	}
	return reqs[len(reqs)-1]
}

// decodeEvents parses the dashboard traffic API's JSON array of events.
func decodeEvents(t *testing.T, body []byte) []analytics.Event {
	t.Helper()
	var evs []analytics.Event
	if err := json.Unmarshal(body, &evs); err != nil {
		t.Fatalf("decode the dashboard traffic response: %v\n%s", err, body)
	}
	return evs
}

// reporter is the slice of testing.TB expectKnown needs, so its own test can
// record a failure instead of failing.
type reporter interface {
	Helper()
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// expectKnown checks one expectation that a documented open issue currently
// breaks. With known == "" it is a plain assertion (holds must be true). With
// known set, the row ASSERTS THE VIOLATION: holds must be false, and the moment
// it turns true the row fails with "appears fixed" so the marker gets removed
// instead of silently outliving the bug. A known row is never skipped and its
// assertion is never weakened — it is inverted, on purpose, and loudly.
func expectKnown(t reporter, known string, holds bool, what string) {
	t.Helper()
	switch {
	case known == "" && !holds:
		t.Fatalf("%s", what)
	case known != "" && holds:
		t.Fatalf("%s: appears fixed: remove knownIssue %q", what, known)
	case known != "":
		t.Logf("known violation %s still present (expected until fixed): %s", known, what)
	}
}
