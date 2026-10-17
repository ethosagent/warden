package harness

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The remote-target tests: a Target that hosts the deployment OUT of this
// process (the compose target, #368) implements the optional capability
// interfaces below, and H routes the corresponding calls through it. These
// tests pin the routing with a scripted fake — the same pattern as
// TestWithTarget_HRoutesThroughTheInterface, one test per capability.

// stubTransport is an http.RoundTripper that answers every request with a
// planted response and records what it was asked.
type stubTransport struct {
	status  int
	body    string
	request *http.Request
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.request = req
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(bytes.NewReader([]byte(s.body))),
		Header:     http.Header{"X-Stub": {"yes"}},
	}, nil
}

func (s *stubTransport) CloseIdleConnections() {}

// remoteTarget is a compose-shaped fake Target: well-known hostnames under
// .example.test, the secret the DEPLOYMENT holds (not what WithSecret
// registered), an agent client it owns, and upstream reads that come back
// through the target instead of an in-process fake.
type remoteTarget struct {
	*fakeTarget

	specs       []SecretSpec
	requests    map[string][]RecordedRequest
	allRequests []RecordedRequest // the whole recorder view, all hosts
	connect     int
	metrics     bool // the MetricsSupport answer

	h1Transport, h2Transport *stubTransport
}

func (r *remoteTarget) Host(alias string) (string, error) {
	if alias != "api" && alias != "llm" && alias != "mcp" && alias != "evil" {
		return "", errors.New("remoteTarget: unknown alias " + alias)
	}
	return alias + ".example.test", nil
}

func (r *remoteTarget) TargetSecrets() []SecretSpec { return r.specs }

func (r *remoteTarget) AgentClient(h2 bool) (*http.Client, error) {
	if h2 {
		return &http.Client{Transport: r.h2Transport}, nil
	}
	return &http.Client{Transport: r.h1Transport}, nil
}

func (r *remoteTarget) UpstreamRequests(host string) ([]RecordedRequest, error) {
	return r.requests[host], nil
}

func (r *remoteTarget) AllUpstreamRequests() ([]RecordedRequest, error) {
	return r.allRequests, nil
}

func (r *remoteTarget) ConnectStatus(string) (int, error) { return r.connect, nil }

func (r *remoteTarget) MetricsAvailable() bool { return r.metrics }

func newRemoteTarget() *remoteTarget {
	return &remoteTarget{
		fakeTarget:  &fakeTarget{},
		requests:    map[string][]RecordedRequest{},
		connect:     http.StatusForbidden,
		metrics:     false,
		h1Transport: &stubTransport{status: http.StatusOK, body: "from h1"},
		h2Transport: &stubTransport{status: http.StatusOK, body: "from h2"},
	}
}

// TestWithTarget_HostComesFromTheTarget: a scenario asks the harness for a
// well-known fake's hostname instead of hard-coding it, and the answer comes
// from the target — .example.test on compose, .example.com in-process.
func TestWithTarget_HostComesFromTheTarget(t *testing.T) {
	rt := newRemoteTarget()
	h := New(t, WithTarget(rt), NoLeakCheck())
	if got, want := h.Host("api"), "api.example.test"; got != want {
		t.Errorf("Host(api) = %q, want the target's %q", got, want)
	}
	if got, want := h.Host("evil"), "evil.example.test"; got != want {
		t.Errorf("Host(evil) = %q, want the target's %q", got, want)
	}

	rec := &recordingTB{T: t}
	h2 := New(rec, WithTarget(rt), NoLeakCheck())
	_ = h2.Host("no-such-fake")
	if !rec.Failed() {
		t.Fatal("Host() of an alias the target does not serve must fail the test")
	}
}

// TestInprocess_HostIsExampleCom pins the in-process answer so the L1
// spellings never move: every L1 scenario keeps its .example.com hosts.
func TestInprocess_HostIsExampleCom(t *testing.T) {
	h := New(t)
	for alias, want := range map[string]string{
		"api": "api.example.com", "llm": "llm.example.com", "mcp": "mcp.example.com",
		"grpc": "grpc.example.com", "ws": "ws.example.com", "evil": "evil.example.com",
		"unlisted": "unlisted.example.com",
	} {
		if got := h.Host(alias); got != want {
			t.Errorf("Host(%s) = %q, want %q", alias, got, want)
		}
	}
}

// TestWithTarget_TargetSecretsWinOverOpts: the target holds the deployment's
// real secret wiring, so when it supplies specs the WithSecret values are
// superseded — the placeholder the agent holds, the value the sweep guards and
// Secret() returns are the target's, and an unnamed ask resolves the one spec.
func TestWithTarget_TargetSecretsWinOverOpts(t *testing.T) {
	rt := newRemoteTarget()
	rt.specs = []SecretSpec{{
		Name: "openai", Placeholder: "example_secret_001",
		Value: "CANARY-target", MatchHosts: []string{"api.example.test"},
	}}
	rt.logs = "the deployment leaked CANARY-target"

	h := New(t, WithTarget(rt), NoLeakCheck(), WithSecret("openai", "CANARY-l1-only"))
	if got := h.Placeholder("openai"); got != "example_secret_001" {
		t.Errorf("Placeholder = %q, want the target's placeholder", got)
	}
	// One spec: a scenario's name resolves to the one secret the target holds.
	if got := h.Placeholder("canary"); got != "example_secret_001" {
		t.Errorf("Placeholder(canary) = %q, want the target's only placeholder", got)
	}
	if got := h.Secret("openai"); got != "CANARY-target" {
		t.Errorf("Secret = %q, want the target's value (the one the worker swaps in)", got)
	}

	// The sweep guards the TARGET's value: it trips on the target's value
	// reaching a surface, never on the superseded WithSecret value.
	if lines := h.CanaryLeaks(); len(lines) != 1 || !strings.Contains(lines[0], "worker/control-plane logs") {
		t.Errorf("the target's value in the logs did not trip the sweep: %v", lines)
	}
	rt.logs = "quiet: CANARY-l1-only"
	if lines := h.CanaryLeaks(); len(lines) != 0 {
		t.Errorf("the superseded WithSecret value tripped the sweep: %v", lines)
	}
}

// TestWithTarget_AgentTrafficGoesThroughTheTarget: the agent's HTTP clients
// are the target's (compose: they shell into the agent container), and the
// AgentH2 flavor asks for HTTP/2 explicitly.
func TestWithTarget_AgentTrafficGoesThroughTheTarget(t *testing.T) {
	rt := newRemoteTarget()
	h := New(t, WithTarget(rt), NoLeakCheck())

	resp, err := h.Agent().Get("https://api.example.test/")
	if err != nil {
		t.Fatalf("GET through the target's agent client: %v", err)
	}
	_ = resp.Body.Close()
	if rt.h1Transport.request == nil || rt.h1Transport.request.URL.Host != "api.example.test" {
		t.Error("h.Agent() did not ride the target's transport")
	}

	resp, err = h.AgentH2().Get("https://api.example.test/")
	if err != nil {
		t.Fatalf("GET through the target's h2 agent client: %v", err)
	}
	_ = resp.Body.Close()
	if rt.h2Transport.request == nil {
		t.Error("h.AgentH2() did not ride the target's h2 transport")
	}
}

// TestWithTarget_UpstreamReadsThroughTheTarget: an upstream a scenario asks
// for on a remote target is a VIEW over the target's fake (compose: the
// recorder), its Requests come back through the target, and the in-process
// fault levers fail the test loudly instead of pretending.
func TestWithTarget_UpstreamReadsThroughTheTarget(t *testing.T) {
	rt := newRemoteTarget()
	rt.requests["api.example.test"] = []RecordedRequest{{
		Method: http.MethodPost, Host: "api.example.test", Path: "/v1/canary",
		Header: http.Header{"X-Api-Key": {"CANARY-target"}},
	}}
	h := New(t, WithTarget(rt), NoLeakCheck())

	u := h.Upstream("api.example.test")
	reqs := u.Requests()
	if len(reqs) != 1 || reqs[0].Path != "/v1/canary" {
		t.Fatalf("Requests through the target = %+v, want the planted record", reqs)
	}
	if again := h.Upstream("api.example.test"); again != u {
		t.Error("Upstream() handed back a second handle for the same host")
	}

	rec := &recordingTB{T: t}
	h2 := New(rec, WithTarget(rt), NoLeakCheck())
	h2.Upstream("api.example.test").Delay(5 * time.Second)
	if !rec.Failed() || !strings.Contains(rec.failureMessage(), "in-process-only") {
		t.Errorf("a fault lever on a remote upstream must fail naming the lever, got: %s", rec.failureMessage())
	}
}

// TestWithTarget_CanarySweepCoversUnregisteredUpstreams pins the sweep's
// whole-recorder clause: a target that hosts the fakes records hosts the
// scenario never registered a view for (compose: the fake DNS serves
// mcp/evil/... whether or not h.Upstream was called for them). The sweep must
// scan the WHOLE recorded view — the raw value is allowed only on the hosts
// the secret's MatchHosts list, every encoded form is a leak anywhere — or a
// worker bug that swaps the secret toward an unregistered host passes clean.
func TestWithTarget_CanarySweepCoversUnregisteredUpstreams(t *testing.T) {
	rt := newRemoteTarget()
	rt.specs = []SecretSpec{{
		Name: "openai", Placeholder: "example_secret_001",
		Value: "CANARY-target", MatchHosts: []string{"api.example.test"},
	}}
	// mcp.example.test is in NO registered view (rt.requests is empty); the
	// recorder still holds what reached it: the raw value on the out-of-scope
	// host, and an encoded form riding a request to a third host. In scope,
	// the raw value on api.example.test is the swap working as designed.
	rt.allRequests = []RecordedRequest{
		{
			Method: http.MethodGet, Host: "mcp.example.test", Path: "/",
			Header: http.Header{"Authorization": {"Bearer CANARY-target"}},
		},
		{
			Method: http.MethodPost, Host: "llm.example.test", Path: "/v1/x",
			Body: []byte("q=" + base64.StdEncoding.EncodeToString([]byte("CANARY-target"))),
		},
		{
			Method: http.MethodGet, Host: "api.example.test", Path: "/",
			Header: http.Header{"Authorization": {"Bearer CANARY-target"}},
		},
	}
	h := New(t, WithTarget(rt), NoLeakCheck())

	lines := h.CanaryLeaks()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "mcp.example.test") || !strings.Contains(joined, "raw") {
		t.Errorf("the raw value reaching the unregistered, out-of-scope mcp.example.test must be reported: %v", lines)
	}
	if !strings.Contains(joined, "base64") {
		t.Errorf("the encoded form on llm.example.test must be reported wherever it lands: %v", lines)
	}
	if strings.Contains(joined, "api.example.test") {
		t.Errorf("the raw value on the in-scope api.example.test must stay excused: %v", lines)
	}
}

// TestWithTarget_ConnectStatusThroughTheTarget: the CONNECT probe rides the
// target when the proxy is not reachable from this process.
func TestWithTarget_ConnectStatusThroughTheTarget(t *testing.T) {
	rt := newRemoteTarget()
	h := New(t, WithTarget(rt), NoLeakCheck())
	if got, want := h.ConnectStatus("evil.example.test:443"), http.StatusForbidden; got != want {
		t.Errorf("ConnectStatus = %d, want the target's %d", got, want)
	}
}

// TestWithTarget_MetricsUnavailable: a target without the metrics oracle says
// so; a scenario asks MetricsAvailable before asserting on metrics, Metrics
// itself fails loudly (never a silent pass), and the canary sweep skips the
// surface that does not exist instead of failing on the read.
func TestWithTarget_MetricsUnavailable(t *testing.T) {
	rt := newRemoteTarget()
	// One secret so the sweep has something to guard; the surface under test
	// here is metrics.
	rt.specs = []SecretSpec{{
		Name: "openai", Placeholder: "example_secret_001", Value: "CANARY-metrics-off",
	}}
	h := New(t, WithTarget(rt), NoLeakCheck())
	if h.MetricsAvailable() {
		t.Fatal("MetricsAvailable = true, want the target's false")
	}
	rec := &recordingTB{T: t}
	h.assertCanaryNeverLeaked(rec) // must not read metrics
	if rec.Failed() {
		t.Fatalf("the sweep read metrics on a target without them: %s", rec.failureMessage())
	}

	rec = &recordingTB{T: t}
	h2 := New(rec, WithTarget(rt), NoLeakCheck())
	_ = h2.Metrics()
	if !rec.Failed() || !strings.Contains(rec.failureMessage(), "not available") {
		t.Errorf("Metrics on a target without them must fail naming the gap, got: %s", rec.failureMessage())
	}
}

// TestInprocess_MetricsAvailable pins the other answer of the capability: the
// in-process target DOES carry the metrics oracle (the harness's OTel readers
// are its Metrics source), so the catalog's metrics assertions — default_deny's
// blocked-count leg — really run instead of silently skipping. The skip is
// documented, but only this pin makes its accidental presence on L1 loud.
func TestInprocess_MetricsAvailable(t *testing.T) {
	h := New(t)
	if !h.MetricsAvailable() {
		t.Fatal("MetricsAvailable = false on the in-process target; the metrics assertions would skip on L1")
	}
}
