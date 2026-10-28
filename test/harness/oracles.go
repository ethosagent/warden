package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The oracles: what a scenario ASSERTS on. Every observable surface the
// harness boots — the workers' structured logs, their analytics stores, the
// OTel meter, the control plane's fleet API — is readable through H, and all
// of it goes through the Target interface (production packages on the
// in-process target: analytics.GetEvents, the dashboard API), never a side
// channel.

// awaitQuiescence blocks until every worker's in-flight request scopes have
// finished their terminal bookkeeping — the deterministic #363 wait. Each
// worker's quiescence tracker (the assembly-only Overrides.Inflight seam) is
// waited on in turn, bounded by the harness's quiescence deadline; expiring it
// fails the test NAMING the work still in flight, never reading short. The
// wait wakes on the drain itself (no polling): finished traffic reaches
// quiescence in microseconds, and an OPEN stream (WS/SSE) never counts — its
// scope stepped out when its response was delivered and only re-enters when
// the stream ends. Targets without in-process workers (compose) have no
// trackers; their oracles wait on the target itself.
func (h *H) awaitQuiescence() {
	h.tb.Helper()
	if len(h.inflights) == 0 {
		return
	}
	deadline := time.Now().Add(h.quiescenceDeadline)
	type stuckWorker struct {
		name string
		open []string
	}
	var stuck []stuckWorker
	for i, tr := range h.inflights {
		ctx, cancel := context.WithTimeout(context.Background(), time.Until(deadline))
		err := tr.WaitIdle(ctx)
		cancel()
		if err == nil {
			continue
		}
		stuck = append(stuck, stuckWorker{
			name: fmt.Sprintf("worker-%d", i+1),
			open: tr.InFlight(),
		})
	}
	if len(stuck) == 0 {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "harness: %d worker(s) still had requests in flight after %s of waiting; "+
		"the oracles wait for every in-flight request's terminal bookkeeping (event, metric, decision log) "+
		"so they never read short — finish or release the traffic below before reading:",
		len(stuck), h.quiescenceDeadline)
	for _, s := range stuck {
		fmt.Fprintf(&b, "\n  %s:", s.name)
		for _, desc := range s.open {
			fmt.Fprintf(&b, "\n    %s", desc)
		}
	}
	h.tb.Fatal(b.String())
}

// Logs returns everything the target's components have logged so far
// (structured lines, exactly as a deployment's stdout), workers first. Like
// every oracle it first waits for the workers' in-flight request scopes to
// finish their terminal bookkeeping — a decision log is bookkeeping too. A
// read that failed fails the test: a log surface the oracles cannot see must
// never read as an empty (clean) one.
func (h *H) Logs() string {
	h.tb.Helper()
	h.awaitQuiescence()
	logs, err := h.target.Logs()
	if err != nil {
		h.tb.Fatalf("harness: read the components' logs: %v", err)
	}
	return logs
}

// Events returns every analytics event across the workers, worker-1 first.
// It first WAITS for every in-flight request scope to finish its terminal
// bookkeeping (the proxy records an allowed request's event only after the
// response is in the agent's hands — the #363 race), then DRAINS every
// worker's async analytics writer (the assembly-only OnAnalyticsWriter seam),
// so the events of traffic a scenario has finished making are readable
// immediately — deterministically, never by outwaiting the writer's 250ms
// flush tick. A drain whose batch write FAILED fails the test: a failed flush
// never acks as persisted, and reading on would find a short list instead of
// the events the scenario knows it made.
func (h *H) Events() []analytics.Event {
	h.tb.Helper()
	h.awaitQuiescence()
	if err := h.flushAnalytics(); err != nil {
		h.tb.Fatalf("harness: drain analytics writers (a failed flush means the queued events were NOT persisted): %v", err)
	}
	evs, err := h.target.Events()
	if err != nil {
		h.tb.Fatalf("harness: read analytics events: %v", err)
	}
	return evs
}

// SeedEvents writes events into worker-1's analytics store, for scenarios that
// prove read-side behaviour on fields the proxy does not stamp yet. It is an
// in-process lever: a target that cannot seed (compose) fails the test, so a
// scenario using it must not set L2.
func (h *H) SeedEvents(evs ...analytics.Event) {
	h.tb.Helper()
	sd, ok := h.target.(interface {
		SeedEvents([]analytics.Event) error
	})
	if !ok {
		h.tb.Fatalf("harness: this target cannot seed events (in-process only)")
	}
	if err := sd.SeedEvents(evs); err != nil {
		h.tb.Fatalf("%v", err)
	}
}

// Metrics returns the fleet-wide OTel view flattened to name{label=value} ->
// value, SUMMED across workers (an aggregation window is per-worker, so a
// fleet's counter under Metrics() is the total). Like every oracle it first
// waits for the workers' in-flight request scopes to finish their terminal
// bookkeeping. Counters, gauges and sums land under their label set;
// histograms get two keys per label set, suffixed #count and #sum. Labels are
// sorted, so keys are stable — build expectations with MetricKey.
func (h *H) Metrics() map[string]float64 {
	h.tb.Helper()
	h.awaitQuiescence()
	if !h.MetricsAvailable() {
		h.tb.Fatalf("harness: Metrics are not available on this target (compose exports no OTel endpoint); " +
			"ask MetricsAvailable first and skip the metrics assertion explicitly on such a target")
	}
	m, err := h.target.Metrics()
	if err != nil {
		h.tb.Fatalf("harness: collect metrics: %v", err)
	}
	return m
}

// collectMetrics flattens one OTel collection into out (the shape MetricKey
// documents). Shared by the in-process target.
func collectMetrics(rm metricdata.ResourceMetrics, out map[string]float64) {
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch agg := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range agg.DataPoints {
					out[MetricKey(m.Name, attrs(dp.Attributes))] += float64(dp.Value)
				}
			case metricdata.Sum[float64]:
				for _, dp := range agg.DataPoints {
					out[MetricKey(m.Name, attrs(dp.Attributes))] += dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range agg.DataPoints {
					out[MetricKey(m.Name, attrs(dp.Attributes))] += float64(dp.Value)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range agg.DataPoints {
					out[MetricKey(m.Name, attrs(dp.Attributes))] += dp.Value
				}
			case metricdata.Histogram[float64]:
				for _, dp := range agg.DataPoints {
					key := MetricKey(m.Name, attrs(dp.Attributes))
					out[key+"#count"] += float64(dp.Count)
					out[key+"#sum"] += dp.Sum
				}
			case metricdata.Histogram[int64]:
				for _, dp := range agg.DataPoints {
					key := MetricKey(m.Name, attrs(dp.Attributes))
					out[key+"#count"] += float64(dp.Count)
					out[key+"#sum"] += float64(dp.Sum)
				}
			}
		}
	}
}

// MetricKey is the stable key format Metrics() uses: name{sorted k=v pairs}.
// Scenarios build expectations through it instead of string-hoping.
func MetricKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+labels[k])
	}
	return name + "{" + strings.Join(pairs, ",") + "}"
}

// attrs flattens an OTel attribute set into a plain map for MetricKey.
func attrs(set attribute.Set) map[string]string {
	out := make(map[string]string, set.Len())
	for _, kv := range set.ToSlice() {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

// CPClient is the harness's view of the control plane's HTTP API: the same
// bearer-token client an operator's dashboard uses, trusting the CA the
// target reports for the control plane (in-process: the harness-minted proxy
// CA).
type CPClient struct {
	h     *H
	addr  string
	token string
	cl    *http.Client
}

// CP returns the control-plane client (cached): the address, bearer token and
// CA all come from the Target, so a compose target needs no scenario change.
// Its fault methods (Stop, Start) live in faults.go with the rest of the
// fault surface.
func (h *H) CP() *CPClient {
	h.tb.Helper()
	h.cpOnce.Do(func() {
		token, err := h.target.ControlPlaneToken()
		if err != nil {
			h.tb.Fatalf("harness: control-plane token: %v", err)
		}
		caPool, err := h.target.ControlPlaneCA()
		if err != nil {
			h.tb.Fatalf("harness: control-plane CA: %v", err)
		}
		h.cpCl = &CPClient{
			h:     h,
			addr:  h.ControlPlaneAddr(),
			token: token,
			cl: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    caPool,
						MinVersion: tls.VersionTLS12,
					},
				},
			},
		}
	})
	return h.cpCl
}

// GetJSON GETs a control-plane path with the bearer token and decodes the
// response into v.
func (c *CPClient) GetJSON(path string, v any) error {
	req, err := http.NewRequest(http.MethodGet, "https://"+c.addr+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("harness: control plane %s = %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// PostJSON POSTs in as JSON to a control-plane path with the bearer token and
// decodes the response into out (nil to ignore it). A non-200 reply is an
// error carrying the status and the control plane's message.
func (c *CPClient) PostJSON(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+c.addr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("harness: control plane POST %s = %d: %s", path, resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// IngestEvents posts events to the control plane's /central/ingest exactly as a
// worker's sync does (bearer token, X-Warden-Proxy-ID), so a scenario can prove
// CP read-side behaviour on fields the proxy does not stamp yet.
func (c *CPClient) IngestEvents(proxyID string, evs []analytics.Event) error {
	body, err := json.Marshal(map[string]any{"events": evs})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+c.addr+"/central/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set(analytics.ProxyIDHeader, proxyID)
	resp, err := c.cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("harness: control plane ingest = %d", resp.StatusCode)
	}
	return nil
}

// RawResponse is a control-plane reply as DoWorker returns it.
type RawResponse struct {
	Status int
	Header http.Header
	Body   string
}

// DoWorker sends one request to the control plane with the credential the caller
// chooses (bearer "" sends no Authorization header; a non-empty proxyID sets
// X-Warden-Proxy-ID), so a scenario can play a worker or an intruder. A
// transport error fails the test; any HTTP status is returned as is.
func (c *CPClient) DoWorker(method, path, bearer, proxyID, body string) RawResponse {
	c.h.tb.Helper()
	req, err := http.NewRequest(method, "https://"+c.addr+path, strings.NewReader(body))
	if err != nil {
		c.h.tb.Fatalf("harness: build request: %v", err)
	}
	return c.doWorkerReq(req, bearer, proxyID, body)
}

// HoldWorker sends one request with the credential and extra headers the
// caller chooses (a held GET /policy?wait=30s with If-None-Match, say) from a
// goroutine and returns the channel its reply arrives on. A transport error is
// reported as Status 0 with the error in Body, because the scenario's test
// goroutine, not this one, owns the testing.TB.
func (c *CPClient) HoldWorker(method, path, bearer string, hdr http.Header) <-chan RawResponse {
	out := make(chan RawResponse, 1)
	go func() {
		req, err := http.NewRequest(method, "https://"+c.addr+path, nil)
		if err != nil {
			out <- RawResponse{Body: err.Error()}
			return
		}
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := c.sendWorker(req, bearer, "", "")
		if err != nil {
			out <- RawResponse{Body: err.Error()}
			return
		}
		out <- resp
	}()
	return out
}

func (c *CPClient) doWorkerReq(req *http.Request, bearer, proxyID, body string) RawResponse {
	c.h.tb.Helper()
	resp, err := c.sendWorker(req, bearer, proxyID, body)
	if err != nil {
		c.h.tb.Fatalf("harness: control plane %s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

func (c *CPClient) sendWorker(req *http.Request, bearer, proxyID, body string) (RawResponse, error) {
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if proxyID != "" {
		req.Header.Set(analytics.ProxyIDHeader, proxyID)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		return RawResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return RawResponse{Status: resp.StatusCode, Header: resp.Header, Body: string(b)}, nil
}

// Workers lists the fleet view: every worker that has pulled policy or
// heartbeated, with its online state.
func (c *CPClient) Workers() ([]dashboard.WorkerView, error) {
	var out []dashboard.WorkerView
	if err := c.GetJSON("/dashboard/api/workers", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CloseIdleConnections drops the client's keep-alives (cleanup).
func (c *CPClient) CloseIdleConnections() { c.cl.CloseIdleConnections() }
