package harness

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

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

// Logs returns everything the target's components have logged so far
// (structured lines, exactly as a deployment's stdout), workers first.
func (h *H) Logs() string { return h.target.Logs() }

// Events returns every analytics event across the workers, worker-1 first.
// It first DRAINS every worker's async analytics writer (the assembly-only
// OnAnalyticsWriter seam), so the events of traffic a scenario has finished
// making are readable immediately — deterministically, never by outwaiting
// the writer's 250ms flush tick. A drain whose batch write FAILED fails the
// test: a failed flush never acks as persisted, and reading on would find a
// short list instead of the events the scenario knows it made.
func (h *H) Events() []analytics.Event {
	h.tb.Helper()
	if err := h.flushAnalytics(); err != nil {
		h.tb.Fatalf("harness: drain analytics writers (a failed flush means the queued events were NOT persisted): %v", err)
	}
	evs, err := h.target.Events()
	if err != nil {
		h.tb.Fatalf("harness: read analytics events: %v", err)
	}
	return evs
}

// Metrics returns the fleet-wide OTel view flattened to name{label=value} ->
// value, SUMMED across workers (an aggregation window is per-worker, so a
// fleet's counter under Metrics() is the total). Counters, gauges and sums
// land under their label set; histograms get two keys per label set, suffixed
// #count and #sum. Labels are sorted, so keys are stable — build expectations
// with MetricKey.
func (h *H) Metrics() map[string]float64 {
	h.tb.Helper()
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
