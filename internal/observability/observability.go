// Package observability provides Warden's OpenTelemetry emission seam.
//
// Phase 1 (this package) wires OTel **metrics** — a Prometheus exporter served
// at GET /metrics on the admin listener plus an optional OTLP/grpc push to a
// collector — and a structured slog logger builder. Traces (Phase 2) and
// collector recipes (Phase 3) are deferred and intentionally not built here.
//
// Non-negotiable invariant: no raw secret value and no request/response body
// ever lands in a metric label or a log record. All metric labels are bounded
// enums or configured names (decision, protocol, reason, kind, outcome, stage,
// placeholder ref) — never a raw domain, which is unbounded. The blocked
// metric's reason label is the one declared deny-reason set (internal/denyreason)
// plus the MCP gateway's bounded verdict reasons.
//
// Bounded MCP enum values (the fixed sets the MCP gateway emits; documented here
// so the bounded-label contract is explicit — an MCP tool name is NEVER a label,
// it is unbounded and lives only in the analytics store):
//
//	RecordBlocked(reason):       mcp_tool_denied, mcp_tool_condition, mcp_poisoning,
//	                              mcp_schema_drift_blocked, mcp_args_constraint, mcp_args_too_large,
//	                              ssrf_blocked, ssrf_denied_hostname (#391 dial refusals)
//	RecordScanFinding(kind):      mcp_args_injection, mcp_args_leak, mcp_args_pii,
//	                              mcp_args_constraint, mcp_args_too_large,
//	                              mcp_result_injection, mcp_result_leak, mcp_result_pii,
//	                              mcp_poisoning_description_injection, mcp_schema_drift_added,
//	                              mcp_chain_read_then_send, mcp_chain_permission_probing,
//	                              mcp_chain_rapid_repeat
//	ObserveAddedLatency(stage):  mcp_scan, identity
//	RecordIdentityVerify:         result is an identity status, reason an identity.Reason
//
// Disabled mode is free: when Config.Enabled is false (or the *Metrics is nil)
// New returns a nil *Metrics and a nil http.Handler, and every record method is
// a nil-receiver no-op with no allocation and no latency on the hot path.
package observability

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config configures the observability emitter. The zero value is disabled and
// harmless.
type Config struct {
	// Enabled gates the entire subsystem. When false, New returns a nil
	// *Metrics, a nil handler, and a no-op shutdown.
	Enabled bool
	// ServiceName and ServiceVersion populate the OTel resource.
	ServiceName    string
	ServiceVersion string
	// MetricsEnabled gates the Prometheus /metrics exporter. When false (but
	// Enabled true), only the OTLP push (if configured) is wired and no handler
	// is returned.
	MetricsEnabled bool
	// OTLPEndpoint, when non-empty, enables an OTLP/grpc metric push to a
	// collector (e.g. "otel-collector:4317"). The export is outbound and batched
	// off the request path.
	OTLPEndpoint string
	// ResourceAttributes are extra bounded key/value pairs added to the resource
	// (e.g. warden.proxy.id for fleet slicing). Never put secrets here.
	ResourceAttributes map[string]string
	// Reader, when set, is attached to the meter provider as an EXTRA metric
	// reader, alongside the Prometheus exporter and/or the OTLP push, so a test
	// can collect metrics in-process (an sdk/metric ManualReader). Assembly-only
	// like worker.Overrides: production wiring never sets it, and no YAML key or
	// CLI flag can — enforced by TestOverridesAreNotConfigurable in
	// internal/worker.
	Reader sdkmetric.Reader
}

// Metrics is the OTel metric emitter. All record methods are safe on a nil
// receiver (the disabled case), so callers never need to nil-check.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	requests       metric.Int64Counter
	blocked        metric.Int64Counter
	secretSwaps    metric.Int64Counter
	scanFindings   metric.Int64Counter
	judge          metric.Int64Counter
	identityVerify metric.Int64Counter
	auditLines     metric.Int64Counter
	auditErrors    metric.Int64Counter
	auditDropped   metric.Int64Counter
	addedLatency   metric.Float64Histogram
	breakerOpen    metric.Int64UpDownCounter
	cacheStale     metric.Int64UpDownCounter
	buildInfo      metric.Int64Gauge
}

// ShutdownFunc flushes and closes the meter provider. It is always non-nil; in
// disabled mode it is a no-op.
type ShutdownFunc func(context.Context) error

// New builds the emitter from cfg. It returns:
//
//   - the *Metrics emitter (nil when disabled — record methods are nil-safe),
//   - the Prometheus /metrics http.Handler (nil when disabled or metrics off),
//   - a shutdown func that flushes+closes the meter provider (no-op when
//     disabled),
//   - an error if SDK construction fails.
//
// When cfg.Enabled is false New short-circuits to (nil, nil, no-op, nil) so the
// disabled path costs nothing.
func New(cfg Config) (*Metrics, http.Handler, ShutdownFunc, error) {
	noop := func(context.Context) error { return nil }
	if !cfg.Enabled {
		return nil, nil, noop, nil
	}

	res, err := buildResource(cfg)
	if err != nil {
		return nil, nil, noop, err
	}

	var (
		readers []sdkmetric.Option
		handler http.Handler
	)

	if cfg.MetricsEnabled {
		// A dedicated Prometheus registry keeps Warden's metrics off the global
		// default registry (no surprise process/go collectors unless we add them).
		registry := prometheus.NewRegistry()
		promExp, perr := promexporter.New(promexporter.WithRegisterer(registry))
		if perr != nil {
			return nil, nil, noop, fmt.Errorf("observability: prometheus exporter: %w", perr)
		}
		readers = append(readers, sdkmetric.WithReader(promExp))
		handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	}

	if cfg.OTLPEndpoint != "" {
		// OTLP/grpc push to a collector. Insecure transport: the collector is
		// expected to be on a trusted/private network; TLS/headers are collector
		// config per the OTel spec and deferred here.
		otlpExp, oerr := otlpmetricgrpc.New(
			context.Background(),
			otlpmetricgrpc.WithEndpoint(cfg.OTLPEndpoint),
			otlpmetricgrpc.WithInsecure(),
		)
		if oerr != nil {
			return nil, nil, noop, fmt.Errorf("observability: otlp metric exporter: %w", oerr)
		}
		readers = append(readers, sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(otlpExp, sdkmetric.WithInterval(15*time.Second)),
		))
	}

	// Assembly-only in-process reader (the L1 harness's metrics oracle). A nil
	// reader (production) adds nothing.
	if cfg.Reader != nil {
		readers = append(readers, sdkmetric.WithReader(cfg.Reader))
	}

	opts := append([]sdkmetric.Option{sdkmetric.WithResource(res)}, readers...)
	provider := sdkmetric.NewMeterProvider(opts...)

	m, err := newMetrics(provider, cfg.ServiceVersion)
	if err != nil {
		_ = provider.Shutdown(context.Background())
		return nil, nil, noop, err
	}

	shutdown := func(ctx context.Context) error { return provider.Shutdown(ctx) }
	return m, handler, shutdown, nil
}

// buildResource assembles the OTel resource (service.name/version + extra
// bounded attributes). Resource attributes are operator-configured and must
// never carry secrets.
func buildResource(cfg Config) (*resource.Resource, error) {
	name := cfg.ServiceName
	if name == "" {
		name = "warden"
	}
	attrs := []attribute.KeyValue{
		semconv.ServiceName(name),
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	for k, v := range cfg.ResourceAttributes {
		attrs = append(attrs, attribute.String(k, v))
	}
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, attrs...),
	)
}

// newMetrics constructs the instrument set on the given provider and records
// build-info once.
func newMetrics(provider *sdkmetric.MeterProvider, serviceVersion string) (*Metrics, error) {
	meter := provider.Meter("github.com/ethosagent/warden")
	m := &Metrics{provider: provider, meter: meter}

	var err error
	if m.requests, err = meter.Int64Counter(
		"warden.requests.total",
		metric.WithDescription("Total proxy requests by decision and protocol."),
	); err != nil {
		return nil, fmt.Errorf("observability: requests counter: %w", err)
	}
	if m.blocked, err = meter.Int64Counter(
		"warden.blocked.total",
		metric.WithDescription("Total blocked requests by reason."),
	); err != nil {
		return nil, fmt.Errorf("observability: blocked counter: %w", err)
	}
	if m.secretSwaps, err = meter.Int64Counter(
		"warden.secret.swaps.total",
		metric.WithDescription("Total secret swaps by placeholder reference (name, never value)."),
	); err != nil {
		return nil, fmt.Errorf("observability: secret swaps counter: %w", err)
	}
	if m.scanFindings, err = meter.Int64Counter(
		"warden.scan.findings.total",
		metric.WithDescription("Total scan findings by kind."),
	); err != nil {
		return nil, fmt.Errorf("observability: scan findings counter: %w", err)
	}
	if m.judge, err = meter.Int64Counter(
		"warden.judge.decisions.total",
		metric.WithDescription("Total LLM judge decisions by outcome."),
	); err != nil {
		return nil, fmt.Errorf("observability: judge counter: %w", err)
	}
	if m.auditLines, err = meter.Int64Counter(
		"warden.auditlog.lines.total",
		metric.WithDescription("JSON decision stream lines written, by schema."),
	); err != nil {
		return nil, fmt.Errorf("observability: auditlog lines counter: %w", err)
	}
	if m.auditErrors, err = meter.Int64Counter(
		"warden.auditlog.write_errors.total",
		metric.WithDescription("JSON decision stream write failures by reason (marshal, write, flush)."),
	); err != nil {
		return nil, fmt.Errorf("observability: auditlog write errors counter: %w", err)
	}
	if m.auditDropped, err = meter.Int64Counter(
		"warden.auditlog.dropped.total",
		metric.WithDescription("JSON decision stream events dropped because the sink queue was full or closed."),
	); err != nil {
		return nil, fmt.Errorf("observability: auditlog dropped counter: %w", err)
	}
	if m.identityVerify, err = meter.Int64Counter(
		"warden.identity.verify.total",
		metric.WithDescription("Identity token outcomes by result (identity status) and reason."),
	); err != nil {
		return nil, fmt.Errorf("observability: identity verify counter: %w", err)
	}
	if m.addedLatency, err = meter.Float64Histogram(
		"warden.request.added_latency",
		metric.WithDescription("Added latency by pipeline stage."),
		metric.WithUnit("s"),
	); err != nil {
		return nil, fmt.Errorf("observability: added latency histogram: %w", err)
	}
	if m.breakerOpen, err = meter.Int64UpDownCounter(
		"warden.llm.circuit_breaker.open",
		metric.WithDescription("LLM circuit breaker open state by provider (1 open, 0 closed)."),
	); err != nil {
		return nil, fmt.Errorf("observability: breaker gauge: %w", err)
	}
	if m.cacheStale, err = meter.Int64UpDownCounter(
		"warden.secret.cache.stale",
		metric.WithDescription("Secret cache stale state by placeholder reference (1 stale, 0 fresh)."),
	); err != nil {
		return nil, fmt.Errorf("observability: cache stale gauge: %w", err)
	}
	if m.buildInfo, err = meter.Int64Gauge(
		"warden.build.info",
		metric.WithDescription("Build info; always 1, attributes carry version and go_version."),
	); err != nil {
		return nil, fmt.Errorf("observability: build info gauge: %w", err)
	}

	if serviceVersion == "" {
		serviceVersion = "unknown"
	}
	m.buildInfo.Record(context.Background(), 1, metric.WithAttributes(
		attribute.String("version", serviceVersion),
		attribute.String("go_version", runtime.Version()),
	))

	return m, nil
}

// RecordRequest increments warden.requests.total{decision,protocol}. decision
// and protocol are bounded enums ("allow"/"deny", "tcp"/"https"/...).
func (m *Metrics) RecordRequest(decision, protocol string) {
	if m == nil {
		return
	}
	m.requests.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("decision", decision),
		attribute.String("protocol", protocol),
	))
}

// RecordBlocked increments warden.blocked.total{reason}. reason is the ONE
// declared deny-reason set (internal/denyreason — policy_no_match,
// policy_denylist, rate_limited, time_window, the #371 constraint reasons,
// judge, no_tls, …) plus the MCP gateway's own bounded verdict reasons
// (mcp_tool_denied, mcp_poisoning, …). Every deny event and its metric carry
// the SAME value. See the package doc for the bounded-label contract; never
// pass an unbounded value (e.g. a tool name).
func (m *Metrics) RecordBlocked(reason string) {
	if m == nil {
		return
	}
	m.blocked.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("reason", reason),
	))
}

// RecordAuditLogLine increments warden.auditlog.lines.total{schema}. schema is
// the bounded record schema id (warden.decision.v1).
func (m *Metrics) RecordAuditLogLine(schema string) {
	if m == nil {
		return
	}
	m.auditLines.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("schema", schema),
	))
}

// RecordAuditLogWriteError increments warden.auditlog.write_errors.total{reason}.
// reason is one of the bounded values marshal, write or flush.
func (m *Metrics) RecordAuditLogWriteError(reason string) {
	if m == nil {
		return
	}
	m.auditErrors.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("reason", reason),
	))
}

// RecordAuditLogDropped adds n to warden.auditlog.dropped.total. n <= 0 is
// ignored.
func (m *Metrics) RecordAuditLogDropped(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.auditDropped.Add(context.Background(), int64(n))
}

// RecordSecretSwap increments warden.secret.swaps.total{placeholder_ref}.
// placeholderRef is the configured placeholder NAME (bounded), never the value.
func (m *Metrics) RecordSecretSwap(placeholderRef string) {
	if m == nil {
		return
	}
	m.secretSwaps.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("placeholder_ref", placeholderRef),
	))
}

// RecordScanFinding increments warden.scan.findings.total{kind}. kind is a
// bounded enum (injection/leakage/mcp-poisoning, plus the MCP scan kinds listed
// in the package doc, e.g. mcp_args_pii/mcp_result_injection/
// mcp_chain_read_then_send). Never pass an unbounded value (e.g. a tool name).
func (m *Metrics) RecordScanFinding(kind string) {
	if m == nil {
		return
	}
	m.scanFindings.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("kind", kind),
	))
}

// RecordJudge increments warden.judge.decisions.total{outcome}. outcome is a
// bounded enum ("allow"/"deny").
func (m *Metrics) RecordJudge(outcome string) {
	if m == nil {
		return
	}
	m.judge.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

// RecordIdentityVerify increments warden.identity.verify.total{result,reason}.
// result is the bounded identity status (none|valid|invalid|expired|
// unverified|conflict) and reason the bounded identity.Reason set, "none" when
// there is no reason. It is not incremented while identity is off, so no
// result="off" series appears here (off is an event status, not a counter label).
// Never pass token text or a claim value.
func (m *Metrics) RecordIdentityVerify(result, reason string) {
	if m == nil {
		return
	}
	m.identityVerify.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.String("reason", reason),
	))
}

// ObserveAddedLatency records warden.request.added_latency{stage} in seconds.
// stage is a bounded enum (tls/policy/swap/forward, plus "mcp_scan" for the MCP
// gateway scan stage).
func (m *Metrics) ObserveAddedLatency(stage string, d time.Duration) {
	if m == nil {
		return
	}
	m.addedLatency.Record(context.Background(), d.Seconds(), metric.WithAttributes(
		attribute.String("stage", stage),
	))
}

// SetCircuitBreakerOpen sets warden.llm.circuit_breaker.open{provider}. The
// UpDownCounter is moved to the absolute open/closed state.
func (m *Metrics) SetCircuitBreakerOpen(provider string, open bool) {
	if m == nil {
		return
	}
	v := int64(0)
	if open {
		v = 1
	}
	m.breakerOpen.Add(context.Background(), v, metric.WithAttributes(
		attribute.String("provider", provider),
	))
}

// RegisterAnalyticsQueueDepth wires an observable gauge
// (warden.analytics.queue_depth) whose value is read from observe() on each
// metric collection. observe() should return the async analytics writer's
// current queue depth — a saturation/backpressure indicator (a persistently
// high value means SQLite is the write bottleneck). Nil-safe no-op when metrics
// are disabled; call once at assembly. No labels: queue depth is a single
// process-wide gauge.
func (m *Metrics) RegisterAnalyticsQueueDepth(observe func() int64) error {
	if m == nil {
		return nil
	}
	_, err := m.meter.Int64ObservableGauge(
		"warden.analytics.queue_depth",
		metric.WithDescription("Depth of the async analytics write queue (backpressure/saturation indicator)."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(observe())
			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("observability: analytics queue depth gauge: %w", err)
	}
	return nil
}

// SetSecretCacheStale sets warden.secret.cache.stale{placeholder_ref}.
// placeholderRef is the placeholder NAME, never the value.
func (m *Metrics) SetSecretCacheStale(placeholderRef string, stale bool) {
	if m == nil {
		return
	}
	v := int64(0)
	if stale {
		v = 1
	}
	m.cacheStale.Add(context.Background(), v, metric.WithAttributes(
		attribute.String("placeholder_ref", placeholderRef),
	))
}
