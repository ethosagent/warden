package integration

import (
	"context"
	"time"
)

// Integration is the base contract every integration implements. It opts into
// delivery capabilities by ALSO implementing the optional interfaces below
// (Alerter, EventStreamer), discovered by type-assertion — no empty stubs.
type Integration interface {
	// Type is the stable registry key: "webhook", "slack", "pagerduty", …
	Type() string
	// Start is called once with the reserved System handle and this instance's
	// decoded Config. In v1 System exposes no mutating actions; it is present so
	// inbound "act on the system" can be added later without changing this
	// signature.
	Start(ctx context.Context, sys System, cfg Config) error
	// Stop releases resources and MUST be idempotent.
	Stop(ctx context.Context) error
}

// Alerter receives the routed subset of Alerts this instance is configured for.
// Implement this to be usable as an alert destination. Delivery is at-least-once,
// so implementations MUST be idempotent on Alert.ID.
type Alerter interface {
	Alert(ctx context.Context, a Alert) error
}

// EventStreamer receives the raw event feed for SIEM / log-forwarding sinks.
// Defined in M1 but NOT wired: the raw event firehose is a fundamentally
// higher-volume stream with a different backpressure regime (sampling/batching,
// not coalesce-by-key). Wiring is M2.
type EventStreamer interface {
	OnEvent(ctx context.Context, e Event) error
}

// System is the reserved inbound seam handed to each integration at Start. In
// v1 it exposes ZERO methods; read/action methods (Snapshot/Subscribe/Do) land
// in a later milestone without changing the Start signature.
type System interface{}

// Event is a minimal placeholder for the raw event feed consumed by
// EventStreamer (M2). This package stays free of any analytics import; Phase 2
// will bridge analytics.Event → this type at the wiring boundary.
type Event struct {
	RuleID  string
	Subject Subject
	Ts      time.Time
}
