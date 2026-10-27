package controlplane

import (
	"context"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// This file names the control plane's responsibilities as role interfaces so
// each is understandable and fakeable in isolation. The god-struct Server is
// decomposed conceptually into: PolicyServer (serve allow/deny + ETag long-poll,
// see policyserver.go), ConfigEditor (persist edits), WorkerTracker (fleet
// visibility), and IngestSink (central analytics/mcp/secrets ingest). Consumers
// (notably the dashboard wiring in Handler) depend on these seams, not on the
// concrete Server.

// ConfigEditor is the config-editing seam: it validates and persists edited
// allow/deny policy, behavioral settings and the LLM-provider registry so
// workers pull them on their next poll. In file mode that is an atomic rewrite
// of the served config file; in versioned mode it is a new policy version built
// from head, authored by the Principal in ctx. The YAML-preservation +
// atomic-rename + validate-before-replace behavior lives in the implementation
// (Server).
type ConfigEditor interface {
	// WritePolicy persists an edited allow/deny policy, preserving every other
	// config block byte-for-byte, then wakes long-poll waiters.
	WritePolicy(ctx context.Context, p config.Policy, meta dashboard.WriteMeta) error
	// WriteSettings persists an edited behavioral settings document, preserving
	// every block it does not own byte-for-byte, then wakes long-poll waiters.
	WriteSettings(ctx context.Context, s config.SettingsWire, meta dashboard.WriteMeta) error
	// WriteLLMProviders persists an edited LLM-provider registry, preserving
	// every other block, then wakes long-poll waiters.
	WriteLLMProviders(ctx context.Context, ps []config.LLMProvider, meta dashboard.WriteMeta) error
}

// WorkerTracker is the fleet-tracking seam: it records the three worker→CP
// activities the control plane observes (policy pulls, analytics ingest, and
// heartbeats) and projects the fleet as dashboard rows. *WorkerRegistry is the
// in-memory implementation.
type WorkerTracker interface {
	// SeenPolicyPull records that the named worker fetched policy.
	SeenPolicyPull(proxyID string)
	// SeenIngest records that the named worker forwarded n analytics events.
	SeenIngest(proxyID string, n int)
	// SeenHeartbeat records a heartbeat and the worker's current policy ETag.
	SeenHeartbeat(proxyID, policyETag string)
	// Views returns the registry as dashboard rows, online-first then by id.
	Views() []dashboard.WorkerView
}

// IngestSink is the central-ingest seam: the surface the /central/ingest handler
// drives after storing a worker's event batch — tagging worker activity in the
// registry, storing the worker's MCP snapshot, and recording its by-reference
// secret inventory. It documents the ingest callbacks wired onto the analytics
// IngestHandler without changing that handler's construction.
type IngestSink interface {
	// SeenIngest tags a stored batch of size n to its originating worker.
	SeenIngest(proxyID string, n int)
	// UpdateMCP stores a worker's latest MCP snapshot for the fleet view.
	UpdateMCP(proxyID string, snap analytics.MCPSnapshot)
}

// ingestSink adapts the Server's ingest-time collaborators (the worker registry
// and the mcp store) to the IngestSink seam, so the ingest wiring depends on the
// named surface rather than reaching into Server's fields directly. Its methods
// forward to the existing implementations, so behavior is byte-for-byte
// identical to wiring the callbacks directly.
type ingestSink struct {
	registry *WorkerRegistry
	mcp      *mcpStore
}

func (s *ingestSink) SeenIngest(proxyID string, n int) { s.registry.SeenIngest(proxyID, n) }
func (s *ingestSink) UpdateMCP(proxyID string, snap analytics.MCPSnapshot) {
	s.mcp.Update(proxyID, snap)
}
