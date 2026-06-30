package analytics

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// ProxyIDHeader carries the originating proxy's identifier from a worker to the
// aggregator so the central store can slice events per proxy.
const ProxyIDHeader = "X-Warden-Proxy-ID"

// maxIngestBytes caps a single ingest request body (defense against a runaway
// or hostile sender). Batches are bounded by the worker's batchSize anyway.
const maxIngestBytes = 16 << 20 // 16 MiB

// MCPSnapshot is a worker's MCP gateway state forwarded to the control plane:
// the tool inventory and the value-free observed request/response schema. It
// carries NO request/response values — only field paths, types, and sensitivity
// classes (the same content-free view the worker dashboard shows).
type MCPSnapshot struct {
	Inventory []gateway.InventoryItem        `json:"inventory"`
	Schema    map[string]mcp.ToolProfileView `json:"schema"`
}

// SecretRefView is a configured secret forwarded by REFERENCE only — the real
// value is never serialized, sent, or stored at the control plane.
type SecretRefView struct {
	Placeholder string `json:"placeholder"`
	SHA256      string `json:"sha256"`
	Last4       string `json:"last4"`
	Length      int    `json:"length"`
}

// ingestEnvelope is the worker→CP ingest payload. All fields are optional so the
// worker can push analytics, an MCP snapshot, or a secrets inventory over the
// SAME endpoint — keeping the worker↔CP contract at three interactions. A bare
// JSON array of Event is still accepted for backward compatibility.
type ingestEnvelope struct {
	Events  []Event         `json:"events,omitempty"`
	MCP     *MCPSnapshot    `json:"mcp,omitempty"`
	Secrets []SecretRefView `json:"secrets,omitempty"`
}

// HTTPRemoteStore is a RemoteStore that forwards event batches to a central
// aggregator over HTTP. It is the worker side of central aggregation: the
// SyncWorker pulls oldest events from the local SQLite store and hands them to
// SendBatch, which POSTs them to the aggregator's ingest endpoint.
type HTTPRemoteStore struct {
	endpoint string
	token    string
	proxyID  string
	client   *http.Client
}

var _ RemoteStore = (*HTTPRemoteStore)(nil)

// NewHTTPRemoteStore creates a worker-side remote store posting to endpoint.
// token (optional) is sent as a bearer credential; proxyID (optional) labels
// this worker's events at the aggregator. A nil client uses a 10s-timeout
// default. The aggregator is the worker's own operator-configured control plane
// (commonly on a private network), so the client should NOT use the SafeDialer —
// SSRF protection is for agent-driven egress, not this trusted infra connection.
func NewHTTPRemoteStore(endpoint, token, proxyID string, client *http.Client) (*HTTPRemoteStore, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("analytics: central endpoint is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPRemoteStore{endpoint: endpoint, token: token, proxyID: proxyID, client: client}, nil
}

// SendBatch posts events to the aggregator (in the ingest envelope). It returns
// an error on transport failure or a non-2xx status so the SyncWorker preserves
// the batch and retries (events are pruned locally only on success).
func (h *HTTPRemoteStore) SendBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	return h.post(ingestEnvelope{Events: events})
}

// SendMCP forwards this worker's MCP inventory + observed schema to the CP.
func (h *HTTPRemoteStore) SendMCP(snap MCPSnapshot) error {
	return h.post(ingestEnvelope{MCP: &snap})
}

// SendSecrets forwards this worker's configured secrets BY REFERENCE only.
func (h *HTTPRemoteStore) SendSecrets(refs []SecretRefView) error {
	if len(refs) == 0 {
		return nil
	}
	return h.post(ingestEnvelope{Secrets: refs})
}

// post marshals and POSTs an ingest envelope to the aggregator's endpoint.
func (h *HTTPRemoteStore) post(env ingestEnvelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("analytics: central: marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("analytics: central: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	if h.proxyID != "" {
		req.Header.Set(ProxyIDHeader, h.proxyID)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("analytics: central: send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("analytics: central: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// IngestHandler is the aggregator side of central aggregation: an HTTP handler
// that accepts batches of events from workers and stores them in a CentralStore,
// tagging each with the originating proxy id from the request header.
type IngestHandler struct {
	store     *CentralStore
	token     string
	onIngest  func(proxyID string, n int)                // optional; see SetOnIngest
	onMCP     func(proxyID string, snap MCPSnapshot)     // optional; see SetOnMCP
	onSecrets func(proxyID string, refs []SecretRefView) // optional; see SetOnSecrets
}

// NewIngestHandler returns a handler that ingests event batches into store.
// When token is non-empty, requests must present it as a bearer credential.
func NewIngestHandler(store *CentralStore, token string) *IngestHandler {
	return &IngestHandler{store: store, token: token}
}

// SetOnIngest registers an optional callback invoked after a batch is stored,
// with the sender's proxy id and the batch size. The control plane uses it to
// track which workers are connected and how much they forward.
func (i *IngestHandler) SetOnIngest(fn func(proxyID string, n int)) {
	i.onIngest = fn
}

// SetOnMCP registers an optional callback invoked when a worker forwards its MCP
// snapshot, so the control plane can store it per worker for the fleet view.
func (i *IngestHandler) SetOnMCP(fn func(proxyID string, snap MCPSnapshot)) {
	i.onMCP = fn
}

// SetOnSecrets registers an optional callback for a worker's by-reference
// secrets inventory.
func (i *IngestHandler) SetOnSecrets(fn func(proxyID string, refs []SecretRefView)) {
	i.onSecrets = fn
}

// ServeHTTP accepts POST <json array of Event> and stores each event with the
// sender's proxy id. It returns 204 on success.
func (i *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if i.token != "" {
		got := r.Header.Get("Authorization")
		want := "Bearer " + i.token
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	proxyID := r.Header.Get(ProxyIDHeader)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIngestBytes))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var env ingestEnvelope
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// Backward compatibility: a bare JSON array of events.
		if err := json.Unmarshal(trimmed, &env.Events); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
	} else if err := json.Unmarshal(trimmed, &env); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	for _, e := range env.Events {
		if err := i.store.StoreAggregatedEvent(AggregatedEvent{Event: e, ProxyID: proxyID}); err != nil {
			http.Error(w, "store failed", http.StatusInternalServerError)
			return
		}
	}
	if len(env.Events) > 0 && i.onIngest != nil {
		i.onIngest(proxyID, len(env.Events))
	}
	if env.MCP != nil && i.onMCP != nil {
		i.onMCP(proxyID, *env.MCP)
	}
	if len(env.Secrets) > 0 && i.onSecrets != nil {
		i.onSecrets(proxyID, env.Secrets)
	}
	w.WriteHeader(http.StatusNoContent)
}
