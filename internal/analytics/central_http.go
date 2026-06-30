package analytics

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// proxyIDHeader carries the originating proxy's identifier from a worker to the
// aggregator so the central store can slice events per proxy.
const proxyIDHeader = "X-Warden-Proxy-ID"

// maxIngestBytes caps a single ingest request body (defense against a runaway
// or hostile sender). Batches are bounded by the worker's batchSize anyway.
const maxIngestBytes = 16 << 20 // 16 MiB

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
// default; callers should pass a SafeDialer-backed client in production so
// forwarding obeys the same SSRF protection as proxied traffic.
func NewHTTPRemoteStore(endpoint, token, proxyID string, client *http.Client) (*HTTPRemoteStore, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("analytics: central endpoint is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPRemoteStore{endpoint: endpoint, token: token, proxyID: proxyID, client: client}, nil
}

// SendBatch posts the events as a JSON array to the aggregator. It returns an
// error on transport failure or a non-2xx status so the SyncWorker preserves
// the batch and retries (events are pruned locally only on success).
func (h *HTTPRemoteStore) SendBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("analytics: central: marshal batch: %w", err)
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
		req.Header.Set(proxyIDHeader, h.proxyID)
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
	store *CentralStore
	token string
}

// NewIngestHandler returns a handler that ingests event batches into store.
// When token is non-empty, requests must present it as a bearer credential.
func NewIngestHandler(store *CentralStore, token string) *IngestHandler {
	return &IngestHandler{store: store, token: token}
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
	proxyID := r.Header.Get(proxyIDHeader)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIngestBytes))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var events []Event
	if err := json.Unmarshal(body, &events); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	for _, e := range events {
		if err := i.store.StoreAggregatedEvent(AggregatedEvent{Event: e, ProxyID: proxyID}); err != nil {
			http.Error(w, "store failed", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
