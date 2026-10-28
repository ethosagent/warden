package dashboard

// dashboard_v3.go adds four read-only, metadata-only endpoints that back
// dashboard tabs which otherwise have no serving API. Each degrades gracefully:
// its source is injected via a SetX setter, and when unset (a worker vs a
// control plane serve the same dashboard) the endpoint returns an empty/absent
// payload rather than failing. Nothing here can surface a secret value or a
// request/response body — every source is value-free by construction
// (secrets.SecretMeta, integration.Alert, receipt metadata, booleans/counts).

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/secrets"
)

// --- setters ---

// SetSecretStore attaches the managed secret store whose KEY metadata (never
// values) the secretstore endpoint lists, plus the name of the active backend
// (echo/aws/env) for display. A nil store (a worker on the env backend, or no
// store configured) leaves the endpoint reporting {backend:"none", entries:[]}.
func (s *Server) SetSecretStore(store secrets.SecretStore, backend string) {
	s.secretStore = store
	s.secretBackend = backend
}

// SetAuthMode records the console sign-in mode (none or oidc) that
// /dashboard/api/setup reports as authMode. Only the control plane sets it.
func (s *Server) SetAuthMode(mode string) {
	s.authMode = mode
}

// SetBackupStatus supplies the scheduled-backup status that /dashboard/api/setup
// reports as backup. fn runs per request and returns nil to omit the field
// (backups off, or a caller that is not an admin). Only the control plane sets
// it.
func (s *Server) SetBackupStatus(fn func(*http.Request) *BackupStatus) {
	s.backupFn = fn
}

// SetAlerts supplies the integration Alert lister for the alerts endpoint. Set
// only where an alert store exists (the control plane); leaving it nil (a worker
// with no integrations) makes the endpoint return []. limit bounds the rows.
func (s *Server) SetAlerts(fn func(limit int) []integration.Alert) {
	s.alertsFn = fn
}

// SetAudit attaches the signed-receipts JSONL path and the trusted Ed25519
// public key so the audit endpoint can count and verify receipts. An empty path
// (receipts disabled, or the control plane which does not sign) leaves the
// receipts block zeroed; the compliance aggregation is always available from the
// event store regardless.
func (s *Server) SetAudit(receiptLogPath string, trustedKey ed25519.PublicKey) {
	s.auditReceiptLog = receiptLogPath
	s.auditTrustedKey = trustedKey
}

// --- 1) secretstore ---

// secretStoreEntry is one managed secret's value-free metadata row.
type secretStoreEntry struct {
	Key       string `json:"key"`
	Version   string `json:"version"`
	UpdatedAt string `json:"updatedAt"`
}

// secretStoreResponse is the payload for /dashboard/api/secretstore: the active
// backend name and the managed KEY metadata (never any value).
type secretStoreResponse struct {
	Backend string             `json:"backend"`
	Entries []secretStoreEntry `json:"entries"`
}

// secretPutRequest is the body accepted by POST /dashboard/api/secretstore. The
// value flows through only for the request: it is handed to the store and then
// logged BY REFERENCE (secrets.Ref) only — never persisted or logged raw in the
// dashboard layer.
type secretPutRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// handleSecretStore serves /dashboard/api/secretstore behind the dashboard's
// existing auth gate. It is method-routed:
//   - GET    lists managed secret KEY metadata (never values).
//   - POST   upserts a key→value into the store (204; value logged by reference).
//   - DELETE removes a key (204, idempotent).
//
// There is deliberately NO "reveal value" path: List is metadata-only and the
// store's Get(value) is never surfaced. Returning a stored value would reintroduce
// the very leak surface Warden exists to close, so the write path is value-free on
// the way out just as the read path always has been.
func (s *Server) handleSecretStore(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getSecretStore(w, r)
	case http.MethodPost:
		s.putSecret(w, r)
	case http.MethodDelete:
		s.deleteSecret(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// getSecretStore serves the GET half: the managed secret KEY list (metadata only
// — key, version, updatedAt — NEVER values). A nil store (or a List error)
// reports the backend name with an empty entries list.
func (s *Server) getSecretStore(w http.ResponseWriter, r *http.Request) {
	resp := secretStoreResponse{Backend: "none", Entries: []secretStoreEntry{}}
	if s.secretStore == nil {
		writeJSON(w, resp)
		return
	}
	if s.secretBackend != "" {
		resp.Backend = s.secretBackend
	}
	metas, err := s.secretStore.List(r.Context())
	if err != nil {
		// Degrade gracefully: keep the backend name, return no entries. The store
		// logs the underlying error; the dashboard must never fail the tab.
		writeJSON(w, resp)
		return
	}
	for _, m := range metas {
		e := secretStoreEntry{Key: m.Key, Version: m.Version}
		if !m.UpdatedAt.IsZero() {
			e.UpdatedAt = m.UpdatedAt.UTC().Format(time.RFC3339)
		}
		resp.Entries = append(resp.Entries, e)
	}
	writeJSON(w, resp)
}

// putSecret serves POST /dashboard/api/secretstore: upsert a key→value into the
// managed store. Like putSettings, it exists only where a writable store is
// configured; a nil store (env backend, or a worker with no store) returns 405 so
// secrets are never mutable where there is nothing to mutate. On success it
// returns 204 with no body — the value is never echoed back. The raw value flows
// through to the store for this request only and is logged BY REFERENCE
// (secrets.Ref: sha256+last4+len), never raw, and never persisted in this layer.
func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		writeError(w, http.StatusMethodNotAllowed, "secret store not configured / not writable on this dashboard")
		return
	}
	var req secretPutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" || req.Value == "" {
		writeError(w, http.StatusBadRequest, "key and value are required")
		return
	}
	// The control plane's admin audit row names the key, never the value.
	adminaudit.Annotate(r.Context(), "secret:"+key, map[string]string{adminaudit.DetailOp: "put"})
	if err := s.secretStore.Put(r.Context(), key, req.Value); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Log by reference only — the raw value must never reach a log line.
	slog.Info("dashboard secret store put", "key", key, "ref", secrets.Ref(req.Value).String())
	w.WriteHeader(http.StatusNoContent)
}

// deleteSecret serves DELETE /dashboard/api/secretstore?key=<key>: remove a key
// from the managed store. Like putSecret it returns 405 when no writable store is
// configured. It is idempotent (deleting an absent key still returns 204). No
// value is ever in hand here, so only the key is logged.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		writeError(w, http.StatusMethodNotAllowed, "secret store not configured / not writable on this dashboard")
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	adminaudit.Annotate(r.Context(), "secret:"+key, map[string]string{adminaudit.DetailOp: "delete"})
	if err := s.secretStore.Delete(r.Context(), key); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("dashboard secret store delete", "key", key)
	w.WriteHeader(http.StatusNoContent)
}

// --- 2) alerts ---

// defaultAlertLimit bounds the alerts endpoint when no ?limit= is supplied.
const defaultAlertLimit = 200

// alertView is one Alert rendered for the dashboard. Every field is bounded,
// egress-safe metadata (integration.Alert is bounded by construction); it never
// carries a body or secret.
type alertView struct {
	ID        string       `json:"id"`
	DedupKey  string       `json:"dedupKey"`
	Category  string       `json:"category"`
	Severity  string       `json:"severity"`
	Subject   alertSubject `json:"subject"`
	Summary   string       `json:"summary"`
	Evidence  string       `json:"evidence"`
	Status    string       `json:"status"`
	Count     int          `json:"count"`
	FirstSeen string       `json:"firstSeen"`
	LastSeen  string       `json:"lastSeen"`
}

// alertSubject mirrors integration.Subject's bounded identifiers.
type alertSubject struct {
	Domain string `json:"domain,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Worker string `json:"worker,omitempty"`
}

// handleAlerts serves GET /dashboard/api/alerts: the integration alert store's
// alerts (metadata only). Supports ?limit= (default defaultAlertLimit). A nil
// source (a worker with no integrations) returns [].
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := defaultAlertLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	out := []alertView{}
	if s.alertsFn != nil {
		for _, a := range s.alertsFn(limit) {
			out = append(out, alertView{
				ID:        a.ID,
				DedupKey:  a.DedupKey,
				Category:  a.Category,
				Severity:  a.Severity.String(),
				Subject:   alertSubject{Domain: a.Subject.Domain, Tool: a.Subject.Tool, Agent: a.Subject.Agent, Worker: a.Subject.Worker},
				Summary:   a.Summary,
				Evidence:  string(a.Evidence),
				Status:    string(a.Status),
				Count:     a.Count,
				FirstSeen: formatTime(a.FirstSeen),
				LastSeen:  formatTime(a.LastSeen),
			})
		}
	}
	writeJSON(w, out)
}

// --- 3) audit ---

// maxAuditEventScan caps the compliance aggregation's event read. It mirrors the
// bound the stats/blocked endpoints use so a large store never materializes an
// unbounded row set for the "prove it" surface.
const maxAuditEventScan = 10000

// maxReceiptTailBytes bounds the receipts-log tail read so a large JSONL log is
// never fully loaded; only the most recent slice is parsed.
const maxReceiptTailBytes = 256 * 1024

// maxRecentReceipts caps the number of receipt summaries returned.
const maxRecentReceipts = 20

// complianceEntry is one aggregated {framework, control} tally derived from
// Event.Compliance tags (e.g. "mitre:T1048" -> framework "mitre", control
// "T1048").
type complianceEntry struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Count     int    `json:"count"`
}

// receiptSummary is one signed receipt's value-free metadata: identity derived
// from the signature, the mediated decision/domain/method, when it was signed,
// and whether its signature verifies against the trusted key.
type receiptSummary struct {
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Domain   string `json:"domain"`
	Method   string `json:"method"`
	SignedAt string `json:"signedAt"`
	Verified bool   `json:"verified"`
}

// receiptsBlock is the receipts half of the audit payload.
type receiptsBlock struct {
	Count         int              `json:"count"`
	VerifiedCount int              `json:"verifiedCount"`
	Recent        []receiptSummary `json:"recent"`
}

// auditResponse is the payload for /dashboard/api/audit.
type auditResponse struct {
	Receipts   receiptsBlock     `json:"receipts"`
	Compliance []complianceEntry `json:"compliance"`
}

// handleAudit serves GET /dashboard/api/audit: the compliance aggregation
// (always available, from the event store) plus the signed-receipts summary
// (optional; zeroed when receipts are disabled or no log is configured).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := s.auditCache.getOrCompute("", s.now(), analyticsCacheTTL, s.computeAudit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONBytes(w, body)
}

// computeAudit builds the audit payload: the compliance tally over the recent
// event window and the receipts summary from the bounded log tail. It is the
// cache-miss path for handleAudit.
func (s *Server) computeAudit() ([]byte, error) {
	resp := auditResponse{
		Receipts:   receiptsBlock{Recent: []receiptSummary{}},
		Compliance: []complianceEntry{},
	}

	// Compliance: aggregate Event.Compliance across the recent event window.
	events, err := s.data.GetEvents(analytics.EventFilter{Limit: maxAuditEventScan})
	if err != nil {
		return nil, err
	}
	resp.Compliance = aggregateCompliance(events)

	// Receipts: read + verify the bounded log tail when configured.
	resp.Receipts = s.receiptsSummary()

	return marshalJSONLine(resp)
}

// aggregateCompliance tallies Event.Compliance control IDs into {framework,
// control, count} rows, splitting each ID on the first ':'. IDs without a ':'
// are reported with an empty framework. Sorted by count desc, then framework,
// then control for a stable payload.
func aggregateCompliance(events []analytics.Event) []complianceEntry {
	type key struct{ framework, control string }
	counts := make(map[key]int)
	for _, e := range events {
		for _, id := range e.Compliance {
			var framework, control string
			if i := strings.IndexByte(id, ':'); i >= 0 {
				framework, control = id[:i], id[i+1:]
			} else {
				control = id
			}
			counts[key{framework, control}]++
		}
	}
	out := make([]complianceEntry, 0, len(counts))
	for k, c := range counts {
		out = append(out, complianceEntry{Framework: k.framework, Control: k.control, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].Control < out[j].Control
	})
	return out
}

// receiptsSummary reads the bounded tail of the signed-receipts JSONL log,
// verifies each receipt against the trusted key, and returns the total count,
// verified count, and the most recent N summaries. A missing/empty log or an
// unset path yields a zeroed block (never an error — the tab must not fail).
func (s *Server) receiptsSummary() receiptsBlock {
	block := receiptsBlock{Recent: []receiptSummary{}}
	if s.auditReceiptLog == "" {
		return block
	}
	lines, err := readTailLines(s.auditReceiptLog, maxReceiptTailBytes)
	if err != nil {
		return block
	}
	summaries := make([]receiptSummary, 0, len(lines))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		receipt, err := audit.UnmarshalReceipt(line)
		if err != nil {
			continue
		}
		block.Count++
		verified := s.verifyReceipt(receipt)
		if verified {
			block.VerifiedCount++
		}
		summaries = append(summaries, receiptSummaryFrom(receipt, verified))
	}
	// Most recent last in the log (append-only JSONL): take the tail N, newest first.
	if len(summaries) > maxRecentReceipts {
		summaries = summaries[len(summaries)-maxRecentReceipts:]
	}
	for i, j := 0, len(summaries)-1; i < j; i, j = i+1, j-1 {
		summaries[i], summaries[j] = summaries[j], summaries[i]
	}
	if len(summaries) > 0 {
		block.Recent = summaries
	}
	return block
}

// verifyReceipt reports whether a receipt's signature is valid. It checks
// against the configured trusted key when one is set; otherwise it falls back to
// the receipt's own embedded public key (self-consistency only).
func (s *Server) verifyReceipt(receipt *audit.Receipt) bool {
	key := s.auditTrustedKey
	if len(key) == 0 {
		key = receipt.PublicKey
	}
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	return audit.Verify(receipt, key)
}

// receiptSummaryFrom derives a value-free summary from a receipt: it parses the
// wrapped analytics.Event (already metadata-only) for decision/domain/method,
// takes signedAt from the receipt timestamp, and derives a stable id from the
// signature. Only the six whitelisted metadata fields are ever surfaced.
func receiptSummaryFrom(receipt *audit.Receipt, verified bool) receiptSummary {
	var ev analytics.Event
	_ = json.Unmarshal(receipt.EventJSON, &ev)
	return receiptSummary{
		ID:       receiptID(receipt),
		Decision: ev.Decision,
		Domain:   ev.Domain,
		Method:   ev.Method,
		SignedAt: formatTime(receipt.Timestamp),
		Verified: verified,
	}
}

// receiptID derives a short, stable, value-free id from a receipt's signature
// (analytics.Event carries no id of its own). Two receipts over the same event
// share a signature, so this is deterministic per receipt.
func receiptID(receipt *audit.Receipt) string {
	const n = 8
	sig := receipt.Signature
	if len(sig) > n {
		sig = sig[:n]
	}
	return hex.EncodeToString(sig)
}

// --- POST /dashboard/api/audit/verify ---

// auditVerifyResponse is the payload for POST /dashboard/api/audit/verify.
type auditVerifyResponse struct {
	Valid bool `json:"valid"`
}

// handleAuditVerify serves POST /dashboard/api/audit/verify: verify a pasted
// receipt JSON. It reports {valid:false} on any parse/verify failure rather than
// erroring, so the demo surface is forgiving. The receipt is verified against the
// trusted key when configured, else against its own embedded key.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, auditVerifyResponse{Valid: false})
		return
	}
	receipt, err := audit.UnmarshalReceipt(raw)
	if err != nil {
		writeJSON(w, auditVerifyResponse{Valid: false})
		return
	}
	writeJSON(w, auditVerifyResponse{Valid: s.verifyReceipt(receipt)})
}

// --- 4) setup ---

// setupResponse is the onboarding-status payload for /dashboard/api/setup: the
// booleans/counts that power the auto-advancing onboarding checklist. All are
// derived from injected sources + the DataSource; no field carries a value.
type setupResponse struct {
	WorkersConnected  int    `json:"workersConnected"`
	FirstEventSeen    bool   `json:"firstEventSeen"`
	PolicyConfigured  bool   `json:"policyConfigured"`
	SecretsConfigured bool   `json:"secretsConfigured"`
	Mode              string `json:"mode"`
	// AuthMode is the console sign-in mode (none or oidc), set by the control
	// plane through SetAuthMode; absent on a worker's dashboard. The UI shows a
	// persistent banner when it is none.
	AuthMode string `json:"authMode,omitempty"`
	// Backup is the scheduled-backup status, present only when the control plane
	// runs backups and the caller is an admin.
	Backup *BackupStatus `json:"backup,omitempty"`
}

// BackupStatus is the value-free state of the control plane's scheduled backups.
// Times are RFC3339 UTC strings, empty when there has been no success yet.
type BackupStatus struct {
	Enabled       bool   `json:"enabled"`
	LastSuccessAt string `json:"lastSuccessAt"`
	LastError     string `json:"lastError"`
	LastSet       string `json:"lastSet"`
	SizeBytes     int64  `json:"sizeBytes"`
}

// handleSetup serves GET /dashboard/api/setup: onboarding status computed from
// the injected sources and the event store. Nil-safe throughout.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp := setupResponse{Mode: s.setupMode(), AuthMode: s.authMode}
	if s.backupFn != nil {
		resp.Backup = s.backupFn(r)
	}

	// workersConnected: the fleet registry size when set (control plane); on a
	// single node the dashboard is itself serving, so report 1.
	if s.workersFn != nil {
		resp.WorkersConnected = len(s.workersFn())
	} else {
		resp.WorkersConnected = 1
	}

	// firstEventSeen: at least one event exists.
	if events, err := s.data.GetEvents(analytics.EventFilter{Limit: 1}); err == nil && len(events) > 0 {
		resp.FirstEventSeen = true
	}

	// policyConfigured: the live (or startup) allowlist is non-empty.
	pol := s.policy
	if s.livePolicy != nil {
		pol = s.livePolicy()
	}
	resp.PolicyConfigured = len(pol.Allowlist) > 0

	// secretsConfigured: a managed store lists >=1 key, OR the policy declares
	// placeholder secrets.
	resp.SecretsConfigured = len(s.policy.Secrets) > 0
	if !resp.SecretsConfigured && s.secretStore != nil {
		if metas, err := s.secretStore.List(r.Context()); err == nil && len(metas) > 0 {
			resp.SecretsConfigured = true
		}
	}

	writeJSON(w, resp)
}

// setupMode reports the proxy's overall enforcement posture for the onboarding
// checklist: "enforce" if any distributed guard (DLP/MCP) is enforcing,
// "monitor" if any is observing, else "off". When no live settings are injected
// (a single-node worker whose local guard modes the dashboard cannot see) it
// reports the honest default "monitor".
func (s *Server) setupMode() string {
	if s.liveSettings == nil {
		return "monitor"
	}
	settings := s.liveSettings()
	if settings == nil {
		return "monitor"
	}
	modes := []string{}
	if settings.DLP != nil {
		modes = append(modes, settings.DLP.Mode)
	}
	if settings.MCP != nil && settings.MCP.Enabled {
		modes = append(modes, settings.MCP.Mode)
	}
	sawMonitor := false
	for _, m := range modes {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "enforce":
			return "enforce"
		case "monitor":
			sawMonitor = true
		}
	}
	if sawMonitor {
		return "monitor"
	}
	// Settings present but no guard in monitor/enforce: report the default posture.
	return "monitor"
}

// --- small helpers ---

// formatTime renders a time as RFC3339 UTC, or "" for the zero time.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// readTailLines returns the newline-delimited lines from the last maxBytes of
// the file at path. When the file exceeds maxBytes it seeks to the tail and
// drops the (likely partial) first line so only whole receipts are parsed.
func readTailLines(path string, maxBytes int64) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-configured audit log path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	dropPartial := false
	if size > maxBytes {
		if _, err := f.Seek(size-maxBytes, io.SeekStart); err != nil {
			return nil, err
		}
		dropPartial = true
	}

	var lines [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	first := true
	for sc.Scan() {
		if first && dropPartial {
			first = false
			continue // discard the truncated first line
		}
		first = false
		line := append([]byte(nil), sc.Bytes()...)
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
