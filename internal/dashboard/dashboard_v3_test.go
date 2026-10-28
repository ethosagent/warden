package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/secrets"
)

// --- fakes ---

// fakeSecretStore is a value-free SecretStore double: List returns canned
// metadata (or an error); the value verbs are never exercised by the dashboard.
type fakeSecretStore struct {
	metas []secrets.SecretMeta
	err   error
}

func (f *fakeSecretStore) Get(context.Context, string) (string, error) { return "", nil }
func (f *fakeSecretStore) Put(context.Context, string, string) error   { return nil }
func (f *fakeSecretStore) Delete(context.Context, string) error        { return nil }
func (f *fakeSecretStore) List(context.Context) ([]secrets.SecretMeta, error) {
	return f.metas, f.err
}

// writableSecretStore is a stateful SecretStore double for the WRITE path: Put
// upserts a key, Delete removes it, List reflects the current key set. It never
// retains the raw value (mirroring a real backend), so the value-hygiene tests
// prove the dashboard — not the store — is what keeps values out of logs/wire.
type writableSecretStore struct {
	mu   sync.Mutex
	keys map[string]secrets.SecretMeta
}

func newWritableSecretStore() *writableSecretStore {
	return &writableSecretStore{keys: map[string]secrets.SecretMeta{}}
}

func (s *writableSecretStore) Get(context.Context, string) (string, error) { return "", nil }

func (s *writableSecretStore) Put(_ context.Context, key, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key] = secrets.SecretMeta{Key: key, Version: "1"}
	return nil
}

func (s *writableSecretStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, key)
	return nil
}

func (s *writableSecretStore) List(context.Context) ([]secrets.SecretMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]secrets.SecretMeta, 0, len(s.keys))
	for _, m := range s.keys {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func emptyProvider() *fakeSecretProvider { return &fakeSecretProvider{values: map[string]string{}} }

// --- 1) secretstore ---

func TestSecretStore_ListsMetadataNoValues(t *testing.T) {
	updated := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeSecretStore{metas: []secrets.SecretMeta{
		{Key: "OPENAI_API_KEY", Version: "v3", UpdatedAt: updated},
		{Key: "STRIPE_KEY", Version: "v1"},
	}}
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSecretStore(store, config.SecretBackendEcho)

	rr := doGet(t, srv.Handler(), "/dashboard/api/secretstore")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp secretStoreResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Backend != "echo" {
		t.Fatalf("backend = %q, want echo", resp.Backend)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(resp.Entries))
	}
	if resp.Entries[0].Key != "OPENAI_API_KEY" || resp.Entries[0].Version != "v3" {
		t.Fatalf("entry[0] = %+v", resp.Entries[0])
	}
	if resp.Entries[0].UpdatedAt != "2026-06-01T12:00:00Z" {
		t.Fatalf("updatedAt = %q", resp.Entries[0].UpdatedAt)
	}
	if resp.Entries[1].UpdatedAt != "" {
		t.Fatalf("zero-time updatedAt should render empty, got %q", resp.Entries[1].UpdatedAt)
	}
	// No value must ever appear in the body — SecretMeta is value-free, but assert
	// the wire form carries no "value" key regardless.
	if strings.Contains(rr.Body.String(), "\"value\"") {
		t.Fatalf("secretstore body must never carry a value: %s", rr.Body.String())
	}
}

func TestSecretStore_NilStoreReportsNone(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	rr := doGet(t, srv.Handler(), "/dashboard/api/secretstore")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp secretStoreResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Backend != "none" {
		t.Fatalf("backend = %q, want none", resp.Backend)
	}
	if len(resp.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(resp.Entries))
	}
	if resp.Entries == nil {
		t.Fatal("entries must be [] not null")
	}
}

func TestSecretStore_ListErrorDegradesToBackendOnly(t *testing.T) {
	store := &fakeSecretStore{err: context.DeadlineExceeded}
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSecretStore(store, config.SecretBackendAWS)
	rr := doGet(t, srv.Handler(), "/dashboard/api/secretstore")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (must not fail the tab)", rr.Code)
	}
	var resp secretStoreResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Backend != "aws" || len(resp.Entries) != 0 {
		t.Fatalf("on List error want {aws, []}, got %+v", resp)
	}
}

func TestSecretStore_PutUpsertsThenListsAndDeletes(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSecretStore(newWritableSecretStore(), config.SecretBackendEcho)
	h := srv.Handler()

	// POST upserts -> 204 with no body (the value is never echoed).
	rr := doPost(t, h, "/dashboard/api/secretstore", `{"key":"OPENAI_API_KEY","value":"sk-live-XYZ"}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("POST status = %d, want 204", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("POST body must be empty, got %q", rr.Body.String())
	}

	// GET now lists the key (metadata only, no value on the wire).
	got := doGet(t, h, "/dashboard/api/secretstore")
	var resp secretStoreResponse
	if err := json.Unmarshal(got.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !hasSecretKey(resp.Entries, "OPENAI_API_KEY") {
		t.Fatalf("GET should list the put key, got %+v", resp.Entries)
	}
	if strings.Contains(got.Body.String(), "sk-live-XYZ") {
		t.Fatalf("GET must never carry a value: %s", got.Body.String())
	}

	// DELETE -> 204, then GET omits the key (idempotent removal).
	rr = doDelete(t, h, "/dashboard/api/secretstore?key=OPENAI_API_KEY")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", rr.Code)
	}
	got = doGet(t, h, "/dashboard/api/secretstore")
	_ = json.Unmarshal(got.Body.Bytes(), &resp)
	if hasSecretKey(resp.Entries, "OPENAI_API_KEY") {
		t.Fatalf("GET should omit the deleted key, got %+v", resp.Entries)
	}

	// DELETE again -> still 204 (idempotent, deleting an absent key is fine).
	if rr := doDelete(t, h, "/dashboard/api/secretstore?key=OPENAI_API_KEY"); rr.Code != http.StatusNoContent {
		t.Fatalf("idempotent DELETE = %d, want 204", rr.Code)
	}
}

func TestSecretStore_WriteRejectsEmptyKeyOrValue(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSecretStore(newWritableSecretStore(), config.SecretBackendEcho)
	h := srv.Handler()

	for _, body := range []string{
		`{"key":"","value":"v"}`,
		`{"key":"K","value":""}`,
		`{"key":"   ","value":"v"}`, // whitespace-only key is empty after trim
	} {
		if rr := doPost(t, h, "/dashboard/api/secretstore", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("POST %s = %d, want 400", body, rr.Code)
		}
	}
	// Malformed JSON -> 400.
	if rr := doPost(t, h, "/dashboard/api/secretstore", `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("POST malformed = %d, want 400", rr.Code)
	}
	// DELETE without a key -> 400.
	if rr := doDelete(t, h, "/dashboard/api/secretstore"); rr.Code != http.StatusBadRequest {
		t.Fatalf("DELETE without key = %d, want 400", rr.Code)
	}
}

func TestSecretStore_PutLogsByReferenceNeverRaw(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSecretStore(newWritableSecretStore(), config.SecretBackendEcho)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	const rawValue = "sk-supersecret-payload-ABCD"
	rr := doPost(t, srv.Handler(), "/dashboard/api/secretstore", `{"key":"K","value":"`+rawValue+`"}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("POST status = %d, want 204", rr.Code)
	}
	// The response body carries no value.
	if strings.Contains(rr.Body.String(), rawValue) {
		t.Fatalf("response leaked the raw value: %s", rr.Body.String())
	}
	logged := buf.String()
	if strings.Contains(logged, rawValue) {
		t.Fatalf("log leaked the raw value: %s", logged)
	}
	// The log DOES carry the key and a by-reference descriptor (sha256+last4).
	if !strings.Contains(logged, "key=K") || !strings.Contains(logged, "sha256:") {
		t.Fatalf("log should carry key + Ref, got: %s", logged)
	}
}

func TestSecretStore_NilStoreRejectsWrites(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	h := srv.Handler()

	if rr := doPost(t, h, "/dashboard/api/secretstore", `{"key":"K","value":"v"}`); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST nil store = %d, want 405", rr.Code)
	}
	if rr := doDelete(t, h, "/dashboard/api/secretstore?key=K"); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE nil store = %d, want 405", rr.Code)
	}
	// GET still degrades gracefully to {backend:"none", entries:[]}.
	got := doGet(t, h, "/dashboard/api/secretstore")
	if got.Code != http.StatusOK {
		t.Fatalf("GET nil store = %d, want 200", got.Code)
	}
	var resp secretStoreResponse
	if err := json.Unmarshal(got.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Backend != "none" || len(resp.Entries) != 0 {
		t.Fatalf("nil-store GET want {none, []}, got %+v", resp)
	}
}

func TestSecretStore_UnsupportedMethod(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSecretStore(newWritableSecretStore(), config.SecretBackendEcho)
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/secretstore", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT = %d, want 405", rr.Code)
	}
}

// --- 2) alerts ---

func sampleAlerts() []integration.Alert {
	t0 := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	return []integration.Alert{
		{ID: "a1", DedupKey: "egress_blocked:evil.com", Category: "egress", Severity: integration.SevHigh,
			Subject: integration.Subject{Domain: "evil.com", Worker: "w-1"}, Summary: "blocked egress",
			Evidence: "rate=7%", Status: integration.StatusFiring, Count: 3, FirstSeen: t0, LastSeen: t0.Add(time.Minute)},
		{ID: "a2", DedupKey: "mcp_poisoning:tool", Category: "mcp", Severity: integration.SevCritical,
			Subject: integration.Subject{Tool: "search"}, Summary: "poisoned tool", Status: integration.StatusFiring,
			Count: 1, FirstSeen: t0, LastSeen: t0},
	}
}

func TestAlerts_ReturnsMetadata(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetAlerts(func(int) []integration.Alert { return sampleAlerts() })
	rr := doGet(t, srv.Handler(), "/dashboard/api/alerts")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var out []alertView
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("alerts = %d, want 2", len(out))
	}
	if out[0].Severity != "high" || out[1].Severity != "critical" {
		t.Fatalf("severities = %q,%q", out[0].Severity, out[1].Severity)
	}
	if out[0].Subject.Domain != "evil.com" || out[0].Subject.Worker != "w-1" {
		t.Fatalf("subject = %+v", out[0].Subject)
	}
	if out[0].FirstSeen != "2026-06-20T09:00:00Z" {
		t.Fatalf("firstSeen = %q", out[0].FirstSeen)
	}
}

func TestAlerts_NilSourceReturnsEmpty(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	rr := doGet(t, srv.Handler(), "/dashboard/api/alerts")
	if strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Fatalf("nil alert source should return [], got %q", rr.Body.String())
	}
}

func TestAlerts_LimitPassedThrough(t *testing.T) {
	var gotLimit int
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetAlerts(func(limit int) []integration.Alert {
		gotLimit = limit
		return nil
	})
	// explicit limit
	doGet(t, srv.Handler(), "/dashboard/api/alerts?limit=5")
	if gotLimit != 5 {
		t.Fatalf("limit passed = %d, want 5", gotLimit)
	}
	// default limit when absent
	doGet(t, srv.Handler(), "/dashboard/api/alerts")
	if gotLimit != defaultAlertLimit {
		t.Fatalf("default limit = %d, want %d", gotLimit, defaultAlertLimit)
	}
	// invalid limit falls back to default
	doGet(t, srv.Handler(), "/dashboard/api/alerts?limit=-3")
	if gotLimit != defaultAlertLimit {
		t.Fatalf("invalid limit = %d, want default %d", gotLimit, defaultAlertLimit)
	}
}

// --- 3) audit ---

func TestAudit_ComplianceAggregation(t *testing.T) {
	now := time.Now()
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: now, Domain: "a.com", Decision: "deny", Compliance: []string{"mitre:T1048", "owasp:LLM01"}},
		{Timestamp: now, Domain: "b.com", Decision: "deny", Compliance: []string{"mitre:T1048"}},
		{Timestamp: now, Domain: "c.com", Decision: "allow", Compliance: []string{"owasp:LLM01", "soc2"}},
	}}
	srv := NewServer(ds, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	rr := doGet(t, srv.Handler(), "/dashboard/api/audit")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp auditResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// mitre:T1048 → count 2 (top), owasp:LLM01 → 2, soc2 (no framework) → 1.
	want := map[string]int{"mitre|T1048": 2, "owasp|LLM01": 2, "|soc2": 1}
	got := map[string]int{}
	for _, c := range resp.Compliance {
		got[c.Framework+"|"+c.Control] = c.Count
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("compliance[%s] = %d, want %d (full=%+v)", k, got[k], v, resp.Compliance)
		}
	}
	// A control ID with no ':' reports an empty framework.
	var sawSoc2 bool
	for _, c := range resp.Compliance {
		if c.Control == "soc2" {
			sawSoc2 = true
			if c.Framework != "" {
				t.Fatalf("soc2 framework = %q, want empty", c.Framework)
			}
		}
	}
	if !sawSoc2 {
		t.Fatal("expected a soc2 compliance row")
	}
	// No receipts configured → zeroed block.
	if resp.Receipts.Count != 0 || resp.Receipts.VerifiedCount != 0 || len(resp.Receipts.Recent) != 0 {
		t.Fatalf("receipts should be zeroed with no log, got %+v", resp.Receipts)
	}
}

func TestAudit_ReceiptsSummary(t *testing.T) {
	trusted, err := audit.NewSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	other, err := audit.NewSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	now := time.Now().UTC()
	mk := func(s *audit.Signer, e analytics.Event) []byte {
		r, err := s.Sign(e)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		b, err := audit.MarshalReceipt(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}
	var lines [][]byte
	lines = append(lines, mk(trusted, analytics.Event{Timestamp: now, Domain: "api.example.com", Method: "GET", Decision: "allow"}))
	lines = append(lines, mk(trusted, analytics.Event{Timestamp: now, Domain: "evil.com", Method: "POST", Decision: "deny"}))
	// A receipt signed by a DIFFERENT key: parses fine but does not verify against
	// the trusted key.
	lines = append(lines, mk(other, analytics.Event{Timestamp: now, Domain: "x.com", Method: "GET", Decision: "allow"}))
	// A garbage line: skipped entirely (not counted).
	lines = append(lines, []byte("{not json"))

	dir := t.TempDir()
	logPath := filepath.Join(dir, "receipts.jsonl")
	if err := os.WriteFile(logPath, append([]byte(strings.Join(bytesToStrings(lines), "\n")), '\n'), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetAudit(logPath, trusted.PubKey())
	rr := doGet(t, srv.Handler(), "/dashboard/api/audit")
	var resp auditResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Receipts.Count != 3 {
		t.Fatalf("count = %d, want 3 (garbage line excluded)", resp.Receipts.Count)
	}
	if resp.Receipts.VerifiedCount != 2 {
		t.Fatalf("verifiedCount = %d, want 2 (other-key receipt not verified)", resp.Receipts.VerifiedCount)
	}
	if len(resp.Receipts.Recent) != 3 {
		t.Fatalf("recent = %d, want 3", len(resp.Receipts.Recent))
	}
	// Newest first: the last written valid receipt (other-key, x.com) leads.
	if resp.Receipts.Recent[0].Domain != "x.com" || resp.Receipts.Recent[0].Verified {
		t.Fatalf("recent[0] = %+v, want x.com unverified", resp.Receipts.Recent[0])
	}
	// Metadata-only: the summary must not surface anything beyond the whitelist —
	// assert no event body/secret leaked (there is none, but guard the shape).
	if resp.Receipts.Recent[0].ID == "" {
		t.Fatal("receipt id should be derived and non-empty")
	}
}

func TestAuditVerify_PastedReceipt(t *testing.T) {
	signer, err := audit.NewSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	receipt, err := signer.Sign(analytics.Event{Domain: "a.com", Decision: "allow"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, err := audit.MarshalReceipt(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetAudit("", signer.PubKey())

	post := func(payload []byte) auditVerifyResponse {
		req := httptest.NewRequest(http.MethodPost, "/dashboard/api/audit/verify", strings.NewReader(string(payload)))
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		var v auditVerifyResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &v)
		return v
	}
	if v := post(body); !v.Valid {
		t.Fatal("a genuine receipt should verify against the trusted key")
	}
	// Tamper the signature (the EventJSON is base64-embedded in the receipt, so we
	// flip a signature byte via unmarshal → remarshal) → verification must fail.
	parsed, err := audit.UnmarshalReceipt(body)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	parsed.Signature[0] ^= 0xff
	tampered, err := audit.MarshalReceipt(parsed)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if v := post(tampered); v.Valid {
		t.Fatal("a tampered receipt must not verify")
	}
	if v := post([]byte("garbage")); v.Valid {
		t.Fatal("garbage input must not verify")
	}
}

// --- 4) setup ---

func TestSetup_States(t *testing.T) {
	t.Run("fresh single node: no events, no policy", func(t *testing.T) {
		srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
		srv.SetWriteGuard(AllowUngatedWritesForTests)
		resp := getSetup(t, srv)
		if resp.WorkersConnected != 1 {
			t.Fatalf("workersConnected = %d, want 1 (single node serving)", resp.WorkersConnected)
		}
		if resp.FirstEventSeen {
			t.Fatal("firstEventSeen should be false with no events")
		}
		if resp.PolicyConfigured {
			t.Fatal("policyConfigured should be false with empty allowlist")
		}
		if resp.SecretsConfigured {
			t.Fatal("secretsConfigured should be false with no secrets")
		}
		if resp.Mode != "monitor" {
			t.Fatalf("mode = %q, want monitor default", resp.Mode)
		}
	})

	t.Run("configured single node", func(t *testing.T) {
		pol := config.Policy{
			Allowlist: []config.AllowlistEntry{{Domain: "api.example.com"}},
			Secrets:   []config.SecretMapping{{Placeholder: "OPENAI_API_KEY"}},
		}
		ds := &fakeDataSource{events: []analytics.Event{{Domain: "api.example.com", Decision: "allow", Timestamp: time.Now()}}}
		srv := NewServer(ds, pol, emptyProvider())
		srv.SetWriteGuard(AllowUngatedWritesForTests)
		resp := getSetup(t, srv)
		if !resp.FirstEventSeen {
			t.Fatal("firstEventSeen should be true")
		}
		if !resp.PolicyConfigured {
			t.Fatal("policyConfigured should be true")
		}
		if !resp.SecretsConfigured {
			t.Fatal("secretsConfigured should be true (policy secrets)")
		}
	})

	t.Run("fleet with live enforce settings", func(t *testing.T) {
		srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
		srv.SetWriteGuard(AllowUngatedWritesForTests)
		srv.SetWorkers(func() []WorkerView { return []WorkerView{{ProxyID: "w-1"}, {ProxyID: "w-2"}} })
		srv.SetLiveSettings(func() *config.SettingsWire {
			return &config.SettingsWire{DLP: &config.DLPSettings{Mode: "enforce"}}
		})
		resp := getSetup(t, srv)
		if resp.WorkersConnected != 2 {
			t.Fatalf("workersConnected = %d, want 2", resp.WorkersConnected)
		}
		if resp.Mode != "enforce" {
			t.Fatalf("mode = %q, want enforce", resp.Mode)
		}
	})

	t.Run("monitor when only monitor guards", func(t *testing.T) {
		srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
		srv.SetWriteGuard(AllowUngatedWritesForTests)
		srv.SetLiveSettings(func() *config.SettingsWire {
			return &config.SettingsWire{
				DLP: &config.DLPSettings{Mode: "off"},
				MCP: &config.MCPSettings{Enabled: true, Mode: "monitor"},
			}
		})
		if resp := getSetup(t, srv); resp.Mode != "monitor" {
			t.Fatalf("mode = %q, want monitor", resp.Mode)
		}
	})

	t.Run("secretsConfigured via managed store", func(t *testing.T) {
		srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
		srv.SetWriteGuard(AllowUngatedWritesForTests)
		srv.SetSecretStore(&fakeSecretStore{metas: []secrets.SecretMeta{{Key: "K"}}}, "echo")
		if resp := getSetup(t, srv); !resp.SecretsConfigured {
			t.Fatal("secretsConfigured should be true when the store lists a key")
		}
	})
}

// --- method gating (same mux, same gate as other /dashboard/api routes) ---

func TestV3Endpoints_RejectWrongMethod(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	h := srv.Handler()
	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/dashboard/api/secretstore"},
		{http.MethodPost, "/dashboard/api/alerts"},
		{http.MethodPost, "/dashboard/api/audit"},
		{http.MethodGet, "/dashboard/api/audit/verify"},
		{http.MethodPost, "/dashboard/api/setup"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s = %d, want 405", c.method, c.path, rr.Code)
		}
	}
}

// TestSetup_AuthMode: authMode is absent until the host sets it (a worker's
// dashboard is not a console) and reports what SetAuthMode was given.
func TestSetup_AuthMode(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	rr := doGet(t, srv.Handler(), "/dashboard/api/setup")
	if strings.Contains(rr.Body.String(), "authMode") {
		t.Fatalf("authMode present without SetAuthMode: %s", rr.Body.String())
	}
	for _, mode := range []string{"none", "oidc"} {
		srv.SetAuthMode(mode)
		if got := getSetup(t, srv).AuthMode; got != mode {
			t.Errorf("authMode = %q, want %q", got, mode)
		}
	}
}

// --- helpers ---

func getSetup(t *testing.T, srv *Server) setupResponse {
	t.Helper()
	rr := doGet(t, srv.Handler(), "/dashboard/api/setup")
	if rr.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want 200", rr.Code)
	}
	var resp setupResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	return resp
}

func doDelete(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func hasSecretKey(entries []secretStoreEntry, key string) bool {
	for _, e := range entries {
		if e.Key == key {
			return true
		}
	}
	return false
}

func bytesToStrings(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}

// TestIndexHTML_AuthNoneBanner pins the open-console banner: it starts hidden
// and applySetup shows it only when /dashboard/api/setup reports authMode none.
func TestIndexHTML_AuthNoneBanner(t *testing.T) {
	html := string(indexHTML)
	if !strings.Contains(html, `<span id="authNoneBanner" role="status" hidden`) {
		t.Error("index.html lacks the hidden-by-default authNoneBanner")
	}
	if !strings.Contains(html, `nb.hidden=(s.authMode!=='none')`) {
		t.Error("applySetup does not drive authNoneBanner from authMode")
	}
}

func TestWorkerViewCaps(t *testing.T) {
	with, _ := json.Marshal(WorkerView{ProxyID: "a", Caps: []string{"blocklist/v1"}})
	if !strings.Contains(string(with), `"caps":["blocklist/v1"]`) {
		t.Errorf("caps missing: %s", with)
	}
	without, _ := json.Marshal(WorkerView{ProxyID: "a"})
	if strings.Contains(string(without), "caps") {
		t.Errorf("empty caps serialized: %s", without)
	}
}

// TestSetup_BackupStatus: backup is absent until SetBackupStatus is given a
// closure that returns a status, and follows that closure per request.
func TestSetup_BackupStatus(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	if rr := doGet(t, srv.Handler(), "/dashboard/api/setup"); strings.Contains(rr.Body.String(), "backup") {
		t.Fatalf("backup present without SetBackupStatus: %s", rr.Body.String())
	}
	var st *BackupStatus
	srv.SetBackupStatus(func(*http.Request) *BackupStatus { return st })
	if getSetup(t, srv).Backup != nil {
		t.Error("backup present when the closure returns nil")
	}
	st = &BackupStatus{Enabled: true, LastSet: "20270115T080000Z", SizeBytes: 9}
	if got := getSetup(t, srv).Backup; got == nil || got.LastSet != st.LastSet || got.SizeBytes != 9 || !got.Enabled {
		t.Errorf("backup = %+v", got)
	}
}

// TestIndexHTML_BackupBadge pins the admin backup badge: hidden by default,
// driven from setup.backup, and filled with textContent (no innerHTML).
func TestIndexHTML_BackupBadge(t *testing.T) {
	html := string(indexHTML)
	for _, want := range []string{`<span id="backupBadge" role="status" hidden`, `applyBackupBadge(s.backup)`, `el.textContent=bad?'Backup failing'`} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	i := strings.Index(html, "function applyBackupBadge")
	if i < 0 || strings.Contains(html[i:i+900], "innerHTML") {
		t.Error("applyBackupBadge must not use innerHTML")
	}
}
