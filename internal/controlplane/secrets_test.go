package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// newSecretsTestServer builds a CP wired to an echo secret store and a buffered
// logger, returning the httptest server and the log buffer so a test can assert
// value hygiene. token gates every /central/secrets route.
func newSecretsTestServer(t *testing.T, token string) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	srv := New(Config{
		PolicyPath:  writePolicyFile(t, "api.openai.com"),
		Token:       token,
		Logger:      logger,
		SecretStore: secrets.NewEchoStore(),
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, buf
}

// do issues a request with an optional bearer token and returns the status code
// and body. It closes the body.
func do(t *testing.T, method, url, token, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestSecrets_NotMountedWithoutStore proves back-compat: a CP with no writable
// secret store does not mount /central/secrets at all → 404 on every verb.
func TestSecrets_NotMountedWithoutStore(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/central/secrets", `{"key":"k","value":"v"}`},
		{http.MethodGet, "/central/secrets", ""},
		{http.MethodDelete, "/central/secrets/k", ""},
	} {
		if code, _ := do(t, tc.method, ts.URL+tc.path, "", tc.body); code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 (endpoints unmounted)", tc.method, tc.path, code)
		}
	}
}

// TestSecrets_Auth mirrors controlplane_test.go's bearer pattern across every
// secret endpoint: no/invalid token → 401; the correct token → success.
func TestSecrets_Auth(t *testing.T) {
	ts, _ := newSecretsTestServer(t, "s3cret")

	cases := []struct {
		name, method, path, body string
		wantOK                   int
	}{
		{"put", http.MethodPost, "/central/secrets", `{"key":"K","value":"V123456"}`, http.StatusNoContent},
		{"list", http.MethodGet, "/central/secrets", "", http.StatusOK},
		{"delete", http.MethodDelete, "/central/secrets/K", "", http.StatusNoContent},
	}
	for _, tc := range cases {
		// No token → 401.
		if code, _ := do(t, tc.method, ts.URL+tc.path, "", tc.body); code != http.StatusUnauthorized {
			t.Errorf("%s no-token = %d, want 401", tc.name, code)
		}
		// Bad token → 401.
		if code, _ := do(t, tc.method, ts.URL+tc.path, "wrong", tc.body); code != http.StatusUnauthorized {
			t.Errorf("%s bad-token = %d, want 401", tc.name, code)
		}
		// Correct token → success.
		if code, _ := do(t, tc.method, ts.URL+tc.path, "s3cret", tc.body); code != tc.wantOK {
			t.Errorf("%s good-token = %d, want %d", tc.name, code, tc.wantOK)
		}
	}
}

// TestSecrets_PutListDelete exercises the full lifecycle: upsert → list (metadata
// only, no value) → delete → list omits.
func TestSecrets_PutListDelete(t *testing.T) {
	ts, _ := newSecretsTestServer(t, "")
	const key = "OPENAI_API_KEY"

	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", "", `{"key":"`+key+`","value":"sk-abc-9999"}`); code != http.StatusNoContent {
		t.Fatalf("POST = %d, want 204", code)
	}

	// List reflects the key as metadata only.
	metas := listSecretsMeta(t, ts.URL, "")
	if !hasKey(metas, key) {
		t.Fatalf("list %+v missing key %q after Put", metas, key)
	}
	for _, m := range metas {
		if m.Version == "" {
			t.Errorf("meta %q has empty version", m.Key)
		}
	}

	// Delete then confirm the key is gone.
	if code, _ := do(t, http.MethodDelete, ts.URL+"/central/secrets/"+key, "", ""); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", code)
	}
	if hasKey(listSecretsMeta(t, ts.URL, ""), key) {
		t.Fatalf("key %q still listed after delete", key)
	}
	// Delete is idempotent: a second delete still 204.
	if code, _ := do(t, http.MethodDelete, ts.URL+"/central/secrets/"+key, "", ""); code != http.StatusNoContent {
		t.Fatalf("idempotent DELETE = %d, want 204", code)
	}
}

// TestSecrets_ListMetadataOnly asserts the GET response body carries NO value
// field — only key/version/updatedAt — even after a value was Put.
func TestSecrets_ListMetadataOnly(t *testing.T) {
	ts, _ := newSecretsTestServer(t, "")
	const value = "super-secret-value-xyz"
	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", "", `{"key":"K","value":"`+value+`"}`); code != http.StatusNoContent {
		t.Fatalf("POST = %d, want 204", code)
	}
	_, raw := do(t, http.MethodGet, ts.URL+"/central/secrets", "", "")
	if strings.Contains(raw, value) {
		t.Fatalf("GET body leaked the value: %s", raw)
	}
	// The value-free field set is fixed; a raw scan for the on-wire shape guards it.
	if strings.Contains(strings.ToLower(raw), `"value"`) {
		t.Fatalf("GET body carries a value field: %s", raw)
	}
}

// TestSecrets_BadBody covers 400s: invalid JSON, empty key, empty value.
func TestSecrets_BadBody(t *testing.T) {
	ts, _ := newSecretsTestServer(t, "")
	for _, body := range []string{
		`not json`,
		`{"key":"","value":"v"}`,
		`{"key":"k","value":""}`,
		`{"key":"   ","value":"v"}`, // whitespace-only key trims to empty
	} {
		if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", "", body); code != http.StatusBadRequest {
			t.Errorf("POST %q = %d, want 400", body, code)
		}
	}
}

// TestSecrets_MethodNotAllowed rejects unsupported verbs on each route.
func TestSecrets_MethodNotAllowed(t *testing.T) {
	ts, _ := newSecretsTestServer(t, "")
	if code, _ := do(t, http.MethodPut, ts.URL+"/central/secrets", "", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /central/secrets = %d, want 405", code)
	}
	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets/k", "", `{}`); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /central/secrets/k = %d, want 405", code)
	}
}

// TestSecrets_ValueHygiene captures the CP logs during a Put and asserts the raw
// value never appears — only the by-reference descriptor (hash + last-4 + len).
func TestSecrets_ValueHygiene(t *testing.T) {
	ts, buf := newSecretsTestServer(t, "")
	const (
		key   = "OPENAI_API_KEY"
		value = "sk-SUPER-SECRET-PLAINTEXT-0001"
	)
	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", "", `{"key":"`+key+`","value":"`+value+`"}`); code != http.StatusNoContent {
		t.Fatalf("POST = %d, want 204", code)
	}
	logs := buf.String()
	if strings.Contains(logs, value) {
		t.Fatalf("CP logs leaked the raw secret value: %s", logs)
	}
	// The by-reference form DID log: the key and a sha256 descriptor.
	if !strings.Contains(logs, key) || !strings.Contains(logs, "sha256:") {
		t.Fatalf("expected key + by-reference log, got: %s", logs)
	}
}

// fakeAWSClient is a minimal in-memory secrets.AWSSecretsClient for the CP's
// aws-backend tests: it models upsert (Put→not-found→Create), delete, and list
// with no AWS and no network.
type fakeAWSClient struct {
	store map[string]string
}

func newFakeAWSClient() *fakeAWSClient { return &fakeAWSClient{store: map[string]string{}} }

func (c *fakeAWSClient) GetSecretValue(name string) (string, error) {
	v, ok := c.store[name]
	if !ok {
		return "", secrets.ErrSecretNotFound
	}
	return v, nil
}

func (c *fakeAWSClient) PutSecretValue(name, value string) (string, error) {
	if _, ok := c.store[name]; !ok {
		return "", secrets.ErrSecretNotFound
	}
	c.store[name] = value
	return "2", nil
}

func (c *fakeAWSClient) CreateSecret(name, value string) (string, error) {
	c.store[name] = value
	return "1", nil
}

func (c *fakeAWSClient) DeleteSecret(name string) error {
	delete(c.store, name)
	return nil
}

func (c *fakeAWSClient) ListSecrets(prefix string) ([]secrets.AWSSecretEntry, error) {
	out := []secrets.AWSSecretEntry{}
	for name := range c.store {
		if strings.HasPrefix(name, prefix) {
			out = append(out, secrets.AWSSecretEntry{Name: name, Version: "1", UpdatedAt: time.Now()})
		}
	}
	return out, nil
}

// withFakeAWSClient swaps the CP's aws client factory for one returning client
// (or err), restoring it on cleanup so no test touches AWS or the network.
func withFakeAWSClient(t *testing.T, client secrets.AWSSecretsClient, err error) {
	t.Helper()
	prev := awsSecretsClientFactory
	awsSecretsClientFactory = func(string) (secrets.AWSSecretsClient, error) {
		return client, err
	}
	t.Cleanup(func() { awsSecretsClientFactory = prev })
}

// TestNewSecretStore covers the backend→store mapping: echo and aws yield a
// writable store; env/none yield a nil store with no error (endpoints unmounted).
func TestNewSecretStore(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if st, err := NewSecretStore(config.SecretStoreConfig{Backend: config.SecretBackendEcho}, logger); st == nil || err != nil {
		t.Errorf("echo backend should yield a writable store, got st=%v err=%v", st, err)
	}

	// aws with an injected fake client yields a writable store.
	withFakeAWSClient(t, newFakeAWSClient(), nil)
	awsCfg := config.SecretStoreConfig{Backend: config.SecretBackendAWS, AWS: &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"}}
	if st, err := NewSecretStore(awsCfg, logger); st == nil || err != nil {
		t.Errorf("aws backend should yield a writable store, got st=%v err=%v", st, err)
	}

	if st, err := NewSecretStore(config.SecretStoreConfig{Backend: config.SecretBackendEnv}, logger); st != nil || err != nil {
		t.Errorf("env backend should be nil (no write surface), got st=%v err=%v", st, err)
	}
	if st, err := NewSecretStore(config.SecretStoreConfig{}, logger); st != nil || err != nil {
		t.Errorf("empty/default backend should be nil (no write surface), got st=%v err=%v", st, err)
	}
}

// TestNewSecretStore_AWSMissingCredsFailFast proves a factory error (e.g. missing
// ENV credentials) surfaces from NewSecretStore rather than silently disabling
// the write endpoints.
func TestNewSecretStore_AWSMissingCredsFailFast(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	withFakeAWSClient(t, nil, errors.New("aws credentials missing"))
	awsCfg := config.SecretStoreConfig{Backend: config.SecretBackendAWS, AWS: &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"}}
	if _, err := NewSecretStore(awsCfg, logger); err == nil {
		t.Fatal("expected a fail-fast error when the aws client factory errors")
	}
}

// TestSecrets_AWSBackendMountsAndWrites proves the CP on backend aws (fake client
// injected) mounts /central/secrets: a POST upserts into the fake store and a GET
// lists the key as metadata only.
func TestSecrets_AWSBackendMountsAndWrites(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	withFakeAWSClient(t, newFakeAWSClient(), nil)
	awsCfg := config.SecretStoreConfig{Backend: config.SecretBackendAWS, AWS: &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"}}
	store, err := NewSecretStore(awsCfg, logger)
	if err != nil {
		t.Fatalf("NewSecretStore(aws): %v", err)
	}
	srv := New(Config{
		PolicyPath:  writePolicyFile(t, "api.openai.com"),
		Logger:      logger,
		SecretStore: store,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	const key = "OPENAI_API_KEY"
	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", "", `{"key":"`+key+`","value":"sk-aws-write"}`); code != http.StatusNoContent {
		t.Fatalf("POST = %d, want 204", code)
	}
	if !hasKey(listSecretsMeta(t, ts.URL, ""), key) {
		t.Fatalf("aws backend GET list missing key %q after POST", key)
	}
}

// TestSecrets_E2EOnEcho is the Phase-4 deliverable: a control plane on backend
// echo accepts an operator POST, lists the key (metadata only), and a WORKER on
// backend echo resolves that same placeholder through its cache (echo Get==key) —
// the whole write→list→resolve loop with zero cloud dependencies.
//
// Echo persists NOTHING (the CP and worker hold separate echo stores), so the
// proof is the WIRING, not shared state: the endpoints accept the write, the list
// reflects it, and the worker's read path resolves the placeholder. The posted
// value must appear in no CP log or response.
func TestSecrets_E2EOnEcho(t *testing.T) {
	ts, buf := newSecretsTestServer(t, "")
	const (
		placeholder = "{{OPENAI_API_KEY}}"
		value       = "whatever-the-operator-typed"
	)

	// 1. Operator POSTs the key+value at the control plane → 204.
	body, _ := json.Marshal(map[string]string{"key": placeholder, "value": value})
	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", "", string(body)); code != http.StatusNoContent {
		t.Fatalf("POST = %d, want 204", code)
	}

	// 2. GET lists the key as metadata only (no value).
	if !hasKey(listSecretsMeta(t, ts.URL, ""), placeholder) {
		t.Fatalf("list did not reflect the posted key %q", placeholder)
	}

	// 3. A worker on backend echo resolves the placeholder through the SAME read
	//    path the proxy swap uses: NewStoreFetcher(EchoStore) behind the Cache.
	fetcher := secrets.NewStoreFetcher(secrets.NewEchoStore())
	cache, err := secrets.NewCache(fetcher, time.Hour, []string{placeholder})
	if err != nil {
		t.Fatalf("worker cache build: %v", err)
	}
	resolved, err := cache.GetSecret(placeholder)
	if err != nil {
		t.Fatalf("worker GetSecret: %v", err)
	}
	if resolved != placeholder { // echo contract: the value IS the key
		t.Fatalf("worker resolved %q, want the placeholder key itself (echo)", resolved)
	}

	// 4. Value hygiene: the operator's value never reached the CP logs.
	if strings.Contains(buf.String(), value) {
		t.Fatalf("CP logs leaked the posted value: %s", buf.String())
	}
}

func listSecretsMeta(t *testing.T, base, token string) []secrets.SecretMeta {
	t.Helper()
	code, raw := do(t, http.MethodGet, base+"/central/secrets", token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /central/secrets = %d, want 200 (%s)", code, raw)
	}
	var out []secrets.SecretMeta
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode list: %v (%s)", err, raw)
	}
	return out
}

func hasKey(metas []secrets.SecretMeta, key string) bool {
	for _, m := range metas {
		if m.Key == key {
			return true
		}
	}
	return false
}
