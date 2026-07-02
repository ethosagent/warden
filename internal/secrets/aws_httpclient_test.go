package secrets

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// smRequest is one captured Secrets Manager call: the X-Amz-Target action, the
// Authorization header, and the decoded JSON body.
type smRequest struct {
	target string
	auth   string
	body   map[string]any
}

// newFakeSM stands up an httptest server that mimics the Secrets Manager JSON
// API. It records each request and dispatches on X-Amz-Target, returning canned
// JSON. A GetSecretValue for the special name "warden/missing" returns a
// ResourceNotFoundException so the not-found mapping can be asserted.
func newFakeSM(t *testing.T, captured *[]smRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		target := r.Header.Get("X-Amz-Target")
		*captured = append(*captured, smRequest{
			target: target,
			auth:   r.Header.Get("Authorization"),
			body:   body,
		})
		if ct := r.Header.Get("Content-Type"); ct != "application/x-amz-json-1.1" {
			t.Errorf("Content-Type = %q, want application/x-amz-json-1.1", ct)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch {
		case strings.HasSuffix(target, "GetSecretValue"):
			if body["SecretId"] == "warden/missing" {
				w.Header().Set("X-Amzn-Errortype", "ResourceNotFoundException")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"__type":"ResourceNotFoundException","message":"not found"}`)
				return
			}
			_, _ = io.WriteString(w, `{"SecretString":"sk-real-value","VersionId":"v-1"}`)
		case strings.HasSuffix(target, "PutSecretValue"):
			if body["SecretId"] == "warden/missing" {
				w.Header().Set("X-Amzn-Errortype", "ResourceNotFoundException")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"__type":"com.amazon.coral#ResourceNotFoundException","message":"nope"}`)
				return
			}
			_, _ = io.WriteString(w, `{"VersionId":"v-2"}`)
		case strings.HasSuffix(target, "CreateSecret"):
			_, _ = io.WriteString(w, `{"VersionId":"v-1"}`)
		case strings.HasSuffix(target, "DeleteSecret"):
			_, _ = io.WriteString(w, `{"Name":"warden/K"}`)
		case strings.HasSuffix(target, "ListSecrets"):
			_, _ = io.WriteString(w, `{"SecretList":[{"Name":"warden/K","LastChangedDate":1700000000.5}]}`)
		default:
			t.Errorf("unexpected X-Amz-Target %q", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestHTTPClient points an awsHTTPClient at the httptest server (overriding
// the derived AWS endpoint) with dummy creds so SigV4 signs.
func newTestHTTPClient(endpoint string) *awsHTTPClient {
	c := newAWSHTTPClient("us-east-1", awsCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "secret",
		SessionToken:    "",
	}, nil)
	c.endpoint = endpoint + "/"
	return c
}

func TestAWSHTTPClient_GetPutCreateDeleteList(t *testing.T) {
	var captured []smRequest
	srv := newFakeSM(t, &captured)
	c := newTestHTTPClient(srv.URL)

	// Get: right target, signed, value parsed.
	val, err := c.GetSecretValue("warden/K")
	if err != nil || val != "sk-real-value" {
		t.Fatalf("GetSecretValue = %q, %v; want sk-real-value", val, err)
	}

	// Put: version parsed, body shape correct.
	ver, err := c.PutSecretValue("warden/K", "sk-new")
	if err != nil || ver != "v-2" {
		t.Fatalf("PutSecretValue = %q, %v; want v-2", ver, err)
	}

	// Create: version parsed.
	if ver, err := c.CreateSecret("warden/K", "sk-new"); err != nil || ver != "v-1" {
		t.Fatalf("CreateSecret = %q, %v; want v-1", ver, err)
	}

	// Delete: no error, ForceDeleteWithoutRecovery set.
	if err := c.DeleteSecret("warden/K"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	// List: entry parsed with UpdatedAt from LastChangedDate.
	entries, err := c.ListSecrets("warden/")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "warden/K" {
		t.Fatalf("ListSecrets = %+v, want one warden/K", entries)
	}
	if entries[0].UpdatedAt.IsZero() {
		t.Error("ListSecrets UpdatedAt zero, want LastChangedDate parsed")
	}

	// Assert per-request invariants across every captured call.
	wantTargets := []string{
		"secretsmanager.GetSecretValue",
		"secretsmanager.PutSecretValue",
		"secretsmanager.CreateSecret",
		"secretsmanager.DeleteSecret",
		"secretsmanager.ListSecrets",
	}
	if len(captured) != len(wantTargets) {
		t.Fatalf("captured %d requests, want %d", len(captured), len(wantTargets))
	}
	for i, want := range wantTargets {
		got := captured[i]
		if got.target != want {
			t.Errorf("request %d target = %q, want %q", i, got.target, want)
		}
		if !strings.HasPrefix(got.auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(got.auth, "Signature=") {
			t.Errorf("request %d missing SigV4 Authorization: %q", i, got.auth)
		}
	}

	// Body-shape spot checks.
	if captured[0].body["SecretId"] != "warden/K" {
		t.Errorf("Get body = %v, want SecretId warden/K", captured[0].body)
	}
	if captured[1].body["SecretString"] != "sk-new" {
		t.Errorf("Put body = %v, want SecretString sk-new", captured[1].body)
	}
	if captured[2].body["Name"] != "warden/K" {
		t.Errorf("Create body = %v, want Name warden/K", captured[2].body)
	}
	if captured[3].body["ForceDeleteWithoutRecovery"] != true {
		t.Errorf("Delete body = %v, want ForceDeleteWithoutRecovery true", captured[3].body)
	}
}

// TestAWSHTTPClient_ResourceNotFound proves both the header-typed and __type-typed
// ResourceNotFoundException map onto ErrSecretNotFound.
func TestAWSHTTPClient_ResourceNotFound(t *testing.T) {
	var captured []smRequest
	srv := newFakeSM(t, &captured)
	c := newTestHTTPClient(srv.URL)

	if _, err := c.GetSecretValue("warden/missing"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get missing err = %v, want ErrSecretNotFound", err)
	}
	if _, err := c.PutSecretValue("warden/missing", "v"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Put missing err = %v, want ErrSecretNotFound", err)
	}
}

// TestAWSHTTPClient_ErrorHidesValue proves a surfaced AWS error never contains
// the secret value that was in the request body.
func TestAWSHTTPClient_ErrorHidesValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Amzn-Errortype", "InternalServiceError")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"__type":"InternalServiceError","message":"boom"}`)
	}))
	t.Cleanup(srv.Close)
	c := newTestHTTPClient(srv.URL)

	const value = "sk-super-secret-999"
	_, err := c.PutSecretValue("warden/K", value)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error leaked the secret value: %v", err)
	}
}

// TestNewAWSSecretsClientFromEnv_MissingCreds proves fail-fast when creds are
// absent from the environment.
func TestNewAWSSecretsClientFromEnv_MissingCreds(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	if _, err := NewAWSSecretsClientFromEnv("us-east-1"); err == nil {
		t.Fatal("expected an error for missing credentials")
	}
	// With creds present it succeeds.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	if _, err := NewAWSSecretsClientFromEnv("us-east-1"); err != nil {
		t.Fatalf("with creds: %v", err)
	}
	// Empty region also fails fast.
	if _, err := NewAWSSecretsClientFromEnv(""); err == nil {
		t.Fatal("expected an error for empty region")
	}
}
