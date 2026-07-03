package secrets

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIMDS stands up an httptest server that mimics IMDSv2: a PUT token endpoint,
// the role listing, and the role credentials document. credsFn supplies the
// credentials JSON per fetch so refresh behavior can be exercised. tokenStatus
// (when non-zero) overrides the token response status to simulate an unreachable /
// disabled metadata service.
func fakeIMDS(t *testing.T, tokenStatus int, credsFn func() (accessKey, secret, session string, exp time.Time)) *httptest.Server {
	t.Helper()
	const role = "warden-role"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if tokenStatus != 0 {
				w.WriteHeader(tokenStatus)
				return
			}
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				t.Error("token request missing TTL header")
			}
			_, _ = w.Write([]byte("imds-session-token"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			if r.Header.Get("X-aws-ec2-metadata-token") == "" {
				t.Error("role request missing token header")
			}
			_, _ = w.Write([]byte(role + "\n"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/"+role:
			ak, sk, tok, exp := credsFn()
			_, _ = fmt.Fprintf(w, `{"AccessKeyId":%q,"SecretAccessKey":%q,"Token":%q,"Expiration":%q}`,
				ak, sk, tok, exp.UTC().Format(time.RFC3339))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// clearAWSEnv makes the env-credential rung of the precedence chain a miss, so a
// test exercises the explicit or IMDS rung deterministically.
func clearAWSEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
}

// asHTTPClient type-asserts the interface to the concrete client and repoints it
// at a fake Secrets Manager endpoint, so a test can observe the SigV4 signature.
func asHTTPClient(t *testing.T, c AWSSecretsClient, smEndpoint string) *awsHTTPClient {
	t.Helper()
	hc, ok := c.(*awsHTTPClient)
	if !ok {
		t.Fatalf("client is %T, want *awsHTTPClient", c)
	}
	hc.endpoint = smEndpoint + "/"
	return hc
}

// TestNewAWSSecretsClient_ExplicitKeysWin proves explicit config keys take
// precedence and the SigV4 request carries THAT access key — even when env
// credentials are also present.
func TestNewAWSSecretsClient_ExplicitKeysWin(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")

	var captured []smRequest
	sm := newFakeSM(t, &captured)
	c, err := NewAWSSecretsClient("us-east-1", "AKIAEXPLICIT", "explicit-secret")
	if err != nil {
		t.Fatalf("NewAWSSecretsClient: %v", err)
	}
	asHTTPClient(t, c, sm.URL)

	if _, err := c.GetSecretValue("warden/K"); err != nil {
		t.Fatalf("GetSecretValue: %v", err)
	}
	if len(captured) != 1 || !strings.Contains(captured[0].auth, "Credential=AKIAEXPLICIT/") {
		t.Fatalf("SigV4 did not use explicit key; auth=%q", captured[0].auth)
	}
}

// TestNewAWSSecretsClient_EnvFallback proves that with no explicit keys the client
// resolves credentials from the process environment (the original behavior).
func TestNewAWSSecretsClient_EnvFallback(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")

	var captured []smRequest
	sm := newFakeSM(t, &captured)
	c, err := NewAWSSecretsClient("us-east-1", "", "")
	if err != nil {
		t.Fatalf("NewAWSSecretsClient: %v", err)
	}
	asHTTPClient(t, c, sm.URL)

	if _, err := c.GetSecretValue("warden/K"); err != nil {
		t.Fatalf("GetSecretValue: %v", err)
	}
	if len(captured) != 1 || !strings.Contains(captured[0].auth, "Credential=AKIAENV/") {
		t.Fatalf("SigV4 did not use env key; auth=%q", captured[0].auth)
	}
}

// TestNewAWSSecretsClient_IMDSFallback proves that with no explicit and no env
// credentials, the client resolves from IMDSv2 and signs Secrets Manager requests
// with the role's access key.
func TestNewAWSSecretsClient_IMDSFallback(t *testing.T) {
	clearAWSEnv(t)
	imds := fakeIMDS(t, 0, func() (string, string, string, time.Time) {
		return "AKIAIMDS", "imds-secret", "imds-session-token", time.Now().Add(time.Hour)
	})

	var captured []smRequest
	sm := newFakeSM(t, &captured)
	c, err := newAWSSecretsClient("us-east-1", "", "", imds.URL, nil)
	if err != nil {
		t.Fatalf("newAWSSecretsClient (imds): %v", err)
	}
	asHTTPClient(t, c, sm.URL)

	if _, err := c.GetSecretValue("warden/K"); err != nil {
		t.Fatalf("GetSecretValue: %v", err)
	}
	if len(captured) != 1 || !strings.Contains(captured[0].auth, "Credential=AKIAIMDS/") {
		t.Fatalf("SigV4 did not use IMDS key; auth=%q", captured[0].auth)
	}
}

// TestNewAWSSecretsClient_IMDSUnreachable proves a non-AWS host (no explicit/env
// creds, IMDS token endpoint failing) fails fast with a clear, credential-free
// error.
func TestNewAWSSecretsClient_IMDSUnreachable(t *testing.T) {
	clearAWSEnv(t)
	imds := fakeIMDS(t, http.StatusForbidden, func() (string, string, string, time.Time) {
		return "", "", "", time.Time{}
	})

	_, err := newAWSSecretsClient("us-east-1", "", "", imds.URL, nil)
	if err == nil || !strings.Contains(err.Error(), "IMDS unreachable") {
		t.Fatalf("err = %v, want a clear IMDS-unreachable error", err)
	}
}

// TestIMDSProvider_RefreshesNearExpiry proves the provider caches credentials but
// refetches once they are within the refresh window of expiry — so a long-lived
// worker always signs with valid temporary credentials.
func TestIMDSProvider_RefreshesNearExpiry(t *testing.T) {
	var n int32
	// First fetch: creds expire SOON (inside the refresh window) → next call must
	// refetch. Second fetch: creds expire far in the future → the call after is
	// served from cache.
	imds := fakeIMDS(t, 0, func() (string, string, string, time.Time) {
		i := atomic.AddInt32(&n, 1)
		if i == 1 {
			return "AKIA1", "s1", "tok1", time.Now().Add(time.Minute) // < imdsRefreshWindow
		}
		return fmt.Sprintf("AKIA%d", i), fmt.Sprintf("s%d", i), fmt.Sprintf("tok%d", i), time.Now().Add(time.Hour)
	})
	p := newIMDSProvider(imds.URL, nil)

	first, err := p.credentials()
	if err != nil || first.AccessKeyID != "AKIA1" {
		t.Fatalf("first credentials = %+v, %v", first, err)
	}
	second, err := p.credentials()
	if err != nil || second.AccessKeyID != "AKIA2" {
		t.Fatalf("near-expiry creds must refresh: got %+v (fetches=%d)", second, atomic.LoadInt32(&n))
	}
	// Third call: cached (far-future expiry) → no new fetch, same key.
	third, err := p.credentials()
	if err != nil || third.AccessKeyID != "AKIA2" || atomic.LoadInt32(&n) != 2 {
		t.Fatalf("far-future creds must be cached: got %+v (fetches=%d)", third, atomic.LoadInt32(&n))
	}
}
