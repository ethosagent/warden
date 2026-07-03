package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AWS credential resolution for the Secrets Manager client follows a strict
// precedence, implemented by NewAWSSecretsClient:
//
//  1. Explicit accessKeyID + secretAccessKey (from config/settings) when BOTH are
//     present — long-lived keys, no expiry.
//  2. Else the process env (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, optional
//     AWS_SESSION_TOKEN) — the original behavior.
//  3. Else the instance/pod IAM role via IMDSv2 — temporary creds that expire, so
//     they are cached with their Expiration and refreshed near expiry.
//
// A non-AWS host with no explicit/env creds fails FAST (short IMDS timeout) with
// a clear, credential-free error.

const (
	// defaultIMDSBaseURL is the EC2/ECS instance metadata endpoint. Overridable in
	// tests (newAWSSecretsClient) so tests hit an httptest server, never real IMDS.
	defaultIMDSBaseURL = "http://169.254.169.254"
	// imdsTokenTTLSeconds is the IMDSv2 session-token lifetime requested on PUT.
	imdsTokenTTLSeconds = "21600"
	// imdsTimeout bounds every IMDS hop so a non-AWS host fails fast instead of
	// hanging the caller.
	imdsTimeout = 2 * time.Second
	// imdsRefreshWindow refreshes IMDS creds this long BEFORE their Expiration, so
	// a request never signs with just-expired temporary credentials.
	imdsRefreshWindow = 5 * time.Minute
)

// NewAWSSecretsClient builds the Secrets Manager client for region, resolving
// credentials by the documented precedence (explicit → env → IMDSv2). The
// explicit keys are honored only when BOTH are non-empty; a lone key falls
// through (validation rejects a lone key upstream, but this stays defensive).
// region must be non-empty. On the IMDS path it probes once so an unreachable
// metadata service fails fast at construction with a clear error.
func NewAWSSecretsClient(region, accessKeyID, secretAccessKey string) (AWSSecretsClient, error) {
	return newAWSSecretsClient(region, accessKeyID, secretAccessKey, defaultIMDSBaseURL, nil)
}

// newAWSSecretsClient is the injectable core of NewAWSSecretsClient: imdsBaseURL
// and imdsHTTP let tests point the IMDS path at an httptest server (or a closed
// one to exercise the unreachable error) without touching real metadata.
func newAWSSecretsClient(region, accessKeyID, secretAccessKey, imdsBaseURL string, imdsHTTP *http.Client) (AWSSecretsClient, error) {
	if strings.TrimSpace(region) == "" {
		return nil, fmt.Errorf("secrets: aws region is required")
	}
	// 1. Explicit config/settings credentials — used only when BOTH are present.
	if accessKeyID != "" && secretAccessKey != "" {
		return newAWSHTTPClient(region, awsCredentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
		}, nil), nil
	}
	// 2. Process environment (both required; a partial env set falls through to IMDS).
	if strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")) != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		return NewAWSSecretsClientFromEnv(region)
	}
	// 3. Instance IAM role via IMDSv2. Probe once so a non-AWS host fails fast.
	provider := newIMDSProvider(imdsBaseURL, imdsHTTP)
	if _, err := provider.credentials(); err != nil {
		return nil, fmt.Errorf("secrets: no AWS credentials: explicit keys unset, env unset, and IMDS unreachable: %w", err)
	}
	return newAWSHTTPClientWithCreds(region, provider.credentials, nil), nil
}

// imdsProvider resolves and caches temporary credentials from IMDSv2, refreshing
// them within imdsRefreshWindow of expiry. It is safe for concurrent use: the
// mutex guards the cached creds so many in-flight Secrets Manager requests share a
// single refresh rather than stampeding the metadata service.
type imdsProvider struct {
	baseURL string
	http    *http.Client

	mu     sync.Mutex
	cached awsCredentials
	expiry time.Time
}

func newIMDSProvider(baseURL string, httpClient *http.Client) *imdsProvider {
	if baseURL == "" {
		baseURL = defaultIMDSBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: imdsTimeout}
	}
	return &imdsProvider{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// credentials returns the current role credentials, fetching fresh ones when the
// cache is empty or within imdsRefreshWindow of expiry. If a refresh fails but the
// cached creds are still valid, it keeps serving them (transient metadata blips do
// not break a running worker); only an empty/expired cache surfaces the error.
func (p *imdsProvider) credentials() (awsCredentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if p.cached.AccessKeyID != "" && now.Before(p.expiry.Add(-imdsRefreshWindow)) {
		return p.cached, nil
	}
	creds, exp, err := p.fetch()
	if err != nil {
		if p.cached.AccessKeyID != "" && now.Before(p.expiry) {
			return p.cached, nil
		}
		return awsCredentials{}, err
	}
	p.cached, p.expiry = creds, exp
	return creds, nil
}

// fetch runs the IMDSv2 dance: PUT a session token, GET the role name, GET the
// role's temporary credentials. Errors carry only status/step context, never a
// credential value.
func (p *imdsProvider) fetch() (awsCredentials, time.Time, error) {
	token, err := p.token()
	if err != nil {
		return awsCredentials{}, time.Time{}, err
	}
	role, err := p.roleName(token)
	if err != nil {
		return awsCredentials{}, time.Time{}, err
	}
	return p.roleCredentials(token, role)
}

// token requests an IMDSv2 session token (PUT with the TTL header).
func (p *imdsProvider) token() (string, error) {
	req, err := http.NewRequest(http.MethodPut, p.baseURL+"/latest/api/token", nil)
	if err != nil {
		return "", fmt.Errorf("secrets: aws imds token request: %w", err)
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", imdsTokenTTLSeconds)
	body, err := p.do(req, "imds token")
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(body))
	if tok == "" {
		return "", fmt.Errorf("secrets: aws imds token empty")
	}
	return tok, nil
}

// roleName reads the single IAM role attached to the instance (the first line of
// the security-credentials listing).
func (p *imdsProvider) roleName(token string) (string, error) {
	body, err := p.get("/latest/meta-data/iam/security-credentials/", token, "imds role")
	if err != nil {
		return "", err
	}
	role := strings.TrimSpace(string(body))
	if i := strings.IndexByte(role, '\n'); i >= 0 {
		role = strings.TrimSpace(role[:i])
	}
	if role == "" {
		return "", fmt.Errorf("secrets: aws imds no IAM role attached to instance")
	}
	return role, nil
}

// imdsRoleCredentials is the IMDS credentials document. Expiration bounds the
// temporary creds' lifetime; credentials() refreshes ahead of it.
type imdsRoleCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

// roleCredentials fetches and parses the temporary credentials for role.
func (p *imdsProvider) roleCredentials(token, role string) (awsCredentials, time.Time, error) {
	body, err := p.get("/latest/meta-data/iam/security-credentials/"+role, token, "imds credentials")
	if err != nil {
		return awsCredentials{}, time.Time{}, err
	}
	var doc imdsRoleCredentials
	if err := json.Unmarshal(body, &doc); err != nil {
		return awsCredentials{}, time.Time{}, fmt.Errorf("secrets: aws imds decode credentials: %w", err)
	}
	if doc.AccessKeyID == "" || doc.SecretAccessKey == "" {
		return awsCredentials{}, time.Time{}, fmt.Errorf("secrets: aws imds credentials incomplete")
	}
	return awsCredentials{
		AccessKeyID:     doc.AccessKeyID,
		SecretAccessKey: doc.SecretAccessKey,
		SessionToken:    doc.Token,
	}, doc.Expiration, nil
}

// get issues an IMDSv2 GET carrying the session token.
func (p *imdsProvider) get(path, token, step string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, p.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: aws %s request: %w", step, err)
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	return p.do(req, step)
}

// do executes an IMDS request and returns the body, mapping transport errors and
// non-2xx status onto a clear, credential-free error.
func (p *imdsProvider) do(req *http.Request, step string) ([]byte, error) {
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: aws %s: %w", step, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("secrets: aws %s read: %w", step, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("secrets: aws %s: HTTP %d", step, resp.StatusCode)
	}
	return body, nil
}
