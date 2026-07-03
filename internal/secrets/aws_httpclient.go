package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/auth"
)

// awsHTTPClient is a thin, purpose-built AWSSecretsClient over the AWS Secrets
// Manager JSON (1.1) API using ONLY net/http + the existing SigV4 signer
// (internal/auth.AWSSigV4). It deliberately implements just the five verbs the
// SecretStore needs — Get/Put/Create/Delete/List — and is NOT a general AWS SDK.
// Keeping it dependency-free is what preserves warden's single static binary
// (no aws-sdk in go.mod).
//
// Each call POSTs to https://secretsmanager.<region>.amazonaws.com/ with
//
//	Content-Type: application/x-amz-json-1.1
//	X-Amz-Target: secretsmanager.<Action>
//
// a JSON body per action, signed with SigV4 (service "secretsmanager"). AWS's
// ResourceNotFoundException is mapped onto ErrSecretNotFound; other AWS errors
// surface as the AWS __type + message (never a secret value).
type awsHTTPClient struct {
	endpoint string
	region   string
	// creds resolves the CURRENT SigV4 credentials per request. For explicit/env
	// credentials it returns a fixed value; for IMDS it refreshes near expiry (so a
	// long-lived worker/CP keeps signing with valid temporary creds). A fresh signer
	// is built per request from the resolved creds, so concurrent calls never share
	// mutable signer state.
	creds credentialsProvider
	http  *http.Client
}

// credentialsProvider yields the current SigV4 credentials. Implementations must
// be safe for concurrent use (the IMDS provider is mutex-guarded).
type credentialsProvider func() (awsCredentials, error)

// staticCredentials wraps a fixed credential set (explicit config keys or env
// vars) as a provider that never changes — long-lived keys never expire and env
// creds are read once at startup, matching the original behavior.
func staticCredentials(c awsCredentials) credentialsProvider {
	return func() (awsCredentials, error) { return c, nil }
}

// Compile-time assertion: the HTTP client satisfies the full mockable seam.
var _ AWSSecretsClient = (*awsHTTPClient)(nil)

// awsCredentials are the SigV4 inputs resolved from the process environment.
// Warden never puts credentials in config or on the wire (same rule as
// Judge.APIKeyEnv); they live only in the plane's own environment.
type awsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional (STS/assumed-role)
}

// defaultAWSHTTPTimeout bounds every Secrets Manager call so a hung control
// plane / worker fails fast rather than blocking the request or the boot
// prefetch indefinitely.
const defaultAWSHTTPTimeout = 15 * time.Second

// NewAWSSecretsClientFromEnv builds the real net/http + SigV4 AWSSecretsClient
// for region, resolving credentials from the process ENVIRONMENT:
//
//	AWS_ACCESS_KEY_ID       (required)
//	AWS_SECRET_ACCESS_KEY   (required)
//	AWS_SESSION_TOKEN       (optional; set for STS/assumed-role creds)
//
// A missing access key or secret key is a hard error so an aws-backed plane
// fails fast at startup rather than silently mis-resolving secrets. region must
// be non-empty (config validation guarantees it for backend: aws). The returned
// value is the AWSSecretsClient interface; the concrete type is unexported.
func NewAWSSecretsClientFromEnv(region string) (AWSSecretsClient, error) {
	if strings.TrimSpace(region) == "" {
		return nil, fmt.Errorf("secrets: aws region is required")
	}
	creds := awsCredentials{
		AccessKeyID:     strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("secrets: aws credentials missing: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
	}
	return newAWSHTTPClient(region, creds, nil), nil
}

// newAWSHTTPClient assembles an awsHTTPClient over a FIXED credential set
// (explicit config keys or env vars). endpoint is derived from region; httpClient
// defaults to one with defaultAWSHTTPTimeout when nil. This is the injectable seam
// the httptest-based test uses to point at a local mock.
func newAWSHTTPClient(region string, creds awsCredentials, httpClient *http.Client) *awsHTTPClient {
	return newAWSHTTPClientWithCreds(region, staticCredentials(creds), httpClient)
}

// newAWSHTTPClientWithCreds assembles an awsHTTPClient over a credentials
// provider (the IMDS path uses this so creds refresh on expiry). httpClient
// defaults to one with defaultAWSHTTPTimeout when nil.
func newAWSHTTPClientWithCreds(region string, creds credentialsProvider, httpClient *http.Client) *awsHTTPClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultAWSHTTPTimeout}
	}
	return &awsHTTPClient{
		endpoint: fmt.Sprintf("https://secretsmanager.%s.amazonaws.com/", region),
		region:   region,
		creds:    creds,
		http:     httpClient,
	}
}

// awsError is the decoded body of an AWS JSON error response. AWS returns the
// exception name in either "__type" or the X-Amzn-Errortype header.
type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
	// AWS is inconsistent about message casing across services/actions.
	MessageAlt string `json:"Message"`
}

// call marshals body, POSTs it to the Secrets Manager endpoint for action,
// signs it with SigV4, and decodes the JSON response into out. A non-2xx status
// is turned into an error: ResourceNotFoundException → ErrSecretNotFound, any
// other into an error carrying the AWS type + message (never a secret value).
func (c *awsHTTPClient) call(action string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("secrets: aws marshal %s: %w", action, err)
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("secrets: aws request %s: %w", action, err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager."+action)
	creds, err := c.creds()
	if err != nil {
		// Never echo a credential; only the action + underlying resolution error.
		return fmt.Errorf("secrets: aws credentials for %s: %w", action, err)
	}
	// A fresh signer per request keeps the CURRENT session token in the signature
	// (IMDS creds rotate) and avoids sharing mutable signer state across goroutines.
	signer := auth.NewAWSSigV4(
		creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken,
		c.region, "secretsmanager",
	)
	if err := signer.Transform(req); err != nil {
		return fmt.Errorf("secrets: aws sign %s: %w", action, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("secrets: aws call %s: %w", action, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("secrets: aws read %s: %w", action, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return awsErrorFrom(action, resp, respBody)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("secrets: aws decode %s: %w", action, err)
		}
	}
	return nil
}

// awsErrorFrom builds an error from a non-2xx AWS response, mapping
// ResourceNotFoundException to ErrSecretNotFound. It never includes the request
// body (which may carry a secret value) — only the AWS exception type/message.
func awsErrorFrom(action string, resp *http.Response, body []byte) error {
	var ae awsError
	_ = json.Unmarshal(body, &ae)
	typ := ae.Type
	if typ == "" {
		typ = resp.Header.Get("X-Amzn-Errortype")
	}
	// __type is often "prefix#ExceptionName"; keep the trailing name.
	if i := strings.LastIndexAny(typ, "#/"); i >= 0 {
		typ = typ[i+1:]
	}
	if strings.Contains(typ, "ResourceNotFoundException") {
		return fmt.Errorf("%w (%s)", ErrSecretNotFound, action)
	}
	msg := ae.Message
	if msg == "" {
		msg = ae.MessageAlt
	}
	if typ == "" {
		typ = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("secrets: aws %s failed: %s: %s", action, typ, msg)
}

// GetSecretValue implements AWSSecretsClient.
func (c *awsHTTPClient) GetSecretValue(name string) (string, error) {
	var out struct {
		SecretString string `json:"SecretString"`
	}
	if err := c.call("GetSecretValue", map[string]string{"SecretId": name}, &out); err != nil {
		return "", err
	}
	return out.SecretString, nil
}

// PutSecretValue implements AWSSecretsClient. It stores a new version of an
// existing secret; AWS returns ResourceNotFoundException (→ ErrSecretNotFound)
// when the secret does not exist yet.
func (c *awsHTTPClient) PutSecretValue(name, value string) (string, error) {
	var out struct {
		VersionID string `json:"VersionId"`
	}
	// A raw SigV4 caller must supply the idempotency token the AWS SDK would
	// otherwise auto-generate; without it AWS rejects the write with
	// InvalidRequestException. A fresh token per call is correct: each Put is a
	// distinct intended write and we do not auto-retry at this layer.
	token, err := newIdempotencyToken()
	if err != nil {
		return "", fmt.Errorf("secrets: aws PutSecretValue token: %w", err)
	}
	req := map[string]string{"SecretId": name, "SecretString": value, "ClientRequestToken": token}
	if err := c.call("PutSecretValue", req, &out); err != nil {
		return "", err
	}
	return out.VersionID, nil
}

// CreateSecret implements AWSSecretsClient.
func (c *awsHTTPClient) CreateSecret(name, value string) (string, error) {
	var out struct {
		VersionID string `json:"VersionId"`
	}
	// See PutSecretValue: CreateSecret likewise requires a caller-supplied
	// ClientRequestToken since we are not using the AWS SDK.
	token, err := newIdempotencyToken()
	if err != nil {
		return "", fmt.Errorf("secrets: aws CreateSecret token: %w", err)
	}
	req := map[string]string{"Name": name, "SecretString": value, "ClientRequestToken": token}
	if err := c.call("CreateSecret", req, &out); err != nil {
		return "", err
	}
	return out.VersionID, nil
}

// newIdempotencyToken returns a fresh RFC 4122 version-4 UUID string (36 chars,
// 8-4-4-4-12 hex) for use as an AWS ClientRequestToken. Secrets Manager requires
// this token on PutSecretValue/CreateSecret (32–64 chars); the AWS SDK generates
// it automatically, but warden's dependency-free SigV4 client must supply its own.
// It is not a secret. crypto/rand.Read failing is near-impossible, but the error
// is propagated rather than swallowed: sending an empty token would just re-trigger
// the same AWS InvalidRequestException.
func newIdempotencyToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}

// DeleteSecret implements AWSSecretsClient. ForceDeleteWithoutRecovery makes the
// delete effective immediately (no recovery window), matching the store's
// idempotent contract.
func (c *awsHTTPClient) DeleteSecret(name string) error {
	req := map[string]any{"SecretId": name, "ForceDeleteWithoutRecovery": true}
	return c.call("DeleteSecret", req, nil)
}

// ListSecrets implements AWSSecretsClient. It pages through ListSecrets with a
// name-prefix filter, returning value-free metadata only. AWS's SecretListEntry
// carries no per-entry version, so Version is left empty; UpdatedAt comes from
// LastChangedDate (epoch seconds).
func (c *awsHTTPClient) ListSecrets(namePrefix string) ([]AWSSecretEntry, error) {
	var entries []AWSSecretEntry
	var nextToken string
	for {
		req := map[string]any{
			"Filters": []map[string]any{
				{"Key": "name", "Values": []string{namePrefix}},
			},
		}
		if nextToken != "" {
			req["NextToken"] = nextToken
		}
		var out struct {
			SecretList []struct {
				Name            string  `json:"Name"`
				LastChangedDate float64 `json:"LastChangedDate"`
			} `json:"SecretList"`
			NextToken string `json:"NextToken"`
		}
		if err := c.call("ListSecrets", req, &out); err != nil {
			return nil, err
		}
		for _, e := range out.SecretList {
			// AWS's name filter is a prefix match, but guard defensively so a
			// broadened filter can never leak names outside our namespace.
			if !strings.HasPrefix(e.Name, namePrefix) {
				continue
			}
			entries = append(entries, AWSSecretEntry{
				Name:      e.Name,
				UpdatedAt: epochToTime(e.LastChangedDate),
			})
		}
		if out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return entries, nil
}

// epochToTime converts AWS epoch-seconds (with fractional millis) to time.Time.
// A zero/absent value yields the zero time.
func epochToTime(epoch float64) time.Time {
	if epoch == 0 {
		return time.Time{}
	}
	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}
