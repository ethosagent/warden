package secrets

import (
	"errors"
	"fmt"
	"time"
)

// ErrSecretNotFound is returned by an AWSSecretsClient when the named secret
// does not exist. It is the errors.Is-able sentinel the upsert path branches on:
// awsSecretStore.Put tries PutSecretValue first and, on ErrSecretNotFound,
// falls back to CreateSecret. The real HTTP client maps AWS's
// ResourceNotFoundException onto this sentinel; the fake returns it directly.
var ErrSecretNotFound = errors.New("secrets: secret not found")

// AWSSecretsClient abstracts the AWS Secrets Manager JSON API. Users wire in
// their own implementation (the real net/http + SigV4 client in
// aws_httpclient.go, or one backed by the AWS SDK); tests use a fake. Keeping
// this an interface is what keeps the AWS SDK out of warden's dependency tree.
//
// It carries the read verb (GetSecretValue) plus the write/list verbs the
// control plane needs, all behind the one mockable seam so the fake covers them
// and the SDK never enters the module graph.
type AWSSecretsClient interface {
	// GetSecretValue returns the current SecretString for name, or an error
	// (ErrSecretNotFound when the secret does not exist).
	GetSecretValue(name string) (string, error)
	// PutSecretValue stores a new version of an EXISTING secret and returns the
	// new version id. It returns ErrSecretNotFound when name does not exist yet —
	// the store's upsert branches on this to CreateSecret.
	PutSecretValue(name, value string) (version string, err error)
	// CreateSecret creates a NEW secret with the given value and returns its
	// version id. It is used only on the not-found branch of an upsert.
	CreateSecret(name, value string) (version string, err error)
	// DeleteSecret removes name. It is idempotent-ish: deleting an absent secret
	// (ErrSecretNotFound) is not surfaced as an error by the store.
	DeleteSecret(name string) error
	// ListSecrets returns value-free metadata for every secret whose name starts
	// with namePrefix. It MUST NOT read any value (no GetSecretValue).
	ListSecrets(namePrefix string) ([]AWSSecretEntry, error)
}

// AWSSecretEntry is value-free metadata for a single stored secret, returned by
// AWSSecretsClient.ListSecrets. It never carries a secret value.
type AWSSecretEntry struct {
	// Name is the full backend secret name (including any namespace prefix).
	Name string
	// Version identifies the current version/stage, when the backend exposes one
	// in its list response. AWS Secrets Manager's ListSecrets does not return a
	// per-entry version, so the real client leaves this empty; the fake sets it.
	Version string
	// UpdatedAt is when the value last changed, per the backend.
	UpdatedAt time.Time
}

// AWSFetcher resolves placeholders by calling AWS Secrets Manager through
// an AWSSecretsClient.
type AWSFetcher struct {
	client  AWSSecretsClient
	mapping map[string]string // placeholder → secret name or ARN
}

// NewAWSFetcher builds an AWSFetcher. client is the AWS Secrets Manager
// client, and mapping maps placeholder names to secret names or ARNs.
func NewAWSFetcher(client AWSSecretsClient, mapping map[string]string) *AWSFetcher {
	m := make(map[string]string, len(mapping))
	for k, v := range mapping {
		m[k] = v
	}
	return &AWSFetcher{client: client, mapping: m}
}

// Fetch retrieves the secret value for the given placeholder from AWS
// Secrets Manager.
func (f *AWSFetcher) Fetch(placeholder string) (string, error) {
	name, ok := f.mapping[placeholder]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownPlaceholder, placeholder)
	}
	val, err := f.client.GetSecretValue(name)
	if err != nil {
		return "", fmt.Errorf("secrets: aws fetch %q: %w", placeholder, err)
	}
	return val, nil
}
