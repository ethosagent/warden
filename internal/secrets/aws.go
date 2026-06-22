package secrets

import "fmt"

// AWSSecretsClient abstracts the AWS Secrets Manager GetSecretValue call.
// Users wire in their own implementation backed by the AWS SDK; tests use a
// fake. This keeps the AWS SDK out of warden's dependency tree.
type AWSSecretsClient interface {
	GetSecretValue(name string) (string, error)
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
