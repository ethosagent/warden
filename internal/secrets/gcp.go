package secrets

import "fmt"

// GCPSecretClient abstracts the GCP Secret Manager AccessSecretVersion call.
// Users wire in their own implementation backed by the GCP SDK; tests use a
// fake. This keeps the GCP SDK out of warden's dependency tree.
type GCPSecretClient interface {
	AccessSecret(name string) (string, error)
}

// GCPFetcher resolves placeholders by calling GCP Secret Manager through
// a GCPSecretClient.
type GCPFetcher struct {
	client  GCPSecretClient
	mapping map[string]string // placeholder → resource name (projects/*/secrets/*/versions/*)
}

// NewGCPFetcher builds a GCPFetcher. client is the GCP Secret Manager
// client, and mapping maps placeholder names to fully qualified secret
// resource names.
func NewGCPFetcher(client GCPSecretClient, mapping map[string]string) *GCPFetcher {
	m := make(map[string]string, len(mapping))
	for k, v := range mapping {
		m[k] = v
	}
	return &GCPFetcher{client: client, mapping: m}
}

// Fetch retrieves the secret value for the given placeholder from GCP
// Secret Manager.
func (f *GCPFetcher) Fetch(placeholder string) (string, error) {
	name, ok := f.mapping[placeholder]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownPlaceholder, placeholder)
	}
	val, err := f.client.AccessSecret(name)
	if err != nil {
		return "", fmt.Errorf("secrets: gcp fetch %q: %w", placeholder, err)
	}
	return val, nil
}
