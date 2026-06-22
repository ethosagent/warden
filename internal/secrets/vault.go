package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// VaultFetcher resolves placeholders by reading from a HashiCorp Vault KV
// store over its HTTP API. It supports both KV v1 and KV v2 response formats.
type VaultFetcher struct {
	client  *http.Client
	addr    string            // Vault address (e.g. "http://vault:8200")
	token   string            // Vault token
	mapping map[string]string // placeholder → Vault KV path (e.g. "secret/data/openai")
}

// NewVaultFetcher builds a VaultFetcher. addr is the Vault server address
// (e.g. "http://vault:8200"), token is the authentication token, and mapping
// maps placeholder names to Vault KV paths.
func NewVaultFetcher(addr, token string, mapping map[string]string) *VaultFetcher {
	m := make(map[string]string, len(mapping))
	for k, v := range mapping {
		m[k] = v
	}
	return &VaultFetcher{
		client:  &http.Client{},
		addr:    addr,
		token:   token,
		mapping: m,
	}
}

// Fetch retrieves the secret value for the given placeholder from Vault.
// It tries KV v2 response format first (.data.data.value), then falls back
// to KV v1 (.data.value).
func (f *VaultFetcher) Fetch(placeholder string) (string, error) {
	path, ok := f.mapping[placeholder]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownPlaceholder, placeholder)
	}

	url := f.addr + "/v1/" + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("secrets: vault request build: %w", err)
	}
	req.Header.Set("X-Vault-Token", f.token)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("secrets: vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("secrets: vault returned status %d for %q", resp.StatusCode, placeholder)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("secrets: vault read body: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", fmt.Errorf("secrets: vault JSON parse: %w", err)
	}

	// Try KV v2 first: .data.data.value
	if data, ok := raw["data"].(map[string]interface{}); ok {
		if inner, ok := data["data"].(map[string]interface{}); ok {
			if val, ok := inner["value"].(string); ok {
				return val, nil
			}
		}
		// Fall back to KV v1: .data.value
		if val, ok := data["value"].(string); ok {
			return val, nil
		}
	}

	return "", fmt.Errorf("secrets: vault response missing value for %q", placeholder)
}
