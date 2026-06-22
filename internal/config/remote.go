package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RemoteProvider pulls policy from a control-plane HTTP endpoint. It implements
// ConfigProvider.
type RemoteProvider struct {
	endpoint string
	token    string
	client   *http.Client
	mu       sync.RWMutex
	policy   *Policy
	lastErr  error
}

var _ ConfigProvider = (*RemoteProvider)(nil)

// NewRemoteProvider creates a provider that fetches policy from the given
// control-plane endpoint, authenticating with the bearer token.
func NewRemoteProvider(endpoint, token string) (*RemoteProvider, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("config: invalid control plane endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("config: control plane endpoint must use HTTPS, got %q", u.Scheme)
	}
	return &RemoteProvider{
		endpoint: endpoint,
		token:    token,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Pull fetches the current policy from the control plane. On success, the
// policy is stored and subsequent GetPolicy calls return it. On failure, the
// error is recorded but the last known good policy (if any) is preserved.
func (r *RemoteProvider) Pull() error {
	req, err := http.NewRequest(http.MethodGet, r.endpoint, nil)
	if err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("config: remote: build request: %w", err)
		r.mu.Unlock()
		return r.lastErr
	}
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("config: remote: fetch: %w", err)
		r.mu.Unlock()
		return r.lastErr
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("config: remote: unexpected status %d", resp.StatusCode)
		r.mu.Unlock()
		return r.lastErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("config: remote: read body: %w", err)
		r.mu.Unlock()
		return r.lastErr
	}

	var p Policy
	if err := json.Unmarshal(body, &p); err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("config: remote: decode json: %w", err)
		r.mu.Unlock()
		return r.lastErr
	}

	// Set sensible defaults for fields not present in the remote response
	// (they have json:"-" tags so JSON decode leaves them at zero values).
	if p.LogLevel == "" {
		p.LogLevel = "info"
	}
	if p.LogFormat == "" {
		p.LogFormat = "json"
	}
	if p.CacheTTLSeconds == 0 {
		p.CacheTTLSeconds = defaultCacheTTLSeconds
	}

	// Normalize domain case, matching the behaviour of the YAML parser.
	for i := range p.Allowlist {
		p.Allowlist[i].Domain = strings.ToLower(p.Allowlist[i].Domain)
	}
	for i := range p.Denylist {
		p.Denylist[i].Domain = strings.ToLower(p.Denylist[i].Domain)
	}

	if err := validate(p); err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("config: remote: %w", err)
		r.mu.Unlock()
		return r.lastErr
	}

	r.mu.Lock()
	r.policy = &p
	r.lastErr = nil
	r.mu.Unlock()
	return nil
}

// GetPolicy returns the last known good policy. If no successful pull has
// occurred yet, it returns an error.
func (r *RemoteProvider) GetPolicy() (Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.policy == nil {
		if r.lastErr != nil {
			return Policy{}, fmt.Errorf("config: remote: no policy available: %w", r.lastErr)
		}
		return Policy{}, fmt.Errorf("config: remote: no policy available (no pull attempted)")
	}
	return r.policy.DeepCopy(), nil
}

// StartPolling begins a background goroutine that calls Pull immediately and
// then at the given interval. It stops when ctx is cancelled.
func (r *RemoteProvider) StartPolling(ctx context.Context, interval time.Duration) {
	go func() {
		_ = r.Pull()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = r.Pull()
			}
		}
	}()
}
