package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// maxPolicyBytes caps a policy response body (defense against a runaway CP).
const maxPolicyBytes = 1 << 20 // 1 MiB

// RemoteProvider pulls policy from a control-plane HTTP endpoint. It implements
// ConfigProvider.
type RemoteProvider struct {
	endpoint string
	token    string
	proxyID  string
	// client is the short-timeout client for one-shot Pull; longClient has no
	// timeout (bounded per request by context) so a held long-poll isn't cut off.
	client     *http.Client
	longClient *http.Client
	mu         sync.RWMutex
	policy     *Policy
	settings   *SettingsWire // behavioral config from the CP (stored, not yet applied)
	etag       string        // last ETag seen, sent as If-None-Match on the next long-poll
	lastErr    error
}

// SetProxyID sets the worker identifier sent on each policy pull (header
// X-Warden-Proxy-ID), letting the control plane list this worker as connected
// even before it forwards any analytics. Empty disables the header.
func (r *RemoteProvider) SetProxyID(id string) {
	r.proxyID = id
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
		endpoint:   endpoint,
		token:      token,
		client:     &http.Client{Timeout: 10 * time.Second},
		longClient: &http.Client{}, // no client timeout; bounded per request by ctx
	}, nil
}

// SetCACert adds the PEM-encoded CA certificate at path to this provider's
// trust pool (in addition to the system roots) and rebuilds the HTTP client to
// use it. This lets a worker trust a control plane that serves a privately
// signed certificate WITHOUT changing the process-wide trust store — upstream
// proxy TLS is unaffected because only this client carries the extra root.
func (r *RemoteProvider) SetCACert(path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: remote: read ca cert %q: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("config: remote: no certificates found in %q", path)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	r.client = &http.Client{Timeout: 10 * time.Second, Transport: transport}
	r.longClient = &http.Client{Transport: transport} // no timeout; ctx-bounded
	return nil
}

// Pull fetches the current policy from the control plane (one-shot, immediate).
// On success the policy is stored; on failure the last known good policy (if
// any) is preserved.
func (r *RemoteProvider) Pull() error {
	req, err := http.NewRequest(http.MethodGet, r.endpoint, nil)
	if err != nil {
		return r.setErr(fmt.Errorf("config: remote: build request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	if r.proxyID != "" {
		req.Header.Set("X-Warden-Proxy-ID", r.proxyID)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return r.setErr(fmt.Errorf("config: remote: fetch: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return r.setErr(fmt.Errorf("config: remote: unexpected status %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
	if err != nil {
		return r.setErr(fmt.Errorf("config: remote: read body: %w", err))
	}
	p, settings, err := parseRemotePolicy(body)
	if err != nil {
		return r.setErr(fmt.Errorf("config: remote: %w", err))
	}
	r.mu.Lock()
	r.policy = p
	r.settings = settings
	r.etag = strings.Trim(resp.Header.Get("ETag"), `"`)
	r.lastErr = nil
	r.mu.Unlock()
	return nil
}

// PollLong issues an ETag-conditional long-poll: the CP holds the request up to
// wait, then responds 200 with a changed policy (returns changed=true) or 304
// Not Modified (changed=false). On 200 the new policy + ETag are stored; on any
// error the last known good policy is preserved and the error returned.
func (r *RemoteProvider) PollLong(ctx context.Context, wait time.Duration) (changed bool, err error) {
	u, err := url.Parse(r.endpoint)
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: endpoint: %w", err))
	}
	q := u.Query()
	q.Set("wait", wait.String())
	u.RawQuery = q.Encode()

	// Bound the request a bit beyond wait so a hung connection still unblocks.
	reqCtx, cancel := context.WithTimeout(ctx, wait+15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: build request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	if r.proxyID != "" {
		req.Header.Set("X-Warden-Proxy-ID", r.proxyID)
	}
	r.mu.RLock()
	etag := r.etag
	r.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}

	resp, err := r.longClient.Do(req)
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: long-poll: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		r.clearErr()
		return false, nil
	case http.StatusOK:
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
		if rerr != nil {
			return false, r.setErr(fmt.Errorf("config: remote: read body: %w", rerr))
		}
		p, settings, perr := parseRemotePolicy(body)
		if perr != nil {
			return false, r.setErr(fmt.Errorf("config: remote: %w", perr))
		}
		r.mu.Lock()
		r.policy = p
		r.settings = settings
		r.etag = strings.Trim(resp.Header.Get("ETag"), `"`)
		r.lastErr = nil
		r.mu.Unlock()
		return true, nil
	default:
		return false, r.setErr(fmt.Errorf("config: remote: unexpected status %d", resp.StatusCode))
	}
}

// Heartbeat pings the control plane's `/control/heartbeat` (derived from the
// policy endpoint's host) so the CP lists this worker as online even when idle.
// It reports the worker's current policy ETag so the dashboard can flag workers
// that are a version behind. Best-effort: errors are returned, not fatal.
func (r *RemoteProvider) Heartbeat(ctx context.Context) error {
	u, err := url.Parse(r.endpoint)
	if err != nil {
		return fmt.Errorf("config: remote: endpoint: %w", err)
	}
	u.Path = "/control/heartbeat"
	u.RawQuery = ""

	r.mu.RLock()
	etag := r.etag
	r.mu.RUnlock()
	body, _ := json.Marshal(map[string]string{"policyETag": etag})

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("config: remote: build heartbeat: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	if r.proxyID != "" {
		req.Header.Set("X-Warden-Proxy-ID", r.proxyID)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("config: remote: heartbeat: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("config: remote: heartbeat status %d", resp.StatusCode)
	}
	return nil
}

// setErr records err as the last error (preserving last-known-good policy) and
// returns it. clearErr resets the last error after a successful 304.
func (r *RemoteProvider) setErr(err error) error {
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
	return err
}

func (r *RemoteProvider) clearErr() {
	r.mu.Lock()
	r.lastErr = nil
	r.mu.Unlock()
}

// remoteWire mirrors the control-plane /policy JSON: the allow/deny Policy
// fields plus the optional behavioral settings document. Decoding into a
// separate envelope keeps Policy free of a wire-only field while letting both be
// parsed in one pass.
type remoteWire struct {
	Policy
	Settings *SettingsWire `json:"settings,omitempty"`
}

// parseRemotePolicy decodes a control-plane policy response, applies the same
// defaults + normalization as the YAML parser, validates the policy, and also
// returns the optional behavioral settings (nil when the CP sends none).
func parseRemotePolicy(body []byte) (*Policy, *SettingsWire, error) {
	var w remoteWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, nil, fmt.Errorf("decode json: %w", err)
	}
	p := w.Policy
	if p.LogLevel == "" {
		p.LogLevel = "info"
	}
	if p.LogFormat == "" {
		p.LogFormat = "json"
	}
	if p.CacheTTLSeconds == 0 {
		p.CacheTTLSeconds = defaultCacheTTLSeconds
	}
	for i := range p.Allowlist {
		p.Allowlist[i].Domain = strings.ToLower(p.Allowlist[i].Domain)
	}
	for i := range p.Denylist {
		p.Denylist[i].Domain = strings.ToLower(p.Denylist[i].Domain)
	}
	if err := validate(p); err != nil {
		return nil, nil, err
	}
	return &p, w.Settings, nil
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

// Settings returns a deep copy of the behavioral settings most recently
// distributed by the control plane, or nil if none have been received (e.g. a
// pure allow/deny CP, or before the first pull). Phase 1 stores settings only;
// nothing in the proxy hot path consumes them yet.
func (r *RemoteProvider) Settings() *SettingsWire {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.settings.DeepCopy()
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
