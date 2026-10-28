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
	"sort"
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
	// caps are the capabilities advertised on every heartbeat (see WorkerCaps).
	caps []string
}

// CapBlocklistV1 is the capability a worker advertises when it enforces
// policy.blockedUsers. An old worker decodes the policy wire without error but
// ignores the list, so the control plane uses this to flag it.
const CapBlocklistV1 = "blocklist/v1"

// WorkerCaps returns the sorted capabilities this binary implements. Later
// features append their own constant here.
func WorkerCaps() []string {
	caps := []string{CapBlocklistV1}
	sort.Strings(caps)
	return caps
}

// heartbeatBody is the JSON a worker POSTs to /control/heartbeat. It carries no
// secret, token or request data.
type heartbeatBody struct {
	PolicyETag string   `json:"policyETag"`
	Caps       []string `json:"caps,omitempty"`
}

// SetCaps sets the capabilities advertised on each heartbeat. Pass WorkerCaps().
func (r *RemoteProvider) SetCaps(caps []string) {
	r.mu.Lock()
	r.caps = append([]string(nil), caps...)
	r.mu.Unlock()
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

// CloseIdleConnections drops the pooled keep-alive connections of the pull and
// long-poll clients. Run calls it on shutdown so a hosted worker (Run inside a
// longer-lived process) leaves no open connections — and no server-side
// goroutines — behind.
func (r *RemoteProvider) CloseIdleConnections() {
	r.client.CloseIdleConnections()
	r.longClient.CloseIdleConnections()
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
	caps := r.caps
	r.mu.RUnlock()
	body, _ := json.Marshal(heartbeatBody{PolicyETag: etag, Caps: caps})

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
//
// ScopedAllowlist / ScopedAllowPos (W-P1-GPOL-06) carry the identity-scoped
// allow entries the control plane moves out of "allowlist" so a worker that does
// not know them cannot read a scoped entry as a global one; parseRemotePolicy
// merges them back.
type remoteWire struct {
	Policy
	// BlockedUsers is decoded here, not through Policy (whose field is
	// json:"-" for rule X2), then copied onto the policy in parseRemotePolicy.
	BlockedUsers    []BlockedUser    `json:"blockedUsers,omitempty"`
	Settings        *SettingsWire    `json:"settings,omitempty"`
	ScopedAllowlist []AllowlistEntry `json:"scopedAllowlist,omitempty"`
	// ScopedAllowPos[i] is the index ScopedAllowlist[i] had in the full
	// allowlist, strictly ascending. Absent: the entries are appended.
	ScopedAllowPos []int `json:"scopedAllowPos,omitempty"`
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
	p.BlockedUsers = normalizeBlockedUsers(w.BlockedUsers)
	// The wire carries scoped entries only in scopedAllowlist: a plain entry
	// with principals is what an older worker would read as global, so it is
	// refused here even though validate (W-P1-GPOL-10) now accepts principals.
	for i, e := range p.Allowlist {
		if len(e.Groups) > 0 || len(e.Users) > 0 {
			return nil, nil, fmt.Errorf("config: remote: policy.allowlist[%d]: groups/users belong in scopedAllowlist", i)
		}
	}
	// validate sees the merged list with principals stripped; the real
	// principals are validated by mergeScopedAllow.
	merged, scoped, err := mergeScopedAllow(p.Allowlist, w.ScopedAllowlist, w.ScopedAllowPos)
	if err != nil {
		return nil, nil, err
	}
	checked := p
	checked.Allowlist = make([]AllowlistEntry, len(merged))
	for i, e := range merged {
		if scoped[i] {
			e.Groups, e.Users = nil, nil
		}
		checked.Allowlist[i] = e
	}
	if err := validate(checked); err != nil {
		return nil, nil, err
	}
	p.Allowlist = merged
	if err := restoreScopedConditions(w.Settings); err != nil {
		return nil, nil, err
	}
	return &p, w.Settings, nil
}

// mergeScopedAllow re-inserts the scoped allow entries into the plain list at
// their original positions (appended when the control plane sent none) and
// returns the merged list plus which entries came from the scoped list. Every
// scoped entry must carry groups or users, which are normalized here; a
// malformed position list fails the pull so the worker keeps its last good
// policy.
func mergeScopedAllow(plain, scopedIn []AllowlistEntry, pos []int) ([]AllowlistEntry, []bool, error) {
	n := len(plain) + len(scopedIn)
	if len(scopedIn) == 0 {
		if len(pos) != 0 {
			return nil, nil, fmt.Errorf("config: remote: scopedAllowPos without scopedAllowlist")
		}
		return plain, make([]bool, n), nil
	}
	if len(pos) == 0 {
		for i := range scopedIn {
			pos = append(pos, len(plain)+i)
		}
	}
	if len(pos) != len(scopedIn) {
		return nil, nil, fmt.Errorf("config: remote: scopedAllowPos has %d values for %d scoped entries", len(pos), len(scopedIn))
	}
	for i, v := range pos {
		if v < 0 || v >= n || (i > 0 && v <= pos[i-1]) {
			return nil, nil, fmt.Errorf("config: remote: scopedAllowPos[%d]=%d out of range or not ascending", i, v)
		}
	}
	merged := make([]AllowlistEntry, 0, n)
	scoped := make([]bool, 0, n)
	next := 0 // next scoped entry to place
	for i := 0; i < n; i++ {
		if next < len(scopedIn) && pos[next] == i {
			e := scopedIn[next]
			path := fmt.Sprintf("policy.scopedAllowlist[%d]", next)
			if len(e.Groups) == 0 && len(e.Users) == 0 {
				return nil, nil, fmt.Errorf("config: remote: %s has no groups or users", path)
			}
			var err error
			if e.Groups, e.Users, err = normalizePrincipals(path, e.Groups, e.Users); err != nil {
				return nil, nil, err
			}
			e.Domain = strings.ToLower(e.Domain)
			merged = append(merged, e)
			scoped = append(scoped, true)
			next++
			continue
		}
		merged = append(merged, plain[len(merged)-next])
		scoped = append(scoped, false)
	}
	return merged, scoped, nil
}

// restoreScopedConditions merges each AllowWhenScoped back into AllowWhen. A
// sentinel AllowWhen without a scoped condition (or the reverse) fails the
// pull: the worker keeps its last good policy rather than run a tool whose
// real condition it cannot see.
func restoreScopedConditions(s *SettingsWire) error {
	if s == nil || s.MCP == nil || s.MCP.Tools == nil {
		return nil
	}
	for tool, tc := range s.MCP.Tools.Constraints {
		sentinel := tc.AllowWhen != nil && tc.AllowWhen.AgentID == ReservedScopedAgentID
		switch {
		case sentinel && tc.AllowWhenScoped == nil:
			return fmt.Errorf("config: remote: mcp tool %q allowWhen is identity-scoped but carries no scoped condition", tool)
		case !sentinel && tc.AllowWhenScoped != nil:
			return fmt.Errorf("config: remote: mcp tool %q has a scoped condition without the identity-scoped marker", tool)
		case !sentinel:
			continue
		}
		path := fmt.Sprintf("mcp.tools.constraints[%q].allowWhen", tool)
		sc := tc.AllowWhenScoped
		if sc.AgentID == ReservedScopedAgentID {
			return fmt.Errorf("config: remote: %s.agentId %q is reserved", path, sc.AgentID)
		}
		if len(sc.Groups) == 0 && len(sc.Users) == 0 {
			return fmt.Errorf("config: remote: %s: scoped condition has no groups or users", path)
		}
		if sc.TimeWindow != "" {
			if err := validateTimeWindow(path, sc.TimeWindow); err != nil {
				return err
			}
		}
		g, u, err := normalizePrincipals(path, sc.Groups, sc.Users)
		if err != nil {
			return err
		}
		sc.Groups, sc.Users = g, u
		tc.AllowWhen, tc.AllowWhenScoped = sc, nil
		s.MCP.Tools.Constraints[tool] = tc
	}
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
