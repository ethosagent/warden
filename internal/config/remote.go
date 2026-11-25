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
	"slices"
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
	etag       string        // ETag of the applied policy: what the heartbeat reports
	// pollETag is sent as If-None-Match on the next long-poll. It equals etag
	// except after a rejected bundle, when it is the rejected envelope's ETag
	// so the same bad bundle is not downloaded again.
	pollETag string
	lastErr  error

	// Signed bundles (remote_bundle.go); trust is nil until SetBundleTrust.
	// applyMu serializes the verify-then-swap of one response.
	applyMu       sync.Mutex
	trust         *BundleTrust
	bundle        *VerifiedBundle
	lastReject    string
	lastRejectAt  time.Time
	rejects       map[string]int64
	loggedRejects map[string]bool
	// caps are the capabilities advertised on every heartbeat (see WorkerCaps).
	caps []string
	// agentID is the registered agent id this worker is bound to, and
	// identityMode returns the effective identity mode; both ride the heartbeat.
	agentID      string
	identityMode func() string
	// onDate, when set, receives the CP's Date header from each long-poll
	// response (see SetDateObserver).
	onDate func(cpNow time.Time)
	// certAuth is true once SetHTTPClient installed a client that presents the
	// worker certificate: no Authorization header is sent then.
	certAuth bool
	// proxyIDFn, when set, supplies the X-Warden-Proxy-ID value (the id of the
	// worker certificate, which may arrive after construction).
	proxyIDFn func() string
	// certInfo reports the serial and expiry of the certificate in use, for the
	// heartbeat; ok is false when the worker holds none.
	certInfo func() (serial string, notAfter time.Time, ok bool)
}

// CapBlocklistV1 is the capability a worker advertises when it enforces
// policy.blockedUsers. An old worker decodes the policy wire without error but
// ignores the list, so the control plane uses this to flag it.
const CapBlocklistV1 = "blocklist/v1"

// CapGroupPolicyV1 is the capability a worker advertises when it understands
// identity-scoped policy rules (scopedAllowlist, scoped MCP conditions). An old
// worker denies scoped destinations (fail closed), so the control plane uses
// this to flag it while scoped rules are served. The value must match the
// control plane's capPattern or it is dropped.
const CapGroupPolicyV1 = "grouppolicy/v1"

// CapIdentityChallengeV1 is the capability a worker advertises when it
// understands identity challenge mode (407 with a sign-in URL). An old worker
// rejects the unknown mode and keeps its previous config, so it would keep
// allowing callers it should challenge; the control plane uses this to flag it
// while challenge mode is served.
const CapIdentityChallengeV1 = "identity/challenge-v1"

// WorkerCaps returns the sorted capabilities this binary implements. Later
// features append their own constant here.
func WorkerCaps() []string {
	caps := []string{CapAgentRegV1, CapBlocklistV1, CapGroupPolicyV1, CapIdentityChallengeV1}
	sort.Strings(caps)
	return caps
}

// CapAgentRegV1 is the capability a worker advertises when it enforces the
// agent registry: it selects its own registeredAgents entry on every apply and
// denies all traffic (agent_disabled) while that agent is disabled. An old
// worker decodes the list and ignores it, so the control plane flags it. Any
// widening of the registeredAgents wire (a third status, more than two keys)
// must be gated on this cap, because a worker rejects the whole policy wire on
// a list it cannot validate and would freeze on its last-known-good policy.
const CapAgentRegV1 = "agentreg/v1"

// CapIdentityRequireV1 is the capability a worker advertises when it enforces
// identity require mode (W-P2-WBND-03). No worker advertises it yet; the
// constant exists so the console and the control plane agree on the literal.
const CapIdentityRequireV1 = "identity/require-v1"

// heartbeatBody is the JSON a worker POSTs to /control/heartbeat. It carries no
// secret, token or request data.
type heartbeatBody struct {
	PolicyETag string   `json:"policyETag"`
	Caps       []string `json:"caps,omitempty"`
	// AgentID and IdentityMode (W-P2-AREG-05) say which agent the worker is
	// bound to and the identity mode it enforces now. Both are self-asserted,
	// like caps, and omitted when unknown so an old control plane sees the old
	// body.
	AgentID      string `json:"agentID,omitempty"`
	IdentityMode string `json:"identityMode,omitempty"`
	// CertSerial and CertNotAfter (W-P2-WCA-03) name the worker certificate in
	// use (serial in lowercase hex, expiry RFC 3339); omitted without one.
	CertSerial   string `json:"certSerial,omitempty"`
	CertNotAfter string `json:"certNotAfter,omitempty"`
	// The signed-bundle state (W-P2-SBND-05), all omitted on a worker without
	// pins so an old control plane sees the old body. BundleSeq stays at the
	// applied bundle's seq after a rejection (a rejected bundle changes nothing
	// applied); LastRejectReason is cleared by the next apply. PinnedKids are
	// the first MaxHeartbeatPinnedKIDs pinned key ids, which keeps the body
	// under the control plane's 4096-byte read limit. Kids are public key
	// thumbprints; no key, signature or payload byte is reported.
	BundleSeq        int64    `json:"bundleSeq,omitempty"`
	BundleKID        string   `json:"bundleKid,omitempty"`
	BundleIssuedAt   string   `json:"bundleIssuedAt,omitempty"`
	PinnedKIDs       []string `json:"pinnedKids,omitempty"`
	BundleStale      bool     `json:"bundleStale,omitempty"`
	LastRejectReason string   `json:"lastRejectReason,omitempty"`
	LastRejectAt     string   `json:"lastRejectAt,omitempty"`
}

// MaxHeartbeatPinnedKIDs bounds the pinned kids one heartbeat reports. Staged
// rotation holds two or three pins; the cap only protects the body size.
const MaxHeartbeatPinnedKIDs = 8

// CapBundleV1 is the capability a worker advertises when it verifies signed
// bundles, that is when it holds pins (W-P2-SBND-05). It is added to the
// heartbeat only then, so the control plane can tell a verifying worker from
// one that applies the unsigned wire.
const CapBundleV1 = "bundle/v1"

// bundleHeartbeat fills hb's signed-bundle fields and returns the caps to
// advertise: caps plus CapBundleV1 when pins are set. st is one BundleStatus
// read, so the fields describe one instant.
func bundleHeartbeat(hb *heartbeatBody, caps []string, st BundleStatus) []string {
	if !st.Enabled {
		return caps
	}
	out := append([]string(nil), caps...)
	if !slices.Contains(out, CapBundleV1) {
		out = append(out, CapBundleV1)
		sort.Strings(out)
	}
	hb.PinnedKIDs = st.PinnedKIDs
	if len(hb.PinnedKIDs) > MaxHeartbeatPinnedKIDs {
		hb.PinnedKIDs = hb.PinnedKIDs[:MaxHeartbeatPinnedKIDs]
	}
	hb.BundleStale = st.Applied && st.Expired
	if st.Applied {
		hb.BundleSeq, hb.BundleKID = st.Seq, st.KID
		hb.BundleIssuedAt = st.IssuedAt.UTC().Format(time.RFC3339)
	}
	hb.LastRejectReason = st.LastRejectReason
	if st.LastRejectReason != "" && !st.LastRejectAt.IsZero() {
		hb.LastRejectAt = st.LastRejectAt.UTC().Format(time.RFC3339)
	}
	return out
}

// SetAgent sets the resolved agent id and the source of the effective identity
// mode reported on each heartbeat. mode may be nil (no mode reported).
func (r *RemoteProvider) SetAgent(agentID string, mode func() string) {
	r.mu.Lock()
	r.agentID = agentID
	r.identityMode = mode
	r.mu.Unlock()
}

// SetCaps sets the capabilities advertised on each heartbeat. Pass WorkerCaps().
func (r *RemoteProvider) SetCaps(caps []string) {
	r.mu.Lock()
	r.caps = append([]string(nil), caps...)
	r.mu.Unlock()
}

// SetDateObserver registers a callback invoked on every PollLong response that
// carries a parseable Date header, with that time. The worker subtracts its own
// clock to get the clock skew (warden.controlplane.clock_skew_seconds), which
// diagnoses mass expired or not-yet-valid token failures. The package reads no
// clock itself. The header has one-second resolution. nil disables it.
func (r *RemoteProvider) SetDateObserver(fn func(cpNow time.Time)) {
	r.mu.Lock()
	r.onDate = fn
	r.mu.Unlock()
}

// observeDate reports the response's Date header (the CP stamps it when it
// writes the response, after holding the poll).
func (r *RemoteProvider) observeDate(resp *http.Response) {
	r.mu.RLock()
	fn := r.onDate
	r.mu.RUnlock()
	if fn == nil {
		return
	}
	d, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return
	}
	fn(d)
}

// SetProxyID sets the worker identifier sent on each policy pull (header
// X-Warden-Proxy-ID), letting the control plane list this worker as connected
// even before it forwards any analytics. Empty disables the header.
func (r *RemoteProvider) SetProxyID(id string) {
	r.proxyID = id
}

// SetProxyIDFunc replaces the fixed id of SetProxyID with a function read on
// every request, for a worker whose id is the one in its certificate. An empty
// result omits the header. nil restores the fixed id.
func (r *RemoteProvider) SetProxyIDFunc(fn func() string) {
	r.mu.Lock()
	r.proxyIDFn = fn
	r.mu.Unlock()
}

// SetCertInfo sets the source of the certificate serial and expiry the heartbeat
// reports. fn must not block.
func (r *RemoteProvider) SetCertInfo(fn func() (serial string, notAfter time.Time, ok bool)) {
	r.mu.Lock()
	r.certInfo = fn
	r.mu.Unlock()
}

// SetHTTPClient makes the provider use the worker's shared control-plane client,
// whose TLS handshake presents the worker certificate (W-P2-WCA-03). The
// transport and its connection pool are shared; the provider keeps its own
// timeouts (10s for a pull and a heartbeat, none for a long-poll, which its
// context bounds). From then on no Authorization header is sent: the
// certificate is the credential. It supersedes SetCACert (the client carries
// its own trust).
func (r *RemoteProvider) SetHTTPClient(c *http.Client) {
	r.client = &http.Client{Timeout: 10 * time.Second, Transport: c.Transport}
	r.longClient = &http.Client{Transport: c.Transport}
	r.certAuth = true
}

// authorize sets the credential and worker id headers on a request.
func (r *RemoteProvider) authorize(req *http.Request) {
	if !r.certAuth {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	r.mu.RLock()
	fn := r.proxyIDFn
	r.mu.RUnlock()
	id := r.proxyID
	if fn != nil {
		id = fn()
	}
	if id != "" {
		req.Header.Set("X-Warden-Proxy-ID", id)
	}
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
	r.authorize(req)
	r.setAccept(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return r.setErr(fmt.Errorf("config: remote: fetch: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return r.setErr(r.statusErr(resp.StatusCode))
	}
	_, err = r.applyResponse(resp)
	return err
}

// applyResponse applies one 200 policy response and reports whether the
// enforced policy changed. With pins set the body must be a verified signed
// bundle; without them it is the legacy wire, read and parsed as it always was.
// Every failure keeps the last-known-good policy and is recorded as lastErr.
func (r *RemoteProvider) applyResponse(resp *http.Response) (bool, error) {
	r.mu.RLock()
	t := r.trust
	r.mu.RUnlock()
	if t != nil {
		return r.applyBundleBody(t, resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: read body: %w", err))
	}
	p, settings, err := parseRemotePolicy(body)
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: %w", err))
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	r.mu.Lock()
	r.policy = p
	r.settings = settings
	r.etag, r.pollETag = etag, etag
	r.lastErr = nil
	r.mu.Unlock()
	return true, nil
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
	r.authorize(req)
	r.setAccept(req)
	r.mu.RLock()
	etag := r.pollETag
	r.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}

	resp, err := r.longClient.Do(req)
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: long-poll: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()
	r.observeDate(resp)

	switch resp.StatusCode {
	case http.StatusNotModified:
		r.clearErr()
		return false, nil
	case http.StatusOK:
		return r.applyResponse(resp)
	default:
		return false, r.setErr(r.statusErr(resp.StatusCode))
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
	hb := heartbeatBody{PolicyETag: etag, Caps: r.caps, AgentID: r.agentID}
	modeFn := r.identityMode
	certFn := r.certInfo
	r.mu.RUnlock()
	if certFn != nil {
		if serial, notAfter, ok := certFn(); ok {
			hb.CertSerial, hb.CertNotAfter = serial, notAfter.UTC().Format(time.RFC3339)
		}
	}
	if modeFn != nil {
		hb.IdentityMode = modeFn()
	}
	hb.Caps = bundleHeartbeat(&hb, hb.Caps, r.BundleStatus())
	body, _ := json.Marshal(hb)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("config: remote: build heartbeat: %w", err)
	}
	r.authorize(req)
	req.Header.Set("Content-Type", "application/json")
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

// statusErr is the error for an unexpected status. A 406 to a worker without
// pins is a control plane in --bundles=require talking to a worker that does
// not ask for the envelope; the error says what to configure.
func (r *RemoteProvider) statusErr(code int) error {
	r.mu.RLock()
	pinned := r.trust != nil
	r.mu.RUnlock()
	if code == http.StatusNotAcceptable && !pinned {
		return fmt.Errorf("config: remote: unexpected status %d: the control plane requires signed bundles; pin its bundle keys in controlPlane.bundleKeys", code)
	}
	return fmt.Errorf("config: remote: unexpected status %d", code)
}

// setAccept asks for the signed envelope when pins are set. Without pins the
// request carries no Accept header, as it never did.
func (r *RemoteProvider) setAccept(req *http.Request) {
	r.mu.RLock()
	signed := r.trust != nil
	r.mu.RUnlock()
	if signed {
		req.Header.Set("Accept", BundleMediaType)
	}
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
	BlockedUsers []BlockedUser `json:"blockedUsers,omitempty"`
	// RegisteredAgents likewise (W-P2-AREG-04): decoded here, sorted and
	// validated in parseRemotePolicy.
	RegisteredAgents []RegisteredAgent `json:"registeredAgents,omitempty"`
	Settings         *SettingsWire     `json:"settings,omitempty"`
	ScopedAllowlist  []AllowlistEntry  `json:"scopedAllowlist,omitempty"`
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
	if len(w.RegisteredAgents) > 0 {
		agents := append([]RegisteredAgent(nil), w.RegisteredAgents...)
		SortRegisteredAgents(agents)
		if err := ValidateRegisteredAgents(agents); err != nil {
			return nil, nil, err
		}
		p.RegisteredAgents = agents
	}
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
