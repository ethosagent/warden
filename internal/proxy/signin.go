package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

// SignInOutcome is the bounded result of asking for a sign-in; it is the
// `outcome` label of warden.identity.signin.started.total and, for the two
// failures, the `sign_in_error` of the 407 body.
type SignInOutcome string

const (
	// SignInStarted: a new device authorization was started at the issuer.
	SignInStarted SignInOutcome = "started"
	// SignInReused: a pending one for the same agent was returned.
	SignInReused SignInOutcome = "reused"
	// SignInRateLimited: the pending-login or start-rate bound was hit. It is
	// spelled through denyreason.RateLimited (rule X6 bans the literal): the
	// sign-in outcome set is separate, but the word is the contract's.
	SignInRateLimited SignInOutcome = SignInOutcome(denyreason.RateLimited)
	// SignInIssuerUnreachable: the issuer failed, answered badly or named a URL
	// off its own origin.
	SignInIssuerUnreachable SignInOutcome = "issuer_unreachable"
)

// SignInOffer is one RFC 8628 device authorization, as the 407 body carries it.
// DeviceCode and UserCode are credentials of the login in progress: they ride
// the response body only and are never logged, counted or stored on an event.
type SignInOffer struct {
	Issuer                  string `json:"issuer"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	UserCode                string `json:"user_code"`
	DeviceCode              string `json:"device_code"`
	TokenEndpoint           string `json:"token_endpoint"`
	ClientID                string `json:"client_id"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

// SignInStarter starts (or reuses) a device authorization for an agent. It is
// the consumer-side seam of challenge mode; *DeviceStarter implements it.
type SignInStarter interface {
	// Start returns an offer and SignInStarted or SignInReused, or the zero
	// offer and SignInRateLimited or SignInIssuerUnreachable. It never blocks
	// longer than the starter's per-call timeout.
	Start(ctx context.Context, agentID string) (SignInOffer, SignInOutcome)
	// Forget drops the agent's pending offer: its sign-in is done (a request
	// carried a valid token), so the next challenge starts a fresh one.
	Forget(agentID string)
}

const (
	// signInCallTimeout bounds one issuer call (discovery or device authorization).
	signInCallTimeout = 3 * time.Second
	// signInReuseMargin ends an offer's reuse this long before it expires, so a
	// client is never handed a code about to lapse.
	signInReuseMargin = 30 * time.Second
	// signInMaxBody caps what is read from the issuer's answers.
	signInMaxBody = 64 << 10

	signInDefaultExpires  = 300
	signInMaxExpires      = 1800
	signInDefaultInterval = 5
	signInMaxInterval     = 60
	maxCodeBytes          = 4096
	maxURLBytes           = 2048
)

// DeviceStarterConfig configures NewDeviceStarter.
type DeviceStarterConfig struct {
	// Issuer is the public issuer string. Every URL the issuer returns must be
	// on its origin to be passed on.
	Issuer string
	// ClientID is the issuer's public device-flow client. Scopes are requested.
	ClientID string
	Scopes   []string
	// MaxPending bounds open offers; StartsPerMinute bounds issuer calls.
	MaxPending      int
	StartsPerMinute int
	// HTTP reaches the issuer (split-horizon rewrite, bounded body and timeout
	// are its job); it must not follow redirects.
	HTTP *http.Client
	// Now is the clock; nil selects time.Now.
	Now func() time.Time
}

// DeviceStarter is the production SignInStarter. Concurrent Starts for one
// agent share one device authorization (single flight) and its result is
// reused until shortly before it expires, so a client retry loop cannot flood
// the issuer. Starts are bounded by MaxPending open offers and a token bucket
// of StartsPerMinute. It holds no user token and no refresh token.
type DeviceStarter struct {
	cfg  DeviceStarterConfig
	base *url.URL // parsed issuer
	now  func() time.Time

	mu      sync.Mutex
	pending map[string]*signInEntry
	size    atomic.Int32 // len(pending), readable without mu
	tokens  float64
	refill  time.Time

	discMu sync.Mutex
	disc   *signInEndpoints // set once discovery succeeded
}

type signInEntry struct {
	done chan struct{} // closed when the start finished
	// The fields below are written before done closes and read after.
	ok         bool
	offer      SignInOffer
	expiresAt  time.Time
	reuseUntil time.Time
}

type signInEndpoints struct{ device, token string }

// NewDeviceStarter validates cfg and returns a starter. It does no I/O.
func NewDeviceStarter(cfg DeviceStarterConfig) (*DeviceStarter, error) {
	base, err := url.Parse(cfg.Issuer)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("proxy: sign-in issuer must be an absolute http(s) URL")
	}
	if cfg.HTTP == nil || cfg.ClientID == "" || cfg.MaxPending <= 0 || cfg.StartsPerMinute <= 0 {
		return nil, errors.New("proxy: sign-in starter needs an HTTP client, a client id and positive bounds")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &DeviceStarter{
		cfg: cfg, base: base, now: now,
		pending: map[string]*signInEntry{},
		tokens:  float64(cfg.StartsPerMinute),
	}, nil
}

// Start implements SignInStarter.
func (d *DeviceStarter) Start(ctx context.Context, agentID string) (SignInOffer, SignInOutcome) {
	now := d.now()
	d.mu.Lock()
	if e, ok := d.pending[agentID]; ok {
		select {
		case <-e.done:
			if e.ok && now.Before(e.reuseUntil) {
				offer := withRemaining(e.offer, e.expiresAt, now)
				d.mu.Unlock()
				return offer, SignInReused
			}
			d.removeLocked(agentID, e) // spent or lapsed: start a new one below
		default:
			// A start for this agent is in flight: wait for it, share its result.
			d.mu.Unlock()
			select {
			case <-e.done:
			case <-ctx.Done():
				return SignInOffer{}, SignInIssuerUnreachable
			}
			if !e.ok {
				return SignInOffer{}, SignInIssuerUnreachable
			}
			return withRemaining(e.offer, e.expiresAt, d.now()), SignInReused
		}
	}
	d.pruneLocked(now)
	if len(d.pending) >= d.cfg.MaxPending || !d.takeLocked(now) {
		d.mu.Unlock()
		return SignInOffer{}, SignInRateLimited
	}
	e := &signInEntry{done: make(chan struct{})}
	d.pending[agentID] = e
	d.size.Add(1)
	d.mu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, signInCallTimeout)
	offer, expires, err := d.begin(cctx)
	cancel()

	d.mu.Lock()
	if err != nil {
		d.removeLocked(agentID, e)
	} else {
		start := d.now()
		e.ok, e.offer = true, offer
		e.expiresAt = start.Add(time.Duration(offer.ExpiresIn) * time.Second)
		e.reuseUntil = start.Add(expires)
	}
	d.mu.Unlock()
	close(e.done)
	if err != nil {
		return SignInOffer{}, SignInIssuerUnreachable
	}
	return offer, SignInStarted
}

// Forget implements SignInStarter. It is a single atomic load when nothing is
// pending, so the hot path of every valid request can call it.
func (d *DeviceStarter) Forget(agentID string) {
	if d.size.Load() == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.pending[agentID]; ok {
		select {
		case <-e.done:
			d.removeLocked(agentID, e)
		default: // in flight: its waiters still need it
		}
	}
}

func (d *DeviceStarter) removeLocked(agentID string, e *signInEntry) {
	if d.pending[agentID] == e {
		delete(d.pending, agentID)
		d.size.Add(-1)
	}
}

// pruneLocked drops finished offers past their reuse window.
func (d *DeviceStarter) pruneLocked(now time.Time) {
	for id, e := range d.pending {
		select {
		case <-e.done:
			if !e.ok || !now.Before(e.reuseUntil) {
				d.removeLocked(id, e)
			}
		default:
		}
	}
}

// takeLocked takes one start from the token bucket (burst StartsPerMinute,
// refilled evenly over a minute).
func (d *DeviceStarter) takeLocked(now time.Time) bool {
	capacity := float64(d.cfg.StartsPerMinute)
	if !d.refill.IsZero() {
		d.tokens = min(capacity, d.tokens+now.Sub(d.refill).Seconds()*capacity/60)
	}
	d.refill = now
	if d.tokens < 1 {
		return false
	}
	d.tokens--
	return true
}

// withRemaining returns offer with expires_in set to what is left of it.
func withRemaining(o SignInOffer, expiresAt, now time.Time) SignInOffer {
	left := int(expiresAt.Sub(now).Round(time.Second) / time.Second)
	o.ExpiresIn = max(left, 1)
	return o
}

// begin discovers the endpoints (once) and starts one device authorization. It
// returns the offer and how long it may be reused. Errors carry no issuer text.
func (d *DeviceStarter) begin(ctx context.Context) (SignInOffer, time.Duration, error) {
	eps, err := d.endpoints(ctx)
	if err != nil {
		return SignInOffer{}, 0, err
	}
	form := url.Values{"client_id": {d.cfg.ClientID}, "scope": {strings.Join(d.cfg.Scopes, " ")}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, eps.device, strings.NewReader(form.Encode()))
	if err != nil {
		return SignInOffer{}, 0, errSignIn
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var resp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := d.doJSON(req, &resp); err != nil {
		return SignInOffer{}, 0, err
	}
	if resp.DeviceCode == "" || resp.UserCode == "" || len(resp.DeviceCode) > maxCodeBytes || len(resp.UserCode) > maxCodeBytes {
		return SignInOffer{}, 0, errSignIn
	}
	// Only URLs on the issuer's own origin are passed to the user: a
	// misbehaving issuer cannot steer a sign-in to another site.
	if !d.onIssuerOrigin(resp.VerificationURI) || (resp.VerificationURIComplete != "" && !d.onIssuerOrigin(resp.VerificationURIComplete)) {
		return SignInOffer{}, 0, errSignIn
	}
	expires := resp.ExpiresIn
	if expires <= 0 {
		expires = signInDefaultExpires
	}
	expires = min(expires, signInMaxExpires)
	interval := resp.Interval
	if interval <= 0 {
		interval = signInDefaultInterval
	}
	interval = min(interval, signInMaxInterval)
	reuse := time.Duration(expires)*time.Second - signInReuseMargin
	if reuse <= 0 {
		reuse = time.Duration(expires) * time.Second / 2
	}
	return SignInOffer{
		Issuer: d.cfg.Issuer, VerificationURI: resp.VerificationURI,
		VerificationURIComplete: resp.VerificationURIComplete,
		UserCode:                resp.UserCode, DeviceCode: resp.DeviceCode,
		TokenEndpoint: eps.token, ClientID: d.cfg.ClientID,
		Interval: interval, ExpiresIn: expires,
	}, reuse, nil
}

var errSignIn = errors.New("proxy: sign-in start failed")

// endpoints reads the issuer's discovery document once and keeps the device
// authorization and token endpoints. The document's issuer must equal the
// configured one and both endpoints must be on its origin.
func (d *DeviceStarter) endpoints(ctx context.Context) (signInEndpoints, error) {
	d.discMu.Lock()
	if d.disc != nil {
		eps := *d.disc
		d.discMu.Unlock()
		return eps, nil
	}
	d.discMu.Unlock()

	u := strings.TrimSuffix(d.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return signInEndpoints{}, errSignIn
	}
	req.Header.Set("Accept", "application/json")
	var doc struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		DeviceAuth    string `json:"device_authorization_endpoint"`
	}
	if err := d.doJSON(req, &doc); err != nil {
		return signInEndpoints{}, err
	}
	if doc.Issuer != d.cfg.Issuer || !d.onIssuerOrigin(doc.TokenEndpoint) || !d.onIssuerOrigin(doc.DeviceAuth) {
		return signInEndpoints{}, errSignIn
	}
	eps := signInEndpoints{device: doc.DeviceAuth, token: doc.TokenEndpoint}
	d.discMu.Lock()
	d.disc = &eps
	d.discMu.Unlock()
	return eps, nil
}

// doJSON sends req and decodes a 200 JSON body (capped) into v.
func (d *DeviceStarter) doJSON(req *http.Request, v any) error {
	resp, err := d.cfg.HTTP.Do(req)
	if err != nil {
		return errSignIn
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errSignIn
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, signInMaxBody)).Decode(v); err != nil {
		return errSignIn
	}
	return nil
}

// onIssuerOrigin reports whether raw is an http(s) URL with a host, no
// userinfo, within a sane length, on the issuer's scheme, host and port.
func (d *DeviceStarter) onIssuerOrigin(raw string) bool {
	if raw == "" || len(raw) > maxURLBytes {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Hostname() == "" {
		return false
	}
	return originKey(u) == originKey(d.base)
}

// originKey is scheme://host:port, lowercased, with the scheme's default port.
func originKey(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}
