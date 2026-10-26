package identityclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"golang.org/x/oauth2"
)

// Typed errors let a caller choose its exit code (the CLI maps them to 2 and 3).
var (
	// ErrLoginRequired means there is no usable login: no cache, no refresh
	// token, or the issuer rejected the refresh token (expired or revoked).
	ErrLoginRequired = errors.New("identityclient: login required; run `warden identity login`")
	// ErrIssuerUnreachable means the issuer could not be reached and no valid
	// cached ID token remains.
	ErrIssuerUnreachable = errors.New("identityclient: the identity issuer is unreachable and no valid cached token remains")
)

const (
	deviceGrant      = "urn:ietf:params:oauth:grant-type:device_code"
	defaultPollSecs  = 5
	slowDownStep     = 5 * time.Second
	defaultDeviceTTL = 15 * time.Minute
)

// Client logs a user in and serves ID tokens from the file cache. The zero
// values of HTTP, Now, Log, Sleep and Getenv select NewHTTPClient, time.Now, a
// discarding logger, a context-aware timer and os.Getenv. A Client is safe for
// concurrent use.
type Client struct {
	Config Config
	HTTP   *http.Client
	Now    func() time.Time
	Log    *slog.Logger

	// Sleep waits d or until ctx ends; tests replace it to drive the device
	// poll without real delays.
	Sleep func(ctx context.Context, d time.Duration) error
	// Getenv reads the client secret named by Config.ClientSecretEnv.
	Getenv func(string) string
}

// TokenResult is a valid ID token. Warning is non-empty when the token was
// served while the issuer could not be reached.
type TokenResult struct {
	IDToken string
	Expiry  time.Time
	Warning string
}

// StatusInfo describes the cached login. It never carries a token.
type StatusInfo struct {
	Issuer    string
	Subject   string
	Email     string
	Groups    []string
	Expiry    time.Time
	CachePath string
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return NewHTTPClient()
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Store returns the file cache of this client's (issuer, client id).
func (c *Client) Store() *FileStore { return NewFileStore(c.Config) }

// oauthConfig builds the oauth2 config for ep. The client id and secret travel
// in the form body, never in a header.
func (c *Client) oauthConfig(ep Endpoints) (*oauth2.Config, error) {
	secret := ""
	if name := c.Config.ClientSecretEnv; name != "" {
		getenv := c.Getenv
		if getenv == nil {
			getenv = osGetenv
		}
		if secret = getenv(name); secret == "" {
			return nil, fmt.Errorf("identityclient: environment variable %s (the client secret) is not set", name)
		}
	}
	return &oauth2.Config{
		ClientID:     c.Config.ClientID,
		ClientSecret: secret,
		Scopes:       c.Config.Scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL:      ep.Token,
			DeviceAuthURL: ep.DeviceAuthorization,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}, nil
}

func (c *Client) withHTTP(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.http())
}

// Login runs the RFC 8628 device authorization grant. The verification URI and
// user code go to prompt only. Before caching, the ID token claims are parsed
// unverified and the returned warnings name a missing groups claim or an aud
// without the configured audience.
func (c *Client) Login(ctx context.Context, prompt io.Writer) ([]string, error) {
	ep, err := Discover(ctx, c.http(), c.Config.Issuer)
	if err != nil {
		return nil, err
	}
	if ep.DeviceAuthorization == "" {
		return nil, errors.New("identityclient: the issuer does not advertise a device_authorization_endpoint")
	}
	cfg, err := c.oauthConfig(ep)
	if err != nil {
		return nil, err
	}
	ctx = c.withHTTP(ctx)
	da, err := cfg.DeviceAuth(ctx)
	if err != nil {
		return nil, c.oauthErr("device authorization", err)
	}
	_, _ = fmt.Fprintf(prompt, "To sign in, open %s and enter the code %s\n", da.VerificationURI, da.UserCode)
	if da.VerificationURIComplete != "" {
		_, _ = fmt.Fprintf(prompt, "Or open %s\n", da.VerificationURIComplete)
	}

	tok, err := c.pollDevice(ctx, cfg, da)
	if err != nil {
		return nil, err
	}
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" {
		return nil, errors.New("identityclient: the token response has no id_token (is the openid scope granted?)")
	}
	cl, err := parseClaims(idToken)
	if err != nil {
		return nil, err
	}
	var warnings []string
	if tok.RefreshToken == "" {
		warnings = append(warnings, "no refresh_token was issued (is offline_access granted?): the login ends with the ID token")
	}
	if len(cl.Groups) == 0 {
		warnings = append(warnings, "the ID token has no groups claim")
	}
	if a := c.Config.Audience; a != "" && !slices.Contains(cl.Aud, a) {
		warnings = append(warnings, fmt.Sprintf("the ID token aud claim does not include the configured audience %q", a))
	}
	store := c.Store()
	err = store.WithLock(func() error {
		return store.Save(Entry{
			Issuer: c.Config.Issuer, ClientID: c.Config.ClientID,
			RefreshToken: tok.RefreshToken, IDToken: idToken, ReceivedAt: c.now(),
		})
	})
	if err != nil {
		return nil, err
	}
	c.log().Debug("login stored", "issuer", c.Config.Issuer, "client_id", c.Config.ClientID,
		"scopes", c.Config.Scopes, "expiry", cl.Expiry, "token_fp", Fingerprint(idToken))
	return warnings, nil
}

// pollDevice polls the token endpoint until the user approves. It honours the
// server interval, adds 5s on slow_down and gives up at expires_in.
func (c *Client) pollDevice(ctx context.Context, cfg *oauth2.Config, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	interval := time.Duration(da.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPollSecs * time.Second
	}
	ttl := defaultDeviceTTL
	if !da.Expiry.IsZero() {
		ttl = time.Until(da.Expiry)
	}
	var waited time.Duration
	for {
		if waited+interval > ttl {
			return nil, errors.New("identityclient: the device code expired before the login was approved")
		}
		if err := c.sleep(ctx, interval); err != nil {
			return nil, err
		}
		waited += interval
		// Exchange is the one public way to send a custom grant through oauth2
		// with the client id and secret handled; the empty authorization code
		// it adds is ignored by the issuer (RFC 6749 section 3.2).
		tok, err := cfg.Exchange(ctx, "",
			oauth2.SetAuthURLParam("grant_type", deviceGrant),
			oauth2.SetAuthURLParam("device_code", da.DeviceCode))
		if err == nil {
			return tok, nil
		}
		var re *oauth2.RetrieveError
		if !errors.As(err, &re) {
			return nil, c.oauthErr("device login", err)
		}
		switch re.ErrorCode {
		case "authorization_pending":
		case "slow_down":
			interval += slowDownStep
		case "access_denied":
			return nil, errors.New("identityclient: the login was denied")
		case "expired_token":
			return nil, errors.New("identityclient: the device code expired before the login was approved")
		default:
			return nil, c.oauthErr("device login", err)
		}
	}
}

// oauthErr turns an oauth2 or transport error into one that carries no body,
// code or URL: only the operation and a fixed class.
func (c *Client) oauthErr(op string, err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.Response != nil && re.Response.StatusCode >= 500 {
			return fmt.Errorf("identityclient: %s: %w", op, ErrIssuerUnreachable)
		}
		return fmt.Errorf("identityclient: %s: the issuer rejected the request (HTTP %d)", op, statusOf(re))
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("identityclient: %s: %w", op, ErrIssuerUnreachable)
}

func statusOf(re *oauth2.RetrieveError) int {
	if re.Response == nil {
		return 0
	}
	return re.Response.StatusCode
}

// fresh reports whether e's ID token is still inside the first 2/3 of its
// lifetime, measured from the local receipt time.
func (c *Client) fresh(e Entry) (TokenResult, bool) {
	cl, err := parseClaims(e.IDToken)
	if err != nil {
		return TokenResult{}, false
	}
	now := c.now()
	life := cl.Expiry.Sub(cl.IssuedAt)
	if now.Before(e.ReceivedAt) || now.Sub(e.ReceivedAt) >= life*2/3 || !now.Before(cl.Expiry) {
		return TokenResult{}, false
	}
	return TokenResult{IDToken: e.IDToken, Expiry: cl.Expiry}, true
}

// Token returns a valid ID token. A cached token inside the first 2/3 of its
// lifetime is returned with no network I/O and no lock. Otherwise it takes the
// cache lock, RE-READS the cache (another process may have refreshed, and some
// issuers rotate refresh tokens on use) and refreshes at most once. It never prompts.
func (c *Client) Token(ctx context.Context) (TokenResult, error) {
	store := c.Store()
	e, err := store.Load()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return TokenResult{}, ErrLoginRequired
	case err != nil:
		return TokenResult{}, err
	}
	if r, ok := c.fresh(e); ok {
		return r, nil
	}
	var res TokenResult
	err = store.WithLock(func() error {
		e, err := store.Load()
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return ErrLoginRequired
		case err != nil:
			return err
		}
		if r, ok := c.fresh(e); ok {
			res = r
			return nil
		}
		res, err = c.refresh(ctx, store, e)
		return err
	})
	return res, err
}

// refresh exchanges e's refresh token under the cache lock and persists the
// rotated one. When the issuer cannot be reached it falls back to a cached
// token that has not expired yet.
func (c *Client) refresh(ctx context.Context, store *FileStore, e Entry) (TokenResult, error) {
	if e.RefreshToken == "" {
		return TokenResult{}, ErrLoginRequired
	}
	unreachable := func() (TokenResult, error) {
		if cl, err := parseClaims(e.IDToken); err == nil && c.now().Before(cl.Expiry) {
			c.log().Warn("issuer unreachable, serving cached token", "issuer", c.Config.Issuer, "token_fp", Fingerprint(e.IDToken))
			return TokenResult{IDToken: e.IDToken, Expiry: cl.Expiry, Warning: "the identity issuer is unreachable; using the cached token until it expires"}, nil
		}
		return TokenResult{}, ErrIssuerUnreachable
	}
	ep, err := Discover(ctx, c.http(), c.Config.Issuer)
	if errors.Is(err, ErrIssuerUnreachable) {
		return unreachable()
	}
	if err != nil {
		return TokenResult{}, err
	}
	cfg, err := c.oauthConfig(ep)
	if err != nil {
		return TokenResult{}, err
	}
	tok, err := cfg.TokenSource(c.withHTTP(ctx), &oauth2.Token{RefreshToken: e.RefreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		switch {
		case errors.As(err, &re) && re.ErrorCode == "invalid_grant":
			return TokenResult{}, ErrLoginRequired
		case errors.Is(c.oauthErr("refresh", err), ErrIssuerUnreachable):
			return unreachable()
		default:
			return TokenResult{}, c.oauthErr("refresh", err)
		}
	}
	idToken, _ := tok.Extra("id_token").(string)
	cl, perr := parseClaims(idToken)
	if idToken == "" || perr != nil {
		return TokenResult{}, errors.New("identityclient: refresh: the token response has no usable id_token")
	}
	next := Entry{
		Issuer: c.Config.Issuer, ClientID: c.Config.ClientID,
		RefreshToken: tok.RefreshToken, IDToken: idToken, ReceivedAt: c.now(),
	}
	if next.RefreshToken == "" {
		next.RefreshToken = e.RefreshToken
	}
	if err := store.Save(next); err != nil {
		return TokenResult{}, err
	}
	c.log().Debug("token refreshed", "issuer", c.Config.Issuer, "client_id", c.Config.ClientID,
		"scopes", c.Config.Scopes, "expiry", cl.Expiry, "token_fp", Fingerprint(idToken))
	return TokenResult{IDToken: idToken, Expiry: cl.Expiry}, nil
}

// Status describes the cached login without contacting the issuer. A missing
// cache is ErrLoginRequired.
func (c *Client) Status() (StatusInfo, error) {
	store := c.Store()
	e, err := store.Load()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return StatusInfo{}, ErrLoginRequired
	case err != nil:
		return StatusInfo{}, err
	}
	cl, err := parseClaims(e.IDToken)
	if err != nil {
		return StatusInfo{}, err
	}
	return StatusInfo{
		Issuer: cl.Issuer, Subject: cl.Subject, Email: cl.Email, Groups: cl.Groups,
		Expiry: cl.Expiry, CachePath: store.Path(),
	}, nil
}

// Logout deletes the cache entry and its lock file.
func (c *Client) Logout() error { return c.Store().Remove() }
