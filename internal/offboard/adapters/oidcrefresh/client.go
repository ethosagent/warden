// Package oidcrefresh is the offboard.TokenClient over an OIDC token
// endpoint: grant_type=refresh_token as a confidential client
// (client_secret_basic), through the shared server-side OIDC HTTP client the
// control plane builds (oidc.NewHTTPClient: no environment proxy, no
// redirects, a 1 MiB body cap, the internal issuer URL rewrite). The request
// body holds the refresh token; neither it nor the response body ever reaches
// an error or a log line.
package oidcrefresh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethosagent/warden/internal/offboard"
)

// maxBody bounds the token response read here (the shared client also caps it).
const maxBody = 1 << 20

// ErrNotReady: discovery has not produced a token endpoint yet.
var ErrNotReady = errors.New("oidcrefresh: token endpoint not discovered yet")

// Config builds a Client. Every field is required.
type Config struct {
	// HTTP is the shared OIDC client (oidc.NewHTTPClient).
	HTTP *http.Client
	// TokenURL returns the discovered token endpoint, or false while lazy
	// discovery has not succeeded.
	TokenURL func() (string, bool)
	// ClientID and ClientSecret are the warden-portal client
	// (consent.oidc.clientID and the value of clientSecretEnv).
	ClientID, ClientSecret string
}

// Client is offboard.TokenClient.
type Client struct{ cfg Config }

var _ offboard.TokenClient = (*Client)(nil)

// New returns the client, or an error naming a missing field.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.HTTP == nil:
		return nil, errors.New("oidcrefresh: needs the shared OIDC HTTP client")
	case cfg.TokenURL == nil:
		return nil, errors.New("oidcrefresh: needs the token endpoint")
	case cfg.ClientID == "":
		return nil, errors.New("oidcrefresh: needs the client id")
	}
	return &Client{cfg: cfg}, nil
}

type tokenResponse struct {
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Refresh posts grant_type=refresh_token. Every HTTP answer is a Result
// (a non-JSON error body gives an empty ErrorCode); no answer is an error
// that names only its kind, never a URL with a token or a body.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (offboard.Result, error) {
	endpoint, ok := c.cfg.TokenURL()
	if !ok {
		return offboard.Result{}, ErrNotReady
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return offboard.Result{}, fmt.Errorf("oidcrefresh: build request (%T)", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 2.3.1: the id and secret are form-encoded inside Basic.
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return offboard.Result{}, fmt.Errorf("oidcrefresh: %w", context.DeadlineExceeded)
		}
		return offboard.Result{}, fmt.Errorf("oidcrefresh: token endpoint unreachable (%T)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return offboard.Result{}, fmt.Errorf("oidcrefresh: %w", context.DeadlineExceeded)
		}
		return offboard.Result{}, fmt.Errorf("oidcrefresh: read token response (%T)", err)
	}
	r := offboard.Result{Status: resp.StatusCode}
	var tr tokenResponse
	if json.Unmarshal(body, &tr) == nil {
		r.ErrorCode, r.Description = tr.Error, tr.ErrorDescription
		if resp.StatusCode == http.StatusOK {
			r.RefreshToken, r.IDToken = tr.RefreshToken, tr.IDToken
		}
	}
	return r, nil
}
