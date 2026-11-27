// Package httpclient is the FormPoster the OAuth broker uses for form POSTs to
// a provider token endpoint (the refresh_token grant today). It dials through
// proxy.SafeDialer so a generic provider URL cannot reach a private, link-local
// or metadata address, ignores the environment proxy, never follows a redirect
// (it drives an http.Transport directly, so a 302 is returned as is and
// credentials are never forwarded), is bound by the caller's context plus a
// hard 10s cap, and caps response bodies at MaxBodyBytes+1.
//
// It is not a general provider client: the authorization-code exchange through
// golang.org/x/oauth2 needs an *http.Client (that ticket builds its own over
// the same SafeDialer policy), while GitHub's revoke, a DELETE with a JSON
// body, goes through Do on this transport.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/proxy"
)

// DialTimeout bounds connect, TLS handshake and response headers.
const DialTimeout = 5 * time.Second

// HardTimeout caps one PostForm call whatever the caller's context says.
const HardTimeout = 10 * time.Second

// MaxBodyBytes is the response cap (the same as oauthbroker.MaxProviderResponseBytes).
const MaxBodyBytes = oauthbroker.MaxProviderResponseBytes

// Poster implements oauthbroker.FormPoster.
type Poster struct{ rt http.RoundTripper }

var (
	_ oauthbroker.FormPoster = (*Poster)(nil)
	_ oauthbroker.Requester  = (*Poster)(nil)
)

// New builds the Poster. allowPrivate lists CIDRs exempted from the SSRF
// blocklist (an operator's GitHub Enterprise Server on a private network, or
// loopback in a dev setup); empty in the default deployment. resolver may be
// nil.
func New(allowPrivate []string, resolver proxy.NameResolver) (*Poster, error) {
	sd, err := proxy.NewSafeDialerWithResolver(DialTimeout, allowPrivate, resolver)
	if err != nil {
		return nil, err
	}
	return &Poster{rt: &http.Transport{
		Proxy: nil,
		DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return sd.DialTLS(network, addr, &tls.Config{MinVersion: tls.VersionTLS12})
		},
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return sd.Dial(network, addr)
		},
		TLSHandshakeTimeout:   DialTimeout,
		ResponseHeaderTimeout: DialTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}}, nil
}

// PostForm implements oauthbroker.FormPoster.
func (p *Poster) PostForm(ctx context.Context, r oauthbroker.FormRequest) (int, []byte, error) {
	return p.Do(ctx, oauthbroker.Request{
		Method: http.MethodPost, URL: r.URL, Body: []byte(r.Form),
		ContentType: "application/x-www-form-urlencoded",
		BasicUser:   r.BasicUser, BasicPass: r.BasicPass,
	})
}

// Do implements oauthbroker.Requester over the same hardened transport.
func (p *Poster) Do(ctx context.Context, r oauthbroker.Request) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, HardTimeout)
	defer cancel()
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
	if err != nil {
		return 0, nil, errBadRequest
	}
	if len(r.Body) > 0 && r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	req.Header.Set("Accept", "application/json")
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	if r.BasicUser != "" {
		req.SetBasicAuth(r.BasicUser, r.BasicPass)
	}
	resp, err := p.rt.RoundTrip(req)
	if err != nil {
		var ssrf *proxy.SSRFError
		if errors.As(err, &ssrf) {
			return 0, nil, &oauthbroker.BlockedError{Reason: ssrf.Reason, AddrClass: ssrf.AddrClass}
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	limit := int64(MaxBodyBytes)
	if r.MaxBytes > 0 && r.MaxBytes < MaxBodyBytes {
		limit = int64(r.MaxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errBadRequest = constErr("httpclient: bad request")
