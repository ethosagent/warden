// Package httpclient is the FormPoster every OAuth broker call to a provider
// token endpoint uses (refresh today; exchange and revoke share it). It dials
// through proxy.SafeDialer so a generic provider URL cannot reach a private,
// link-local or metadata address, ignores the environment proxy, never follows
// a redirect (it drives an http.Transport directly, so a 302 is returned as
// is and credentials are never forwarded), is bound by the caller's context,
// and caps response bodies at MaxBodyBytes+1.
package httpclient

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/proxy"
)

// DialTimeout bounds connect, TLS handshake and response headers.
const DialTimeout = 5 * time.Second

// MaxBodyBytes is the response cap (the same as oauthbroker.MaxProviderResponseBytes).
const MaxBodyBytes = oauthbroker.MaxProviderResponseBytes

// Poster implements oauthbroker.FormPoster.
type Poster struct{ rt http.RoundTripper }

var _ oauthbroker.FormPoster = (*Poster)(nil)

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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, strings.NewReader(r.Form))
	if err != nil {
		return 0, nil, errBadRequest
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.BasicUser != "" {
		req.SetBasicAuth(r.BasicUser, r.BasicPass)
	}
	resp, err := p.rt.RoundTrip(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errBadRequest = constErr("httpclient: bad request")
