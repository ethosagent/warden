package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/identity"
)

const (
	clientTimeout = 5 * time.Second
	maxBodyBytes  = 1 << 20
)

var errBodyTooLarge = errors.New("oidc client: response body over 1 MiB")

// HTTPClientConfig configures the shared OIDC client. Issuer is the public
// issuer string. InternalIssuerURL, when set, is the origin that containers use
// to reach the IdP. CAFile optionally adds a private CA to this client only.
type HTTPClientConfig struct{ Issuer, InternalIssuerURL, CAFile string }

// NewHTTPClient builds the one http.Client for server-side OIDC calls. It runs
// CheckIssuer first. Requests whose origin equals the issuer's origin are sent
// to InternalIssuerURL (scheme, host and port only; the Host header, path,
// query, headers and body are unchanged). All other origins pass through. The
// client ignores the environment proxy, uses a plain dialer (an IdP on a
// private network is reachable), has a 5s timeout, a 1 MiB body cap, follows no
// redirects and requires TLS 1.2. If the internal URL is https and its host
// differs from the issuer host, TLS verifies the internal host name. It does no
// network I/O.
func NewHTTPClient(cfg HTTPClientConfig) (*http.Client, error) {
	return newHTTPClient(cfg, clientTimeout)
}

func newHTTPClient(cfg HTTPClientConfig, timeout time.Duration) (*http.Client, error) {
	if err := identity.CheckIssuer(cfg.Issuer, cfg.InternalIssuerURL); err != nil {
		return nil, err
	}
	var pool *x509.CertPool
	if cfg.CAFile != "" {
		var err error
		if pool, err = loadPool(cfg.CAFile); err != nil {
			return nil, err
		}
	}
	base := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}
	rw := rewriteTransport{next: base}
	if cfg.InternalIssuerURL != "" {
		// CheckIssuer already proved both parse.
		iu, _ := url.Parse(cfg.Issuer)
		xu, _ := url.Parse(cfg.InternalIssuerURL)
		rw.from, rw.to = originOf(iu), xu
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: capBody{next: rw},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("oidc client: read ca file: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("oidc client: no certificates found in ca file")
	}
	return pool, nil
}

type origin struct{ scheme, host, port string }

func originOf(u *url.URL) origin {
	o := origin{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(u.Hostname()), port: u.Port()}
	if o.port == "" {
		if o.scheme == "https" {
			o.port = "443"
		} else {
			o.port = "80"
		}
	}
	return o
}

// rewriteTransport sends issuer-origin requests to the internal origin. It
// works on a clone, so the caller's request is never mutated.
type rewriteTransport struct {
	next http.RoundTripper
	from origin
	to   *url.URL
}

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.to == nil || originOf(r.URL) != t.from {
		return t.next.RoundTrip(r)
	}
	r2 := r.Clone(r.Context())
	r2.Host = r.URL.Host
	r2.URL.Scheme = t.to.Scheme
	r2.URL.Host = t.to.Host
	return t.next.RoundTrip(r2)
}

// capBody fails the read that passes maxBodyBytes. Transport errors pass
// through unchanged and carry no URL. http.Client itself adds the request URL
// (query included, never the body) to the errors it returns, and a RoundTripper
// cannot prevent that, so callers must keep codes and tokens in POST bodies,
// never in URLs.
type capBody struct{ next http.RoundTripper }

func (t capBody) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &capReader{rc: resp.Body}
	return resp, nil
}

type capReader struct {
	rc io.ReadCloser
	n  int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	if c.n > maxBodyBytes {
		return n, errBodyTooLarge
	}
	return n, err
}

func (c *capReader) Close() error { return c.rc.Close() }

// WithHTTPClient returns ctx carrying c for both go-oidc (discovery and JWKS,
// via gooidc.ClientContext) and oauth2 (Exchange and Refresh, via
// oauth2.HTTPClient). Every go-oidc and oauth2 call must receive a context made
// through it. A context given to gooidc.NewRemoteKeySet outlives the call, so
// it must not be a request context.
func WithHTTPClient(ctx context.Context, c *http.Client) context.Context {
	ctx = gooidc.ClientContext(ctx, c)
	return context.WithValue(ctx, oauth2.HTTPClient, c)
}
