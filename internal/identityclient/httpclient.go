package identityclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	httpTimeout  = 10 * time.Second
	maxBodyBytes = 1 << 20
)

var errBodyTooLarge = errors.New("identityclient: response body over 1 MiB")

// NewHTTPClient builds the http.Client the CLI uses for the IdP: it ignores the
// environment proxy (a shell that exports HTTPS_PROXY=<worker> for its children
// must not route its own IdP calls through it), follows no redirects, caps the
// response body at 1 MiB and times out after 10s.
func NewHTTPClient() *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	return &http.Client{
		Timeout:   httpTimeout,
		Transport: capBody{next: base, limit: maxBodyBytes},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewCPHTTPClient builds the http.Client for the control plane: it ignores the
// environment proxy, follows no redirects, caps the body at 64 KiB, times out
// after 10s and trusts the PEM roots in caFile (the system roots when empty).
func NewCPHTTPClient(caFile string) (*http.Client, error) {
	return NewCPHTTPClientCapped(caFile, maxExchangeBody)
}

// NewCPHTTPClientCapped is NewCPHTTPClient with the response body cap named:
// the keys CLI reads the fleet list (a few KiB per worker) through it.
func NewCPHTTPClientCapped(caFile string, limit int64) (*http.Client, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pemBytes, err := readRegularFile(caFile, "control-plane CA file", maxCAFileBytes, false)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("identityclient: %s holds no PEM certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	base.TLSClientConfig = tlsCfg
	return &http.Client{
		Timeout:       httpTimeout,
		Transport:     capBody{next: base, limit: limit},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// maxCAFileBytes caps the --cp-ca read.
const maxCAFileBytes = 1 << 20

type capBody struct {
	next  http.RoundTripper
	limit int64
}

func (t capBody) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &capReader{rc: resp.Body, limit: t.limit}
	return resp, nil
}

type capReader struct {
	rc    io.ReadCloser
	n     int64
	limit int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		return n, errBodyTooLarge
	}
	return n, err
}

func (c *capReader) Close() error { return c.rc.Close() }
