package identityclient

import (
	"errors"
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
		Transport: capBody{next: base},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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
