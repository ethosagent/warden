package harness

import (
	"net/http"
	"time"
)

// ClientOptions tune NewLoopbackClient.
type ClientOptions struct {
	// Jar keeps cookies (a console browser).
	Jar http.CookieJar
	// Timeout bounds one request (0 = none).
	Timeout time.Duration
	// FollowRedirects lets the client follow redirects; by default the client
	// returns the first redirect response so a test sees each hop.
	FollowRedirects bool
}

// NewLoopbackClient builds an HTTP client over rt for a test that plays the
// outside world: the console user, the agent or an attacker dialling a loopback
// control plane, worker or fake, never the internet. It is the one place test
// packages construct a bare client (the harness baseline allows it), so the
// security suite does not.
func NewLoopbackClient(rt http.RoundTripper, o ClientOptions) *http.Client {
	c := &http.Client{Transport: rt, Jar: o.Jar, Timeout: o.Timeout}
	if !o.FollowRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}
