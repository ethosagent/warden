package webauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hostPrefix is the cookie-name prefix that makes a browser insist on Secure,
// Path=/ and no Domain.
const hostPrefix = "__Host-"

// defaultPort lists the ports a browser leaves out of Origin.
func defaultPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// Cookie names and flags a session (or login-binding) cookie. Secure is
// decided from the configured redirect URL, never from r.TLS: a
// TLS-terminating proxy in front of the control plane must not downgrade the
// cookie.
type Cookie struct {
	Name   string
	Secure bool
	// origin is scheme://host of the redirect URL, the only Origin accepted on
	// state-changing requests.
	origin string
}

// NewCookie derives the cookie spec for base (e.g. "warden_console") from a
// front door's redirect URL. An https URL gives "__Host-"+base (Secure, Path=/,
// no Domain). Plain http is accepted only for a loopback host and gives the
// unprefixed, non-Secure base name.
func NewCookie(redirectURL, base string) (Cookie, error) {
	u, err := url.Parse(redirectURL)
	if err != nil || u.Host == "" {
		return Cookie{}, fmt.Errorf("session cookie: redirect URL %q is not absolute", redirectURL)
	}
	// Browsers send Origin lowercased and without the scheme's default port.
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && p != defaultPort(u.Scheme) {
		host += ":" + p
	}
	origin := strings.ToLower(u.Scheme) + "://" + host
	switch u.Scheme {
	case "https":
		return Cookie{Name: hostPrefix + base, Secure: true, origin: origin}, nil
	case "http":
		if !IsLoopback(u.Hostname()) {
			return Cookie{}, errors.New("session cookie: an http redirect URL is allowed only on a loopback host")
		}
		return Cookie{Name: base, origin: origin}, nil
	}
	return Cookie{}, fmt.Errorf("session cookie: redirect URL scheme %q is not http(s)", u.Scheme)
}

// IsLoopback reports whether h is localhost or a loopback IP literal.
func IsLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Origin is scheme://host of the redirect URL the cookie was derived from.
func (c Cookie) Origin() string { return c.origin }

// Named returns a cookie with the same flags and origin under another base
// name ("__Host-"+base when Secure), e.g. the login-binding cookie next to a
// session cookie.
func (c Cookie) Named(base string) Cookie {
	n := c
	n.Name = base
	if c.Secure {
		n.Name = hostPrefix + base
	}
	return n
}

// New returns the Set-Cookie value for value, living maxAge.
func (c Cookie) New(value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: c.Name, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		Secure: c.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// Clear returns the Set-Cookie value that deletes the cookie.
func (c Cookie) Clear() *http.Cookie {
	return &http.Cookie{
		Name: c.Name, Value: "", Path: "/", MaxAge: -1,
		Secure: c.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// From returns the non-empty value the request carries under the cookie's
// name, if any. Only this exact name is read.
func (c Cookie) From(r *http.Request) (string, bool) {
	ck, err := r.Cookie(c.Name)
	if err != nil || ck.Value == "" {
		return "", false
	}
	return ck.Value, true
}
