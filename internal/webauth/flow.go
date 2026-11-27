package webauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/identity"
)

// Login error codes: the whole vocabulary a front door may show the browser
// for a failed callback. IdP error text is never echoed.
const (
	CodeStateInvalid   = "state_invalid"
	CodeNonceMismatch  = "nonce_mismatch"
	CodeTokenInvalid   = "token_invalid"
	CodeExchangeFailed = "exchange_failed"
	CodeIDPError       = "idp_error"
	CodeIDPUnavailable = "idp_unavailable"
)

// MaxNextBytes bounds the stored post-login path.
const MaxNextBytes = 512

// ErrUnavailable is returned by Begin and Complete, before they write
// anything, while the provider has not been discovered.
var ErrUnavailable = errors.New("webauth: identity provider unavailable")

// Error is a failed callback. Code is one of the Code constants. Consumed is
// true once a pending state of this purpose was taken (the attempt is then
// worth recording). Sub is the token's subject for the log line, verified or
// not, when a token got that far.
type Error struct {
	Code     string
	Consumed bool
	Sub      string
}

func (e *Error) Error() string { return "webauth: login failed: " + e.Code }

// Login is a completed callback: the verified ID-token claims, the stored
// post-login path, and the refresh token when the token response carried one
// (empty otherwise). A consumer that does not keep refresh tokens ignores it;
// it is never logged.
type Login struct {
	Claims       identity.Claims
	Next         string
	RefreshToken string
}

// Flow is one front door's OIDC authorization-code login with S256 PKCE,
// state and nonce. Begin stores a pending row of Purpose keyed by the state's
// hash, binds it to the browser with LoginCookie and redirects to the IdP;
// Complete consumes that row (only when the purpose matches), checks the
// binding cookie, exchanges the code and verifies the ID token with nonce.
// What happens to the verified claims (admission, session) is the consumer's.
type Flow struct {
	// Name labels log lines ("console").
	Name     string
	Provider *Provider
	// Verifier checks the ID token: pinned to the front door's client
	// (Audience and AllowedAZP), with nonce support (identity.WithNonce).
	Verifier identity.Verifier
	Pending  Pendings
	Purpose  string
	// LoginCookie is the browser-binding cookie, distinct per front door.
	LoginCookie Cookie
	// AllowNext reports whether a requested post-login path may be kept;
	// anything else, and an empty next, becomes DefaultNext.
	AllowNext   func(next string) bool
	DefaultNext string
	Logger      *slog.Logger
}

// Ready reports whether the provider has been discovered.
func (f *Flow) Ready() bool { return f != nil && f.Provider.Ready() }

func (f *Flow) logger() *slog.Logger {
	if f.Logger == nil {
		return slog.Default()
	}
	return f.Logger
}

func (f *Flow) next(raw string) string {
	if raw == "" || f.AllowNext == nil || !f.AllowNext(raw) {
		return f.DefaultNext
	}
	return raw
}

// Begin starts a login for the browser: it stores the pending row, sets the
// binding cookie and redirects to the IdP. On an error it writes nothing:
// ErrUnavailable before discovery, ErrPendingFull at the cap, any other error
// when the row could not be stored.
func (f *Flow) Begin(w http.ResponseWriter, r *http.Request, next string) error {
	oc, ok := f.Provider.Config()
	if !ok {
		return ErrUnavailable
	}
	state, nonce, browser := RandomToken(32), RandomToken(32), RandomToken(32)
	verifier := oauth2.GenerateVerifier()
	err := f.Pending.Put(r.Context(), Pending{
		StateHash: SHA256Hex(state), Purpose: f.Purpose, Nonce: nonce, Verifier: verifier,
		Next: f.next(next), BrowserHash: SHA256Hex(browser),
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, f.LoginCookie.New(browser, PendingTTL))
	NoStore(w)
	http.Redirect(w, r, oc.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), http.StatusFound)
	return nil
}

// Complete finishes a login from the IdP's redirect. Before discovery it
// returns ErrUnavailable and writes nothing. Otherwise it marks the response
// no-store and clears the binding cookie (single use whatever happens), then
// returns the Login or an *Error. It sets no session cookie and writes no
// body: the consumer does both.
func (f *Flow) Complete(w http.ResponseWriter, r *http.Request) (Login, error) {
	oc, ok := f.Provider.Config()
	if !ok {
		return Login{}, ErrUnavailable
	}
	NoStore(w)
	http.SetCookie(w, f.LoginCookie.Clear())
	return f.complete(r, oc)
}

func (f *Flow) complete(r *http.Request, oc oauth2.Config) (Login, error) {
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		return Login{}, &Error{Code: CodeStateInvalid}
	}
	p, found, err := f.Pending.Take(ctx, SHA256Hex(state), f.Purpose)
	if err != nil {
		f.logger().Error(f.Name+" login: pending lookup failed", "error", err)
		return Login{}, &Error{Code: CodeStateInvalid}
	}
	if !found {
		return Login{}, &Error{Code: CodeStateInvalid}
	}
	bc, err := r.Cookie(f.LoginCookie.Name)
	if err != nil || bc.Value == "" ||
		subtle.ConstantTimeCompare([]byte(SHA256Hex(bc.Value)), []byte(p.BrowserHash)) != 1 {
		return Login{}, &Error{Code: CodeStateInvalid, Consumed: true}
	}
	if q.Get("error") != "" {
		return Login{}, &Error{Code: CodeIDPError, Consumed: true}
	}
	code := q.Get("code")
	if code == "" {
		return Login{}, &Error{Code: CodeExchangeFailed, Consumed: true}
	}
	ectx := f.Provider.httpContext(ctx)
	tok, err := oc.Exchange(ectx, code, oauth2.VerifierOption(p.Verifier))
	if err != nil {
		return Login{}, &Error{Code: CodeExchangeFailed, Consumed: true}
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Login{}, &Error{Code: CodeTokenInvalid, Consumed: true}
	}
	claims, status, reason := f.Verifier.Verify(ectx, raw, identity.WithNonce(p.Nonce))
	switch {
	case status == identity.StatusUnverified:
		return Login{}, &Error{Code: CodeIDPUnavailable, Consumed: true}
	case status != identity.StatusValid && reason == identity.ReasonWrongNonce:
		return Login{}, &Error{Code: CodeNonceMismatch, Consumed: true, Sub: claims.Sub}
	case status != identity.StatusValid || claims.Sub == "":
		return Login{}, &Error{Code: CodeTokenInvalid, Consumed: true, Sub: claims.Sub}
	}
	return Login{Claims: claims, Next: p.Next, RefreshToken: tok.RefreshToken}, nil
}

// SafeNext reports whether raw is a plain same-origin absolute path under one
// of prefixes (each ending in "/"): no scheme or host, no "//", no backslash,
// no dot segment, no control character, at most MaxNextBytes, and the decoded
// path passes the same rules.
func SafeNext(raw string, prefixes ...string) bool {
	if raw == "" || len(raw) > MaxNextBytes ||
		strings.ContainsAny(raw, "\\\r\n\t") || strings.Contains(raw, "//") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return false
	}
	// The decoded path must pass the same separator rules as the raw string.
	if strings.Contains(u.Path, "//") || strings.ContainsAny(u.Path, "\\\r\n\t") {
		return false
	}
	under := false
	for _, pfx := range prefixes {
		if strings.HasPrefix(raw, pfx) && strings.HasPrefix(u.Path, pfx) {
			under = true
			break
		}
	}
	if !under {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

// RandomToken returns n random bytes, base64url without padding.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("control plane: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NoStore marks a response uncacheable and sends no Referer onward.
func NoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
