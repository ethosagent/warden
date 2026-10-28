package identityclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// The sign-in challenge (#558, docs/identity-contract.md). A worker in
// identity challenge mode answers a CONNECT with no valid token with a 407 whose
// JSON body carries a sign-in offer: an RFC 8628 device authorization the worker
// started at the issuer. The forwarder shows the URL, polls the issuer for the
// token itself and stores it; the worker holds no user token and no refresh
// token. The device_code in the offer is the claim on the login in progress, so
// it never goes on to the agent process.

// challengeError is the `error` of a challenge body.
const challengeError = "identity_required"

// challengeBody is the 407 body as a worker writes it and as the agent gets it
// (without the device code).
type challengeBody struct {
	Error       string      `json:"error"`
	Reason      string      `json:"reason,omitempty"`
	SignInError string      `json:"sign_in_error,omitempty"`
	SignIn      *signInInfo `json:"sign_in,omitempty"`
}

type signInInfo struct {
	Issuer                  string `json:"issuer,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	DeviceCode              string `json:"device_code,omitempty"`
	TokenEndpoint           string `json:"token_endpoint,omitempty"`
	ClientID                string `json:"client_id,omitempty"`
	Interval                int    `json:"interval,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
}

// parseChallenge decodes a 407 body; ok is false for anything that is not an
// identity_required challenge.
func parseChallenge(body []byte) (challengeBody, bool) {
	var cb challengeBody
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&cb); err != nil || cb.Error != challengeError {
		return challengeBody{}, false
	}
	return cb, true
}

// Challenger answers worker sign-in challenges for a Forwarder: it checks the
// offer against the configured issuer and client, tells the user where to sign
// in, polls the issuer once at a time and stores the login. The zero value is
// not usable; set Client. Safe for concurrent use.
type Challenger struct {
	// Client holds the issuer, client id and cache the login is stored in.
	Client *Client
	// Notify is told the sign-in URL and code once per new offer (the stderr
	// line and the --signin-notify hook). Nil means silent. It must not block
	// for long; it runs on the connection's goroutine.
	Notify func(url, code string)
	// Log receives outcomes only: never a device code, user code or token.
	Log *slog.Logger

	mu      sync.Mutex
	polling bool
	// done is the device code of the last poll that ended in a stored login, so
	// a 407 that raced it (and still names that code) does not start another.
	done string
	wg   sync.WaitGroup
}

func (c *Challenger) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Handle processes the body of a worker 407. It returns the body to relay to
// the agent: the worker's own with the device code removed, or, when the offer
// is not trusted, with the whole sign_in object removed. ctx bounds the
// background poll (the forwarder's Serve context).
func (c *Challenger) Handle(ctx context.Context, body []byte) []byte {
	cb, ok := parseChallenge(body)
	if !ok {
		return mustJSON(challengeBody{Error: challengeError})
	}
	si := cb.SignIn
	if si == nil {
		out := cb
		out.SignIn = nil
		return mustJSON(out)
	}
	// A compromised or misconfigured worker must not make this client poll a
	// foreign issuer or sign in with another client.
	if si.Issuer != c.Client.Config.Issuer || si.ClientID != c.Client.Config.ClientID || si.DeviceCode == "" {
		c.log().Warn("identity challenge ignored: the offer is not for this issuer and client")
		cb.SignIn = nil
		cb.SignInError = "untrusted_offer"
		return mustJSON(cb)
	}
	c.start(ctx, *si)
	relay := cb
	pub := *si
	pub.DeviceCode = ""
	relay.SignIn = &pub
	return mustJSON(relay)
}

// start tells the user and begins the one background poll, unless one is
// already running or the offer is the login that just finished.
func (c *Challenger) start(ctx context.Context, si signInInfo) {
	c.mu.Lock()
	if c.polling || si.DeviceCode == c.done {
		c.mu.Unlock()
		return
	}
	c.polling = true
	c.wg.Add(1)
	c.mu.Unlock()

	if c.Notify != nil {
		u := si.VerificationURIComplete
		if u == "" {
			u = si.VerificationURI
		}
		c.Notify(u, si.UserCode)
	}
	go func() {
		defer c.wg.Done()
		_, err := c.Client.CompleteDevice(ctx, si.DeviceCode, si.Interval, si.ExpiresIn)
		c.mu.Lock()
		c.polling = false
		if err == nil {
			c.done = si.DeviceCode
		}
		c.mu.Unlock()
		if err != nil {
			// The error text carries no code or token (Client.oauthErr).
			c.log().Warn("identity sign-in did not complete", "error", err)
			return
		}
		c.log().Info("identity sign-in complete")
	}()
}

// Wait blocks until the background poll, if any, has ended. Cancel the context
// given to Handle first.
func (c *Challenger) Wait() { c.wg.Wait() }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil { // plain strings and ints: cannot fail
		return []byte(`{"error":"` + challengeError + `"}`)
	}
	return b
}

// readLimited reads up to limit bytes of r.
func readLimited(r io.Reader, limit int) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, int64(limit)))
	return b
}

// headerValue returns the value of the named header in a raw head, or "".
func headerValue(head, name string) string {
	for _, l := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
