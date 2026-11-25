package identityclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// healthBody is what /healthz returns: the state enum and the token's exp,
// never a token, a fingerprint or an error text.
type healthBody struct {
	State string `json:"state"`
	Exp   string `json:"exp,omitempty"`
}

// HealthHandler serves GET /healthz from state. The status is 200 while a token
// is held (valid or expiring) and 503 otherwise, so a container health check
// can use the status alone.
func HealthHandler(state func() State, now func() time.Time) http.Handler {
	return healthMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := state()
		body := healthBody{State: string(st.Reason)}
		if !st.Expiry.IsZero() {
			body.Exp = st.Expiry.UTC().Format(time.RFC3339)
		}
		code := http.StatusServiceUnavailable
		if st.Reason == ReasonValid || st.Reason == ReasonExpiring && st.Expiry.After(now()) {
			code = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

// ClientState adapts the P1 login (a *Client) to the forwarder's health: Token
// is the Forwarder's Token function, and it remembers what the last call
// returned so State can report it. It never prompts.
type ClientState struct {
	Client *Client
	// Now defaults to time.Now.
	Now func() time.Time

	mu  sync.Mutex
	exp time.Time
	err error
	// failures counts consecutive refresh failures; until holds the earliest
	// time the next attempt may reach the issuer.
	failures int
	until    time.Time
}

// Failure backoff of ClientState: 1s doubling to 60s, like WardenTokenSource.
const (
	clientBackoffMin = time.Second
	clientBackoffMax = time.Minute
)

func (c *ClientState) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Token returns the current ID token and records the outcome.
//
// After a failure other than ErrLoginRequired (which costs no request) it does
// not call the client again until a cooldown has passed, 1s growing to 60s, and
// returns the last error meanwhile, so a failing issuer sees at most one request
// per cooldown however often Token is called.
func (c *ClientState) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.err != nil && c.now().Before(c.until) {
		err := c.err
		c.mu.Unlock()
		return "", err
	}
	c.mu.Unlock()
	res, err := c.Client.Token(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.err = err
		if errors.Is(err, ErrLoginRequired) {
			c.failures, c.until = 0, time.Time{}
		} else {
			c.failures++
			c.until = c.now().Add(min(clientBackoffMin<<min(c.failures-1, 6), clientBackoffMax))
		}
		return "", err
	}
	c.failures, c.until = 0, time.Time{}
	c.exp, c.err = res.Expiry, nil
	return res.IDToken, nil
}

// State maps the last Token outcome onto the health states.
func (c *ClientState) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := State{Expiry: c.exp}
	switch {
	case c.err == nil && c.exp.IsZero():
		st.Reason = ReasonExpiring // not asked yet
	case c.err == nil && c.now().Before(c.exp):
		st.Reason = ReasonValid
	case c.err == nil:
		st.Reason = ReasonExpiring
	case errors.Is(c.err, ErrLoginRequired), errors.Is(c.err, ErrIssuerUnreachable):
		st.Reason, st.LastError = ReasonLoginRequired, errorKind(c.err)
	default:
		st.Reason, st.LastError = ReasonCPUnreachable, errorKind(c.err)
	}
	return st
}
