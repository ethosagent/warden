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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
	})
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
}

func (c *ClientState) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Token returns the current ID token and records the outcome.
func (c *ClientState) Token(ctx context.Context) (string, error) {
	res, err := c.Client.Token(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.err = err
		return "", err
	}
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
