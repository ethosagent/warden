package scenarios

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The in-tunnel challenge (#621): the agent sits behind the real forwarder and
// Challenger, the worker is in challenge mode, the issuer is the in-process
// fake. The agent's FIRST request gets a 403 whose error.message holds the
// sign-in link (the worker answered inside the tunnel: no dial, no policy); the
// forwarder notifies the user and polls; once the fake approves, the next
// request is allowed and attributed to the user. No device_code ever reaches the
// agent, and no token, device_code or user_code reaches a log, event or metric.

// inTunnelBody is the 403 body the agent reads.
type inTunnelBody struct {
	Type  string `json:"type"`
	Error struct {
		Type, Code, Message string
	} `json:"error"`
	SignIn *struct {
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		UserCode                string `json:"user_code"`
		ExpiresIn               int    `json:"expires_in"`
	} `json:"sign_in"`
}

// signInAgent is an HTTP client whose only way out is a forwarder in front of
// the harness worker, with the same challenge wiring `warden identity exec
// --challenge` has. notes records what the user would be told.
type signInAgent struct {
	cl    *http.Client
	cli   *identityclient.Client
	chal  *identityclient.Challenger
	mu    sync.Mutex
	notes [][2]string
}

func newSignInAgent(t *testing.T, h *harness.H) *signInAgent {
	t.Helper()
	a := &signInAgent{}
	a.cli = &identityclient.Client{
		Config: identityclient.Config{
			Issuer: h.Issuer().Issuer(), ClientID: "warden-cli", Audience: harness.IdentityAudience,
			Scopes: identityclient.DefaultScopes, CacheDir: t.TempDir(),
		},
		// The poll interval is the issuer's 5 s: do not wait it out.
		Sleep: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
				return nil
			}
		},
	}
	a.chal = &identityclient.Challenger{
		Client: a.cli,
		Notify: func(url, code string) {
			a.mu.Lock()
			a.notes = append(a.notes, [2]string{url, code})
			a.mu.Unlock()
		},
		Log: slog.New(slog.DiscardHandler),
	}
	const cred = "scenario-forwarder-credential"
	fwd := &identityclient.Forwarder{
		WorkerAddr: h.ProxyAddr(), ClientCredential: cred, Challenge: a.chal,
		Token: func(ctx context.Context) (string, error) {
			res, err := a.cli.Token(ctx)
			return res.IDToken, err
		},
		Log: slog.New(slog.DiscardHandler),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fwd.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	proxyURL := &url.URL{Scheme: "http", User: url.UserPassword("wx", cred), Host: ln.Addr().String()}
	a.cl = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   h.AgentTLSConfig(),
			DisableKeepAlives: true,
		},
	}
	return a
}

func (a *signInAgent) notified() [][2]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][2]string(nil), a.notes...)
}

// get sends GET https://identityHost<path> and returns the status and body.
func (a *signInAgent) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := a.cl.Get("https://" + identityHost + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
}

// challengeInTunnel is the scenario: first request -> 403 with the link in the
// message; sign in; second request -> allowed and attributed.
func challengeInTunnel(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	a := newSignInAgent(t, h)

	status, raw := a.get(t, "/first")
	if status != http.StatusForbidden {
		t.Fatalf("first request: status %d, want the in-tunnel 403 (body %q)", status, raw)
	}
	var body inTunnelBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("first request body %q: %v", raw, err)
	}
	iss := h.Issuer().Issuer()
	if body.Type != "error" || body.Error.Type != "identity_required" || body.SignIn == nil ||
		!strings.HasPrefix(body.SignIn.VerificationURIComplete, iss+"/") || body.SignIn.UserCode == "" {
		t.Fatalf("first request body = %s", raw)
	}
	link := body.SignIn.VerificationURIComplete
	if !strings.Contains(body.Error.Message, link) || !strings.Contains(body.Error.Message, body.SignIn.UserCode) {
		t.Errorf("error.message %q does not show the link and the code", body.Error.Message)
	}
	codes := h.Issuer().DeviceCodes()
	if len(codes) != 1 {
		t.Fatalf("%d device authorizations, want 1", len(codes))
	}
	for _, banned := range []string{codes[0], "device_code", "token_endpoint"} {
		if strings.Contains(raw, banned) {
			t.Errorf("the agent's 403 body contains %q", banned)
		}
	}
	if n := a.notified(); len(n) != 1 || n[0][0] != link || n[0][1] != body.SignIn.UserCode {
		t.Errorf("the user was told %v, want the link and code once", n)
	}
	if n := len(up.Requests()); n != 0 {
		t.Errorf("the upstream saw %d requests before the sign-in; the challenge tunnel never dials", n)
	}
	h.Eventually("the challenge to be recorded as one deny event", func() bool { return len(identityRequiredEvents(h)) == 1 })
	if e := identityRequiredEvents(h)[0]; e.Domain != identityHost || e.IdentityStatus != "none" || e.UserSub != "" {
		t.Errorf("deny event = %+v", e)
	}
	for _, e := range h.Events() {
		if e.Decision == "allow" {
			t.Errorf("an allow event before the sign-in: %+v", e)
		}
	}

	// The user signs in: the fake approves the device code, the forwarder's poll
	// stores the login.
	tok := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	h.Issuer().ApproveDevice(codes[0], tok, "scenario-refresh-token")
	h.Eventually("the forwarder to store the login", func() bool { _, err := a.cli.Status(); return err == nil })

	status, raw = a.get(t, "/second")
	if status != http.StatusOK {
		t.Fatalf("second request: status %d, want the upstream's 200 (body %q)", status, raw)
	}
	c := idToken{name: "valid", status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng"}}
	assertIdentityEvent(t, "after sign-in", only(t, h.Events(), "https://"+identityHost+"/second"), c, "allow")
	assertUpstreamClean(t, up, 1)
	if n := a.notified(); len(n) != 1 {
		t.Errorf("%d notifications after the sign-in, want still 1", len(n))
	}
	assertSignInCounts(t, h, map[string]float64{"started": 1})
	assertNoSignInSecrets(t, h, codes[0], body.SignIn.UserCode, tok)
}
