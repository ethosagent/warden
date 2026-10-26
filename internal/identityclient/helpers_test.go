package identityclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	tokenTTL    = 30 * time.Minute
	markerBody  = "IDP-ERROR-BODY-MARKER"
	deviceCode  = "DEVICE-CODE-SECRET-0001"
	userCode    = "ABCD-EFGH"
	baseRefresh = "refresh-token-secret"
)

// fakeClock is a settable clock shared by the client and the token minter.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeIdP is an httptest OIDC issuer with discovery, device authorization and
// token endpoints. Tokens are real signed JWTs minted by test/fakes.OIDCIssuer.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	clock  *fakeClock
	signer *fakes.OIDCIssuer

	mu        sync.Mutex
	script    []string // device poll outcomes before success: pending, slow_down, denied, expired
	refresh   string   // the only refresh token currently accepted
	rotations int
	groups    []string
	aud       []string
	down      bool
	// Mismatch makes discovery report a different issuer.
	issuerOverride string

	refreshCalls atomic.Int64
	deviceCalls  atomic.Int64
	tokenDelay   time.Duration
	lastForm     map[string][]string
}

func newIdP(t *testing.T, clk *fakeClock) *fakeIdP {
	t.Helper()
	p := &fakeIdP{t: t, clock: clk, refresh: baseRefresh, groups: []string{"eng"}, aud: []string{"warden"},
		signer: fakes.NewOIDCIssuer(t, fakes.WithIssuerClock(clk.Now))}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/device", p.device)
	mux.HandleFunc("/token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) URL() string { return p.srv.URL }

func (p *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	if p.isDown(w) {
		return
	}
	iss := p.srv.URL
	if p.issuerOverride != "" {
		iss = p.issuerOverride
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"issuer":                        iss,
		"token_endpoint":                p.srv.URL + "/token",
		"device_authorization_endpoint": p.srv.URL + "/device",
	})
}

func (p *fakeIdP) isDown(w http.ResponseWriter) bool {
	p.mu.Lock()
	down := p.down
	p.mu.Unlock()
	if down {
		http.Error(w, markerBody, http.StatusServiceUnavailable)
	}
	return down
}

func (p *fakeIdP) device(w http.ResponseWriter, r *http.Request) {
	p.deviceCalls.Add(1)
	_ = r.ParseForm()
	p.mu.Lock()
	p.lastForm = r.PostForm
	p.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code": deviceCode, "user_code": userCode,
		"verification_uri": p.srv.URL + "/activate", "expires_in": 600, "interval": 1,
	})
}

func (p *fakeIdP) mint() string {
	now := p.clock.Now()
	return p.signer.Mint(
		fakes.Valid("user-1", "u@example.com", p.groups...),
		fakes.WithIss(p.srv.URL), fakes.WithAud(p.aud...), fakes.WithAZP("warden-cli"),
		fakes.WithIAT(now), fakes.WithExp(now.Add(tokenTTL)))
}

func (p *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if p.isDown(w) {
		return
	}
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": markerBody})
	}
	switch r.PostForm.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:device_code":
		if r.PostForm.Get("device_code") != deviceCode || r.PostForm.Get("client_id") == "" {
			fail(400, "invalid_grant")
			return
		}
		if len(p.script) > 0 {
			next := p.script[0]
			p.script = p.script[1:]
			switch next {
			case "pending":
				fail(400, "authorization_pending")
			case "slow_down":
				fail(400, "slow_down")
			case "denied":
				fail(400, "access_denied")
			case "expired":
				fail(400, "expired_token")
			}
			return
		}
		p.writeTokens(w)
	case "refresh_token":
		p.refreshCalls.Add(1)
		if p.tokenDelay > 0 {
			time.Sleep(p.tokenDelay)
		}
		if r.PostForm.Get("refresh_token") != p.refresh {
			fail(400, "invalid_grant")
			return
		}
		p.writeTokens(w)
	default:
		fail(400, "unsupported_grant_type")
	}
}

// writeTokens rotates the refresh token (as Dex does) and answers. Caller holds mu.
func (p *fakeIdP) writeTokens(w http.ResponseWriter) {
	p.rotations++
	p.refresh = fmt.Sprintf("%s-%d", baseRefresh, p.rotations)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-token-secret", "token_type": "bearer", "expires_in": int(tokenTTL.Seconds()),
		"refresh_token": p.refresh, "id_token": p.mint(),
	})
}

func (p *fakeIdP) setDown(v bool) {
	p.mu.Lock()
	p.down = v
	p.mu.Unlock()
}

func (p *fakeIdP) setScript(s ...string) {
	p.mu.Lock()
	p.script = s
	p.mu.Unlock()
}

// sleeps records the device-poll waits without waiting.
type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return ctx.Err()
}

type rig struct {
	idp   *fakeIdP
	clock *fakeClock
	cl    *identityclient.Client
	logs  *bytes.Buffer
	slept *sleeps
	out   *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	clk := newClock()
	idp := newIdP(t, clk)
	logs := &bytes.Buffer{}
	r := &rig{idp: idp, clock: clk, logs: logs, slept: &sleeps{}, out: &bytes.Buffer{}}
	r.cl = &identityclient.Client{
		Config: identityclient.Config{
			Issuer: idp.URL(), ClientID: identityclient.DefaultClientID, Audience: identityclient.DefaultAudience,
			Scopes: identityclient.DefaultScopes, CacheDir: filepath.Join(t.TempDir(), "cache"),
		},
		HTTP:  idp.srv.Client(),
		Now:   clk.Now,
		Sleep: r.slept.sleep,
		Log:   slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return r
}

func (r *rig) login(t *testing.T) []string {
	t.Helper()
	w, err := r.cl.Login(context.Background(), r.out)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return w
}

func contains(s string, subs ...string) string {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return sub
		}
	}
	return ""
}
