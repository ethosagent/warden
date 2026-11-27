package oauthbroker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
	"github.com/ethosagent/warden/internal/ratelimit"
)

const (
	startIss   = "https://idp.example.test"
	startRedir = "https://warden.example.test/connect/callback"
)

// startUserKey is a stand-in for secrets.UserKey: distinct per (iss, sub).
func startUserKey(_, sub string) (string, error) { return oauthbrokertest.UserKey(sub), nil }

func wantUserKey(sub string) string { k, _ := startUserKey(startIss, sub); return k }

// countingStore counts the writes Start may make, so a refusal is proved to
// leave zero rows.
type countingStore struct {
	oauthbroker.GrantStore
	attempts, pendings int
}

func (c *countingStore) CreateAttempt(ctx context.Context, a oauthbroker.Attempt) (oauthbroker.Attempt, error) {
	c.attempts++
	return c.GrantStore.CreateAttempt(ctx, a)
}

func (c *countingStore) CreatePending(ctx context.Context, p oauthbroker.Pending, ttl time.Duration) (oauthbroker.Pending, error) {
	c.pendings++
	return c.GrantStore.CreatePending(ctx, p, ttl)
}

type fakeBlocks struct {
	subs map[string]bool
	err  error
}

func (f *fakeBlocks) IsBlocked(_ context.Context, sub, _ string) (bool, error) {
	return f.subs[sub], f.err
}

type startEnv struct {
	b      *oauthbroker.Broker
	store  *countingStore
	blocks *fakeBlocks
	clk    *clocktest.Fake
	logs   *bytes.Buffer
	reg    *oauthbroker.Registry
}

func startProviders() []config.OAuthProviderConfig {
	return []config.OAuthProviderConfig{
		{ID: "google", Type: config.OAuthProviderGoogle, ClientID: "g-client", ClientSecretEnv: "G_SECRET",
			AllowedScopes: []string{"calendar.readonly", "drive.readonly", "openid"}, DefaultScopes: []string{"drive.readonly"}},
		{ID: "ghapp", Type: config.OAuthProviderGitHubApp, ClientID: "app-client", ClientSecretEnv: "G_SECRET"},
		{ID: "gh", Type: config.OAuthProviderGitHub, ClientID: "gh-client", ClientSecretEnv: "G_SECRET",
			AllowedScopes: []string{"repo", "read:user"}, DefaultScopes: []string{"read:user"}},
		{ID: "corp", Type: config.OAuthProviderGeneric, ClientID: "corp-client", ClientSecretEnv: "G_SECRET",
			AuthURL:  "https://sso.example.test/auth",
			TokenURL: "https://sso.example.test/token", AllowedScopes: []string{"read"},
			ExtraAuthParams: map[string]string{"audience": "api"}},
	}
}

func newStartEnv(t *testing.T, limiter ratelimit.RateLimiter) *startEnv {
	t.Helper()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	reg, err := oauthbroker.NewRegistry(startProviders(), oauthbroker.Options{
		LookupEnv: func(string) (string, bool) { return "client-secret-value", true }, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	clk := clocktest.NewFake(oauthbrokertest.Start)
	store := &countingStore{GrantStore: newSQLiteStore(t, clk)}
	blocks := &fakeBlocks{subs: map[string]bool{}}
	b, err := oauthbroker.New(oauthbroker.Config{
		Registry: reg, Store: store, Blocks: blocks, Limiter: limiter, RedirectURL: startRedir,
		UserKey: startUserKey, Rand: rand.Reader, Now: clk.Now, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &startEnv{b: b, store: store, blocks: blocks, clk: clk, logs: logs, reg: reg}
}

func req(sub, provider string, scopes ...string) oauthbroker.StartRequest {
	return oauthbroker.StartRequest{Iss: startIss, Sub: sub, Email: sub + "@example.com", Provider: provider, Scopes: scopes}
}

func startCode(t *testing.T, err error) string {
	t.Helper()
	var se *oauthbroker.StartError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *StartError", err)
	}
	return se.Code
}

func mustLocation(t *testing.T, res oauthbroker.StartResult) url.Values {
	t.Helper()
	u, err := url.Parse(res.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// TestConnectStart: a valid start stores one attempt whose verifier hashes to
// the code_challenge in the Location, whose state hashes to the stored hash,
// and whose browser token hashes to browser_hash; the scopes are exactly the
// capped set and the redirect_uri the configured one.
func TestConnectStart(t *testing.T) {
	e := newStartEnv(t, nil)
	res, err := e.b.Start(context.Background(), req("alice", "google", "drive.readonly", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.RedirectURL, "https://accounts.google.com/o/oauth2/v2/auth?") {
		t.Fatalf("Location = %q", res.RedirectURL)
	}
	q := mustLocation(t, res)
	state := q.Get("state")
	att, err := e.store.ConsumeAttempt(context.Background(), oauthbroker.HashState(state))
	if err != nil {
		t.Fatalf("no attempt stored under the SHA-256 of the state: %v", err)
	}
	sum := sha256.Sum256([]byte(att.Verifier))
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "g-client", "redirect_uri": startRedir,
		"code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]),
		"scope": "drive.readonly openid", "access_type": "offline", "prompt": "consent",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if len(state) < 43 || len(att.Verifier) < 43 || len(res.BrowserToken) < 43 {
		t.Errorf("state/verifier/cookie lengths %d/%d/%d, want at least 43 (32 random bytes)", len(state), len(att.Verifier), len(res.BrowserToken))
	}
	if att.BrowserHash != oauthbroker.HashBrowserBinding(res.BrowserToken) {
		t.Error("browser_hash is not the hash of the cookie value")
	}
	if att.UserKey != wantUserKey("alice") || att.Provider != "google" || att.Sub != "alice" || att.Iss != startIss {
		t.Errorf("attempt identity = %+v", att)
	}
	if !slices.Equal(att.Scopes, []string{"drive.readonly", "openid"}) {
		t.Errorf("attempt scopes = %v", att.Scopes)
	}
	if res.CookieMaxAge != 10*time.Minute {
		t.Errorf("CookieMaxAge = %v, want 10m", res.CookieMaxAge)
	}
	if _, err := e.store.ConsumeAttempt(context.Background(), oauthbroker.HashState(state)); !errors.Is(err, oauthbroker.ErrNotFound) {
		t.Errorf("the attempt was consumable twice: %v", err)
	}

	// Two starts never share state, verifier or cookie.
	r2, err := e.b.Start(context.Background(), req("alice", "google"))
	if err != nil {
		t.Fatal(err)
	}
	if mustLocation(t, r2).Get("state") == state || r2.BrowserToken == res.BrowserToken {
		t.Error("two starts reused a state or cookie value")
	}
	if got := mustLocation(t, r2).Get("scope"); got != "drive.readonly" {
		t.Errorf("default scope = %q, want the provider default", got)
	}
}

// TestConnectStartScopeCap: a scope outside allowedScopes, outside the pending's
// scopes or outside the caller's ceiling is refused with the names, and no row
// is written.
func TestConnectStartScopeCap(t *testing.T) {
	e := newStartEnv(t, nil)
	ctx := context.Background()
	_, err := e.b.Start(ctx, req("alice", "google", "drive.readonly", "gmail.send", "contacts"))
	var se *oauthbroker.StartError
	if !errors.As(err, &se) || se.Code != oauthbroker.CodeScopeNotAllowed || !slices.Equal(se.Scopes, []string{"contacts", "gmail.send"}) {
		t.Fatalf("err = %v, want scope_not_allowed naming contacts and gmail.send", err)
	}

	p, err := e.store.GrantStore.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google", "drive.readonly"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e.store.pendings = 0
	r := req("alice", "google", "calendar.readonly")
	r.PendingID = p.ID
	if _, err := e.b.Start(ctx, r); startCode(t, err) != oauthbroker.CodeScopeNotAllowed {
		t.Fatalf("a scope outside the pending's scopes: %v", err)
	}

	c := req("alice", "google", "drive.readonly", "calendar.readonly")
	c.Ceiling, c.HasCeiling = []string{"drive.readonly"}, true
	if _, err := e.b.Start(ctx, c); startCode(t, err) != oauthbroker.CodeScopeNotAllowed {
		t.Fatalf("a scope outside the ceiling: %v", err)
	}
	// An empty ceiling allows no scope; it is not "no cap".
	c.Scopes, c.Ceiling = nil, []string{}
	if _, err := e.b.Start(ctx, c); startCode(t, err) != oauthbroker.CodeScopeNotAllowed {
		t.Fatalf("defaults under an empty ceiling: %v", err)
	}
	if e.store.attempts != 0 || e.store.pendings != 0 {
		t.Fatalf("a refused start wrote %d attempts, %d pendings", e.store.attempts, e.store.pendings)
	}

	// Defaults narrow to the ceiling instead of failing when something is left.
	c.Ceiling = []string{"drive.readonly", "calendar.readonly"}
	res, err := e.b.Start(ctx, c)
	if err != nil || mustLocation(t, res).Get("scope") != "drive.readonly" {
		t.Fatalf("defaults under a ceiling: %v %v", res.RedirectURL, err)
	}
	// With a pending, none named means the pending's scopes.
	r.Scopes = nil
	res, err = e.b.Start(ctx, r)
	if err != nil || mustLocation(t, res).Get("scope") != "drive.readonly" {
		t.Fatalf("pending scopes: %v %v", res.RedirectURL, err)
	}
	// The provider cap still applies when a pending's ceiling is wider.
	wide, err := e.store.GrantStore.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google", "drive.readonly", "gmail.send"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r2 := req("alice", "google", "gmail.send")
	r2.PendingID = wide.ID
	if _, err := e.b.Start(ctx, r2); startCode(t, err) != oauthbroker.CodeScopeNotAllowed {
		t.Fatalf("a scope outside the provider's allowedScopes under a wider pending: %v", err)
	}
}

// TestConnectStartPendingOwnership: another user's pending and an unknown id
// are the same refusal; a closed pending is 409; no row is written.
func TestConnectStartPendingOwnership(t *testing.T) {
	e := newStartEnv(t, nil)
	ctx := context.Background()
	mine, err := e.store.GrantStore.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google", "drive.readonly"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e.store.attempts = 0

	r := req("mallory", "google", "drive.readonly")
	r.PendingID = mine.ID
	_, foreign := e.b.Start(ctx, r)
	r.PendingID = "no-such-pending-id"
	_, unknown := e.b.Start(ctx, r)
	if startCode(t, foreign) != oauthbroker.CodePendingNotFound || foreign.Error() != unknown.Error() {
		t.Fatalf("foreign = %v, unknown = %v; they must be identical", foreign, unknown)
	}
	var f, u *oauthbroker.StartError
	if !errors.As(foreign, &f) || !errors.As(unknown, &u) || f.Code != u.Code || len(f.Scopes) != 0 || len(u.Scopes) != 0 {
		t.Fatalf("foreign and unknown differ: %+v %+v", f, u)
	}

	// The owner may start it; then it is closed and refused.
	ok := req("alice", "google", "drive.readonly")
	ok.PendingID = mine.ID
	if _, err := e.b.Start(ctx, ok); err != nil {
		t.Fatalf("owner start: %v", err)
	}
	if err := e.store.CompletePending(ctx, mine.ID, oauthbroker.StatusDenied, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.b.Start(ctx, ok); startCode(t, err) != oauthbroker.CodePendingNotActive {
		t.Fatalf("closed pending: %v", err)
	}
	// An expired one reads as not active before any sweep.
	old, err := e.store.GrantStore.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google", "drive.readonly"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(2 * time.Minute)
	ok.PendingID = old.ID
	if _, err := e.b.Start(ctx, ok); startCode(t, err) != oauthbroker.CodePendingNotActive {
		t.Fatalf("expired pending: %v", err)
	}
	// A pending for another provider does not authorize this one.
	gh, err := e.store.GrantStore.CreatePending(ctx, oauthbrokertest.NewPending("alice", "gh", "repo"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ok.PendingID = gh.ID
	if _, err := e.b.Start(ctx, ok); startCode(t, err) != oauthbroker.CodeInvalidRequest {
		t.Fatalf("provider mismatch: %v", err)
	}
	if e.store.attempts != 1 {
		t.Fatalf("attempts = %d, want only the one owner start", e.store.attempts)
	}
}

// TestConnectStartBlocked: a blocked user is refused before any row is written,
// and an unreadable block list fails closed.
func TestConnectStartBlocked(t *testing.T) {
	e := newStartEnv(t, nil)
	ctx := context.Background()
	e.blocks.subs["eve"] = true
	if _, err := e.b.Start(ctx, req("eve", "google")); startCode(t, err) != oauthbroker.CodeUserBlocked {
		t.Fatalf("blocked: %v", err)
	}
	e.blocks.err = errors.New("snapshot not loaded")
	if _, err := e.b.Start(ctx, req("alice", "google")); startCode(t, err) != oauthbroker.CodeBlockListUnavailable {
		t.Fatalf("unreadable block list: %v", err)
	}
	if e.store.attempts != 0 {
		t.Fatalf("attempts = %d", e.store.attempts)
	}
	if _, err := e.b.Start(ctx, req("alice", "nope")); startCode(t, err) != oauthbroker.CodeUnknownProvider {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, err := e.b.Start(ctx, req("alice", "")); startCode(t, err) != oauthbroker.CodeInvalidRequest {
		t.Fatalf("no provider: %v", err)
	}
}

// TestConnectStartRateLimit: the 11th start in a minute for one user is
// refused with a wait; another user and the next minute are not.
func TestConnectStartRateLimit(t *testing.T) {
	e := newStartEnv(t, ratelimit.NewLimiter(oauthbroker.StartsPerMinute, time.Minute))
	ctx := context.Background()
	for i := 0; i < oauthbroker.StartsPerMinute; i++ {
		if _, err := e.b.Start(ctx, req("alice", "google")); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
	}
	_, err := e.b.Start(ctx, req("alice", "google"))
	var se *oauthbroker.StartError
	if !errors.As(err, &se) || se.Code != oauthbroker.CodeRateLimited || se.RetryAfter < time.Second {
		t.Fatalf("11th start: %v", err)
	}
	if _, err := e.b.Start(ctx, req("bob", "google")); err != nil {
		t.Fatalf("another user is throttled: %v", err)
	}
	e.clk.Advance(time.Minute)
	if _, err := e.b.Start(ctx, req("alice", "google")); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

// TestConnectStartAttemptCap: the store's open-attempt cap surfaces as its own
// code (HTTP 429).
func TestConnectStartAttemptCap(t *testing.T) {
	e := newStartEnv(t, nil)
	for i := 0; i < oauthbroker.MaxOpenAttemptsPerUser; i++ {
		if _, err := e.b.Start(context.Background(), req("alice", "google")); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
	}
	if _, err := e.b.Start(context.Background(), req("alice", "google")); startCode(t, err) != oauthbroker.CodeTooManyAttempts {
		t.Fatalf("21st attempt: %v", err)
	}
}

// TestConnectStartAuthURL: the broker owns the protocol parameters. extraAuthParams
// cannot set or replace them, in any letter
// case; a githubApp sends no scope; other extra parameters survive.
func TestConnectStartAuthURL(t *testing.T) {
	e := newStartEnv(t, nil)
	// Config validation already bars these; the broker drops them again so a
	// future provider source (or a bug) cannot replace a protocol parameter.
	corp, err := e.reg.Get("corp")
	if err != nil {
		t.Fatal(err)
	}
	corp.AuthURL += "?state=evil&scope=evil&redirect_uri=https://evil.test&foo=bar"
	for k := range map[string]bool{"request": true, "Response_Mode": true, "claims": true, "Scope": true, "NONCE": true, "State": true} {
		corp.ExtraAuthParams[k] = "evil"
	}
	res, err := e.b.Start(context.Background(), req("alice", "corp", "read"))
	if err != nil {
		t.Fatal(err)
	}
	q := mustLocation(t, res)
	if q.Get("scope") != "read" || q.Get("redirect_uri") != startRedir || q.Get("client_id") != "corp-client" {
		t.Errorf("broker params replaced: %v", q)
	}
	if len(q["state"]) != 1 || len(q["scope"]) != 1 || len(q["redirect_uri"]) != 1 {
		t.Errorf("duplicate broker params: %v", q)
	}
	if q.Get("audience") != "api" {
		t.Errorf("a non-reserved extra param was lost: %v", q)
	}
	if q.Get("foo") != "bar" {
		t.Errorf("a non-reserved authURL query param was lost: %v", q)
	}
	for _, k := range []string{"request", "Response_Mode", "response_mode", "claims", "Scope", "NONCE", "nonce", "State"} {
		if q.Has(k) {
			t.Errorf("reserved extra param %q reached the provider URL: %v", k, q)
		}
	}

	res, err = e.b.Start(context.Background(), req("alice", "ghapp"))
	if err != nil {
		t.Fatal(err)
	}
	if q := mustLocation(t, res); q.Has("scope") || q.Get("code_challenge_method") != "S256" {
		t.Errorf("githubApp query = %v", q)
	}
	if _, err := e.b.Start(context.Background(), req("alice", "ghapp", "repo")); startCode(t, err) != oauthbroker.CodeScopeNotAllowed {
		t.Fatalf("githubApp with a scope: %v", err)
	}
}

// TestConnectStartUnionsActiveGrant: the provider is asked for the union of the
// active grant's scopes that are still allowed and the new ones, and that union
// is what the attempt records. A scope the operator has since removed from
// allowedScopes (legacy.scope) is never requested again.
func TestConnectStartUnionsActiveGrant(t *testing.T) {
	e := newStartEnv(t, nil)
	ctx := context.Background()
	g, err := e.store.BeginGrant(ctx, oauthbroker.GrantRef{UserKey: wantUserKey("alice"), Iss: startIss, Sub: "alice", Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.ActivateGrant(ctx, g.GrantID, []string{"drive.readonly", "legacy.scope"}, oauthbroker.Account{}); err != nil {
		t.Fatal(err)
	}
	res, err := e.b.Start(ctx, req("alice", "google", "calendar.readonly"))
	if err != nil {
		t.Fatal(err)
	}
	q := mustLocation(t, res)
	if got := q.Get("scope"); got != "calendar.readonly drive.readonly" {
		t.Fatalf("scope = %q, want the union without the removed scope", got)
	}
	att, err := e.store.ConsumeAttempt(ctx, oauthbroker.HashState(q.Get("state")))
	if err != nil || !slices.Equal(att.Scopes, []string{"calendar.readonly", "drive.readonly"}) || slices.Contains(att.Scopes, "legacy.scope") {
		t.Fatalf("attempt scopes = %v, %v", att.Scopes, err)
	}
}

// TestConnectStartStaleGrantScopesGitHubApp: a githubApp has an empty cap, so
// stale scopes on its grant never make the attempt's scopes non-empty.
func TestConnectStartStaleGrantScopesGitHubApp(t *testing.T) {
	e := newStartEnv(t, nil)
	ctx := context.Background()
	g, err := e.store.BeginGrant(ctx, oauthbroker.GrantRef{UserKey: wantUserKey("alice"), Iss: startIss, Sub: "alice", Provider: "ghapp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.ActivateGrant(ctx, g.GrantID, []string{"repo"}, oauthbroker.Account{}); err != nil {
		t.Fatal(err)
	}
	res, err := e.b.Start(ctx, req("alice", "ghapp"))
	if err != nil {
		t.Fatal(err)
	}
	q := mustLocation(t, res)
	att, err := e.store.ConsumeAttempt(ctx, oauthbroker.HashState(q.Get("state")))
	if err != nil || len(att.Scopes) != 0 || q.Has("scope") {
		t.Fatalf("attempt scopes = %v, scope param %q, %v; want none", att.Scopes, q.Get("scope"), err)
	}
}

// TestConnectStartLogsAndCounters: one oauth_connect_start line per start with
// no state, verifier, challenge or cookie value, and the counter by outcome.
func TestConnectStartLogsAndCounters(t *testing.T) {
	e := newStartEnv(t, nil)
	ctx := context.Background()
	res, err := e.b.Start(ctx, req("alice", "google", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	q := mustLocation(t, res)
	att, err := e.store.ConsumeAttempt(ctx, oauthbroker.HashState(q.Get("state")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.b.Start(ctx, req("alice", "google", "contacts"))
	_, _ = e.b.Start(ctx, req("alice", "no-such"))

	logs := e.logs.String()
	if n := strings.Count(logs, `"msg":"oauth_connect_start"`); n != 3 {
		t.Fatalf("%d oauth_connect_start lines, want 3:\n%s", n, logs)
	}
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, "oauth_connect_start") {
			continue
		}
		for _, f := range []string{`"provider"`, `"user_key"`, `"pending_id"`, `"scopes_count"`, `"outcome"`, `"reason"`} {
			if !strings.Contains(line, f) {
				t.Errorf("line lacks %s: %s", f, line)
			}
		}
	}
	for _, secret := range []string{q.Get("state"), att.Verifier, q.Get("code_challenge"), res.BrowserToken, "client-secret-value"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("a log line holds a state, verifier, challenge, cookie value or client secret")
		}
	}
	got := e.b.ConnectCounts()
	for k, want := range map[oauthbroker.ConnectKey]uint64{
		{Provider: "google", Stage: "start", Outcome: "ok"}:      1,
		{Provider: "google", Stage: "start", Outcome: "denied"}:  1,
		{Provider: "unknown", Stage: "start", Outcome: "denied"}: 1,
	} {
		if got[k] != want {
			t.Errorf("counter %+v = %d, want %d (all: %v)", k, got[k], want, got)
		}
	}
}
