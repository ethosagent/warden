package oauthbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

type fakeResolver struct {
	mu    sync.Mutex
	vals  map[string]string
	err   error
	calls int
}

func (f *fakeResolver) ResolveSecret(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.vals[key], nil
}

func noEnv(string) (string, bool) { return "", false }

func newReg(t *testing.T, cfgs []config.OAuthProviderConfig, o Options) (*Registry, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	}
	if o.LookupEnv == nil {
		o.LookupEnv = noEnv
	}
	r, err := NewRegistry(cfgs, o)
	if err != nil {
		t.Fatal(err)
	}
	return r, &buf
}

func TestRegistryDefaults(t *testing.T) {
	res := &fakeResolver{vals: map[string]string{"oauth-clients/google": "g-secret", "oauth-clients/github": "h-secret", "oauth-clients/ghapp": "a-secret"}}
	r, logs := newReg(t, []config.OAuthProviderConfig{
		{ID: "google", Type: "google", ClientID: "gcid", ClientSecretKey: "oauth-clients/google"},
		{ID: "github", Type: "github", ClientID: "hcid", ClientSecretKey: "oauth-clients/github"},
		{ID: "ghapp", Type: "githubApp", ClientID: "acid", ClientSecretKey: "oauth-clients/ghapp"},
	}, Options{Resolver: res})

	g, err := r.Get("google")
	if err != nil {
		t.Fatal(err)
	}
	if g.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" ||
		g.TokenURL != "https://oauth2.googleapis.com/token" ||
		g.RevokeURL != "https://oauth2.googleapis.com/revoke" || g.UserinfoURL != "" {
		t.Errorf("google endpoints = %+v", g)
	}
	if want := map[string]string{"access_type": "offline", "prompt": "consent"}; !reflect.DeepEqual(g.ExtraAuthParams, want) {
		t.Errorf("google params = %v, want %v", g.ExtraAuthParams, want)
	}
	for _, id := range []string{"github", "ghapp"} {
		h, _ := r.Get(id)
		if h.AuthURL != "https://github.com/login/oauth/authorize" ||
			h.TokenURL != "https://github.com/login/oauth/access_token" ||
			h.RevokeURL != "https://api.github.com/applications/{client_id}/grant" ||
			h.UserinfoURL != "https://api.github.com/user" {
			t.Errorf("%s endpoints = %+v", id, h)
		}
		if len(h.ExtraAuthParams) != 0 {
			t.Errorf("%s params = %v, want none", id, h.ExtraAuthParams)
		}
	}
	h, _ := r.Get("github")
	if got := h.RevokeEndpoint(); got != "https://api.github.com/applications/hcid/grant" {
		t.Errorf("RevokeEndpoint = %q", got)
	}
	if line := logs.String(); !strings.Contains(line, `"msg":"oauth_providers_loaded"`) || !strings.Contains(line, `"ids":["ghapp","github","google"]`) {
		t.Errorf("startup log = %s", line)
	}
}

func TestRegistryOverridesAndPinnedDefaults(t *testing.T) {
	r, _ := newReg(t, []config.OAuthProviderConfig{
		{ID: "ghe", Type: "github", ClientID: "c", ClientSecretKey: "oauth-clients/ghe",
			AuthURL: "https://ghe.example.com/login/oauth/authorize", TokenURL: "https://ghe.example.com/login/oauth/access_token",
			RevokeURL: "https://ghe.example.com/api/v3/applications/{client_id}/grant", UserinfoURL: "https://ghe.example.com/api/v3/user"},
		{ID: "google", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/google",
			ExtraAuthParams: map[string]string{"prompt": "select_account", "hd": "example.com"}},
		{ID: "gen", Type: "generic", ClientID: "c", ClientSecretKey: "oauth-clients/gen",
			AuthURL: "https://gen.example.com/a", TokenURL: "https://gen.example.com/t"},
	}, Options{})
	ghe, _ := r.Get("ghe")
	if ghe.TokenURL != "https://ghe.example.com/login/oauth/access_token" || ghe.RevokeEndpoint() != "https://ghe.example.com/api/v3/applications/c/grant" {
		t.Errorf("override ignored: %+v", ghe)
	}
	g, _ := r.Get("google")
	if g.ExtraAuthParams["prompt"] != "select_account" || g.ExtraAuthParams["access_type"] != "offline" || g.ExtraAuthParams["hd"] != "example.com" {
		t.Errorf("google params = %v", g.ExtraAuthParams)
	}
	gen, _ := r.Get("gen")
	if gen.RevokeURL != "" || gen.UserinfoURL != "" || gen.RevokeEndpoint() != "" {
		t.Errorf("generic must have no implicit endpoints: %+v", gen)
	}
	// Mutating a returned map or the config input must not change the registry's view of google defaults.
	if g2, _ := r.Get("google"); g2 != g {
		t.Error("Get must return the same provider")
	}
}

func TestRegistryGetAndList(t *testing.T) {
	r, logs := newReg(t, []config.OAuthProviderConfig{
		{ID: "zeta", Type: "github", ClientID: "c", ClientSecretKey: "oauth-clients/zeta"},
		{ID: "alpha", Type: "github", ClientID: "c", ClientSecretKey: "oauth-clients/alpha"},
	}, Options{})
	if _, err := r.Get("unknown"); !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("Get(unknown) = %v, want ErrUnknownProvider", err)
	}
	if got := r.List(); !reflect.DeepEqual(got, []string{"alpha", "zeta"}) {
		t.Errorf("List = %v", got)
	}
	r.List()[0] = "tampered"
	if r.List()[0] != "alpha" {
		t.Error("List must return a copy")
	}
	_ = logs
	// No providers: empty registry, no log line.
	e, elogs := newReg(t, nil, Options{})
	if e.Len() != 0 || len(e.List()) != 0 || elogs.Len() != 0 {
		t.Errorf("empty registry: len=%d list=%v log=%q", e.Len(), e.List(), elogs.String())
	}
	if _, err := e.Get("google"); !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("empty Get = %v", err)
	}
}

func TestRegistryRejectsInvalidConfig(t *testing.T) {
	bad := []config.OAuthProviderConfig{{ID: "_x", Type: "github", ClientID: "c", ClientSecretKey: "oauth-clients/_x"}}
	if _, err := NewRegistry(bad, Options{LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), "consent.providers[0].id") {
		t.Errorf("err = %v, want id validation", err)
	}
	insecure := []config.OAuthProviderConfig{{ID: "x", Type: "github", ClientID: "c", ClientSecretKey: "oauth-clients/x", TokenURL: "http://evil.example.com/t"}}
	if _, err := NewRegistry(insecure, Options{LookupEnv: noEnv}); err == nil {
		t.Error("non-loopback http token URL must be refused by the registry too")
	}
}

func TestRegistryEnvSecret(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "gh", Type: "github", ClientID: "c", ClientSecretEnv: "GH_SECRET"}}
	if _, err := NewRegistry(cfg, Options{LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), "GH_SECRET") {
		t.Errorf("missing env must be fatal and name the variable, got %v", err)
	}
	empty := func(string) (string, bool) { return "", true }
	if _, err := NewRegistry(cfg, Options{LookupEnv: empty}); err == nil || !strings.Contains(err.Error(), "GH_SECRET") {
		t.Errorf("empty env must be fatal, got %v", err)
	}
	if _, err := NewRegistry(cfg, Options{}); err == nil {
		t.Error("nil LookupEnv with an env secret must be an error")
	}
	r, _ := newReg(t, cfg, Options{LookupEnv: func(k string) (string, bool) {
		if k == "GH_SECRET" {
			return "s3cr3t", true
		}
		return "", false
	}})
	p, _ := r.Get("gh")
	s, err := p.ClientSecret(context.Background())
	if err != nil || s.Reveal() != "s3cr3t" {
		t.Errorf("ClientSecret = %v, %v", s, err)
	}
}

func TestRegistryKeySecretRetry(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "google", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/google"}}
	res := &fakeResolver{err: errors.New("store down")}
	r, logs := newReg(t, cfg, Options{Resolver: res})
	if !strings.Contains(logs.String(), `"level":"WARN"`) || !strings.Contains(logs.String(), "oauth_client_secret_unavailable") {
		t.Errorf("startup read failure must log WARN, got %s", logs.String())
	}
	p, _ := r.Get("google")
	if _, err := p.ClientSecret(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	// An empty stored value is also unavailable.
	res.mu.Lock()
	res.err = nil
	res.mu.Unlock()
	if _, err := p.ClientSecret(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("empty secret err = %v, want ErrProviderUnavailable", err)
	}
	res.mu.Lock()
	res.vals = map[string]string{"oauth-clients/google": "late-secret"}
	res.mu.Unlock()
	s, err := p.ClientSecret(context.Background())
	if err != nil || s.Reveal() != "late-secret" {
		t.Fatalf("retry on first use = %v, %v", s, err)
	}
	res.mu.Lock()
	calls := res.calls
	res.mu.Unlock()
	if _, _ = p.ClientSecret(context.Background()); res.calls != calls {
		t.Error("a successful read must be cached")
	}
	// No resolver at all.
	r2, _ := newReg(t, cfg, Options{})
	p2, _ := r2.Get("google")
	if _, err := p2.ClientSecret(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Errorf("no resolver err = %v", err)
	}
}

func TestProviderRedaction(t *testing.T) {
	const secret = "TOP-SECRET-CLIENT-VALUE"
	var logs bytes.Buffer
	res := &fakeResolver{vals: map[string]string{"oauth-clients/google": secret}}
	r, _ := newReg(t, []config.OAuthProviderConfig{
		{ID: "google", Type: "google", ClientID: "cid", ClientSecretKey: "oauth-clients/google"},
		{ID: "gh", Type: "github", ClientID: "cid2", ClientSecretEnv: "E"},
	}, Options{Resolver: res, LookupEnv: func(string) (string, bool) { return secret, true }})
	for _, id := range []string{"google", "gh"} {
		p, _ := r.Get(id)
		s, err := p.ClientSecret(context.Background())
		if err != nil || s.Reveal() != secret {
			t.Fatalf("secret not loaded: %v", err)
		}
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("p", "provider", p, "secret", s)
		outs := []string{
			fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p),
			fmt.Sprintf("%#v", s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", struct{ S Secret }{s}),
			logs.String(),
		}
		j, _ := json.Marshal(s)
		outs = append(outs, string(j))
		for i, o := range outs {
			if strings.Contains(o, secret) {
				t.Errorf("%s output %d leaks the secret: %s", id, i, o)
			}
		}
	}
}

func TestProviderCapScopes(t *testing.T) {
	r, _ := newReg(t, []config.OAuthProviderConfig{
		{ID: "google", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/google",
			AllowedScopes: []string{"openid", "drive", "drive"}, DefaultScopes: []string{"openid"}},
		{ID: "ghapp", Type: "githubApp", ClientID: "c", ClientSecretKey: "oauth-clients/ghapp"},
	}, Options{})
	g, _ := r.Get("google")
	if !reflect.DeepEqual(g.AllowedScopes, []string{"drive", "openid"}) {
		t.Errorf("AllowedScopes = %v (want sorted, de-duplicated)", g.AllowedScopes)
	}
	capped, rej := g.CapScopes([]string{"drive", "gmail.send"})
	if !reflect.DeepEqual(capped, []string{"drive"}) || !reflect.DeepEqual(rej, []string{"gmail.send"}) {
		t.Errorf("cap = %v rejected %v", capped, rej)
	}
	// githubApp has no scopes: any requested scope is outside the cap.
	a, _ := r.Get("ghapp")
	if _, rej := a.CapScopes([]string{"repo"}); !reflect.DeepEqual(rej, []string{"repo"}) {
		t.Errorf("githubApp rejected = %v", rej)
	}
}

func TestRegistryDoesNotAliasConfig(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "g", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/g",
		AllowedScopes: []string{"a"}, AllowedAccountDomains: []string{"example.com"}, ExtraAuthParams: map[string]string{"login_hint": "x"}}}
	r, _ := newReg(t, cfg, Options{})
	cfg[0].AllowedScopes[0] = "zzz"
	cfg[0].AllowedAccountDomains[0] = "evil.com"
	p, _ := r.Get("g")
	if p.AllowedScopes[0] != "a" || p.AllowedAccountDomains[0] != "example.com" {
		t.Errorf("registry aliases the config slices: %+v", p)
	}
}

// Secret must not leak when held in an unexported field of a printed struct
// (fmt cannot call methods on unexported fields).
func TestSecretInUnexportedField(t *testing.T) {
	type holder struct{ s Secret }
	h := holder{s: NewSecret("HIDDEN-VALUE")}
	for _, o := range []string{fmt.Sprintf("%v", h), fmt.Sprintf("%+v", h), fmt.Sprintf("%#v", h)} {
		if strings.Contains(o, "HIDDEN-VALUE") {
			t.Errorf("leak: %s", o)
		}
	}
	if NewSecret("x").Reveal() != "x" || !(Secret{}).IsZero() || (Secret{}).Reveal() != "" {
		t.Error("Secret accessors broken")
	}
}

type countingResolver struct {
	mu    sync.Mutex
	calls int
	gate  chan struct{}
	err   error
}

func (c *countingResolver) ResolveSecret(context.Context, string) (string, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if c.gate != nil {
		<-c.gate
	}
	if c.err != nil {
		return "", c.err
	}
	return "v", nil
}

func TestClientSecretSingleflightAndFailureCache(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "g", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/g"}}
	// Failure cache: an outage costs one store call within the window.
	res := &countingResolver{err: errors.New("down")}
	r, _ := newReg(t, cfg, Options{Resolver: res, Now: time.Now})
	p, _ := r.Get("g")
	base := res.calls // startup read
	for i := 0; i < 5; i++ {
		if _, err := p.ClientSecret(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("err = %v", err)
		}
	}
	if res.calls != base {
		t.Errorf("store called %d extra times during the failure window, want 0", res.calls-base)
	}
	// Singleflight: concurrent first reads share one store call, and the lock is not held across it.
	gate := make(chan struct{})
	res2 := &countingResolver{gate: gate}
	r2, _ := NewRegistry(cfg, Options{LookupEnv: noEnv, Logger: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))})
	p2, _ := r2.Get("g")
	p2.resolver = res2
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, err := p2.ClientSecret(context.Background()); err != nil || s.Reveal() != "v" {
				t.Errorf("secret = %v, %v", s, err)
			}
		}()
	}
	for { // wait until the leader is inside the store call
		res2.mu.Lock()
		n := res2.calls
		res2.mu.Unlock()
		if n > 0 {
			break
		}
		runtime.Gosched()
	}
	close(gate)
	wg.Wait()
	if res2.calls != 1 {
		t.Errorf("store calls = %d, want 1 (singleflight)", res2.calls)
	}
}

func TestRegistryDoesNotAliasExtraParams(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "g", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/g",
		ExtraAuthParams: map[string]string{"hd": "example.com", "prompt": "select_account"}}}
	r, _ := newReg(t, cfg, Options{})
	cfg[0].ExtraAuthParams["hd"] = "evil.com"
	delete(cfg[0].ExtraAuthParams, "prompt")
	p, _ := r.Get("g")
	want := map[string]string{"access_type": "offline", "prompt": "select_account", "hd": "example.com"}
	if !reflect.DeepEqual(p.ExtraAuthParams, want) {
		t.Errorf("params after config mutation = %v, want %v", p.ExtraAuthParams, want)
	}
	// A second registry from pristine google config is unaffected by the first's map.
	r2, _ := newReg(t, []config.OAuthProviderConfig{{ID: "g", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/g"}}, Options{})
	p.ExtraAuthParams["access_type"] = "online"
	p2, _ := r2.Get("g")
	if p2.ExtraAuthParams["access_type"] != "offline" {
		t.Errorf("registries share default maps: %v", p2.ExtraAuthParams)
	}
	// Scope slices carry no spare capacity to append into.
	if s := normalizeScopes([]string{"a", "b", "a"}); cap(s) != len(s) {
		t.Errorf("cap %d != len %d", cap(s), len(s))
	}
}

func TestClientSecretFailureCacheExpires(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "g", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/g"}}
	res := &countingResolver{err: errors.New("down")}
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	r, _ := newReg(t, cfg, Options{Resolver: res, Now: clock})
	p, _ := r.Get("g")
	base := res.calls
	_, _ = p.ClientSecret(context.Background())
	if res.calls != base {
		t.Fatalf("failure inside the window re-read the store (%d calls)", res.calls-base)
	}
	mu.Lock()
	now = now.Add(secretFailCache + time.Second)
	mu.Unlock()
	res.mu.Lock()
	res.err = nil
	res.mu.Unlock()
	s, err := p.ClientSecret(context.Background())
	if err != nil || s.Reveal() != "v" || res.calls != base+1 {
		t.Errorf("after the window: %v, %v, calls %d (want one fresh read)", s, err, res.calls-base)
	}
}

func TestClientSecretHonoursCallerDeadline(t *testing.T) {
	cfg := []config.OAuthProviderConfig{{ID: "g", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/g"}}
	gate := make(chan struct{})
	defer close(gate)
	r, _ := NewRegistry(cfg, Options{LookupEnv: noEnv, Logger: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))})
	p, _ := r.Get("g")
	p.resolver = &countingResolver{gate: gate}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.ClientSecret(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrProviderUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want ErrProviderUnavailable wrapping the deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClientSecret ignored the caller's deadline while the store hung")
	}
}

// TestClientSecretFromUserStore: a clientSecretKey provider resolves its secret
// through the consent.store resolver only, and a key other than
// oauth-clients/<id> fails validation.
func TestClientSecretFromUserStore(t *testing.T) {
	// Options has no other secret source: the distributed secretStore is not reachable from here.
	consent := &fakeResolver{vals: map[string]string{"oauth-clients/google": "from-consent-store"}}
	cfg := []config.OAuthProviderConfig{{ID: "google", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/google"}}
	r, _ := newReg(t, cfg, Options{Resolver: consent})
	p, _ := r.Get("google")
	s, err := p.ClientSecret(context.Background())
	if err != nil || s.Reveal() != "from-consent-store" {
		t.Fatalf("ClientSecret = %v, %v", s, err)
	}
	consent.mu.Lock()
	calls := consent.calls
	consent.mu.Unlock()
	if calls != 1 {
		t.Errorf("consent.store reads = %d, want 1 (startup read, then cached)", calls)
	}

	for _, key := range []string{"oauth-clients/other", "users/x/google", "cp/keys/google", "google"} {
		bad := []config.OAuthProviderConfig{{ID: "google", Type: "google", ClientID: "c", ClientSecretKey: key}}
		if _, err := NewRegistry(bad, Options{LookupEnv: noEnv, Resolver: consent}); err == nil {
			t.Errorf("clientSecretKey %q for provider google must fail validation", key)
		}
	}
}
