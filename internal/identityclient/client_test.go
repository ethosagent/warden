package identityclient_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

func TestDeviceLogin(t *testing.T) {
	r := newRig(t)
	r.idp.setScript("pending")
	warnings := r.login(t)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if !strings.Contains(r.out.String(), userCode) || !strings.Contains(r.out.String(), r.idp.URL()+"/activate") {
		t.Fatalf("prompt lacks verification uri and user code: %q", r.out.String())
	}
	e, err := r.cl.Store().Load()
	if err != nil {
		t.Fatal(err)
	}
	if e.RefreshToken == "" || e.IDToken == "" || !e.ReceivedAt.Equal(r.clock.Now()) {
		t.Fatalf("cache entry incomplete: %+v", e)
	}
	if got := r.idp.lastForm["scope"]; len(got) != 1 || !strings.Contains(got[0], "offline_access") {
		t.Fatalf("device request scope = %v", got)
	}
	st, err := r.cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Subject != "user-1" || st.Email != "u@example.com" || len(st.Groups) != 1 || st.Issuer != r.idp.URL() || st.CachePath != r.cl.Store().Path() {
		t.Fatalf("status = %+v", st)
	}
}

func TestDevicePollSlowDown(t *testing.T) {
	r := newRig(t)
	r.idp.setScript("pending", "slow_down")
	r.login(t)
	want := []time.Duration{time.Second, time.Second, 6 * time.Second}
	if len(r.slept.d) != len(want) {
		t.Fatalf("waits = %v, want %v", r.slept.d, want)
	}
	for i := range want {
		if r.slept.d[i] != want[i] {
			t.Fatalf("waits = %v, want %v", r.slept.d, want)
		}
	}
}

func TestDeviceLoginFailures(t *testing.T) {
	for _, outcome := range []string{"denied", "expired"} {
		r := newRig(t)
		r.idp.setScript(outcome)
		if _, err := r.cl.Login(context.Background(), r.out); err == nil {
			t.Fatalf("%s: want error", outcome)
		}
		if _, err := os.Stat(r.cl.Store().Path()); err == nil {
			t.Fatalf("%s: cache written on failure", outcome)
		}
	}
	// Device code expiry on the client's clock: expires_in is 600s, interval 1s.
	r := newRig(t)
	script := make([]string, 700)
	for i := range script {
		script[i] = "pending"
	}
	r.idp.setScript(script...)
	if _, err := r.cl.Login(context.Background(), r.out); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expiry error, got %v", err)
	}
}

func TestLoginWarnings(t *testing.T) {
	r := newRig(t)
	r.idp.groups = nil
	r.idp.aud = []string{"someone-else"}
	w := strings.Join(r.login(t), "|")
	if !strings.Contains(w, "groups") || !strings.Contains(w, "aud") {
		t.Fatalf("warnings = %q", w)
	}
	if contains(w, r.idp.mint(), baseRefresh) != "" {
		t.Fatal("warning leaks a token")
	}
}

func TestLoginClientSecretFromEnvOnly(t *testing.T) {
	r := newRig(t)
	r.cl.Config.ClientSecretEnv = "WARDEN_TEST_SECRET"
	r.cl.Getenv = func(string) string { return "" }
	_, err := r.cl.Login(context.Background(), r.out)
	if err == nil || !strings.Contains(err.Error(), "WARDEN_TEST_SECRET") {
		t.Fatalf("want error naming the variable, got %v", err)
	}
	r.cl.Getenv = func(k string) string {
		if k == "WARDEN_TEST_SECRET" {
			return "s3cret"
		}
		return ""
	}
	r.login(t)
}

func TestRefreshAtTwoThirds(t *testing.T) {
	r := newRig(t)
	r.login(t)
	first, err := r.cl.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Warning != "" || r.idp.refreshCalls.Load() != 0 {
		t.Fatalf("fresh cache must not refresh: %+v calls=%d", first, r.idp.refreshCalls.Load())
	}
	r.clock.Advance(tokenTTL*2/3 - time.Second)
	if got, _ := r.cl.Token(context.Background()); got.IDToken != first.IDToken || r.idp.refreshCalls.Load() != 0 {
		t.Fatal("token refreshed before 2/3 of its lifetime")
	}
	r.clock.Advance(2 * time.Second)
	second, err := r.cl.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.IDToken == first.IDToken || r.idp.refreshCalls.Load() != 1 {
		t.Fatalf("want exactly one refresh, got %d", r.idp.refreshCalls.Load())
	}
	// The rotated refresh token was persisted: a second refresh succeeds.
	r.clock.Advance(tokenTTL)
	third, err := r.cl.Token(context.Background())
	if err != nil || third.IDToken == second.IDToken || r.idp.refreshCalls.Load() != 2 {
		t.Fatalf("second refresh: err=%v calls=%d", err, r.idp.refreshCalls.Load())
	}
	if !third.Expiry.After(r.clock.Now()) {
		t.Fatalf("expiry %v not in the future", third.Expiry)
	}
}

func TestTokenNoPrompt(t *testing.T) {
	// No cache at all.
	r := newRig(t)
	if _, err := r.cl.Token(context.Background()); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatalf("no cache: %v", err)
	}
	if _, err := r.cl.Status(); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatalf("status no cache: %v", err)
	}
	if r.idp.deviceCalls.Load() != 0 || r.out.Len() != 0 {
		t.Fatal("Token must never start a login or write a prompt")
	}
	// Revoked refresh token.
	r.login(t)
	devices := r.idp.deviceCalls.Load()
	r.idp.mu.Lock()
	r.idp.refresh = "revoked-elsewhere"
	r.idp.mu.Unlock()
	r.clock.Advance(tokenTTL)
	r.out.Reset()
	_, err := r.cl.Token(context.Background())
	if !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatalf("revoked: %v", err)
	}
	if r.idp.deviceCalls.Load() != devices || r.out.Len() != 0 {
		t.Fatal("Token prompted")
	}
	// An entry with no refresh token.
	e, _ := r.cl.Store().Load()
	e.RefreshToken = ""
	if err := r.cl.Store().Save(e); err != nil {
		t.Fatal(err)
	}
	if _, err := r.cl.Token(context.Background()); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatalf("no refresh token: %v", err)
	}
}

func TestIssuerDownServesCache(t *testing.T) {
	r := newRig(t)
	r.login(t)
	first, _ := r.cl.Token(context.Background())
	r.idp.setDown(true)
	r.clock.Advance(tokenTTL * 3 / 4) // past 2/3, before expiry
	got, err := r.cl.Token(context.Background())
	if err != nil {
		t.Fatalf("want the cached token, got %v", err)
	}
	if got.IDToken != first.IDToken || got.Warning == "" {
		t.Fatalf("want cached token with a warning: %+v", got)
	}
	r.clock.Advance(tokenTTL) // expired
	if _, err := r.cl.Token(context.Background()); !errors.Is(err, identityclient.ErrIssuerUnreachable) {
		t.Fatalf("want ErrIssuerUnreachable, got %v", err)
	}
	// The failed refresh left the cache usable once the issuer is back.
	r.idp.setDown(false)
	if _, err := r.cl.Token(context.Background()); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestIssuerConnectionRefused(t *testing.T) {
	r := newRig(t)
	r.login(t)
	r.idp.srv.Close()
	r.clock.Advance(tokenTTL * 3 / 4)
	got, err := r.cl.Token(context.Background())
	if err != nil || got.Warning == "" {
		t.Fatalf("closed server: %+v %v", got, err)
	}
	r.clock.Advance(tokenTTL)
	if _, err := r.cl.Token(context.Background()); !errors.Is(err, identityclient.ErrIssuerUnreachable) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentRefreshSingleFlight(t *testing.T) {
	r := newRig(t)
	r.login(t)
	r.idp.tokenDelay = 50 * time.Millisecond
	r.clock.Advance(tokenTTL * 3 / 4)
	var wg sync.WaitGroup
	res := make([]identityclient.TokenResult, 2)
	errs := make([]error, 2)
	for i := range res {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = r.cl.Token(context.Background())
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := r.idp.refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh requests = %d, want exactly 1", n)
	}
	if res[0].IDToken != res[1].IDToken || res[0].IDToken == "" {
		t.Fatal("callers got different tokens")
	}
}

func TestConcurrentRefreshSeparateClients(t *testing.T) {
	// Two Clients on one cache dir stand in for two processes.
	r := newRig(t)
	r.login(t)
	r.idp.tokenDelay = 50 * time.Millisecond
	r.clock.Advance(tokenTTL * 3 / 4)
	other := *r.cl
	var wg sync.WaitGroup
	for _, c := range []*identityclient.Client{r.cl, &other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Token(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := r.idp.refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh requests = %d, want 1", n)
	}
}

func TestLogout(t *testing.T) {
	r := newRig(t)
	r.login(t)
	r.clock.Advance(tokenTTL) // force a refresh so the lock file exists
	if _, err := r.cl.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.cl.Logout(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(r.cl.Config.CacheDir)
	if len(entries) != 0 {
		t.Fatalf("cache dir not empty: %v", entries)
	}
	if err := r.cl.Logout(); err != nil {
		t.Fatalf("second logout must succeed: %v", err)
	}
	if _, err := r.cl.Token(context.Background()); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatal("token after logout")
	}
}

func TestFingerprint(t *testing.T) {
	a := identityclient.Fingerprint("abc")
	if len(a) != 8 || a != identityclient.Fingerprint("abc") || a == identityclient.Fingerprint("abd") {
		t.Fatalf("fingerprint %q", a)
	}
	if strings.Contains("abc", a) {
		t.Fatal("fingerprint must not be a token substring")
	}
}

func TestLoginWarnsOnExpiredToken(t *testing.T) {
	r := newRig(t)
	r.idp.clockSkew = -2 * tokenTTL
	if w := strings.Join(r.login(t), "|"); !strings.Contains(w, "expired") {
		t.Fatalf("warnings = %q", w)
	}
}
