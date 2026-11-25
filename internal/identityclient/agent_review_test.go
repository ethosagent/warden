package identityclient_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

func TestExchangeRejectsOutOfRangeExpiresIn(t *testing.T) {
	for _, secs := range []int{0, 1, 29, 10_000_000_000, -5, 86401} {
		a := newAgentRig(t)
		a.cp.expiresIn = secs
		if _, err := a.ex.Exchange(context.Background(), "subject-secret"); !errors.Is(err, identityclient.ErrBadExchangeResponse) {
			t.Errorf("expires_in %d = %v, want ErrBadExchangeResponse", secs, err)
		}
	}
	for _, secs := range []int{30, 86400} {
		a := newAgentRig(t)
		a.cp.expiresIn = secs
		tok, err := a.ex.Exchange(context.Background(), "subject-secret")
		if err != nil || tok.Expiry.Sub(tok.ReceivedAt) != time.Duration(secs)*time.Second {
			t.Errorf("expires_in %d = %v %v, want accepted", secs, tok.Expiry, err)
		}
	}
}

func TestExchangeBadExpiresInBacksOff(t *testing.T) {
	a := newAgentRig(t)
	a.cp.expiresIn = 1
	src := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
	src.Now = a.clock.Now
	if _, err := src.Token(context.Background()); !errors.Is(err, identityclient.ErrBadExchangeResponse) {
		t.Fatalf("Token = %v, want ErrBadExchangeResponse", err)
	}
	if _, err := src.Token(context.Background()); !errors.Is(err, identityclient.ErrBadExchangeResponse) || a.cp.calls() != 1 {
		t.Fatalf("second Token = %v after %d calls, want the backoff to hold it at 1", err, a.cp.calls())
	}
}

func newSource(a *agentRig) *identityclient.WardenTokenSource {
	src := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
	src.Now, src.Jitter = a.clock.Now, func() float64 { return 0 }
	src.AgentID = "agent-1"
	return src
}

func TestRefreshFloorAfterSuccess(t *testing.T) {
	a := newAgentRig(t)
	src := newSource(a)
	first, _ := src.Token(context.Background())
	got, err := src.Refresh(context.Background())
	if err != nil || got.AccessToken != first.AccessToken || a.cp.calls() != 1 {
		t.Fatalf("Refresh within 2s: %v calls=%d, want the held token and no exchange", err, a.cp.calls())
	}
	a.clock.Advance(3 * time.Second)
	got, err = src.Refresh(context.Background())
	if err != nil || got.AccessToken == first.AccessToken || a.cp.calls() != 2 {
		t.Fatalf("Refresh after 3s: %v calls=%d, want a new exchange", err, a.cp.calls())
	}
}

func TestRefreshReportsDenialAndHonoursCooldown(t *testing.T) {
	a := newAgentRig(t)
	src := newSource(a)
	first, _ := src.Token(context.Background())
	a.clock.Advance(3 * time.Second)
	a.cp.reply(oauthErr(401, "invalid_client"))
	got, err := src.Refresh(context.Background())
	var denied identityclient.ErrExchangeDenied
	if !errors.As(err, &denied) || denied.Code != "invalid_client" || got.AccessToken != first.AccessToken {
		t.Fatalf("Refresh = %q, %v; want the held token with ErrExchangeDenied", got.AccessToken, err)
	}
	st := src.State()
	if st.Reason != identityclient.ReasonExpiring || st.LastError != "exchange_denied:invalid_client" || !st.Expiry.Equal(first.Expiry) {
		t.Fatalf("State = %+v, want expiring with the denial code", st)
	}
	calls := a.cp.calls()
	got, err = src.Refresh(context.Background())
	if !errors.As(err, &denied) || got.AccessToken != first.AccessToken || a.cp.calls() != calls {
		t.Fatalf("Refresh in the cooldown: %v, calls %d -> %d; want the same error and no request", err, calls, a.cp.calls())
	}
	// Token keeps its old contract: the held token and no error.
	if tok, err := src.Token(context.Background()); err != nil || tok.AccessToken != first.AccessToken {
		t.Fatalf("Token = %v", err)
	}
	// Past exp with the denial standing, the reason is the denial.
	a.clock.Advance(time.Hour)
	if st := src.State(); st.Reason != identityclient.ReasonExchangeDenied {
		t.Fatalf("State past exp = %+v, want exchange_denied", st)
	}
}

func TestRefreshHonoursRetryAfterOn429(t *testing.T) {
	a := newAgentRig(t)
	src := newSource(a)
	first, _ := src.Token(context.Background())
	a.clock.Advance(3 * time.Second)
	rl := oauthErr(429, "slow_down")
	rl.retryAfter = "30"
	a.cp.reply(rl)
	got, err := src.Refresh(context.Background())
	var limited identityclient.ErrRateLimited
	if !errors.As(err, &limited) || got.AccessToken != first.AccessToken {
		t.Fatalf("Refresh = %v, want the held token with ErrRateLimited", err)
	}
	calls := a.cp.calls()
	a.clock.Advance(20 * time.Second)
	if _, err := src.Refresh(context.Background()); !errors.As(err, &limited) || a.cp.calls() != calls {
		t.Fatalf("Refresh 20s into a 30s Retry-After: %v, calls %d -> %d", err, calls, a.cp.calls())
	}
	a.clock.Advance(15 * time.Second)
	if _, err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh after the Retry-After: %v", err)
	}
}

func TestSourceState(t *testing.T) {
	ctx := context.Background()
	a := newAgentRig(t)
	src := newSource(a)
	if st := src.State(); st.Reason != identityclient.ReasonExpiring || !st.Expiry.IsZero() {
		t.Fatalf("fresh State = %+v", st)
	}
	tok, _ := src.Token(ctx)
	if st := src.State(); st.Reason != identityclient.ReasonValid || st.LastError != "" || !st.Expiry.Equal(tok.Expiry) {
		t.Fatalf("State = %+v, want valid", st)
	}
	a.clock.Advance(601 * time.Second) // past the refresh point
	if st := src.State(); st.Reason != identityclient.ReasonExpiring {
		t.Fatalf("State past the refresh point = %+v, want expiring", st)
	}

	b := newAgentRig(t)
	lr := identityclient.NewWardenTokenSource(b.ex, staticSubject{err: identityclient.ErrLoginRequired})
	lr.Now = b.clock.Now
	if _, err := lr.Token(ctx); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatal(err)
	}
	if st := lr.State(); st.Reason != identityclient.ReasonLoginRequired || st.LastError != "login_required" {
		t.Fatalf("State = %+v, want login_required", st)
	}

	c := newAgentRig(t)
	c.cp.srv.Close()
	up := newSource(c)
	if _, err := up.Token(ctx); !errors.Is(err, identityclient.ErrCPUnreachable) {
		t.Fatal(err)
	}
	if st := up.State(); st.Reason != identityclient.ReasonCPUnreachable || st.LastError != "cp_unreachable" {
		t.Fatalf("State = %+v, want cp_unreachable", st)
	}

	d := newAgentRig(t)
	d.cp.reply(oauthErr(401, "invalid_client"))
	den := newSource(d)
	if _, err := den.Token(ctx); err == nil {
		t.Fatal("denial not reported")
	}
	if st := den.State(); st.Reason != identityclient.ReasonExchangeDenied || st.LastError != "exchange_denied:invalid_client" {
		t.Fatalf("State = %+v, want exchange_denied", st)
	}
}

func TestSourceFormattingNeverShowsToken(t *testing.T) {
	a := newAgentRig(t)
	src := newSource(a)
	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("source", "src", src)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("source", slog.Any("src", src))
	out := map[string]string{
		"%v": fmt.Sprintf("%v", src), "%+v": fmt.Sprintf("%+v", src), "%#v": fmt.Sprintf("%#v", src),
		"Sprint": fmt.Sprint(src), "slog": buf.String(),
	}
	for form, s := range out {
		if strings.Contains(s, tok.AccessToken) || strings.Contains(s, "warden-token-secret") {
			t.Errorf("%s leaks the token: %s", form, s)
		}
		if !strings.Contains(s, "agent-1") || !strings.Contains(s, identityclient.Fingerprint(tok.AccessToken)) {
			t.Errorf("%s lacks the agent id or fingerprint: %s", form, s)
		}
	}
}

func TestOnRotateCallbackMayCallTokenAndRefresh(t *testing.T) {
	a := newAgentRig(t)
	src := newSource(a)
	done := make(chan error, 1)
	var once sync.Once
	src.OnRotate(func() {
		once.Do(func() {
			_, err1 := src.Token(context.Background())
			_, err2 := src.Refresh(context.Background())
			done <- errors.Join(err1, err2)
		})
	})
	go func() { _, _ = src.Token(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("callback Token/Refresh: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnRotate callback calling Token/Refresh deadlocked")
	}
}

func TestSaveAgentKeyRefusesExistingAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents", "a.key")
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range errs {
		k, err := identityclient.GenerateAgentKey()
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = identityclient.SaveAgentKey(path, k, false)
		}()
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, identityclient.ErrKeyExists):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d writers won, want exactly 1", wins)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".tmp-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if _, err := identityclient.LoadAgentKey(path); err != nil {
		t.Fatalf("the winner's key does not load: %v", err)
	}
}

func TestSaveAgentKeyRefusesDanglingSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agents")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.key")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), path); err != nil {
		t.Fatal(err)
	}
	k, _ := identityclient.GenerateAgentKey()
	if err := identityclient.SaveAgentKey(path, k, false); !errors.Is(err, identityclient.ErrKeyExists) {
		t.Fatalf("SaveAgentKey over a symlink = %v, want ErrKeyExists", err)
	}
}

func TestSaveAgentKeyRefusesWritableDir(t *testing.T) {
	k, _ := identityclient.GenerateAgentKey()
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		dir := filepath.Join(t.TempDir(), "agents")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		err := identityclient.SaveAgentKey(filepath.Join(dir, "a.key"), k, true)
		if err == nil || !strings.Contains(err.Error(), dir) {
			t.Errorf("mode %04o: %v, want an error naming %s", mode, err, dir)
		}
		if _, serr := os.Stat(filepath.Join(dir, "a.key")); serr == nil {
			t.Errorf("mode %04o: the key was written anyway", mode)
		}
	}
}

func writeFileOf(path string, n int) error {
	return os.WriteFile(path, bytes.Repeat([]byte("A"), n), 0o644)
}
