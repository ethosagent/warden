package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestBreakGlass_MeFields: a break-glass session made through
// SessionStore.Create reports authMethod breakglass and an expiresAt of its
// creation plus the session TTL.
func TestBreakGlass_MeFields(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	r.srv.sessions.now = r.clk.Now
	created := r.clk.Now()
	raw, _, err := r.srv.sessions.Create(context.Background(),
		SessionInput{Iss: "breakglass", Sub: "breakglass:" + bgUser, AuthMethod: AuthMethodBreakglass},
		CreateOptions{AbsoluteTTL: r.srv.cfg.Console.BreakGlass.SessionTTL})
	if err != nil {
		t.Fatal(err)
	}
	rec := r.me(raw)
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("/auth/me = %d %s", rec.Code, rec.Body.String())
	}
	if got["authMethod"] != "breakglass" {
		t.Errorf("authMethod = %q, want breakglass", got["authMethod"])
	}
	if want := created.Add(time.Hour).UTC().Format(time.RFC3339); got["expiresAt"] != want {
		t.Errorf("expiresAt = %q, want %q", got["expiresAt"], want)
	}
}

// TestBreakGlass_SessionWarn: the loop Server.Start launches logs one WARN per
// tick while a break-glass session is live and nothing once it has expired, and
// it never logs a session id.
func TestBreakGlass_SessionWarn(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	r.srv.sessions.now = r.clk.Now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.srv.Start(ctx)

	// tick fires the next 5 minute tick and waits until the loop has re-armed,
	// so its body has run.
	armed := func() bool { return r.clk.PendingTimers() == 1 }
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; i < 500 && !cond(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !cond() {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	tick := func() {
		t.Helper()
		waitFor("the loop to arm its timer", armed)
		r.clk.Advance(5 * time.Minute)
		waitFor("the loop to finish the tick", armed)
	}

	tick()
	if n := countLogs(r.logs.String(), "breakglass_session_active"); n != 0 {
		t.Fatalf("%d warns with no break-glass session, want 0", n)
	}

	created := r.clk.Now()
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	ck := r.cookie(rec)
	if ck == nil {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	for want := 1; want <= 2; want++ {
		tick()
		if n := countLogs(r.logs.String(), "breakglass_session_active"); n != want {
			t.Fatalf("after tick %d: %d warns, want %d", want, n, want)
		}
	}
	var line string
	for _, l := range strings.Split(r.logs.String(), "\n") {
		if strings.Contains(l, "msg=breakglass_session_active") {
			line = l
		}
	}
	wantExpiry := "earliest_expiry=" + created.Add(time.Hour).UTC().Format(time.RFC3339)
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "count=1") || !strings.Contains(line, wantExpiry) {
		t.Errorf("warn line = %q, want WARN with count=1 and %s", line, wantExpiry)
	}
	if strings.Contains(line, ck.Value) || strings.Contains(line, hashID(ck.Value)[:9]) {
		t.Errorf("warn line carries a session id: %q", line)
	}

	// Past its expiry the session no longer counts.
	r.clk.Advance(time.Hour)
	waitFor("the loop to re-arm after the jump", armed)
	before := countLogs(r.logs.String(), "breakglass_session_active")
	tick()
	if n := countLogs(r.logs.String(), "breakglass_session_active"); n != before {
		t.Errorf("warns grew from %d to %d for an expired session", before, n)
	}
}

// TestBreakGlass_NoSessionWarnLoopWhenDisabled: without break-glass Start arms
// no timer on the control plane's clock.
func TestBreakGlass_NoSessionWarnLoopWhenDisabled(t *testing.T) {
	r := newBGRig(t, bgOpts{disabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.srv.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	if n := r.clk.PendingTimers(); n != 0 {
		t.Fatalf("%d timers armed with break-glass disabled, want 0", n)
	}
}
