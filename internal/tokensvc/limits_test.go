package tokensvc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/tokensvc"
)

type memRecorder struct {
	mu     sync.Mutex
	events []tokensvc.Event
	err    error
}

func (m *memRecorder) Record(_ context.Context, ev tokensvc.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, ev)
	return nil
}

func (m *memRecorder) all() []tokensvc.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]tokensvc.Event(nil), m.events...)
}

func TestLimiterBucket(t *testing.T) {
	l := tokensvc.NewLimiter(30, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 30; i++ {
		if ok, _ := l.Allow("a", now); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, wait := l.Allow("a", now)
	if ok || wait != 2*time.Second {
		t.Fatalf("31st = %v, %v; want refused with 2s", ok, wait)
	}
	if ok, _ := l.Allow("b", now); !ok {
		t.Fatal("another key shares the budget")
	}
	if ok, _ := l.Allow("a", now.Add(time.Second)); ok {
		t.Fatal("allowed after 1s, a token takes 2s")
	}
	if ok, _ := l.Allow("a", now.Add(2*time.Second)); !ok {
		t.Fatal("refused after 2s")
	}
	// A clock that steps back neither refills nor panics.
	if ok, _ := l.Allow("a", now.Add(-time.Hour)); ok {
		t.Fatal("a backwards clock refilled the bucket")
	}
}

func TestLimiterRetryAfterIsAtLeastOneSecond(t *testing.T) {
	l := tokensvc.NewLimiter(1, time.Second/2) // 2 per second: the raw wait is 0.5s
	now := time.Unix(1_700_000_000, 0)
	l.Allow("k", now)
	if ok, wait := l.Allow("k", now); ok || wait < time.Second {
		t.Fatalf("refusal = %v, %v; want a wait of at least 1s", ok, wait)
	}
}

func TestLimiterBoundedAndEvictsIdleFirst(t *testing.T) {
	l := tokensvc.NewLimiterSize(1, time.Minute, 3)
	now := time.Unix(1_700_000_000, 0)
	l.Allow("old", now)
	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprintf("flood-%d", i), now.Add(time.Duration(i)*time.Millisecond))
		if l.Len() > 3 {
			t.Fatalf("limiter holds %d keys, cap 3", l.Len())
		}
	}
	// A key idle for a full window is dropped even with room to spare.
	l2 := tokensvc.NewLimiterSize(1, time.Minute, 10)
	l2.Allow("idle", now)
	l2.Allow("fresh", now.Add(2*time.Minute))
	if l2.Len() != 1 {
		t.Fatalf("idle key kept: %d keys", l2.Len())
	}
}

func TestRateLimitBuckets(t *testing.T) {
	rec := &memRecorder{}
	m := tokensvc.NewMetrics()
	e := newSvcEnvWith(t, func(c *tokensvc.Config) {
		c.AgentLimiter = tokensvc.NewLimiter(30, time.Minute)
		c.Recorder, c.Metrics = rec, m
	})
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if _, err := e.svc.Exchange(ctx, e.req()); err != nil {
			t.Fatalf("exchange %d: %v", i+1, err)
		}
	}
	got, err := e.svc.Exchange(ctx, e.req())
	te := wantErr(t, err, tokensvc.CodeRateLimited, tokensvc.ReasonRateLimited)
	if got != nil || te.RetryAfter < time.Second || te.AgentID != "agent-1" || !te.Verified {
		t.Fatalf("31st exchange = %+v, %+v; want a verified rate_limited for agent-1 with Retry-After >= 1s", got, te)
	}
	e.now = e.now.Add(2 * time.Second)
	if _, err := e.svc.Exchange(ctx, e.req()); err != nil {
		t.Fatalf("exchange after 2s: %v", err)
	}
	if m.DeniedTotal(tokensvc.ReasonRateLimited) != 1 || m.IssuedTotal("agent-1") != 31 {
		t.Errorf("metrics: rate_limited %d issued %d, want 1 and 31", m.DeniedTotal(tokensvc.ReasonRateLimited), m.IssuedTotal("agent-1"))
	}
	events := rec.all()
	var denied int
	for _, ev := range events {
		if ev.Outcome == tokensvc.OutcomeDenied && ev.Reason == tokensvc.ReasonRateLimited && ev.AgentID == "agent-1" {
			denied++
		}
	}
	if len(events) != 32 || denied != 1 {
		t.Errorf("%d events with %d rate_limited denials, want 32 and 1", len(events), denied)
	}
}

func TestRateLimitPerUser(t *testing.T) {
	e := newSvcEnvWith(t, func(c *tokensvc.Config) { c.UserLimiter = tokensvc.NewLimiter(2, time.Minute) })
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := e.svc.Exchange(ctx, e.req()); err != nil {
			t.Fatal(err)
		}
	}
	_, err := e.svc.Exchange(ctx, e.req())
	wantErr(t, err, tokensvc.CodeRateLimited, tokensvc.ReasonRateLimited)
	// Another user of the same IdP has a budget of their own.
	c := e.claims()
	c.Sub = "user-2"
	e.verifier.Set(subjectToken, c, identity.StatusValid, "")
	if _, err := e.svc.Exchange(ctx, e.req()); err != nil {
		t.Fatalf("another user: %v", err)
	}
}

func TestRateLimitedAgentDoesNotReachTheIdP(t *testing.T) {
	e := newSvcEnvWith(t, func(c *tokensvc.Config) { c.AgentLimiter = tokensvc.NewLimiter(1, time.Hour) })
	ctx := context.Background()
	if _, err := e.svc.Exchange(ctx, e.req()); err != nil {
		t.Fatal(err)
	}
	before := e.verifier.Calls()
	_, err := e.svc.Exchange(ctx, e.req())
	wantErr(t, err, tokensvc.CodeRateLimited, tokensvc.ReasonRateLimited)
	if e.verifier.Calls() != before {
		t.Error("a rate-limited agent still cost an IdP verification")
	}
}

func TestExchangeEventStoreFailClosed(t *testing.T) {
	rec := &memRecorder{err: errors.New("disk full")}
	m := tokensvc.NewMetrics()
	e := newSvcEnvWith(t, func(c *tokensvc.Config) { c.Recorder, c.Metrics = rec, m })
	got, err := e.svc.Exchange(context.Background(), e.req())
	te := wantErr(t, err, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonEventStoreUnavailable)
	if got != nil {
		t.Fatalf("a token was released although the event could not be recorded: %v", got)
	}
	if strings.Contains(te.Error(), "disk full") {
		t.Errorf("the store's error text reached the error: %v", te)
	}
	if m.IssuedTotal("agent-1") != 0 || m.DeniedTotal(tokensvc.ReasonEventStoreUnavailable) != 1 {
		t.Errorf("metrics counted an issuance: issued %d, event_store_unavailable %d", m.IssuedTotal("agent-1"), m.DeniedTotal(tokensvc.ReasonEventStoreUnavailable))
	}
	// A denial is still a denial when its own record cannot be written.
	e.blocks.subs["user-1"] = true
	_, err = e.svc.Exchange(context.Background(), e.req())
	wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonUserBlocked)
}

func TestExchangeRecordsOnlyAuthenticatedOutcomes(t *testing.T) {
	rec := &memRecorder{}
	e := newSvcEnvWith(t, func(c *tokensvc.Config) { c.Recorder = rec })
	ctx := context.Background()
	ok, err := e.svc.Exchange(ctx, e.req())
	if err != nil {
		t.Fatal(err)
	}
	// Unauthenticated: a replay of the same assertion, an unknown token type.
	replayed := e.req()
	if _, err := e.svc.Exchange(ctx, replayed); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Exchange(ctx, replayed); err == nil {
		t.Fatal("replay accepted")
	}
	bad := e.req()
	bad.SubjectTokenType = "urn:example:nope"
	_, err = e.svc.Exchange(ctx, bad)
	wantErr(t, err, tokensvc.CodeInvalidRequest, tokensvc.ReasonUnsupportedTokenType)
	// Authenticated denial.
	e.blocks.subs["user-1"] = true
	_, err = e.svc.Exchange(ctx, e.req())
	te := wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonUserBlocked)
	if !te.Verified {
		t.Error("a denial after the assertion verified is not marked Verified")
	}

	events := rec.all()
	if len(events) != 3 {
		t.Fatalf("%d events, want 3 (two issuances, one authenticated denial): %+v", len(events), events)
	}
	if ev := events[0]; ev.Outcome != tokensvc.OutcomeIssued || ev.AgentID != "agent-1" || ev.Sub != "user-1" || ev.IdPIss != idpIssuer ||
		ev.SID != ok.SID || ev.JTI != ok.JTI || ev.KID != ok.KID || !ev.Exp.Equal(ok.Exp) || ev.TS.IsZero() {
		t.Errorf("issued event = %+v", ev)
	}
	if ev := events[2]; ev.Outcome != tokensvc.OutcomeDenied || ev.Reason != tokensvc.ReasonUserBlocked || ev.SID != "" || ev.JTI != "" {
		t.Errorf("denied event = %+v", ev)
	}
}

func TestMetricReasonsBounded(t *testing.T) {
	m := tokensvc.NewMetrics()
	for _, r := range tokensvc.AllReasons() {
		m.Denied(r)
	}
	// Anything outside the enum, such as a value from a request, folds into
	// malformed instead of becoming a label.
	for _, junk := range []tokensvc.Reason{"", "attacker-chosen", "agent_unknown ", "RATE_LIMITED"} {
		m.Denied(junk)
	}
	snap := m.DeniedSnapshot()
	var got, want []string
	for r := range snap {
		got = append(got, string(r))
	}
	for _, r := range tokensvc.AllReasons() {
		want = append(want, string(r))
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("denied label set = %v, want exactly the Reason enum %v", got, want)
	}
	if n := m.DeniedTotal(tokensvc.ReasonMalformed); n != 5 {
		t.Errorf("malformed = %d, want 1 own count + 4 folded", n)
	}
	// The enum itself is pinned: the p2-security-tests case and docs list it.
	if len(want) != 31 || !tokensvc.KnownReason(tokensvc.ReasonSessionStoreUnavailable) || !tokensvc.KnownReason(tokensvc.ReasonEventStoreUnavailable) {
		t.Errorf("the Reason enum has %d members, want 31 including session_store_unavailable and event_store_unavailable", len(want))
	}
	seen := map[tokensvc.Reason]bool{}
	for _, r := range tokensvc.AllReasons() {
		if seen[r] {
			t.Errorf("duplicate reason %s", r)
		}
		seen[r] = true
	}
}

func TestMetricsAgentLabelsBounded(t *testing.T) {
	m := tokensvc.NewMetrics()
	m.Issued("")
	m.Issued("agent-1")
	for i := 0; i < 3000; i++ {
		m.Issued(fmt.Sprintf("agent-%d", i))
	}
	snap := m.IssuedSnapshot()
	if snap[tokensvc.UnknownAgent] != 1 {
		t.Errorf("unknown = %d, want 1", snap[tokensvc.UnknownAgent])
	}
	if len(snap) > 1100 || snap[tokensvc.OtherAgent] == 0 {
		t.Errorf("%d agent labels with other=%d: the label set must be bounded", len(snap), snap[tokensvc.OtherAgent])
	}
}

func TestMetricsNilSafeAndHistogram(t *testing.T) {
	var nilM *tokensvc.Metrics
	nilM.Issued("a")
	nilM.Denied(tokensvc.ReasonReplay)
	nilM.Observe(time.Second)
	if nilM.IssuedTotal("a") != 0 || nilM.DeniedTotal(tokensvc.ReasonReplay) != 0 || nilM.Duration().Count != 0 ||
		len(nilM.DeniedSnapshot()) != 0 || len(nilM.IssuedSnapshot()) != 0 {
		t.Error("a nil Metrics reports something")
	}
	m := tokensvc.NewMetrics()
	m.Observe(2 * time.Millisecond)
	m.Observe(300 * time.Millisecond)
	m.Observe(time.Hour)
	m.Observe(-time.Second)
	h := m.Duration()
	if h.Count != 4 || len(h.Counts) != len(h.Bounds)+1 || h.Counts[0] != 2 || h.Counts[len(h.Counts)-1] != 1 {
		t.Errorf("histogram = %+v", h)
	}
}

func TestExchangeCountsEveryRefusal(t *testing.T) {
	m := tokensvc.NewMetrics()
	e := newSvcEnvWith(t, func(c *tokensvc.Config) { c.Metrics = m })
	ctx := context.Background()
	if _, err := e.svc.Exchange(ctx, e.req()); err != nil {
		t.Fatal(err)
	}
	// A forged agent id: the claimed id is never a label.
	forged := e.req()
	forged.ClientAssertion = e.sign(e.agent, e.claimsFor("ghost-agent"))
	_, err := e.svc.Exchange(ctx, forged)
	te := wantErr(t, err, tokensvc.CodeInvalidClient, tokensvc.ReasonAgentUnknown)
	if te.Verified {
		t.Error("a forged assertion is marked Verified")
	}
	for label := range m.IssuedSnapshot() {
		if strings.Contains(label, "ghost") {
			t.Errorf("claimed agent id %q became a metric label", label)
		}
	}
	if m.DeniedTotal(tokensvc.ReasonAgentUnknown) != 1 || m.IssuedTotal("agent-1") != 1 {
		t.Errorf("counters: agent_unknown %d issued %d", m.DeniedTotal(tokensvc.ReasonAgentUnknown), m.IssuedTotal("agent-1"))
	}
	if m.Duration().Count != 2 {
		t.Errorf("duration observations = %d, want 2", m.Duration().Count)
	}
}

// A denial whose record cannot be written is still a denial, and is logged
// once per reason per minute with the error's type and never its text.
func TestDeniedRecordFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	rec := &memRecorder{err: errors.New("disk-secret-text")}
	e := newSvcEnvWith(t, func(c *tokensvc.Config) {
		c.Recorder, c.Logger = rec, slog.New(slog.NewTextHandler(&buf, nil))
	})
	e.blocks.subs["user-1"] = true
	for i := 0; i < 3; i++ {
		_, err := e.svc.Exchange(context.Background(), e.req())
		wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonUserBlocked)
	}
	out := buf.String()
	if strings.Count(out, "token_event_record_failed") != 1 || !strings.Contains(out, "user_blocked") || strings.Contains(out, "disk-secret-text") {
		t.Fatalf("log = %q, want one warning with the reason and no error text", out)
	}
	e.now = e.now.Add(time.Minute)
	_, _ = e.svc.Exchange(context.Background(), e.req())
	if strings.Count(buf.String(), "token_event_record_failed") != 2 {
		t.Errorf("no new warning after a minute: %q", buf.String())
	}
}
