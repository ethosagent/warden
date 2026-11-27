// Package oauthbrokertest is the conformance suite every oauthbroker.GrantStore
// must pass: the SQLite store today, a Postgres store for p5-postgres-ha later.
package oauthbrokertest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/oauthbroker"
)

// Start is the fake clock's first instant in every subtest.
var Start = time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)

// Factory returns a new, empty store that reads time from clk and enforces
// limits (zero fields mean the defaults). Each subtest calls it once.
type Factory func(t *testing.T, clk *clocktest.Fake, limits oauthbroker.Limits) oauthbroker.GrantStore

// totalCap is the MaxLiveAttempts the AttemptLimitTotal subtest configures, so
// the global cap is exercised without ten thousand rows.
const totalCap = 45

const (
	iss      = "https://idp.example.test"
	ttl      = 15 * time.Minute
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
)

// Run exercises every GrantStore method against the contract.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	for _, tc := range []struct {
		name   string
		fn     func(*testing.T, context.Context, oauthbroker.GrantStore, *clocktest.Fake)
		limits oauthbroker.Limits
	}{
		{"PendingRoundTrip", pendingRoundTrip, oauthbroker.Limits{}},
		{"PendingValidation", pendingValidation, oauthbroker.Limits{}},
		{"PendingExpiresBeforeSweep", pendingExpiresBeforeSweep, oauthbroker.Limits{}},
		{"CompletePendingCompareAndSet", completePendingCAS, oauthbroker.Limits{}},
		{"CompletePendingConcurrentOneWins", completePendingConcurrent, oauthbroker.Limits{}},
		{"SubscribeClosesOnComplete", subscribeClosesOnComplete, oauthbroker.Limits{}},
		{"SubscribeTerminalOrUnknown", subscribeTerminalOrUnknown, oauthbroker.Limits{}},
		{"SubscribeCancel", subscribeCancel, oauthbroker.Limits{}},
		{"PendingLimitPerUser", pendingLimit, oauthbroker.Limits{}},
		{"PendingLimitConcurrent", pendingLimitConcurrent, oauthbroker.Limits{}},
		{"AttemptConsumedOnce", attemptConsumedOnce, oauthbroker.Limits{}},
		{"AttemptConsumeConcurrentOneWins", attemptConsumeConcurrent, oauthbroker.Limits{}},
		{"AttemptExpired", attemptExpired, oauthbroker.Limits{}},
		{"AttemptDuplicateAndValidation", attemptDuplicate, oauthbroker.Limits{}},
		{"AttemptLimitPerUser", attemptLimitPerUser, oauthbroker.Limits{}},
		{"AttemptLimitConcurrent", attemptLimitConcurrent, oauthbroker.Limits{}},
		{"AttemptLimitTotal", attemptLimitTotal, oauthbroker.Limits{MaxLiveAttempts: totalCap}},
		{"GrantReconnectKeepsOneRow", grantReconnect, oauthbroker.Limits{}},
		{"GrantActivateCompareAndSet", grantActivateCAS, oauthbroker.Limits{}},
		{"GrantRevokeIdempotent", grantRevoke, oauthbroker.Limits{}},
		{"GrantRevokeCompareAndSet", grantRevokeCAS, oauthbroker.Limits{}},
		{"GrantPrevGrantID", grantPrevGrantID, oauthbroker.Limits{}},
		{"GrantRestoreCompareAndSet", grantRestore, oauthbroker.Limits{}},
		{"GrantReconsentRequired", grantReconsent, oauthbroker.Limits{}},
		{"GrantListPerUser", grantList, oauthbroker.Limits{}},
		{"TouchLastUsedThrottled", touchLastUsed, oauthbroker.Limits{}},
		{"Sweep", sweep, oauthbroker.Limits{}},
		{"NoValueFields", noValueFields, oauthbroker.Limits{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := clocktest.NewFake(Start)
			tc.fn(t, context.Background(), newStore(t, clk, tc.limits), clk)
		})
	}
}

// UserKey derives a stand-in user key for sub (the suite needs no real
// secrets.UserKey, only distinct values).
func UserKey(sub string) string {
	sum := sha256.Sum256([]byte(iss + "\x00" + sub))
	return hex.EncodeToString(sum[:16])
}

// NewPending is a valid CreatePending input for sub.
func NewPending(sub, provider string, scopes ...string) oauthbroker.Pending {
	return oauthbroker.Pending{
		Iss: iss, Sub: sub, UserKey: UserKey(sub), AgentID: "agent-a", Provider: provider,
		Scopes: scopes, Message: "agent-a needs Google Drive",
		Request: oauthbroker.RequestInfo{Method: "GET", Host: "www.googleapis.com", Path: "/drive/v3/files", MCPTool: "drive.list"},
	}
}

// NewAttempt is a valid CreateAttempt input for sub with a state derived from n.
func NewAttempt(sub, provider, pendingID string, n int) oauthbroker.Attempt {
	return oauthbroker.Attempt{
		StateHash: oauthbroker.HashState(fmt.Sprintf("state-%s-%d", sub, n)),
		PendingID: pendingID, Iss: iss, Sub: sub, UserKey: UserKey(sub), Provider: provider,
		Scopes: []string{"openid", "email"}, Verifier: verifier,
		BrowserHash: oauthbroker.HashBrowserBinding(fmt.Sprintf("cookie-%d", n)),
	}
}

func ref(sub, provider string) oauthbroker.GrantRef {
	return oauthbroker.GrantRef{UserKey: UserKey(sub), Iss: iss, Sub: sub, Provider: provider}
}

func mustPending(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, p oauthbroker.Pending) oauthbroker.Pending {
	t.Helper()
	got, err := s.CreatePending(ctx, p, ttl)
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	return got
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

var base64URLID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

func pendingRoundTrip(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	in := NewPending("alice", "google", "drive.readonly", "email", "drive.readonly", "")
	got := mustPending(t, ctx, s, in)
	if !base64URLID.MatchString(got.ID) {
		t.Fatalf("id %q is not 16 random bytes base64url", got.ID)
	}
	if got.Status != oauthbroker.StatusPending || !got.CreatedAt.Equal(Start) || !got.ExpiresAt.Equal(Start.Add(ttl)) || !got.CompletedAt.IsZero() {
		t.Fatalf("created pending = %+v", got)
	}
	if want := []string{"drive.readonly", "email"}; !slices.Equal(got.Scopes, want) {
		t.Fatalf("scopes = %v, want canonical %v", got.Scopes, want)
	}
	read, err := s.GetPending(ctx, got.ID)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if !reflect.DeepEqual(read, got) {
		t.Fatalf("GetPending = %+v\nwant        %+v", read, got)
	}
	if read.Request != in.Request || read.AgentID != in.AgentID || read.Message != in.Message || read.UserKey != in.UserKey {
		t.Fatalf("optional columns lost: %+v", read)
	}
	other := mustPending(t, ctx, s, oauthbroker.Pending{Iss: iss, Sub: "bob", UserKey: UserKey("bob"), Provider: "github"})
	if other.AgentID != "" || other.Request != (oauthbroker.RequestInfo{}) || other.Scopes == nil || len(other.Scopes) != 0 {
		t.Fatalf("portal pending without optional fields = %+v", other)
	}
	if other.ID == got.ID {
		t.Fatal("two pendings share an id")
	}
	_, err = s.GetPending(ctx, "no-such-id")
	wantErr(t, "GetPending(unknown)", err, oauthbroker.ErrNotFound)
}

func pendingValidation(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	good := NewPending("alice", "google")
	for name, mut := range map[string]func(*oauthbroker.Pending){
		"no iss":       func(p *oauthbroker.Pending) { p.Iss = "" },
		"no sub":       func(p *oauthbroker.Pending) { p.Sub = "" },
		"no user_key":  func(p *oauthbroker.Pending) { p.UserKey = "" },
		"no provider":  func(p *oauthbroker.Pending) { p.Provider = "" },
		"query":        func(p *oauthbroker.Pending) { p.Request.Path = "/a?token=x" },
		"scope space":  func(p *oauthbroker.Pending) { p.Scopes = []string{"a b"} },
		"long message": func(p *oauthbroker.Pending) { p.Message = strings.Repeat("m", 2000) },
	} {
		p := good
		mut(&p)
		_, err := s.CreatePending(ctx, p, ttl)
		wantErr(t, name, err, oauthbroker.ErrInvalid)
	}
	_, err := s.CreatePending(ctx, good, 0)
	wantErr(t, "zero ttl", err, oauthbroker.ErrInvalid)
}

func pendingExpiresBeforeSweep(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	p := mustPending(t, ctx, s, NewPending("alice", "google"))
	clk.Advance(ttl)
	got, err := s.GetPending(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if got.Status != oauthbroker.StatusExpired {
		t.Fatalf("status at expires_at = %s, want expired before any sweep", got.Status)
	}
	wantErr(t, "CompletePending after expiry", s.CompletePending(ctx, p.ID, oauthbroker.StatusGranted, ""), oauthbroker.ErrNotPending)
}

func completePendingCAS(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	p := mustPending(t, ctx, s, NewPending("alice", "google"))
	wantErr(t, "complete with pending", s.CompletePending(ctx, p.ID, oauthbroker.StatusPending, ""), oauthbroker.ErrInvalid)
	clk.Advance(time.Second)
	if err := s.CompletePending(ctx, p.ID, oauthbroker.StatusDenied, "insufficient_scope"); err != nil {
		t.Fatalf("CompletePending: %v", err)
	}
	got, err := s.GetPending(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if got.Status != oauthbroker.StatusDenied || got.Reason != "insufficient_scope" || !got.CompletedAt.Equal(Start.Add(time.Second)) {
		t.Fatalf("completed pending = %+v", got)
	}
	wantErr(t, "second complete", s.CompletePending(ctx, p.ID, oauthbroker.StatusGranted, ""), oauthbroker.ErrNotPending)
	wantErr(t, "unknown id", s.CompletePending(ctx, "no-such-id", oauthbroker.StatusGranted, ""), oauthbroker.ErrNotFound)
}

func completePendingConcurrent(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	for round := range 10 {
		p := mustPending(t, ctx, s, NewPending(fmt.Sprintf("user-%d", round), "google"))
		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				st := oauthbroker.StatusGranted
				if i%2 == 1 {
					st = oauthbroker.StatusDenied
				}
				errs[i] = s.CompletePending(ctx, p.ID, st, "")
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, oauthbroker.ErrNotPending):
				t.Fatalf("loser err = %v, want ErrNotPending", err)
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: %d CompletePending calls succeeded, want exactly 1", round, wins)
		}
	}
}

// Received waits up to 1s for ch to deliver a status and close.
func Received(t *testing.T, ch <-chan oauthbroker.PendingStatus) oauthbroker.PendingStatus {
	t.Helper()
	timeout := time.After(time.Second)
	var got oauthbroker.PendingStatus
	for {
		select {
		case st, ok := <-ch:
			if !ok {
				return got
			}
			got = st
		case <-timeout:
			t.Fatal("subscription channel not closed within 1s")
		}
	}
}

func subscribeClosesOnComplete(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	p := mustPending(t, ctx, s, NewPending("alice", "google"))
	ch1, cancel1 := s.Subscribe(p.ID)
	defer cancel1()
	ch2, cancel2 := s.Subscribe(p.ID)
	defer cancel2()
	select {
	case <-ch1:
		t.Fatal("channel fired before completion")
	default:
	}
	if err := s.CompletePending(ctx, p.ID, oauthbroker.StatusGranted, ""); err != nil {
		t.Fatalf("CompletePending: %v", err)
	}
	if got := Received(t, ch1); got != oauthbroker.StatusGranted {
		t.Fatalf("waiter 1 got %q, want granted", got)
	}
	if got := Received(t, ch2); got != oauthbroker.StatusGranted {
		t.Fatalf("waiter 2 got %q, want granted", got)
	}
}

func subscribeTerminalOrUnknown(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	p := mustPending(t, ctx, s, NewPending("alice", "google"))
	if err := s.CompletePending(ctx, p.ID, oauthbroker.StatusDenied, "access_denied"); err != nil {
		t.Fatalf("CompletePending: %v", err)
	}
	ch, cancel := s.Subscribe(p.ID)
	cancel()
	if got := Received(t, ch); got != oauthbroker.StatusDenied {
		t.Fatalf("subscribe after completion got %q, want denied", got)
	}
	ch, cancel = s.Subscribe("no-such-id")
	cancel()
	if got := Received(t, ch); got != "" {
		t.Fatalf("subscribe to unknown id got %q, want a closed empty channel", got)
	}
	q := mustPending(t, ctx, s, NewPending("bob", "google"))
	clk.Advance(ttl)
	ch, cancel = s.Subscribe(q.ID)
	defer cancel()
	if got := Received(t, ch); got != oauthbroker.StatusExpired {
		t.Fatalf("subscribe after expires_at got %q, want expired", got)
	}
}

func subscribeCancel(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	p := mustPending(t, ctx, s, NewPending("alice", "google"))
	ch, cancel := s.Subscribe(p.ID)
	cancel()
	cancel() // idempotent
	if err := s.CompletePending(ctx, p.ID, oauthbroker.StatusGranted, ""); err != nil {
		t.Fatalf("CompletePending: %v", err)
	}
	select {
	case st, ok := <-ch:
		t.Fatalf("cancelled waiter received %q (open=%v)", st, ok)
	case <-time.After(50 * time.Millisecond):
	}
}

func pendingLimit(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	var first oauthbroker.Pending
	for i := range oauthbroker.MaxOpenPendingsPerUser {
		p := mustPending(t, ctx, s, NewPending("alice", "google"))
		if i == 0 {
			first = p
		}
	}
	_, err := s.CreatePending(ctx, NewPending("alice", "github"), ttl)
	wantErr(t, "21st open pending", err, oauthbroker.ErrTooMany)
	mustPending(t, ctx, s, NewPending("bob", "google")) // another user is unaffected
	if err := s.CompletePending(ctx, first.ID, oauthbroker.StatusGranted, ""); err != nil {
		t.Fatalf("CompletePending: %v", err)
	}
	mustPending(t, ctx, s, NewPending("alice", "google")) // a completed pending frees a slot
	_, err = s.CreatePending(ctx, NewPending("alice", "google"), ttl)
	wantErr(t, "full again", err, oauthbroker.ErrTooMany)
	clk.Advance(ttl)
	mustPending(t, ctx, s, NewPending("alice", "google")) // expired pendings do not count
}

// concurrentCreates runs n creates at once and returns how many succeeded;
// every failure must be ErrTooMany.
func concurrentCreates(t *testing.T, n int, create func(i int) error) int {
	t.Helper()
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = create(i)
		}()
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, oauthbroker.ErrTooMany):
			t.Fatalf("create err = %v, want nil or ErrTooMany", err)
		}
	}
	return ok
}

func pendingLimitConcurrent(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	limit := oauthbroker.MaxOpenPendingsPerUser
	ok := concurrentCreates(t, limit+5, func(int) error {
		_, err := s.CreatePending(ctx, NewPending("alice", "google"), ttl)
		return err
	})
	if ok != limit {
		t.Fatalf("%d of %d concurrent CreatePending succeeded, want exactly %d", ok, limit+5, limit)
	}
}

func attemptLimitConcurrent(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	limit := oauthbroker.MaxOpenAttemptsPerUser
	ok := concurrentCreates(t, limit+5, func(i int) error {
		_, err := s.CreateAttempt(ctx, NewAttempt("alice", "google", "", i))
		return err
	})
	if ok != limit {
		t.Fatalf("%d of %d concurrent CreateAttempt succeeded, want exactly %d", ok, limit+5, limit)
	}
}

func attemptConsumedOnce(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	in := NewAttempt("alice", "google", "pend-1", 1)
	created, err := s.CreateAttempt(ctx, in)
	if err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}
	if !created.CreatedAt.Equal(Start) || !created.ExpiresAt.Equal(Start.Add(oauthbroker.AttemptTTL)) {
		t.Fatalf("created attempt times = %v, %v", created.CreatedAt, created.ExpiresAt)
	}
	got, err := s.ConsumeAttempt(ctx, in.StateHash)
	if err != nil {
		t.Fatalf("ConsumeAttempt: %v", err)
	}
	if !reflect.DeepEqual(got, created) {
		t.Fatalf("consumed %+v\nwant     %+v", got, created)
	}
	if got.Verifier != verifier || got.BrowserHash != in.BrowserHash || got.PendingID != "pend-1" {
		t.Fatalf("consumed attempt lost fields: pending=%q", got.PendingID)
	}
	_, err = s.ConsumeAttempt(ctx, in.StateHash)
	wantErr(t, "second ConsumeAttempt", err, oauthbroker.ErrNotFound)
	_, err = s.ConsumeAttempt(ctx, oauthbroker.HashState("never-stored"))
	wantErr(t, "unknown state", err, oauthbroker.ErrNotFound)

	portal := NewAttempt("alice", "github", "", 2)
	if _, err := s.CreateAttempt(ctx, portal); err != nil {
		t.Fatalf("CreateAttempt(no pending): %v", err)
	}
	got, err = s.ConsumeAttempt(ctx, portal.StateHash)
	if err != nil || got.PendingID != "" {
		t.Fatalf("ConsumeAttempt(no pending) = %q, %v", got.PendingID, err)
	}
}

func attemptConsumeConcurrent(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	a := NewAttempt("alice", "google", "", 1)
	if _, err := s.CreateAttempt(ctx, a); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = s.ConsumeAttempt(ctx, a.StateHash)
		}()
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, oauthbroker.ErrNotFound):
			t.Fatalf("loser err = %v, want ErrNotFound", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d ConsumeAttempt calls succeeded, want exactly 1", wins)
	}
}

func attemptExpired(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	a := NewAttempt("alice", "google", "", 1)
	if _, err := s.CreateAttempt(ctx, a); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}
	clk.Advance(oauthbroker.AttemptTTL)
	_, err := s.ConsumeAttempt(ctx, a.StateHash)
	wantErr(t, "ConsumeAttempt at expires_at", err, oauthbroker.ErrNotFound)
}

func attemptDuplicate(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	a := NewAttempt("alice", "google", "", 1)
	if _, err := s.CreateAttempt(ctx, a); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}
	_, err := s.CreateAttempt(ctx, a)
	wantErr(t, "duplicate state hash", err, oauthbroker.ErrExists)
	for name, mut := range map[string]func(*oauthbroker.Attempt){
		"raw state":      func(a *oauthbroker.Attempt) { a.StateHash = "raw-state-value" },
		"upper hex":      func(a *oauthbroker.Attempt) { a.StateHash = strings.ToUpper(a.StateHash) },
		"browser hash":   func(a *oauthbroker.Attempt) { a.BrowserHash = "cookie" },
		"short verifier": func(a *oauthbroker.Attempt) { a.Verifier = "short" },
		"no user_key":    func(a *oauthbroker.Attempt) { a.UserKey = "" },
	} {
		b := NewAttempt("alice", "google", "", 2)
		mut(&b)
		_, err := s.CreateAttempt(ctx, b)
		wantErr(t, name, err, oauthbroker.ErrInvalid)
	}
}

func attemptLimitPerUser(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	for i := range oauthbroker.MaxOpenAttemptsPerUser {
		if _, err := s.CreateAttempt(ctx, NewAttempt("alice", "google", "", i)); err != nil {
			t.Fatalf("CreateAttempt %d: %v", i, err)
		}
	}
	_, err := s.CreateAttempt(ctx, NewAttempt("alice", "google", "", 100))
	wantErr(t, "21st open attempt", err, oauthbroker.ErrTooMany)
	if _, err := s.CreateAttempt(ctx, NewAttempt("bob", "google", "", 100)); err != nil {
		t.Fatalf("another user: %v", err)
	}
	if _, err := s.ConsumeAttempt(ctx, NewAttempt("alice", "google", "", 0).StateHash); err != nil {
		t.Fatalf("ConsumeAttempt: %v", err)
	}
	if _, err := s.CreateAttempt(ctx, NewAttempt("alice", "google", "", 101)); err != nil {
		t.Fatalf("after a consume: %v", err)
	}
	clk.Advance(oauthbroker.AttemptTTL)
	if _, err := s.CreateAttempt(ctx, NewAttempt("alice", "google", "", 102)); err != nil {
		t.Fatalf("expired attempts must not count: %v", err)
	}
}

func attemptLimitTotal(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	per := oauthbroker.MaxOpenAttemptsPerUser
	for i := range totalCap {
		sub := fmt.Sprintf("u%d", i/per)
		if _, err := s.CreateAttempt(ctx, NewAttempt(sub, "google", "", i)); err != nil {
			t.Fatalf("CreateAttempt %d: %v", i, err)
		}
	}
	_, err := s.CreateAttempt(ctx, NewAttempt("fresh-user", "google", "", 0))
	wantErr(t, "attempt past the global cap", err, oauthbroker.ErrTooMany)
	if _, err := s.ConsumeAttempt(ctx, NewAttempt("u0", "google", "", 0).StateHash); err != nil {
		t.Fatalf("ConsumeAttempt: %v", err)
	}
	if _, err := s.CreateAttempt(ctx, NewAttempt("fresh-user", "google", "", 0)); err != nil {
		t.Fatalf("a consumed attempt frees a global slot: %v", err)
	}
}

func grantReconnect(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	g1, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if g1.State != oauthbroker.GrantConnecting || !base64URLID.MatchString(g1.GrantID) || len(g1.Scopes) != 0 {
		t.Fatalf("begun grant = %+v", g1)
	}
	clk.Advance(time.Second)
	a1, err := s.ActivateGrant(ctx, g1.GrantID, []string{"email", "drive.readonly"}, oauthbroker.Account{ID: "1234", Login: "alice@example.com"})
	if err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}
	if a1.State != oauthbroker.GrantActive || !slices.Equal(a1.Scopes, []string{"drive.readonly", "email"}) ||
		a1.Account.Login != "alice@example.com" || !a1.GrantedAt.Equal(Start.Add(time.Second)) {
		t.Fatalf("activated grant = %+v", a1)
	}

	clk.Advance(time.Minute)
	g2, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant (reconnect): %v", err)
	}
	if g2.GrantID == g1.GrantID || g2.State != oauthbroker.GrantConnecting {
		t.Fatalf("reconnect grant = %+v, want a new grant_id in connecting", g2)
	}
	if !slices.Equal(g2.Scopes, a1.Scopes) || g2.Account != a1.Account {
		t.Fatalf("reconnect dropped the earlier scopes or account: %+v", g2)
	}
	_, err = s.ActivateGrant(ctx, g1.GrantID, []string{"email"}, oauthbroker.Account{})
	wantErr(t, "activate the replaced grant id", err, oauthbroker.ErrNotFound)
	clk.Advance(time.Minute)
	a2, err := s.ActivateGrant(ctx, g2.GrantID, []string{"email", "drive.readonly", "calendar"}, oauthbroker.Account{ID: "1234", Login: "alice@example.com"})
	if err != nil {
		t.Fatalf("ActivateGrant (reconnect): %v", err)
	}
	if !a2.UpdatedAt.After(a1.UpdatedAt) || a2.GrantID != g2.GrantID || len(a2.Scopes) != 3 {
		t.Fatalf("reconnected grant = %+v, want advanced updated_at and the new id", a2)
	}
	all, err := s.ListGrants(ctx, UserKey("alice"), true)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(all) != 1 || !reflect.DeepEqual(all[0], a2) {
		t.Fatalf("ListGrants = %+v, want exactly the reconnected row", all)
	}
	got, err := s.GetGrant(ctx, UserKey("alice"), "google")
	if err != nil || !reflect.DeepEqual(got, a2) {
		t.Fatalf("GetGrant = %+v, %v", got, err)
	}
}

func grantActivateCAS(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	g, err := s.BeginGrant(ctx, ref("alice", "github"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if _, err := s.ActivateGrant(ctx, g.GrantID, []string{"repo"}, oauthbroker.Account{}); err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}
	_, err = s.ActivateGrant(ctx, g.GrantID, []string{"repo"}, oauthbroker.Account{})
	wantErr(t, "activate an active grant", err, oauthbroker.ErrGrantState)
	_, err = s.ActivateGrant(ctx, "no-such-grant", nil, oauthbroker.Account{})
	wantErr(t, "activate unknown", err, oauthbroker.ErrNotFound)
	_, err = s.BeginGrant(ctx, oauthbroker.GrantRef{UserKey: UserKey("alice"), Iss: iss, Sub: "alice"})
	wantErr(t, "begin without provider", err, oauthbroker.ErrInvalid)
	_, err = s.GetGrant(ctx, UserKey("alice"), "google")
	wantErr(t, "GetGrant unknown", err, oauthbroker.ErrNotFound)
}

func grantRevoke(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	_, err := s.RevokeGrant(ctx, UserKey("alice"), "google", "")
	wantErr(t, "revoke with no row", err, oauthbroker.ErrNotFound)
	g, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if _, err := s.ActivateGrant(ctx, g.GrantID, []string{"email"}, oauthbroker.Account{}); err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}
	clk.Advance(time.Second)
	r1, err := s.RevokeGrant(ctx, UserKey("alice"), "google", "")
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if r1.State != oauthbroker.GrantRevoked || !r1.RevokedAt.Equal(Start.Add(time.Second)) {
		t.Fatalf("revoked grant = %+v", r1)
	}
	clk.Advance(time.Second)
	r2, err := s.RevokeGrant(ctx, UserKey("alice"), "google", "")
	if err != nil {
		t.Fatalf("second RevokeGrant: %v", err)
	}
	if !reflect.DeepEqual(r2, r1) {
		t.Fatalf("second revoke changed the row: %+v, want %+v", r2, r1)
	}
	live, err := s.ListGrants(ctx, UserKey("alice"), false)
	if err != nil || len(live) != 0 {
		t.Fatalf("ListGrants without revoked = %+v, %v", live, err)
	}
	_, err = s.ActivateGrant(ctx, g.GrantID, []string{"email"}, oauthbroker.Account{})
	wantErr(t, "activate a revoked grant", err, oauthbroker.ErrGrantState)

	g3, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant after revoke: %v", err)
	}
	if g3.State != oauthbroker.GrantConnecting || !g3.RevokedAt.IsZero() {
		t.Fatalf("reconnect after revoke = %+v, want connecting with revoked_at cleared", g3)
	}
	// A revoke while connecting also counts (the reconciler and offboarding).
	if _, err := s.RevokeGrant(ctx, UserKey("alice"), "google", ""); err != nil {
		t.Fatalf("RevokeGrant(connecting): %v", err)
	}
	_, err = s.ActivateGrant(ctx, g3.GrantID, []string{"email"}, oauthbroker.Account{})
	wantErr(t, "activate after a revoke during connect", err, oauthbroker.ErrGrantState)
}

func grantRevokeCAS(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	uk := UserKey("alice")
	_, err := s.RevokeGrant(ctx, uk, "google", "any-id")
	wantErr(t, "CAS revoke with no row", err, oauthbroker.ErrNotFound)
	old, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if _, err := s.ActivateGrant(ctx, old.GrantID, []string{"email"}, oauthbroker.Account{}); err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}
	// A reconnect replaces the grant id; a reconciler holding the old id loses.
	cur, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant (reconnect): %v", err)
	}
	_, err = s.RevokeGrant(ctx, uk, "google", old.GrantID)
	wantErr(t, "revoke with a replaced grant id", err, oauthbroker.ErrGrantState)
	if got, _ := s.GetGrant(ctx, uk, "google"); got.State != oauthbroker.GrantConnecting || got.GrantID != cur.GrantID {
		t.Fatalf("a mismatched revoke changed the row: %+v", got)
	}
	// The matching id revokes, and repeating it is idempotent.
	r, err := s.RevokeGrant(ctx, uk, "google", cur.GrantID)
	if err != nil || r.State != oauthbroker.GrantRevoked || r.GrantID != cur.GrantID {
		t.Fatalf("revoke with the current id = %+v, %v", r, err)
	}
	if _, err := s.RevokeGrant(ctx, uk, "google", cur.GrantID); err != nil {
		t.Fatalf("repeat CAS revoke: %v", err)
	}
	_, err = s.RevokeGrant(ctx, uk, "google", old.GrantID)
	wantErr(t, "revoke a revoked grant with another id", err, oauthbroker.ErrGrantState)
	// "" revokes whatever grant the row holds.
	next, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant after revoke: %v", err)
	}
	r, err = s.RevokeGrant(ctx, uk, "google", "")
	if err != nil || r.State != oauthbroker.GrantRevoked || r.GrantID != next.GrantID {
		t.Fatalf("revoke with \"\" = %+v, %v", r, err)
	}
}

func grantPrevGrantID(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	uk := UserKey("alice")
	first, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if first.PrevGrantID != "" {
		t.Fatalf("a new row has prev_grant_id %q", first.PrevGrantID)
	}
	// Reconnect over connecting: nothing working was replaced.
	again, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil || again.PrevGrantID != "" {
		t.Fatalf("reconnect over connecting = %+v, %v; want empty prev_grant_id", again, err)
	}
	active, err := s.ActivateGrant(ctx, again.GrantID, []string{"email"}, oauthbroker.Account{})
	if err != nil || active.PrevGrantID != "" {
		t.Fatalf("ActivateGrant = %+v, %v", active, err)
	}
	// Reconnect over active records the replaced id ...
	re, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil || re.PrevGrantID != active.GrantID {
		t.Fatalf("reconnect over active = %+v, %v; want prev_grant_id %s", re, err, active.GrantID)
	}
	if got, _ := s.GetGrant(ctx, uk, "google"); got.PrevGrantID != active.GrantID {
		t.Fatalf("GetGrant prev_grant_id = %q", got.PrevGrantID)
	}
	// ... and a second Begin before the callback keeps it (the replaced
	// working grant is still the one to restore).
	re2, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil || re2.PrevGrantID != active.GrantID {
		t.Fatalf("second reconnect = %+v, %v; want prev_grant_id kept", re2, err)
	}
	// Activation clears it.
	done, err := s.ActivateGrant(ctx, re2.GrantID, []string{"email"}, oauthbroker.Account{})
	if err != nil || done.PrevGrantID != "" {
		t.Fatalf("ActivateGrant after reconnect = %+v, %v; want prev_grant_id cleared", done, err)
	}
	// Reconnect over reconsent_required or revoked: nothing working to restore.
	if _, err := s.MarkReconsentRequired(ctx, uk, "google", done.GrantID); err != nil {
		t.Fatalf("MarkReconsentRequired: %v", err)
	}
	rc, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil || rc.PrevGrantID != "" {
		t.Fatalf("reconnect over reconsent_required = %+v, %v", rc, err)
	}
	rb, err := s.BeginGrant(ctx, ref("alice", "github"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateGrant(ctx, rb.GrantID, nil, oauthbroker.Account{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginGrant(ctx, ref("alice", "github")); err != nil {
		t.Fatal(err)
	}
	rv, err := s.RevokeGrant(ctx, uk, "github", "")
	if err != nil || rv.PrevGrantID != "" {
		t.Fatalf("revoke = %+v, %v; want prev_grant_id cleared", rv, err)
	}
	after, err := s.BeginGrant(ctx, ref("alice", "github"))
	if err != nil || after.PrevGrantID != "" {
		t.Fatalf("reconnect over revoked = %+v, %v", after, err)
	}
}

func grantRestore(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	uk := UserKey("alice")
	if _, err := s.RestoreGrant(ctx, uk, "google", "a", "b"); !errors.Is(err, oauthbroker.ErrNotFound) {
		t.Fatalf("RestoreGrant with no row = %v, want ErrNotFound", err)
	}
	first, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatal(err)
	}
	// A first connect has nothing to restore.
	if _, err := s.RestoreGrant(ctx, uk, "google", first.GrantID, "x"); !errors.Is(err, oauthbroker.ErrGrantState) {
		t.Fatalf("RestoreGrant of a first connect = %v, want ErrGrantState", err)
	}
	active, err := s.ActivateGrant(ctx, first.GrantID, []string{"email"}, oauthbroker.Account{ID: "acct", Login: "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	re, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil || re.PrevGrantID != active.GrantID {
		t.Fatalf("reconnect = %+v, %v", re, err)
	}
	// Wrong ids change nothing.
	for _, ids := range [][2]string{{"other", active.GrantID}, {re.GrantID, "other"}} {
		if _, err := s.RestoreGrant(ctx, uk, "google", ids[0], ids[1]); !errors.Is(err, oauthbroker.ErrGrantState) {
			t.Fatalf("RestoreGrant(%v) = %v, want ErrGrantState", ids, err)
		}
	}
	if _, err := s.RestoreGrant(ctx, uk, "google", "", ""); !errors.Is(err, oauthbroker.ErrInvalid) {
		t.Fatalf("RestoreGrant with empty ids = %v, want ErrInvalid", err)
	}
	got, err := s.RestoreGrant(ctx, uk, "google", re.GrantID, active.GrantID)
	if err != nil {
		t.Fatalf("RestoreGrant: %v", err)
	}
	if got.State != oauthbroker.GrantActive || got.GrantID != active.GrantID || got.PrevGrantID != "" ||
		!slices.Equal(got.Scopes, []string{"email"}) || got.Account.ID != "acct" {
		t.Fatalf("restored grant = %+v, want the earlier active grant back with its scopes and account", got)
	}
	// The failed attempt's id is dead: it cannot activate, and a second
	// restore is a state error.
	if _, err := s.ActivateGrant(ctx, re.GrantID, nil, oauthbroker.Account{}); !errors.Is(err, oauthbroker.ErrNotFound) {
		t.Fatalf("ActivateGrant of the abandoned id = %v, want ErrNotFound", err)
	}
	if _, err := s.RestoreGrant(ctx, uk, "google", re.GrantID, active.GrantID); !errors.Is(err, oauthbroker.ErrGrantState) {
		t.Fatalf("second RestoreGrant = %v, want ErrGrantState", err)
	}
}

func grantReconsent(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	uk := UserKey("alice")
	_, err := s.MarkReconsentRequired(ctx, uk, "google", "x")
	wantErr(t, "mark with no row", err, oauthbroker.ErrNotFound)
	g, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	_, err = s.MarkReconsentRequired(ctx, uk, "google", g.GrantID)
	wantErr(t, "mark a connecting grant", err, oauthbroker.ErrGrantState)
	if _, err := s.ActivateGrant(ctx, g.GrantID, []string{"email"}, oauthbroker.Account{}); err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}
	_, err = s.MarkReconsentRequired(ctx, uk, "google", "stale-grant-id")
	wantErr(t, "mark with a stale grant id", err, oauthbroker.ErrGrantState)
	got, err := s.MarkReconsentRequired(ctx, uk, "google", g.GrantID)
	if err != nil || got.State != oauthbroker.GrantReconsentRequired {
		t.Fatalf("MarkReconsentRequired = %+v, %v", got, err)
	}
	if _, err := s.MarkReconsentRequired(ctx, uk, "google", g.GrantID); err != nil {
		t.Fatalf("second MarkReconsentRequired: %v", err)
	}
	if _, err := s.RevokeGrant(ctx, uk, "google", ""); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	_, err = s.MarkReconsentRequired(ctx, uk, "google", g.GrantID)
	wantErr(t, "mark a revoked grant", err, oauthbroker.ErrGrantState)
}

func grantList(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	for _, p := range []string{"github", "google", "atlassian"} {
		if _, err := s.BeginGrant(ctx, ref("alice", p)); err != nil {
			t.Fatalf("BeginGrant(%s): %v", p, err)
		}
	}
	if _, err := s.BeginGrant(ctx, ref("bob", "google")); err != nil {
		t.Fatalf("BeginGrant(bob): %v", err)
	}
	if _, err := s.RevokeGrant(ctx, UserKey("alice"), "github", ""); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	names := func(gs []oauthbroker.Grant) []string {
		var out []string
		for _, g := range gs {
			if g.UserKey != UserKey("alice") {
				t.Fatalf("ListGrants(alice) returned %s's row", g.Sub)
			}
			out = append(out, g.Provider)
		}
		return out
	}
	all, err := s.ListGrants(ctx, UserKey("alice"), true)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if got := names(all); !slices.Equal(got, []string{"atlassian", "github", "google"}) {
		t.Fatalf("ListGrants(all) = %v", got)
	}
	live, err := s.ListGrants(ctx, UserKey("alice"), false)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if got := names(live); !slices.Equal(got, []string{"atlassian", "google"}) {
		t.Fatalf("ListGrants(live) = %v", got)
	}
	none, err := s.ListGrants(ctx, UserKey("nobody"), true)
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("ListGrants(nobody) = %#v, %v; want an empty non-nil slice", none, err)
	}
}

func touchLastUsed(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, _ *clocktest.Fake) {
	uk := UserKey("alice")
	if err := s.TouchLastUsed(ctx, uk, "google", Start); err != nil {
		t.Fatalf("TouchLastUsed with no row: %v", err)
	}
	g, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if err := s.TouchLastUsed(ctx, uk, "google", Start); err != nil {
		t.Fatalf("TouchLastUsed(connecting): %v", err)
	}
	if got, _ := s.GetGrant(ctx, uk, "google"); !got.LastUsedAt.IsZero() {
		t.Fatalf("a connecting grant was touched: %v", got.LastUsedAt)
	}
	if _, err := s.ActivateGrant(ctx, g.GrantID, []string{"email"}, oauthbroker.Account{}); err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}
	last := func() time.Time {
		t.Helper()
		got, err := s.GetGrant(ctx, uk, "google")
		if err != nil {
			t.Fatalf("GetGrant: %v", err)
		}
		return got.LastUsedAt
	}
	t0 := Start.Add(time.Hour)
	for _, step := range []struct {
		at   time.Time
		want time.Time
	}{
		{t0, t0},                                   // first use writes
		{t0.Add(30 * time.Second), t0},             // within a minute: no write
		{t0.Add(59 * time.Second), t0},             // still within
		{t0.Add(time.Minute), t0.Add(time.Minute)}, // a minute later: writes
		{t0.Add(-time.Hour), t0.Add(time.Minute)},  // never backward
		{t0.Add(3 * time.Minute), t0.Add(3 * time.Minute)},
	} {
		if err := s.TouchLastUsed(ctx, uk, "google", step.at); err != nil {
			t.Fatalf("TouchLastUsed(%v): %v", step.at, err)
		}
		if got := last(); !got.Equal(step.want) {
			t.Fatalf("after touch at %v: last_used_at = %v, want %v", step.at, got, step.want)
		}
	}
}

func sweep(t *testing.T, ctx context.Context, s oauthbroker.GrantStore, clk *clocktest.Fake) {
	// Attempts: one expires, one stays.
	old := NewAttempt("alice", "google", "", 1)
	if _, err := s.CreateAttempt(ctx, old); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}
	// Pendings: one to expire, one completed long ago, one open.
	expiring := mustPending(t, ctx, s, NewPending("alice", "google"))
	done := mustPending(t, ctx, s, NewPending("alice", "github"))
	if err := s.CompletePending(ctx, done.ID, oauthbroker.StatusGranted, ""); err != nil {
		t.Fatalf("CompletePending: %v", err)
	}
	// Grants: one stuck connecting, one active.
	stuck, err := s.BeginGrant(ctx, ref("alice", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	active, err := s.BeginGrant(ctx, ref("bob", "google"))
	if err != nil {
		t.Fatalf("BeginGrant: %v", err)
	}
	if _, err := s.ActivateGrant(ctx, active.GrantID, []string{"email"}, oauthbroker.Account{}); err != nil {
		t.Fatalf("ActivateGrant: %v", err)
	}

	res, err := s.Sweep(ctx, clk.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.AttemptsDeleted != 0 || res.PendingsExpired != 0 || res.PendingsDeleted != 0 || len(res.StaleConnecting) != 0 {
		t.Fatalf("early sweep changed things: %+v", res)
	}

	ch, cancel := s.Subscribe(expiring.ID)
	defer cancel()
	clk.Advance(ttl)
	fresh := NewAttempt("bob", "google", "", 2)
	if _, err := s.CreateAttempt(ctx, fresh); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}
	open := mustPending(t, ctx, s, NewPending("bob", "google"))
	res, err = s.Sweep(ctx, clk.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.AttemptsDeleted != 1 || res.PendingsExpired != 1 || res.PendingsDeleted != 0 {
		t.Fatalf("sweep = %+v, want 1 attempt deleted and 1 pending expired", res)
	}
	if len(res.StaleConnecting) != 1 || res.StaleConnecting[0].GrantID != stuck.GrantID {
		t.Fatalf("stale connecting = %+v, want only %s", res.StaleConnecting, stuck.GrantID)
	}
	if got := Received(t, ch); got != oauthbroker.StatusExpired {
		t.Fatalf("waiter got %q, want expired", got)
	}
	got, err := s.GetPending(ctx, expiring.ID)
	if err != nil || got.Status != oauthbroker.StatusExpired || got.Reason != oauthbroker.ReasonExpired || got.CompletedAt.IsZero() {
		t.Fatalf("swept pending = %+v, %v", got, err)
	}
	if _, err := s.ConsumeAttempt(ctx, fresh.StateHash); err != nil {
		t.Fatalf("a live attempt was swept: %v", err)
	}
	if got, err := s.GetPending(ctx, open.ID); err != nil || got.Status != oauthbroker.StatusPending {
		t.Fatalf("open pending after sweep = %+v, %v", got, err)
	}

	clk.Advance(oauthbroker.TerminalPendingRetention)
	res, err = s.Sweep(ctx, clk.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	// done and expiring are past retention; open expired in this pass and is kept.
	if res.PendingsDeleted != 2 || res.PendingsExpired != 1 {
		t.Fatalf("retention sweep = %+v, want 2 deleted and 1 expired", res)
	}
	for _, id := range []string{done.ID, expiring.ID} {
		_, err := s.GetPending(ctx, id)
		wantErr(t, "pending past retention", err, oauthbroker.ErrNotFound)
	}
}

// valueWords are the names a field or column holding a credential would carry.
var valueWords = []string{"token", "secret", "value", "password", "credential"}

// NamesValue reports whether name looks like a credential-bearing field.
func NamesValue(name string) bool {
	l := strings.ToLower(name)
	for _, w := range valueWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func noValueFields(t *testing.T, _ context.Context, _ oauthbroker.GrantStore, _ *clocktest.Fake) {
	for _, v := range []any{
		oauthbroker.Pending{}, oauthbroker.Attempt{}, oauthbroker.Grant{}, oauthbroker.Account{},
		oauthbroker.RequestInfo{}, oauthbroker.GrantRef{}, oauthbroker.SweepResult{},
	} {
		typ := reflect.TypeOf(v)
		for _, p := range ValueFields(typ, typ.PkgPath()) {
			t.Errorf("%s names a token, secret or value", p)
		}
	}
}

// ValueFields walks typ (through slices and pointers, into struct types
// declared in pkgPath and into anonymous structs) and returns every type or field whose name NamesValue
// flags, as a dotted path.
func ValueFields(typ reflect.Type, pkgPath string) []string {
	return valueFields(typ, pkgPath, typ.Name())
}

func valueFields(typ reflect.Type, pkgPath, path string) []string {
	for typ.Kind() == reflect.Slice || typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	var out []string
	if NamesValue(typ.Name()) {
		out = append(out, path+" ("+typ.String()+")")
	}
	if typ.Kind() != reflect.Struct || (typ.Name() != "" && typ.PkgPath() != pkgPath) {
		return out // a named struct from elsewhere (time.Time) is not walked
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		if NamesValue(f.Name) {
			out = append(out, path+"."+f.Name)
		}
		out = append(out, valueFields(f.Type, pkgPath, path+"."+f.Name)...)
	}
	return out
}
