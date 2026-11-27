package cost

import (
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNow is a settable clock.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeNow) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeNow) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func TestTracks(t *testing.T) {
	e := NewEstimator()
	for _, tc := range []struct {
		domain, provider string
		ok               bool
	}{
		{"api.openai.com", "openai", true},
		{" API.Anthropic.com ", "anthropic", true},
		{"api.openai.com.", "openai", true},
		{"API.OPENAI.COM..", "openai", true},
		{"generativelanguage.googleapis.com", "google", true},
		{"api.cohere.com", "cohere", true},
		{"example.com", "", false},
		{"openai.com", "", false},
		{"", "", false},
	} {
		p, ok := e.Tracks(tc.domain)
		if p != tc.provider || ok != tc.ok {
			t.Errorf("Tracks(%q) = %q, %v; want %q, %v", tc.domain, p, ok, tc.provider, tc.ok)
		}
		// Tracks and Estimate agree on every domain.
		if est := e.Estimate(tc.domain, 4, 4); (est != nil) != tc.ok {
			t.Errorf("Estimate(%q) != nil is %v, Tracks says %v", tc.domain, est != nil, tc.ok)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = e.Tracks("api.openai.com") }); n != 0 {
		t.Errorf("Tracks allocates %v per call, want 0", n)
	}
}

func TestLedger_AddSpent(t *testing.T) {
	clk := &fakeNow{t: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)}
	l := NewLedger(clk.now)
	alice := UserKey("alice", "agent", "eng-llm")
	bob := UserKey("bob", "agent", "eng-llm")
	l.Add(alice, 0.006)
	l.Add(alice, 0.006)
	l.Add(bob, 0.001)
	l.Add(alice, 0)          // ignored
	l.Add(alice, -1)         // ignored
	l.Add(alice, math.NaN()) // ignored
	if got, ok := l.Spent(alice); !ok || math.Abs(got-0.012) > 1e-12 {
		t.Errorf("alice spent %v (%v), want 0.012", got, ok)
	}
	if got, _ := l.Spent(bob); got != 0.001 {
		t.Errorf("bob spent %v, want 0.001", got)
	}
	// Another rule is another key.
	if got, ok := l.Spent(UserKey("alice", "agent", "other")); got != 0 || !ok {
		t.Errorf("alice under another rule = %v (%v), want 0 tracked", got, ok)
	}
	if n := l.Keys(); n != 2 {
		t.Errorf("Keys = %d, want 2", n)
	}
}

// Past 00:00 UTC every previous-day key is dropped: a cap lapses at midnight.
func TestLedger_UTCRollover(t *testing.T) {
	clk := &fakeNow{t: time.Date(2026, 11, 27, 23, 59, 59, 0, time.UTC)}
	l := NewLedger(clk.now)
	k := UserKey("alice", "agent", "eng-llm")
	l.Add(k, 5)
	// Local time zones do not matter: 00:30 in UTC+1 is still 23:30 UTC.
	clk.set(time.Date(2026, 11, 28, 0, 30, 0, 0, time.FixedZone("CET", 3600)))
	if got, _ := l.Spent(k); got != 5 {
		t.Errorf("before UTC midnight spent = %v, want 5", got)
	}
	clk.set(time.Date(2026, 11, 28, 0, 0, 1, 0, time.UTC))
	if got, ok := l.Spent(k); got != 0 || !ok {
		t.Errorf("after UTC midnight spent = %v (%v), want 0", got, ok)
	}
	if n := l.Keys(); n != 0 {
		t.Errorf("Keys after rollover = %d, want 0", n)
	}
	// A clock that steps back does not resurrect or reset anything.
	l.Add(k, 1)
	clk.set(time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC))
	if got, _ := l.Spent(k); got != 1 {
		t.Errorf("after a backwards step spent = %v, want 1", got)
	}
}

func TestLedger_Seed(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	l := NewLedger(func() time.Time { return now })
	k := UserKey("alice", "agent", "eng-llm")
	midnight := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	l.Seed(midnight, k, 0.02)
	l.Seed(midnight.Add(-24*time.Hour), k, 100) // yesterday's sum: ignored
	if got, _ := l.Spent(k); got != 0.02 {
		t.Errorf("seeded spend = %v, want 0.02", got)
	}
}

// At the cap a new key is not stored and reads untracked (the proxy denies);
// existing keys keep counting.
func TestLedger_Bounded(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	l := newLedger(func() time.Time { return now }, 2)
	a, b, c := UserKey("a", "", "r"), UserKey("b", "", "r"), UserKey("c", "", "r")
	l.Add(a, 1)
	l.Add(b, 1)
	l.Add(c, 1)
	if l.Refused() != 1 {
		t.Errorf("Refused = %d, want 1", l.Refused())
	}
	if _, ok := l.Spent(c); ok {
		t.Error("a key refused at the cap reads tracked")
	}
	l.Add(a, 1)
	if got, ok := l.Spent(a); got != 2 || !ok {
		t.Errorf("existing key at the cap = %v (%v), want 2", got, ok)
	}
	if MaxLedgerKeys != 100000 {
		t.Errorf("MaxLedgerKeys = %d, want 100000", MaxLedgerKeys)
	}
}

func TestUserKey(t *testing.T) {
	if k := UserKey("", "agent-1", "anonymous"); k.User != "" || k.Agent != "agent-1" || k.String() != "anonymous:anon:agent-1" {
		t.Errorf("anonymous key = %+v %q", k, k.String())
	}
	if k := UserKey("alice", "agent-1", "eng"); k.Agent != "" || k.String() != "eng:alice" {
		t.Errorf("user key = %+v %q (a user's spend is not per agent)", k, k.String())
	}
	// A sub over 255 bytes is cut on a rune boundary, as the fleet rollup and
	// costBlockedUsers cut it.
	long := strings.Repeat("a", 254) + "é" + "tail"
	if got := CutSub(long); got != strings.Repeat("a", 254) {
		t.Errorf("CutSub split a rune or kept too much: %d bytes", len(got))
	}
	if got := CutSub(strings.Repeat("b", 300)); len(got) != 255 {
		t.Errorf("CutSub = %d bytes, want 255", len(got))
	}
	if n := testing.AllocsPerRun(100, func() { _ = UserKey(long, "a", "r") }); n != 0 {
		t.Errorf("UserKey allocates %v, want 0", n)
	}
}

func TestNextUTCMidnight(t *testing.T) {
	got := NextUTCMidnight(time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC))
	if want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("NextUTCMidnight = %v, want %v", got, want)
	}
}

func TestLedger_Concurrent(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	l := NewLedger(func() time.Time { return now })
	k := UserKey("alice", "", "r")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Add(k, 1)
				_, _ = l.Spent(k)
			}
		}()
	}
	wg.Wait()
	if got, _ := l.Spent(k); got != 800 {
		t.Errorf("spent = %v, want 800", got)
	}
}
