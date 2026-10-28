package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func TestIsBlocked(t *testing.T) {
	e := NewEvaluator(config.Policy{BlockedUsers: []config.BlockedUser{
		{Sub: "u1"},
		{Email: "Bob@Corp.com"},
		{Sub: "u3", Email: "carol@corp.com"},
	}})
	cases := []struct {
		name       string
		sub, email string
		want       bool
	}{
		{"sub match", "u1", "", true},
		{"sub match, other email", "u1", "x@corp.com", true},
		{"email match (stored lowercased)", "", "bob@corp.com", true},
		{"email match, unknown sub", "zzz", "bob@corp.com", true},
		{"entry with both: sub only", "u3", "", true},
		{"entry with both: email only", "", "carol@corp.com", true},
		{"unlisted user", "u2", "alice@corp.com", false},
		{"sub is exact, not a prefix", "u10", "", false},
		{"caller must lowercase the email", "", "BOB@corp.com", false},
		{"empty claims never match", "", "", false},
	}
	for _, tc := range cases {
		if got := e.IsBlocked(tc.sub, tc.email); got != tc.want {
			t.Errorf("%s: IsBlocked(%q, %q) = %v, want %v", tc.name, tc.sub, tc.email, got, tc.want)
		}
	}
}

func TestIsBlocked_EmptyEntriesNeverMatchEmptyClaims(t *testing.T) {
	// An entry with only an email must not put "" into the sub set.
	e := NewEvaluator(config.Policy{BlockedUsers: []config.BlockedUser{{Email: "a@b.c"}}})
	if e.IsBlocked("", "") {
		t.Fatal("empty claims matched")
	}
	if NewEvaluator(config.Policy{}).IsBlocked("u1", "a@b.c") {
		t.Fatal("empty list blocked someone")
	}
}

func TestIsBlocked_ReplaceSwaps(t *testing.T) {
	e := NewEvaluator(config.Policy{})
	if e.IsBlocked("u1", "") {
		t.Fatal("blocked before any entry")
	}
	e.Replace(config.Policy{BlockedUsers: []config.BlockedUser{{Sub: "u1"}}})
	if !e.IsBlocked("u1", "") {
		t.Fatal("not blocked after Replace added u1")
	}
	e.Replace(config.Policy{BlockedUsers: []config.BlockedUser{{Email: "alice@corp.com"}}})
	if e.IsBlocked("u1", "") {
		t.Fatal("u1 still blocked after Replace removed it")
	}
	if !e.IsBlocked("", "alice@corp.com") {
		t.Fatal("alice not blocked after Replace")
	}
	e.Replace(config.Policy{})
	if e.IsBlocked("", "alice@corp.com") {
		t.Fatal("alice still blocked after an empty Replace")
	}
}

// A Replace is one critical section for allow/deny and the block set: a reader
// never sees the new allowlist with the old block list.
func TestIsBlocked_ReplaceAtomicWithAllowlist(t *testing.T) {
	pA := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.example.com"}}}
	pB := config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: "b.example.com"}},
		BlockedUsers: []config.BlockedUser{{Sub: "u1"}},
	}
	e := NewEvaluator(pA)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				e.Replace(pB)
			} else {
				e.Replace(pA)
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		e.swapMu.RLock()
		_, blocked := e.blockedSubs["u1"]
		isB := len(e.allowlist) == 1 && e.allowlist[0].Domain == "b.example.com"
		e.swapMu.RUnlock()
		if blocked != isB {
			t.Fatalf("torn swap: blocked=%v allowlist-is-B=%v", blocked, isB)
		}
	}
	close(stop)
	wg.Wait()
}

func TestIsBlockedAllocs(t *testing.T) {
	users := make([]config.BlockedUser, 0, config.MaxBlockedUsers)
	for i := 0; i < config.MaxBlockedUsers; i++ {
		users = append(users, config.BlockedUser{Sub: fmt.Sprintf("sub-%d", i), Email: fmt.Sprintf("user%d@corp.com", i)})
	}
	e := NewEvaluator(config.Policy{BlockedUsers: users})
	for name, args := range map[string][2]string{
		"hit by sub":   {"sub-4999", ""},
		"hit by email": {"nobody", "user4999@corp.com"},
		"miss":         {"sub-x", "x@corp.com"},
	} {
		sub, email := args[0], args[1]
		if n := testing.AllocsPerRun(1000, func() { _ = e.IsBlocked(sub, email) }); n != 0 {
			t.Errorf("%s: IsBlocked allocates %v per call, want 0", name, n)
		}
	}
}

func BenchmarkIsBlocked(b *testing.B) {
	users := make([]config.BlockedUser, 0, config.MaxBlockedUsers)
	for i := 0; i < config.MaxBlockedUsers; i++ {
		users = append(users, config.BlockedUser{Sub: fmt.Sprintf("sub-%d", i)})
	}
	e := NewEvaluator(config.Policy{BlockedUsers: users})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.IsBlocked("sub-x", "x@corp.com")
	}
}

func TestBlockedCount(t *testing.T) {
	e := NewEvaluator(config.Policy{BlockedUsers: []config.BlockedUser{{Sub: "u1"}, {Email: "A@b.com"}, {Sub: "u2", Email: "u2@b.com"}, {}}})
	if got := e.BlockedCount(); got != 3 {
		t.Errorf("BlockedCount = %d, want 3 (users with a sub or an email)", got)
	}
	e.Replace(config.Policy{})
	if got := e.BlockedCount(); got != 0 {
		t.Errorf("after Replace: BlockedCount = %d, want 0", got)
	}
}
