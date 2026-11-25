package policyeval

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func apiEvent(decision string) analytics.Event {
	return analytics.Event{
		Timestamp: time.Now(), Domain: "api.example.com", Port: 443, Protocol: "https",
		Method: "GET", URL: "https://api.example.com/v1/items?token=abc", Decision: decision,
	}
}

func allowAPI() config.Policy {
	return config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "api.example.com", Port: 443}}}
}

func TestCompare_DraftAddsDeny(t *testing.T) {
	draft := allowAPI()
	draft.Denylist = []config.DenylistEntry{{Domain: "api.example.com", Port: 443}}
	c := NewComparer(allowAPI(), draft)
	for i := 0; i < 7; i++ {
		c.Add(apiEvent("allow"))
	}
	r := c.Result()
	if r.Events != 7 || r.Agreed != 0 {
		t.Fatalf("events/agreed = %d/%d", r.Events, r.Agreed)
	}
	if len(r.ChangedToAllow) != 0 {
		t.Fatalf("changed_to_allow = %+v, want none", r.ChangedToAllow)
	}
	if len(r.ChangedToDeny) != 1 {
		t.Fatalf("changed_to_deny = %+v", r.ChangedToDeny)
	}
	g := r.ChangedToDeny[0]
	if g.Domain != "api.example.com" || g.Port != 443 || g.Count != 7 || g.Method != "GET" {
		t.Errorf("group = %+v", g)
	}
	// An explicit deny is not a judge outcome.
	if g.JudgeCount != 0 {
		t.Errorf("JudgeCount = %d, want 0", g.JudgeCount)
	}
}

// The recorded decision is ignored: events the live proxy denied for DLP or a
// user block are not false changes when both policies allow the destination.
func TestCompare_RecordedDenyIsNotAChange(t *testing.T) {
	c := NewComparer(allowAPI(), allowAPI())
	dlp, blocked := apiEvent("deny"), apiEvent("deny")
	dlp.Reason, blocked.Reason = "dlp_block", "user_blocked"
	c.Add(dlp)
	c.Add(blocked)
	r := c.Result()
	if len(r.ChangedToAllow) != 0 || len(r.ChangedToDeny) != 0 || r.Agreed != 2 {
		t.Fatalf("result = %+v, want two agreed events and no change", r)
	}
}

func TestCompare_NoMatchIsJudgeEligibleNotPlainDeny(t *testing.T) {
	// Base allows; the draft drops the entry: the destination now matches no
	// list, so it would go to the judge, and the group says so.
	c := NewComparer(allowAPI(), config.Policy{})
	c.Add(apiEvent("allow"))
	c.Add(apiEvent("allow"))
	r := c.Result()
	if len(r.ChangedToDeny) != 1 || r.ChangedToDeny[0].Count != 2 || r.ChangedToDeny[0].JudgeCount != 2 {
		t.Fatalf("changed_to_deny = %+v, want one group with judge_count 2", r.ChangedToDeny)
	}
	if r.JudgeDraft != 2 || r.JudgeBase != 0 {
		t.Errorf("judge base/draft = %d/%d, want 0/2", r.JudgeBase, r.JudgeDraft)
	}

	// The other direction: base left it to the judge, the draft allows it.
	c = NewComparer(config.Policy{}, allowAPI())
	c.Add(apiEvent("deny"))
	r = c.Result()
	if len(r.ChangedToAllow) != 1 || r.ChangedToAllow[0].JudgeCount != 1 || r.JudgeBase != 1 {
		t.Fatalf("result = %+v", r)
	}

	// An explicit denylist match in the draft is a deny, not a judge outcome.
	draft := config.Policy{Denylist: []config.DenylistEntry{{Domain: "api.example.com", Port: 443}}}
	c = NewComparer(allowAPI(), draft)
	c.Add(apiEvent("allow"))
	if g := c.Result().ChangedToDeny[0]; g.JudgeCount != 0 {
		t.Errorf("explicit deny JudgeCount = %d, want 0", g.JudgeCount)
	}
}

func TestCompare_RateLimitedEntriesAreFlagged(t *testing.T) {
	limited := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "api.example.com", Port: 443, RateLimit: "1/m", TimeWindow: "9-17"}}}
	draft := limited
	draft.Denylist = []config.DenylistEntry{{Domain: "api.example.com", Port: 443}}
	c := NewComparer(limited, draft)
	for i := 0; i < 5; i++ {
		c.Add(apiEvent("allow"))
	}
	r := c.Result()
	// Stateless: five events all evaluate as allowed under the base (no bucket),
	// and are flagged rather than silently treated as plain allows.
	if r.LimitGoverned != 5 || len(r.ChangedToDeny) != 1 || r.ChangedToDeny[0].LimitGoverned != 5 {
		t.Fatalf("result = %+v", r)
	}
	plain := NewComparer(allowAPI(), allowAPI())
	plain.Add(apiEvent("allow"))
	if plain.Result().LimitGoverned != 0 {
		t.Error("an entry without a limit must not be flagged")
	}
	if len(r.Limitations) == 0 || !strings.Contains(strings.Join(r.Limitations, " "), "rate limits") {
		t.Errorf("limitations = %v, want the stateless-limit note", r.Limitations)
	}
}

func TestCompare_SkipsMCPAndUsesIdentity(t *testing.T) {
	base := scopedTo("eng")
	draft := scopedTo("sales")
	c := NewComparer(base, draft)
	mcp := userEvent("u-a", "a@corp.example", "valid", "allow", "eng")
	mcp.Protocol = "mcp"
	c.Add(mcp)
	c.Add(userEvent("u-a", "a@corp.example", "valid", "allow", "eng"))
	c.Add(userEvent("u-b", "", "valid", "allow", "eng"))
	c.Add(userEvent("", "", "", "allow"))
	r := c.Result()
	if r.SkippedMCP != 1 || r.Events != 3 {
		t.Fatalf("skipped/events = %d/%d", r.SkippedMCP, r.Events)
	}
	// The anonymous event is a Conditional deny on both sides: it agrees.
	if r.Agreed != 1 || r.AnonymousCount != 0 {
		t.Errorf("agreed/anonymous = %d/%d", r.Agreed, r.AnonymousCount)
	}
	if len(r.ChangedToDeny) != 1 {
		t.Fatalf("groups = %+v", r.ChangedToDeny)
	}
	g := r.ChangedToDeny[0]
	if !reflect.DeepEqual(g.AffectedUsers, []string{"a@corp.example", "u-b"}) || g.AffectedUsersTotal != 2 {
		t.Errorf("users = %v (%d)", g.AffectedUsers, g.AffectedUsersTotal)
	}
}

func TestCompare_AnonymousCountedOnDisagreement(t *testing.T) {
	// Base allows everyone; the draft scopes the entry. An anonymous event
	// changes to deny and is counted as anonymous, not as a user.
	c := NewComparer(allowAPI(), config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "api.example.com", Port: 443, Groups: []string{"eng"}}}})
	c.Add(apiEvent("allow"))
	r := c.Result()
	if r.AnonymousCount != 1 || r.ChangedToDeny[0].AffectedUsersTotal != 0 {
		t.Fatalf("result = %+v", r)
	}
}

func TestCompare_SortAndCapUsers(t *testing.T) {
	draft := config.Policy{}
	c := NewComparer(config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: "a.example.com"}, {Domain: "b.example.com"}, {Domain: "c.example.com"},
	}}, draft)
	add := func(domain string, n int) {
		for i := 0; i < n; i++ {
			e := apiEvent("allow")
			e.Domain = domain
			e.UserSub, e.IdentityStatus = fmt.Sprintf("u-%02d", i), "valid"
			c.Add(e)
		}
	}
	add("b.example.com", 30)
	add("a.example.com", 3)
	add("c.example.com", 3)
	r := c.Result()
	var got []string
	for _, g := range r.ChangedToDeny {
		got = append(got, fmt.Sprintf("%s:%d", g.Domain, g.Count))
	}
	if want := []string{"b.example.com:30", "a.example.com:3", "c.example.com:3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if g := r.ChangedToDeny[0]; len(g.AffectedUsers) != MaxAffectedUsers || g.AffectedUsersTotal != 30 {
		t.Errorf("users = %d total %d", len(g.AffectedUsers), g.AffectedUsersTotal)
	}
}

// The stored result carries no URL, path, query or header.
func TestCompare_ResultJSONHasNoURL(t *testing.T) {
	draft := allowAPI()
	draft.Denylist = []config.DenylistEntry{{Domain: "api.example.com", Port: 443}}
	c := NewComparer(allowAPI(), draft)
	for i := 0; i < 3; i++ {
		e := apiEvent("allow")
		e.URL = fmt.Sprintf("https://api.example.com/secret/path/%d?token=hunter2", i)
		c.Add(e)
	}
	b, err := json.Marshal(c.Result())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{`"url"`, "/", "?", "hunter2", "secret", "token"} {
		if strings.Contains(s, bad) {
			t.Errorf("result JSON contains %q: %s", bad, s)
		}
	}
}

func TestCompare_GroupCap(t *testing.T) {
	base := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "~.*"}}}
	c := NewComparer(base, config.Policy{})
	for i := 0; i < maxCompareGroups+5; i++ {
		e := apiEvent("allow")
		e.Domain = fmt.Sprintf("h%04d.example.com", i)
		c.Add(e)
	}
	r := c.Result()
	if len(r.ChangedToDeny) != maxCompareGroups || r.GroupsTruncated != 5 {
		t.Fatalf("groups/truncated = %d/%d", len(r.ChangedToDeny), r.GroupsTruncated)
	}
}
