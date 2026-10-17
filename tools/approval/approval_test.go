package approval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// fakeGH is the whole GitHub surface Verify uses, held in memory.
type fakeGH struct {
	pr       PullRequest
	events   []LabelEvent
	pushedAt time.Time
	perms    map[string]string
	err      error
	calls    []string
}

func (f *fakeGH) PullRequest(context.Context, int) (PullRequest, error) {
	f.calls = append(f.calls, "pr")
	return f.pr, f.err
}

func (f *fakeGH) LabelEvents(context.Context, int, string) ([]LabelEvent, error) {
	f.calls = append(f.calls, "events")
	return f.events, f.err
}

func (f *fakeGH) HeadPushedAt(context.Context, int, string) (time.Time, error) {
	f.calls = append(f.calls, "push")
	return f.pushedAt, f.err
}

func (f *fakeGH) Permission(_ context.Context, login string) (string, error) {
	f.calls = append(f.calls, "perm:"+login)
	return f.perms[login], f.err
}

func human(login string) Account { return Account{Login: login, Type: "User"} }

// base is a bot PR whose gate label was added by a maintainer after the push.
func base() *fakeGH {
	return &fakeGH{
		pr:       PullRequest{Author: Account{Login: "claude-bot[bot]", Type: "Bot"}, HeadSHA: "abc", Labels: []string{"risk:gates", Label}},
		events:   []LabelEvent{{Added: true, Actor: human("mitesh"), At: t0.Add(time.Hour)}},
		pushedAt: t0,
		perms:    map[string]string{"mitesh": "maintain", "writer": "write", "boss": "admin"},
	}
}

func isAgent(login, typ string) bool {
	return typ == "Bot" || strings.HasSuffix(login, "[bot]") || login == "agent-user"
}

func TestVerify(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeGH)
		want   bool
		reason string
	}{
		{"maintainer after the push", func(*fakeGH) {}, true, ""},
		{"admin after the push", func(f *fakeGH) { f.events[0].Actor = human("boss") }, true, ""},
		{"label not on the PR", func(f *fakeGH) { f.pr.Labels = []string{"risk:gates"} }, false, "not on the PR"},
		{"no label event at all", func(f *fakeGH) { f.events = nil }, false, "no event"},
		{"added by the bot itself", func(f *fakeGH) {
			f.events[0].Actor = Account{Login: "claude-bot[bot]", Type: "Bot"}
		}, false, "bot or agent"},
		{"added by a bot that has admin", func(f *fakeGH) {
			f.events[0].Actor = Account{Login: "ci[bot]", Type: "Bot"}
			f.perms["ci[bot]"] = "admin"
		}, false, "bot or agent"},
		{"added by an agent account typed User", func(f *fakeGH) {
			f.events[0].Actor = human("agent-user")
			f.perms["agent-user"] = "admin"
		}, false, "bot or agent"},
		{"added by a writer", func(f *fakeGH) { f.events[0].Actor = human("writer") }, false, "needs maintain or admin"},
		{"added by a stranger", func(f *fakeGH) { f.events[0].Actor = human("nobody") }, false, "needs maintain or admin"},
		{"added before the latest push", func(f *fakeGH) { f.pushedAt = t0.Add(2 * time.Hour) }, false, "before the latest push"},
		{"added in the same second as the push", func(f *fakeGH) { f.pushedAt = f.events[0].At }, false, "before the latest push"},
		{"removed after being added", func(f *fakeGH) {
			f.events = append(f.events, LabelEvent{Added: false, Actor: human("mitesh"), At: t0.Add(2 * time.Hour)})
		}, false, "removed"},
		{"re-added by the bot after the maintainer", func(f *fakeGH) {
			f.events = append(f.events,
				LabelEvent{Added: false, Actor: Account{Login: "claude-bot[bot]", Type: "Bot"}, At: t0.Add(2 * time.Hour)},
				LabelEvent{Added: true, Actor: Account{Login: "claude-bot[bot]", Type: "Bot"}, At: t0.Add(3 * time.Hour)})
		}, false, "bot or agent"},
		{"maintainer re-adds after a bot", func(f *fakeGH) {
			f.events = []LabelEvent{
				{Added: true, Actor: Account{Login: "claude-bot[bot]", Type: "Bot"}, At: t0.Add(time.Hour)},
				{Added: false, Actor: human("mitesh"), At: t0.Add(2 * time.Hour)},
				{Added: true, Actor: human("mitesh"), At: t0.Add(3 * time.Hour)},
			}
		}, true, ""},
		{"events arrive out of order", func(f *fakeGH) {
			f.events = []LabelEvent{
				{Added: true, Actor: human("mitesh"), At: t0.Add(3 * time.Hour)},
				{Added: true, Actor: Account{Login: "claude-bot[bot]", Type: "Bot"}, At: t0.Add(time.Hour)},
			}
		}, true, ""},
	}
	for _, c := range cases {
		f := base()
		c.mutate(f)
		v, err := Verify(context.Background(), f, 7, isAgent)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if v.Approved != c.want || !strings.Contains(v.Reason, c.reason) {
			t.Errorf("%s: verdict = %+v, want approved=%v reason~%q", c.name, v, c.want, c.reason)
		}
	}
}

func TestVerifyFailsClosedOnAPIError(t *testing.T) {
	f := base()
	f.err = errors.New("403 forbidden")
	v, err := Verify(context.Background(), f, 7, isAgent)
	if err == nil || v.Approved {
		t.Fatalf("an API error must never approve: %+v, %v", v, err)
	}
}

func TestVerifyDoesNotAskPermissionOfBots(t *testing.T) {
	f := base()
	f.events[0].Actor = Account{Login: "ci[bot]", Type: "Bot"}
	if _, err := Verify(context.Background(), f, 7, isAgent); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "perm:") {
			t.Errorf("a bot actor is rejected before any permission lookup, saw %v", f.calls)
		}
	}
}

func TestIsMaintainer(t *testing.T) {
	for role, want := range map[string]bool{"admin": true, "maintain": true, "Maintain": true, "write": false, "triage": false, "read": false, "": false, "none": false} {
		if got := isMaintainerRole(role); got != want {
			t.Errorf("isMaintainerRole(%q) = %v, want %v", role, got, want)
		}
	}
}
