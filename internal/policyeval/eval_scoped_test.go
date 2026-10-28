package policyeval

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func userEvent(sub, email, status, decision string, groups ...string) analytics.Event {
	return analytics.Event{
		Timestamp: time.Now(), Domain: "api.github.com", Port: 443, Protocol: "https",
		Method: "GET", URL: "https://api.github.com/repos/x", Decision: decision,
		UserSub: sub, UserEmail: email, UserGroups: groups, IdentityStatus: status,
	}
}

func scopedTo(groups ...string) config.Policy {
	return config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "api.github.com", Groups: groups}}}
}

func TestEvaluate_AffectedUsers(t *testing.T) {
	events := []analytics.Event{
		userEvent("u-alice", "alice@corp.example", "valid", "allow", "eng"),
		userEvent("u-alice", "alice@corp.example", "valid", "allow", "eng"),
		userEvent("u-bob", "bob@corp.example", "valid", "allow", "sales"),
	}
	r := Evaluate(events, scopedTo("sales"))
	if len(r.NewDenies) != 1 {
		t.Fatalf("NewDenies = %+v, want 1 entry", r.NewDenies)
	}
	d := r.NewDenies[0]
	if want := []string{"alice@corp.example"}; !reflect.DeepEqual(d.AffectedUsers, want) {
		t.Errorf("AffectedUsers = %v, want %v", d.AffectedUsers, want)
	}
	if d.AffectedUsersTotal != 1 || d.Count != 2 || d.AnonymousCount != 0 {
		t.Errorf("diff = %+v", d)
	}
}

func TestEvaluate_AffectedUsersFallsBackToSub(t *testing.T) {
	r := Evaluate([]analytics.Event{userEvent("u-carol", "", "valid", "allow", "eng")}, scopedTo("sales"))
	if got := r.NewDenies[0].AffectedUsers; !reflect.DeepEqual(got, []string{"u-carol"}) {
		t.Errorf("AffectedUsers = %v, want [u-carol]", got)
	}
}

func TestEvaluate_AnonymousCount(t *testing.T) {
	events := []analytics.Event{
		userEvent("u-alice", "alice@corp.example", "expired", "allow", "eng"),
		userEvent("", "", "", "allow"),
	}
	r := Evaluate(events, scopedTo("eng"))
	if len(r.NewDenies) != 1 {
		t.Fatalf("NewDenies = %+v, want 1 entry", r.NewDenies)
	}
	d := r.NewDenies[0]
	if d.AnonymousCount != 2 || len(d.AffectedUsers) != 0 || d.AffectedUsersTotal != 0 {
		t.Errorf("diff = %+v, want anonymous 2 and no users", d)
	}
	if r.AnonymousCount != 2 {
		t.Errorf("result AnonymousCount = %d, want 2", r.AnonymousCount)
	}
}

func TestEvaluate_AffectedUsersCap(t *testing.T) {
	var events []analytics.Event
	for i := 24; i >= 0; i-- {
		events = append(events, userEvent(fmt.Sprintf("u-%02d", i), fmt.Sprintf("user%02d@corp.example", i), "valid", "allow", "eng"))
	}
	d := Evaluate(events, scopedTo("sales")).NewDenies[0]
	if len(d.AffectedUsers) != 20 || d.AffectedUsersTotal != 25 {
		t.Fatalf("len=%d total=%d, want 20 and 25", len(d.AffectedUsers), d.AffectedUsersTotal)
	}
	if d.AffectedUsers[0] != "user00@corp.example" || d.AffectedUsers[19] != "user19@corp.example" {
		t.Errorf("not the sorted first 20: %v", d.AffectedUsers)
	}
}

func TestEvaluate_ScopedWithConstraints(t *testing.T) {
	pol := config.Policy{Allowlist: []config.AllowlistEntry{{
		Domain: "api.github.com", Groups: []string{"eng"}, Methods: []string{"GET"},
	}}}
	events := []analytics.Event{
		userEvent("u-a", "a@corp.example", "valid", "allow", "eng"), // GET, eng: agrees
		userEvent("u-b", "b@corp.example", "valid", "allow", "sales"),
	}
	post := userEvent("u-a", "a@corp.example", "valid", "allow", "eng")
	post.Method = "POST"
	events = append(events, post)
	r := Evaluate(events, pol)
	if r.Agreed != 1 {
		t.Errorf("Agreed = %d, want 1", r.Agreed)
	}
	if len(r.NewDenies) != 2 {
		t.Fatalf("NewDenies = %+v, want GET (bob) and POST (alice)", r.NewDenies)
	}
}

func TestEvaluate_ScopedWithPaths(t *testing.T) {
	pol := config.Policy{Allowlist: []config.AllowlistEntry{{
		Domain: "api.github.com", Groups: []string{"eng"}, Paths: []string{"/repos/*"},
	}}}
	in := userEvent("u-a", "a@corp.example", "valid", "allow", "eng") // /repos/x: inside
	out := userEvent("u-a", "a@corp.example", "valid", "allow", "eng")
	out.URL = "https://api.github.com/admin/x"
	r := Evaluate([]analytics.Event{in, out}, pol)
	if r.Agreed != 1 || len(r.NewDenies) != 1 || r.NewDenies[0].AffectedUsersTotal != 1 {
		t.Fatalf("result = %+v, want the out-of-path request denied for a member", r)
	}
}
