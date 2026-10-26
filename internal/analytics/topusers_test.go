package analytics

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func userEvent(sub, email, decision string, at time.Time) Event {
	return Event{Timestamp: at, Decision: decision, UserSub: sub, UserEmail: email}
}

func TestTopUsersGroupsBySubWithLatestEmail(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := TopUsers([]Event{
		userEvent("s1", "old@corp", "allow", t0),
		userEvent("s1", "new@corp", "deny", t0.Add(2*time.Minute)),
		userEvent("s1", "", "allow", t0.Add(3*time.Minute)), // empty email never wins
		userEvent("s1", "mid@corp", "allow", t0.Add(time.Minute)),
		userEvent("", "", "allow", t0),
		userEvent("", "", "deny", t0),
	})
	want := []UserCount{
		{Sub: "s1", Email: "new@corp", Count: 4, Denied: 1},
		{Count: 2, Denied: 1, Unattributed: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTopUsersOrderAndTieBreak(t *testing.T) {
	t0 := time.Now()
	var evs []Event
	for _, s := range []string{"c", "a", "b"} { // all tie at 1
		evs = append(evs, userEvent(s, "", "allow", t0))
	}
	evs = append(evs, userEvent("z", "", "allow", t0), userEvent("z", "", "allow", t0))
	got := TopUsers(evs)
	var subs []string
	for _, u := range got {
		subs = append(subs, u.Sub)
	}
	if want := []string{"z", "a", "b", "c"}; !reflect.DeepEqual(subs, want) {
		t.Fatalf("order %v, want %v", subs, want)
	}
}

func TestTopUsersCapKeepsUnattributed(t *testing.T) {
	t0 := time.Now()
	var evs []Event
	for i := 0; i < 15; i++ {
		for n := 0; n <= i; n++ { // user i has i+1 events
			evs = append(evs, userEvent(fmt.Sprintf("u%02d", i), "", "allow", t0))
		}
	}
	got := TopUsers(evs)
	if len(got) != MaxTopUsers {
		t.Fatalf("no unattributed: %d rows, want %d", len(got), MaxTopUsers)
	}
	if got[0].Sub != "u14" || got[0].Count != 15 {
		t.Errorf("first = %+v, want u14 with 15", got[0])
	}

	evs = append(evs, userEvent("", "", "allow", t0)) // one unattributed event, lowest count
	got = TopUsers(evs)
	if len(got) != MaxTopUsers {
		t.Fatalf("with unattributed: %d rows, want %d", len(got), MaxTopUsers)
	}
	last := got[len(got)-1]
	if !last.Unattributed || last.Count != 1 {
		t.Errorf("unattributed bucket dropped or misplaced: %+v", last)
	}
	un := 0
	for _, u := range got {
		if u.Unattributed {
			un++
		}
	}
	if un != 1 {
		t.Errorf("unattributed buckets = %d, want exactly 1", un)
	}
}

// With no identity data every event is unattributed. The choice: report an
// empty list, not a single bucket that holds every event.
func TestTopUsersNoIdentityIsEmpty(t *testing.T) {
	got := TopUsers([]Event{{Decision: "allow"}, {Decision: "deny"}})
	if got == nil || len(got) != 0 {
		t.Fatalf("got %#v, want empty non-nil slice", got)
	}
	if got := TopUsers(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil events: got %#v, want empty non-nil slice", got)
	}
}
