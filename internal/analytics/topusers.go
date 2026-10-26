package analytics

import (
	"sort"
	"time"
)

// MaxTopUsers caps the TopUsers result, the unattributed bucket included.
const MaxTopUsers = 10

// UserCount is one row of the top-users breakdown. Sub and Email are IdP claim
// values: callers must render them as text, never as markup.
type UserCount struct {
	// Sub is the verified OIDC subject; "" only on the unattributed bucket.
	Sub string `json:"sub"`
	// Email is the latest non-empty user_email seen for Sub ("" when none).
	Email string `json:"email"`
	// Count is the number of events for this user; Denied those with decision deny.
	Count  int `json:"count"`
	Denied int `json:"denied"`
	// Unattributed marks the single bucket of events that carry no user_sub.
	Unattributed bool `json:"unattributed"`
}

// TopUsers aggregates events per user_sub for the dashboard's top-users table.
// Rows are grouped by user_sub and display the latest non-empty user_email. All
// events with an empty user_sub fall into exactly one Unattributed bucket. The
// result is sorted by Count descending, ties broken by Sub ascending, and holds
// at most MaxTopUsers rows: the unattributed bucket, when present, always keeps
// its place, so at most MaxTopUsers-1 attributed users share the list with it.
//
// With no attributed user at all, the result is empty (non-nil): a store with no
// identity data reports no breakdown rather than one bucket holding everything.
func TopUsers(events []Event) []UserCount {
	type agg struct {
		UserCount
		emailAt time.Time
	}
	byUser := make(map[string]*agg)
	var unattributed *agg
	for i := range events {
		e := &events[i]
		var a *agg
		if e.UserSub == "" {
			if unattributed == nil {
				unattributed = &agg{UserCount: UserCount{Unattributed: true}}
			}
			a = unattributed
		} else {
			var ok bool
			if a, ok = byUser[e.UserSub]; !ok {
				a = &agg{UserCount: UserCount{Sub: e.UserSub}}
				byUser[e.UserSub] = a
			}
			if e.UserEmail != "" && (a.Email == "" || e.Timestamp.After(a.emailAt)) {
				a.Email, a.emailAt = e.UserEmail, e.Timestamp
			}
		}
		a.Count++
		if e.Decision == "deny" {
			a.Denied++
		}
	}
	if len(byUser) == 0 {
		return []UserCount{}
	}

	attributed := make([]UserCount, 0, len(byUser))
	for _, a := range byUser {
		attributed = append(attributed, a.UserCount)
	}
	sortUserCounts(attributed)
	limit := MaxTopUsers
	if unattributed != nil {
		limit--
	}
	if len(attributed) > limit {
		attributed = attributed[:limit]
	}
	if unattributed != nil {
		attributed = append(attributed, unattributed.UserCount)
		sortUserCounts(attributed)
	}
	return attributed
}

func sortUserCounts(u []UserCount) {
	sort.Slice(u, func(i, j int) bool {
		if u[i].Count != u[j].Count {
			return u[i].Count > u[j].Count
		}
		return u[i].Sub < u[j].Sub
	})
}
