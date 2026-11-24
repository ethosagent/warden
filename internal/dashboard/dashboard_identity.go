package dashboard

import (
	"sort"

	"github.com/ethosagent/warden/internal/analytics"
)

// identityTopReasons is how many identity_reason values the summary lists.
const identityTopReasons = 5

// identitySummary is the identity block of the analytics response. Values are
// the bounded identity statuses and reasons stored on events; it carries no
// subject, email or token.
type identitySummary struct {
	ByStatus   []identityStatusCount `json:"byStatus"`
	TopReasons []identityReasonCount `json:"topReasons"`
}

type identityStatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type identityReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// summarizeIdentity counts events by identity_status and lists the top
// identityTopReasons identity_reason values (count descending, then name). It
// returns nil when no event carries identity fields.
func summarizeIdentity(events []analytics.Event) *identitySummary {
	statuses := map[string]int{}
	reasons := map[string]int{}
	for _, e := range events {
		if e.IdentityStatus != "" {
			statuses[e.IdentityStatus]++
		}
		if e.IdentityReason != "" {
			reasons[e.IdentityReason]++
		}
	}
	if len(statuses) == 0 && len(reasons) == 0 {
		return nil
	}
	out := &identitySummary{ByStatus: []identityStatusCount{}, TopReasons: []identityReasonCount{}}
	for k, n := range statuses {
		out.ByStatus = append(out.ByStatus, identityStatusCount{Status: k, Count: n})
	}
	sort.Slice(out.ByStatus, func(i, j int) bool {
		a, b := out.ByStatus[i], out.ByStatus[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Status < b.Status
	})
	for k, n := range reasons {
		out.TopReasons = append(out.TopReasons, identityReasonCount{Reason: k, Count: n})
	}
	sort.Slice(out.TopReasons, func(i, j int) bool {
		a, b := out.TopReasons[i], out.TopReasons[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Reason < b.Reason
	})
	if len(out.TopReasons) > identityTopReasons {
		out.TopReasons = out.TopReasons[:identityTopReasons]
	}
	return out
}
