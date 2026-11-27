package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// The per-user usage and cost view (W-P3-PUL-05): GET /dashboard/api/usage/users.
// The data is the W-P3-PUL-07 rollup on the control plane and the local events
// table on a standalone worker, both behind analytics.UserUsageQuerier. The
// response holds identifiers and counters only: the IdP sub and email the
// traffic view already shows, deny reason enums, agent ids, rule names and
// estimated cost. Never a URL, header, body or secret.

const (
	// userUsageCacheTTL is how long a computed usage payload is reused. The
	// rollup moves with ingest and the view refreshes rarely, so 30s keeps a
	// refresh burst to one aggregation per (window, sort, limit).
	userUsageCacheTTL = 30 * time.Second

	defaultUsageWindow = "7d"
	defaultUsageSort   = "cost"
	defaultUsageLimit  = 100
	maxUsageLimit      = 500
	maxTopAgents       = 5
)

// usageWindows maps the window parameter to its length.
var usageWindows = map[string]time.Duration{
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// CostBlockStatus is the control plane's cost block computation state, shown
// on the usage view so an operator can tell an empty block list from one that
// is not being computed (W-P3-PUL-08).
type CostBlockStatus struct {
	// Enabled is false when the aggregator is off, which is the case with the
	// memory analytics provider: caps are then enforced per worker only.
	Enabled bool `json:"enabled"`
	// Truncated counts over-cap users left out of the served list by its size
	// limits; they are still enforced on the worker that saw the spend.
	Truncated int64 `json:"truncated"`
	// RecomputeErrors counts failed recomputes since the control plane started.
	RecomputeErrors int64 `json:"recomputeErrors"`
}

// SetUsagePolicy supplies the policy the usage view reads its rules and cost
// block list from. The control plane passes its served policy (user limit
// rules plus the computed costBlockedUsers); unset, the startup policy is used.
func (s *Server) SetUsagePolicy(fn func() config.Policy) { s.usagePolicy = fn }

// SetCostBlockStatus supplies the cost block computation state (control plane
// only). Unset, the response carries no costBlocks object.
func (s *Server) SetCostBlockStatus(fn func() CostBlockStatus) { s.costBlockStatus = fn }

type userUsageAgent struct {
	AgentID  string  `json:"agentID"`
	Requests int64   `json:"requests"`
	CostUSD  float64 `json:"costUSD"`
}

type userUsageUser struct {
	Sub          string           `json:"sub"`
	Email        string           `json:"email"`
	Requests     int64            `json:"requests"`
	Denies       map[string]int64 `json:"denies"`
	CostUSD      float64          `json:"costUSD"`
	TodayCostUSD float64          `json:"todayCostUSD"`
	TopAgents    []userUsageAgent `json:"topAgents"`
	LimitRule    string           `json:"limitRule"`
	CapUSD       float64          `json:"capUSD"`
	AtLimit      bool             `json:"atLimit"`
	CostBlocked  bool             `json:"costBlocked"`
}

type userUsageResponse struct {
	Window       string           `json:"window"`
	From         string           `json:"from"`
	To           string           `json:"to"`
	Users        []userUsageUser  `json:"users"`
	Unattributed userUsageTotals  `json:"unattributed"`
	CostBlocks   *CostBlockStatus `json:"costBlocks,omitempty"`
}

type userUsageTotals struct {
	Requests int64   `json:"requests"`
	CostUSD  float64 `json:"costUSD"`
}

func (s *Server) handleUserUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	window := q.Get("window")
	if window == "" {
		window = defaultUsageWindow
	}
	span, ok := usageWindows[window]
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_window")
		return
	}
	sortBy := q.Get("sort")
	if sortBy == "" {
		sortBy = defaultUsageSort
	}
	if sortBy != "cost" && sortBy != "requests" {
		writeError(w, http.StatusBadRequest, "invalid_sort")
		return
	}
	limit := defaultUsageLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxUsageLimit {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = n
	}
	uq, ok := s.data.(analytics.UserUsageQuerier)
	if !ok {
		writeError(w, http.StatusNotFound, "usage_unavailable")
		return
	}

	// The payload is a pure function of window, sort and limit (plus the
	// store, the served policy and the clock), so those are the whole key; NUL
	// cannot occur in any of them.
	key := window + "\x00" + sortBy + "\x00" + strconv.Itoa(limit)
	now := s.now()
	body, err := s.userUsageCache.getOrCompute(key, now, userUsageCacheTTL, func() ([]byte, error) {
		return s.computeUserUsage(r.Context(), uq, window, span, sortBy, limit, now)
	})
	if err != nil {
		// The error can name a store path or SQL; never echo it.
		writeError(w, http.StatusInternalServerError, "usage_query_failed")
		return
	}
	writeJSONBytes(w, body)
}

func (s *Server) computeUserUsage(ctx context.Context, uq analytics.UserUsageQuerier, window string, span time.Duration, sortBy string, limit int, now time.Time) ([]byte, error) {
	from := now.Add(-span)
	// Fetch every user the store will return and order and cut here, so
	// sort=requests ranks the whole window rather than the top spenders.
	usage, err := uq.UsageByUser(ctx, from, now, analytics.MaxUsageUsers)
	if err != nil {
		return nil, err
	}
	today := analytics.UsageDay(now)
	todayCosts, err := uq.TodayCostByRule(ctx, today)
	if err != nil {
		return nil, err
	}
	// Per user: the rule it spent most under today.
	type ruleCost struct {
		rule string
		cost float64
	}
	topRule := map[string]ruleCost{}
	for _, c := range todayCosts {
		if cur, ok := topRule[c.Sub]; !ok || c.CostUSD > cur.cost {
			topRule[c.Sub] = ruleCost{c.Rule, c.CostUSD}
		}
	}

	pol := s.policy
	if s.usagePolicy != nil {
		pol = s.usagePolicy()
	}
	blocked := map[string]bool{}
	for _, b := range pol.CostBlockedUsers {
		if b.Day == today {
			blocked[b.Sub] = true
		}
	}

	resp := userUsageResponse{
		Window: window,
		From:   from.UTC().Format(time.RFC3339),
		To:     now.UTC().Format(time.RFC3339),
		Users:  []userUsageUser{},
	}
	for _, u := range usage {
		if u.Sub == "" {
			resp.Unattributed = userUsageTotals{Requests: u.Requests, CostUSD: u.CostUSD}
			continue
		}
		out := userUsageUser{
			Sub: u.Sub, Email: u.Email, Requests: u.Requests, Denies: u.Denies, CostUSD: u.CostUSD,
			TopAgents:   []userUsageAgent{},
			CostBlocked: blocked[u.Sub],
		}
		if out.Denies == nil {
			out.Denies = map[string]int64{}
		}
		for i, a := range u.Agents {
			if i == maxTopAgents {
				break
			}
			out.TopAgents = append(out.TopAgents, userUsageAgent{AgentID: a.AgentID, Requests: a.Requests, CostUSD: a.CostUSD})
		}
		if rc, ok := topRule[u.Sub]; ok {
			out.LimitRule, out.TodayCostUSD = rc.rule, rc.cost
		} else {
			for _, ru := range u.Rules {
				if ru.Rule != "" && ru.Rule != analytics.AnonymousLimitRule {
					out.LimitRule = ru.Rule
					break
				}
			}
		}
		out.CapUSD = ruleCap(pol, out.LimitRule)
		out.AtLimit = out.CapUSD > 0 && out.TodayCostUSD >= out.CapUSD
		resp.Users = append(resp.Users, out)
	}
	sort.SliceStable(resp.Users, func(i, j int) bool {
		a, b := resp.Users[i], resp.Users[j]
		if sortBy == "requests" {
			if a.Requests != b.Requests {
				return a.Requests > b.Requests
			}
			return a.CostUSD > b.CostUSD
		}
		return a.CostUSD > b.CostUSD
	})
	if len(resp.Users) > limit {
		resp.Users = resp.Users[:limit]
	}
	if s.costBlockStatus != nil {
		st := s.costBlockStatus()
		resp.CostBlocks = &st
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ruleCap is the dailyCostUSD of the named rule in pol; 0 (no cap) when the
// rule is empty or no longer configured. "default" and "anonymous" name the
// two single rules, as they do in costBlockedUsers and on events.
func ruleCap(pol config.Policy, name string) float64 {
	switch name {
	case "":
		return 0
	case "default":
		if pol.DefaultUserLimit != nil {
			return pol.DefaultUserLimit.DailyCostUSD
		}
		return 0
	case analytics.AnonymousLimitRule:
		if pol.AnonymousLimit != nil {
			return pol.AnonymousLimit.DailyCostUSD
		}
		return 0
	}
	for _, r := range pol.UserLimits {
		if r.Name == name {
			return r.DailyCostUSD
		}
	}
	return 0
}
