// Package dashboard provides an HTTP handler that serves a read-only
// operational dashboard for the Warden proxy. It exposes JSON APIs for
// traffic events, policy inspection, secret references, and aggregate
// stats, plus a single embedded HTML page that consumes them.
package dashboard

import (
	"embed"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

//go:embed index.html
var indexHTML []byte

// DataSource is a narrow read-only view of the analytics store used by the
// dashboard. It intentionally excludes write methods so the dashboard can
// never mutate event data.
type DataSource interface {
	GetEvents(filter analytics.EventFilter) ([]analytics.Event, error)
}

// Server holds the dependencies needed by the dashboard HTTP handlers.
type Server struct {
	data    DataSource
	policy  config.Policy
	secrets secrets.SecretProvider
}

// NewServer constructs a dashboard Server.
func NewServer(data DataSource, policy config.Policy, sec secrets.SecretProvider) *Server {
	return &Server{
		data:    data,
		policy:  policy,
		secrets: sec,
	}
}

// --- JSON response types ---

type secretEntry struct {
	Placeholder string   `json:"placeholder"`
	Ref         *refJSON `json:"ref,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type refJSON struct {
	SHA256 string `json:"sha256"`
	Last4  string `json:"last4"`
	Length int    `json:"length"`
}

type blockedGroup struct {
	Domain    string `json:"domain"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type statsResponse struct {
	Total           int         `json:"total"`
	AllowCount      int         `json:"allow_count"`
	DenyCount       int         `json:"deny_count"`
	TopDestinations []destCount `json:"top_destinations"`
}

type destCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type policyResponse struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
}

// Handler returns an http.Handler that serves the dashboard routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/api/traffic", s.handleTraffic)
	mux.HandleFunc("/dashboard/api/policy", s.handlePolicy)
	mux.HandleFunc("/dashboard/api/secrets", s.handleSecrets)
	mux.HandleFunc("/dashboard/api/blocked", s.handleBlocked)
	mux.HandleFunc("/dashboard/api/stats", s.handleStats)
	mux.HandleFunc("/dashboard/", s.handleIndex)
	return mux
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeJSON marshals v and writes it as a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Header already sent; nothing useful we can do.
		_ = err
	}
}

// handleTraffic serves GET /dashboard/api/traffic.
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	q := r.URL.Query()
	filter := analytics.EventFilter{
		Domain:   q.Get("domain"),
		Decision: q.Get("decision"),
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since parameter")
			return
		}
		filter.Since = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit parameter")
			return
		}
		filter.Limit = n
	} else {
		// Default to 1000 when no limit is specified.
		filter.Limit = 1000
	}

	events, err := s.data.GetEvents(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []analytics.Event{}
	}
	writeJSON(w, events)
}

// handlePolicy serves GET /dashboard/api/policy.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp := policyResponse{
		Allowlist: s.policy.Allowlist,
		Denylist:  s.policy.Denylist,
	}
	if resp.Allowlist == nil {
		resp.Allowlist = []config.AllowlistEntry{}
	}
	if resp.Denylist == nil {
		resp.Denylist = []config.DenylistEntry{}
	}
	writeJSON(w, resp)
}

// handleSecrets serves GET /dashboard/api/secrets.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	entries := make([]secretEntry, 0, len(s.policy.Secrets))
	for _, m := range s.policy.Secrets {
		se := secretEntry{Placeholder: m.Placeholder}
		val, err := s.secrets.GetSecret(m.Placeholder)
		if err != nil {
			se.Error = err.Error()
		} else {
			ref := secrets.Ref(val)
			se.Ref = &refJSON{
				SHA256: ref.SHA256,
				Last4:  ref.Last4,
				Length: ref.Length,
			}
		}
		entries = append(entries, se)
	}
	writeJSON(w, entries)
}

// handleBlocked serves GET /dashboard/api/blocked.
func (s *Server) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	events, err := s.data.GetEvents(analytics.EventFilter{Decision: "deny", Limit: 10000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type domainInfo struct {
		count     int
		firstSeen time.Time
		lastSeen  time.Time
	}
	grouped := make(map[string]*domainInfo)
	for _, e := range events {
		info, ok := grouped[e.Domain]
		if !ok {
			grouped[e.Domain] = &domainInfo{
				count:     1,
				firstSeen: e.Timestamp,
				lastSeen:  e.Timestamp,
			}
			continue
		}
		info.count++
		if e.Timestamp.Before(info.firstSeen) {
			info.firstSeen = e.Timestamp
		}
		if e.Timestamp.After(info.lastSeen) {
			info.lastSeen = e.Timestamp
		}
	}

	result := make([]blockedGroup, 0, len(grouped))
	for domain, info := range grouped {
		result = append(result, blockedGroup{
			Domain:    domain,
			Count:     info.count,
			FirstSeen: info.firstSeen.Format(time.RFC3339),
			LastSeen:  info.lastSeen.Format(time.RFC3339),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Domain < result[j].Domain
	})
	writeJSON(w, result)
}

// handleStats serves GET /dashboard/api/stats.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	events, err := s.data.GetEvents(analytics.EventFilter{Limit: 10000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var allowCount, denyCount int
	domainCounts := make(map[string]int)
	for _, e := range events {
		switch e.Decision {
		case "allow":
			allowCount++
		case "deny":
			denyCount++
		}
		domainCounts[e.Domain]++
	}

	dests := make([]destCount, 0, len(domainCounts))
	for d, c := range domainCounts {
		dests = append(dests, destCount{Domain: d, Count: c})
	}
	sort.Slice(dests, func(i, j int) bool {
		if dests[i].Count != dests[j].Count {
			return dests[i].Count > dests[j].Count
		}
		return dests[i].Domain < dests[j].Domain
	})
	if len(dests) > 10 {
		dests = dests[:10]
	}

	writeJSON(w, statsResponse{
		Total:           len(events),
		AllowCount:      allowCount,
		DenyCount:       denyCount,
		TopDestinations: dests,
	})
}

// handleIndex serves the embedded HTML dashboard page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

// Ensure embed import is used.
var _ embed.FS
