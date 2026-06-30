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
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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

// MCPProvider is the read-only view of the MCP gateway the dashboard needs to
// render the MCP Tools view. The gateway satisfies it directly. It is optional:
// when nil, the dashboard reports MCP as disabled. Both methods return
// content-free metadata only — a tool catalog and the observed field schema with
// sensitivity classes, never any argument or result value.
type MCPProvider interface {
	Inventory() []gateway.InventoryItem
	SchemaSnapshot() map[string]mcp.ToolProfileView
}

// Server holds the dependencies needed by the dashboard HTTP handlers.
type Server struct {
	data         DataSource
	policy       config.Policy
	secrets      secrets.SecretProvider
	mcp          MCPProvider               // nil when the MCP gateway is disabled
	livePolicy   func() config.Policy      // nil = serve the static startup policy
	policyWriter func(config.Policy) error // nil = read-only (worker / no editor)
	// liveSettings returns the behavioral settings currently in force (nil = none);
	// settingsWriter applies an edited settings document. Both are control-plane-
	// only: a worker leaves settingsWriter nil so its settings panel is read-only.
	liveSettings   func() *config.SettingsWire
	settingsWriter func(config.SettingsWire) error
	workersFn      func() []WorkerView // nil = no fleet worker registry
	// mcpFleet, when set (control plane), returns the inventory + observed schema
	// for a given worker (empty proxyID = most-recent worker). It takes precedence
	// over the single-node mcp gateway.
	mcpFleet func(proxyID string) ([]gateway.InventoryItem, map[string]mcp.ToolProfileView)
}

// WorkerView is one connected data-plane worker in the control plane's fleet
// view: its id, when it was first/last heard from, when it last pulled policy,
// how many analytics events it has forwarded, and whether it is currently online.
type WorkerView struct {
	ProxyID         string `json:"proxyID"`
	FirstSeen       string `json:"firstSeen"`
	LastSeen        string `json:"lastSeen"`
	LastPolicyPull  string `json:"lastPolicyPull,omitempty"`
	EventsForwarded int64  `json:"eventsForwarded"`
	// PolicyETag is the worker's current policy version; Behind is true when it
	// differs from the policy the control plane is currently serving.
	PolicyETag string `json:"policyETag,omitempty"`
	Behind     bool   `json:"behind"`
	Online     bool   `json:"online"`
}

// NewServer constructs a dashboard Server. The policy argument is the static
// startup policy used for the secret-usage view; for the allow/deny policy
// panel prefer SetLivePolicy so the dashboard reflects hot-reloaded policy.
func NewServer(data DataSource, policy config.Policy, sec secrets.SecretProvider) *Server {
	return &Server{
		data:    data,
		policy:  policy,
		secrets: sec,
	}
}

// SetMCPProvider attaches the MCP gateway view to the dashboard. Passing nil (or
// never calling it) leaves the MCP view in its disabled state.
func (s *Server) SetMCPProvider(p MCPProvider) {
	s.mcp = p
}

// SetLivePolicy supplies a function returning the allow/deny policy currently in
// force, so the policy panel reflects control-plane hot-reloads instead of the
// startup snapshot. The function must return allow/deny only (no secrets).
func (s *Server) SetLivePolicy(fn func() config.Policy) {
	s.livePolicy = fn
}

// SetPolicyWriter enables editing allow/deny policy from the dashboard. It is a
// control-plane-only capability: when set, POST /dashboard/api/policy validates
// and applies the new policy via fn (which persists it so workers pull it on
// their next poll). Workers never set this, so they expose no policy-write path.
func (s *Server) SetPolicyWriter(fn func(config.Policy) error) {
	s.policyWriter = fn
}

// SetLiveSettings supplies a function returning the behavioral worker-config
// settings currently in force, so the settings panel reflects control-plane
// hot-reloads. Returning nil means "no settings distributed". The returned value
// is secret-free (config.SettingsWire carries env-name references only).
func (s *Server) SetLiveSettings(fn func() *config.SettingsWire) {
	s.liveSettings = fn
}

// SetSettingsWriter enables editing behavioral settings from the dashboard. Like
// SetPolicyWriter it is a control-plane-only capability: when set,
// POST /dashboard/api/settings validates and applies the new settings via fn
// (which persists them so workers pull them on their next poll). Workers never
// set this, so they expose no settings-write path.
func (s *Server) SetSettingsWriter(fn func(config.SettingsWire) error) {
	s.settingsWriter = fn
}

// SetWorkers supplies the "connected workers" rows for the fleet view. Set only
// on the control plane; when unset, the workers endpoint returns an empty list
// and the UI hides the panel.
func (s *Server) SetWorkers(fn func() []WorkerView) {
	s.workersFn = fn
}

// SetMCPFleet supplies a per-worker MCP source for the control-plane fleet view:
// fn(proxyID) returns that worker's inventory + observed schema (empty proxyID =
// most-recent worker). When set it supersedes the single-node MCP gateway, so the
// MCP panel follows the dashboard's worker selector.
func (s *Server) SetMCPFleet(fn func(proxyID string) ([]gateway.InventoryItem, map[string]mcp.ToolProfileView)) {
	s.mcpFleet = fn
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

// endpointGroup is one aggregated (method, url) row in the endpoints response.
type endpointGroup struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	Domain       string `json:"domain"`
	Count        int    `json:"count"`
	FirstSeen    string `json:"firstSeen"`
	LastSeen     string `json:"lastSeen"`
	LastDecision string `json:"lastDecision"`
	LastStatus   int    `json:"lastStatus"`
}

// endpointsResponse is the paginated payload for /dashboard/api/endpoints.
type endpointsResponse struct {
	Items      []endpointGroup `json:"items"`
	Page       int             `json:"page"`
	PageSize   int             `json:"pageSize"`
	Total      int             `json:"total"`
	TotalPages int             `json:"totalPages"`
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
	// Editable reports whether this dashboard can save policy changes (true only
	// on the control plane, where a policy writer is configured).
	Editable bool `json:"editable"`
}

// policyEditRequest is the body accepted by POST /dashboard/api/policy.
type policyEditRequest struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
}

// settingsResponse is the payload for GET /dashboard/api/settings. Settings is
// nil when no behavioral settings are distributed. Editable reports whether this
// dashboard can save settings changes (true only on the control plane, where a
// settings writer is configured).
type settingsResponse struct {
	Settings *config.SettingsWire `json:"settings"`
	Editable bool                 `json:"editable"`
}

// Handler returns an http.Handler that serves the dashboard routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/api/traffic", s.handleTraffic)
	mux.HandleFunc("/dashboard/api/policy", s.handlePolicy)
	mux.HandleFunc("/dashboard/api/settings", s.handleSettings)
	mux.HandleFunc("/dashboard/api/secrets", s.handleSecrets)
	mux.HandleFunc("/dashboard/api/blocked", s.handleBlocked)
	mux.HandleFunc("/dashboard/api/endpoints", s.handleEndpoints)
	mux.HandleFunc("/dashboard/api/stats", s.handleStats)
	mux.HandleFunc("/dashboard/api/analytics", s.handleAnalytics)
	mux.HandleFunc("/dashboard/api/mcp", s.handleMCP)
	mux.HandleFunc("/dashboard/api/workers", s.handleWorkers)
	mux.HandleFunc("/dashboard/", s.handleIndex)
	return mux
}

// rangeWindows maps a ?range= token to a finite lookback duration. Only these
// tokens are honored; "all", empty, or anything else means no time filter.
var rangeWindows = map[string]time.Duration{
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

// rangeCutoff maps a ?range= token to a cutoff time relative to now.
// It returns (cutoff, true) for a known finite range, or (zero, false)
// for "all", missing, or any unrecognized value (meaning: no time filter).
func rangeCutoff(rangeParam string, now time.Time) (time.Time, bool) {
	if d, ok := rangeWindows[rangeParam]; ok {
		return now.Add(-d), true
	}
	return time.Time{}, false
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
	switch r.Method {
	case http.MethodGet:
		s.getPolicy(w, r)
	case http.MethodPost, http.MethodPut:
		s.putPolicy(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	// Prefer the live (hot-reloadable) policy so the panel matches what is
	// actually being enforced; fall back to the startup snapshot.
	pol := s.policy
	if s.livePolicy != nil {
		pol = s.livePolicy()
	}
	resp := policyResponse{
		Allowlist: pol.Allowlist,
		Denylist:  pol.Denylist,
		Editable:  s.policyWriter != nil,
	}
	if resp.Allowlist == nil {
		resp.Allowlist = []config.AllowlistEntry{}
	}
	if resp.Denylist == nil {
		resp.Denylist = []config.DenylistEntry{}
	}
	writeJSON(w, resp)
}

// putPolicy applies an edited allow/deny policy. It exists only where a policy
// writer is configured (the control plane); on a worker it returns 405 so policy
// is never mutable from the data plane. The writer validates and persists, so an
// invalid edit is rejected here with the validation error.
func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	if s.policyWriter == nil {
		writeError(w, http.StatusMethodNotAllowed, "policy editing is not available on this dashboard")
		return
	}
	var req policyEditRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	pol := config.Policy{Allowlist: req.Allowlist, Denylist: req.Denylist}
	if err := s.policyWriter(pol); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Echo back the now-current policy so the UI can refresh from the response.
	s.getPolicy(w, r)
}

// handleSettings serves GET/POST/PUT /dashboard/api/settings: the behavioral
// worker-config (mcp/judge/observability/…) editor. GET returns the live
// settings plus an editable flag; POST/PUT applies a full settings document. The
// POST carries the WHOLE document (the UI does read-modify-write) so later phases
// add blocks to the same endpoint without a new route.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getSettings(w, r)
	case http.MethodPost, http.MethodPut:
		s.putSettings(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	var settings *config.SettingsWire
	if s.liveSettings != nil {
		settings = s.liveSettings()
	}
	writeJSON(w, settingsResponse{
		Settings: settings,
		Editable: s.settingsWriter != nil,
	})
}

// putSettings applies an edited settings document. Like putPolicy it exists only
// where a writer is configured (the control plane); on a worker it returns 405 so
// settings are never mutable from the data plane. The writer validates and
// persists, so an invalid edit is rejected here with the validation error.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	if s.settingsWriter == nil {
		writeError(w, http.StatusMethodNotAllowed, "settings editing is not available on this dashboard")
		return
	}
	var settings config.SettingsWire
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.settingsWriter(settings); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Echo back the now-current settings so the UI can refresh from the response.
	s.getSettings(w, r)
}

// handleWorkers serves GET /dashboard/api/workers: the connected-workers list
// for the fleet view. Empty (non-nil) on a worker dashboard, which hides the panel.
func (s *Server) handleWorkers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	workers := []WorkerView{}
	if s.workersFn != nil {
		workers = s.workersFn()
	}
	writeJSON(w, workers)
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

// handleEndpoints serves GET /dashboard/api/endpoints. It collapses repeated
// hits to the same (method, url) into a single aggregated, paginated row so a
// polling agent that hammers one endpoint shows up as one informative entry
// rather than flooding the traffic view.
//
// Aggregation runs in-Go over all events, mirroring handleBlocked; this is fine
// for a single-node local dashboard. A SQL GROUP BY in the analytics store
// would be the future optimization at large scale.
func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	q := r.URL.Query()
	page := 1
	if n, err := strconv.Atoi(q.Get("page")); err == nil && n > 0 {
		page = n
	}
	pageSize := 50
	if n, err := strconv.Atoi(q.Get("pageSize")); err == nil && n > 0 {
		pageSize = n
	}
	if pageSize < 1 {
		pageSize = 1
	}
	if pageSize > 200 {
		pageSize = 200
	}

	// Optional domain filter for the domain→endpoints drill-down.
	domainFilter := q.Get("domain")

	// Optional time-window filter, mirroring handleAnalytics.
	cutoff, finite := rangeCutoff(q.Get("range"), time.Now())

	// Limit 0 means no cap — aggregate over every recorded event.
	f := analytics.EventFilter{Domain: domainFilter, ProxyID: q.Get("proxy"), Limit: 0}
	if finite {
		f.Since = cutoff
	}
	events, err := s.data.GetEvents(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type groupInfo struct {
		domain       string
		method       string
		url          string
		count        int
		firstSeen    time.Time
		lastSeen     time.Time
		lastDecision string
		lastStatus   int
	}
	grouped := make(map[string]*groupInfo)
	for _, e := range events {
		key := e.Method + " " + e.URL
		info, ok := grouped[key]
		if !ok {
			grouped[key] = &groupInfo{
				domain:       e.Domain,
				method:       e.Method,
				url:          e.URL,
				count:        1,
				firstSeen:    e.Timestamp,
				lastSeen:     e.Timestamp,
				lastDecision: e.Decision,
				lastStatus:   e.ResponseStatus,
			}
			continue
		}
		info.count++
		if e.Timestamp.Before(info.firstSeen) {
			info.firstSeen = e.Timestamp
		}
		if !e.Timestamp.Before(info.lastSeen) {
			// On ties keep the latest-iterated event as "most recent".
			info.lastSeen = e.Timestamp
			info.lastDecision = e.Decision
			info.lastStatus = e.ResponseStatus
		}
	}

	groups := make([]*groupInfo, 0, len(grouped))
	for _, info := range grouped {
		groups = append(groups, info)
	}
	sort.Slice(groups, func(i, j int) bool {
		if !groups[i].lastSeen.Equal(groups[j].lastSeen) {
			return groups[i].lastSeen.After(groups[j].lastSeen)
		}
		return groups[i].count > groups[j].count
	})

	all := make([]endpointGroup, 0, len(groups))
	for _, info := range groups {
		all = append(all, endpointGroup{
			URL:          info.url,
			Method:       info.method,
			Domain:       info.domain,
			Count:        info.count,
			FirstSeen:    info.firstSeen.Format(time.RFC3339),
			LastSeen:     info.lastSeen.Format(time.RFC3339),
			LastDecision: info.lastDecision,
			LastStatus:   info.lastStatus,
		})
	}

	total := len(all)
	totalPages := (total + pageSize - 1) / pageSize
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items := all[start:end]
	if items == nil {
		items = []endpointGroup{}
	}

	writeJSON(w, endpointsResponse{
		Items:      items,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	})
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

// --- analytics aggregate types ---

type analyticsTotals struct {
	Requests        int `json:"requests"`
	Allowed         int `json:"allowed"`
	Denied          int `json:"denied"`
	UniqueDomains   int `json:"uniqueDomains"`
	UniqueEndpoints int `json:"uniqueEndpoints"`
	Writes          int `json:"writes"`
	NewDomainsToday int `json:"newDomainsToday"`
	NewDenials      int `json:"newDenials"`
}

type statusClasses struct {
	C2xx  int `json:"2xx"`
	C3xx  int `json:"3xx"`
	C4xx  int `json:"4xx"`
	C5xx  int `json:"5xx"`
	Other int `json:"other"`
}

type methodCount struct {
	Method string `json:"method"`
	Count  int    `json:"count"`
}

type protocolCount struct {
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
}

type timelineBucket struct {
	Bucket string `json:"bucket"`
	Allow  int    `json:"allow"`
	Deny   int    `json:"deny"`
}

type hourlyBucket struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type topDomain struct {
	Domain    string `json:"domain"`
	Count     int    `json:"count"`
	Endpoints int    `json:"endpoints"`
	Allowed   int    `json:"allowed"`
	Denied    int    `json:"denied"`
	LastSeen  string `json:"lastSeen"`
}

type topEndpoint struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Domain     string `json:"domain"`
	Count      int    `json:"count"`
	LastStatus int    `json:"lastStatus"`
	LastSeen   string `json:"lastSeen"`
}

type secretUsage struct {
	Ref     string   `json:"ref"`
	Count   int      `json:"count"`
	Domains []string `json:"domains"`
}

type judgeEntry struct {
	Time     string `json:"time"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type writeEntry struct {
	Method     string `json:"method"`
	Domain     string `json:"domain"`
	URL        string `json:"url"`
	Count      int    `json:"count"`
	LastStatus int    `json:"lastStatus"`
}

type analyticsResponse struct {
	GeneratedAt   string           `json:"generatedAt"`
	Totals        analyticsTotals  `json:"totals"`
	StatusClasses statusClasses    `json:"statusClasses"`
	Methods       []methodCount    `json:"methods"`
	Protocols     []protocolCount  `json:"protocols"`
	Timeline      []timelineBucket `json:"timeline"`
	Hourly        []hourlyBucket   `json:"hourly"`
	TopDomains    []topDomain      `json:"topDomains"`
	TopEndpoints  []topEndpoint    `json:"topEndpoints"`
	Blocked       []blockedGroup   `json:"blocked"`
	Secrets       []secretUsage    `json:"secrets"`
	Judge         []judgeEntry     `json:"judge"`
	Writes        []writeEntry     `json:"writes"`
	Cost          costSummary      `json:"cost"`
	Compliance    []complianceTag  `json:"compliance"`
	// Proxies is the per-worker breakdown for a fleet (aggregator) view. Empty on
	// a single-node dashboard. SelectedProxy echoes the active ?proxy= filter.
	Proxies       []proxyCount `json:"proxies"`
	SelectedProxy string       `json:"selectedProxy"`
}

// proxyCount is one worker's contribution to the fleet, for the proxy selector.
type proxyCount struct {
	ProxyID string `json:"proxyID"`
	Count   int    `json:"count"`
	Allowed int    `json:"allowed"`
	Denied  int    `json:"denied"`
}

// costSummary aggregates estimated LLM spend over the selected window. Figures
// are heuristic (bytes/4 ≈ tokens × provider pricing), never billing-grade.
type costSummary struct {
	TotalUSD   float64        `json:"totalUSD"`
	ByProvider []providerCost `json:"byProvider"`
}

// providerCost is the estimated spend attributed to one LLM provider.
type providerCost struct {
	Provider string  `json:"provider"`
	CostUSD  float64 `json:"costUSD"`
	Requests int     `json:"requests"`
}

// complianceTag is one OWASP/MITRE control ID and how many events mapped to it.
type complianceTag struct {
	ControlID string `json:"controlID"`
	Count     int    `json:"count"`
}

// isWriteMethod reports whether an HTTP method mutates remote state (non-GET,
// non-HEAD). These are the data-modification / exfil-risk egress calls.
func isWriteMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "":
		return false
	default:
		return true
	}
}

// timelineBuckets distributes events across ~30 even buckets spanning the
// min..max timestamp, tallying allow/deny per bucket. It handles the 0-event
// and single-instant cases gracefully (returns one bucket when the span is
// zero or there is only one event).
func timelineBuckets(events []analytics.Event) []timelineBucket {
	out := []timelineBucket{}
	if len(events) == 0 {
		return out
	}
	minT, maxT := events[0].Timestamp, events[0].Timestamp
	for _, e := range events {
		if e.Timestamp.Before(minT) {
			minT = e.Timestamp
		}
		if e.Timestamp.After(maxT) {
			maxT = e.Timestamp
		}
	}
	const nBuckets = 30
	span := maxT.Sub(minT)
	if span <= 0 {
		// All events share ~one instant: a single bucket.
		b := timelineBucket{Bucket: minT.Format(time.RFC3339)}
		for _, e := range events {
			if e.Decision == "deny" {
				b.Deny++
			} else {
				b.Allow++
			}
		}
		return append(out, b)
	}
	step := span / nBuckets
	if step <= 0 {
		step = 1
	}
	buckets := make([]timelineBucket, nBuckets)
	for i := range buckets {
		buckets[i].Bucket = minT.Add(time.Duration(i) * step).Format(time.RFC3339)
	}
	for _, e := range events {
		idx := int(e.Timestamp.Sub(minT) / step)
		if idx < 0 {
			idx = 0
		}
		if idx >= nBuckets {
			idx = nBuckets - 1
		}
		if e.Decision == "deny" {
			buckets[idx].Deny++
		} else {
			buckets[idx].Allow++
		}
	}
	return append(out, buckets...)
}

// timelineBucketsWindow distributes events across ~30 even buckets spanning the
// FIXED window [start, end], tallying allow/deny per bucket. Unlike
// timelineBuckets it does not derive the span from the events, so the x-axis
// covers the whole selected range and sparse periods render as gaps. Events
// outside [start, end] are clamped into the first/last bucket.
func timelineBucketsWindow(events []analytics.Event, start, end time.Time) []timelineBucket {
	out := []timelineBucket{}
	const nBuckets = 30
	span := end.Sub(start)
	if span <= 0 {
		// Degenerate window: a single bucket holding every event.
		b := timelineBucket{Bucket: start.Format(time.RFC3339)}
		for _, e := range events {
			if e.Decision == "deny" {
				b.Deny++
			} else {
				b.Allow++
			}
		}
		return append(out, b)
	}
	step := span / nBuckets
	if step <= 0 {
		step = 1
	}
	buckets := make([]timelineBucket, nBuckets)
	for i := range buckets {
		buckets[i].Bucket = start.Add(time.Duration(i) * step).Format(time.RFC3339)
	}
	for _, e := range events {
		idx := int(e.Timestamp.Sub(start) / step)
		if idx < 0 {
			idx = 0
		}
		if idx >= nBuckets {
			idx = nBuckets - 1
		}
		if e.Decision == "deny" {
			buckets[idx].Deny++
		} else {
			buckets[idx].Allow++
		}
	}
	return append(out, buckets...)
}

// handleAnalytics serves GET /dashboard/api/analytics: a single aggregate
// payload computed in one pass over all recorded events. Empty DB yields zeroed
// totals and empty (non-nil) arrays.
// proxyBreakdown tallies events per originating worker for the fleet selector,
// sorted by count desc then id. Events with no proxy id (single node) are
// ignored, so the result is empty for a non-fleet dashboard.
func proxyBreakdown(events []analytics.Event) []proxyCount {
	byProxy := make(map[string]*proxyCount)
	for _, e := range events {
		if e.ProxyID == "" {
			continue
		}
		pc, ok := byProxy[e.ProxyID]
		if !ok {
			pc = &proxyCount{ProxyID: e.ProxyID}
			byProxy[e.ProxyID] = pc
		}
		pc.Count++
		switch e.Decision {
		case "allow":
			pc.Allowed++
		case "deny":
			pc.Denied++
		}
	}
	out := make([]proxyCount, 0, len(byProxy))
	for _, pc := range byProxy {
		out = append(out, *pc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ProxyID < out[j].ProxyID
	})
	return out
}

// filterByProxy returns only the events from the named worker.
func filterByProxy(events []analytics.Event, proxyID string) []analytics.Event {
	out := make([]analytics.Event, 0, len(events))
	for _, e := range events {
		if e.ProxyID == proxyID {
			out = append(out, e)
		}
	}
	return out
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	now := time.Now()
	q := r.URL.Query()
	cutoff, finite := rangeCutoff(q.Get("range"), now)

	f := analytics.EventFilter{Limit: 0}
	if finite {
		f.Since = cutoff
	}
	events, err := s.data.GetEvents(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Fleet per-proxy breakdown is computed across ALL in-range events so the
	// selector always lists every worker; the rest of the view then reflects the
	// selected proxy (empty = whole fleet). On a single-node dashboard no event
	// carries a proxy id, so proxies is empty and the UI hides the selector.
	selectedProxy := q.Get("proxy")
	proxies := proxyBreakdown(events)
	if selectedProxy != "" {
		events = filterByProxy(events, selectedProxy)
	}

	dayAgo := now.Add(-24 * time.Hour)

	resp := analyticsResponse{
		GeneratedAt:   now.Format(time.RFC3339),
		Methods:       []methodCount{},
		Protocols:     []protocolCount{},
		Timeline:      []timelineBucket{},
		Hourly:        make([]hourlyBucket, 24),
		TopDomains:    []topDomain{},
		TopEndpoints:  []topEndpoint{},
		Blocked:       []blockedGroup{},
		Secrets:       []secretUsage{},
		Judge:         []judgeEntry{},
		Writes:        []writeEntry{},
		Cost:          costSummary{ByProvider: []providerCost{}},
		Compliance:    []complianceTag{},
		Proxies:       proxies,
		SelectedProxy: selectedProxy,
	}
	providerCosts := make(map[string]*providerCost)
	complianceCounts := make(map[string]int)
	for h := 0; h < 24; h++ {
		resp.Hourly[h].Hour = h
	}

	methodCounts := make(map[string]int)
	protocolCounts := make(map[string]int)

	type domAgg struct {
		count      int
		allowed    int
		denied     int
		firstSeen  time.Time
		lastSeen   time.Time
		endpoints  map[string]struct{}
		firstIsDen bool // decision of the chronologically-first event
	}
	domains := make(map[string]*domAgg)

	type endpAgg struct {
		method     string
		url        string
		domain     string
		count      int
		lastSeen   time.Time
		lastStatus int
	}
	endpoints := make(map[string]*endpAgg)

	type blockedAgg struct {
		count     int
		firstSeen time.Time
		lastSeen  time.Time
	}
	blocked := make(map[string]*blockedAgg)

	type secretAgg struct {
		count   int
		domains map[string]struct{}
	}
	secretMap := make(map[string]*secretAgg)

	type writeAgg struct {
		method     string
		domain     string
		url        string
		count      int
		lastSeen   time.Time
		lastStatus int
	}
	writeMap := make(map[string]*writeAgg)

	var judges []judgeEntry

	for _, e := range events {
		resp.Totals.Requests++
		switch e.Decision {
		case "allow":
			resp.Totals.Allowed++
		case "deny":
			resp.Totals.Denied++
		}

		// Status classes.
		switch {
		case e.ResponseStatus >= 200 && e.ResponseStatus < 300:
			resp.StatusClasses.C2xx++
		case e.ResponseStatus >= 300 && e.ResponseStatus < 400:
			resp.StatusClasses.C3xx++
		case e.ResponseStatus >= 400 && e.ResponseStatus < 500:
			resp.StatusClasses.C4xx++
		case e.ResponseStatus >= 500 && e.ResponseStatus < 600:
			resp.StatusClasses.C5xx++
		default:
			resp.StatusClasses.Other++
		}

		methodCounts[strings.ToUpper(e.Method)]++
		protocolCounts[e.Protocol]++

		resp.Hourly[e.Timestamp.Local().Hour()].Count++

		// Domains.
		d, ok := domains[e.Domain]
		if !ok {
			d = &domAgg{firstSeen: e.Timestamp, lastSeen: e.Timestamp, endpoints: map[string]struct{}{}, firstIsDen: e.Decision == "deny"}
			domains[e.Domain] = d
		}
		d.count++
		switch e.Decision {
		case "allow":
			d.allowed++
		case "deny":
			d.denied++
		}
		if e.Timestamp.Before(d.firstSeen) {
			d.firstSeen = e.Timestamp
			d.firstIsDen = e.Decision == "deny"
		}
		if e.Timestamp.After(d.lastSeen) {
			d.lastSeen = e.Timestamp
		}
		d.endpoints[e.Method+" "+e.URL] = struct{}{}

		// Endpoints.
		ekey := e.Method + " " + e.URL
		ep, ok := endpoints[ekey]
		if !ok {
			ep = &endpAgg{method: e.Method, url: e.URL, domain: e.Domain, lastSeen: e.Timestamp, lastStatus: e.ResponseStatus}
			endpoints[ekey] = ep
		}
		ep.count++
		if !e.Timestamp.Before(ep.lastSeen) {
			ep.lastSeen = e.Timestamp
			ep.lastStatus = e.ResponseStatus
		}

		// Blocked (denied) grouped by domain.
		if e.Decision == "deny" {
			b, ok := blocked[e.Domain]
			if !ok {
				b = &blockedAgg{firstSeen: e.Timestamp, lastSeen: e.Timestamp}
				blocked[e.Domain] = b
			}
			b.count++
			if e.Timestamp.Before(b.firstSeen) {
				b.firstSeen = e.Timestamp
			}
			if e.Timestamp.After(b.lastSeen) {
				b.lastSeen = e.Timestamp
			}
		}

		// Secrets by reference.
		if e.SecretRef != "" {
			sa, ok := secretMap[e.SecretRef]
			if !ok {
				sa = &secretAgg{domains: map[string]struct{}{}}
				secretMap[e.SecretRef] = sa
			}
			sa.count++
			sa.domains[e.Domain] = struct{}{}
		}

		// Judge log.
		if e.JudgeReason != "" {
			judges = append(judges, judgeEntry{
				Time:     e.Timestamp.Format(time.RFC3339),
				Method:   e.Method,
				URL:      e.URL,
				Decision: e.Decision,
				Reason:   e.JudgeReason,
			})
		}

		// Writes (non-GET/HEAD egress).
		if isWriteMethod(e.Method) {
			wkey := e.Method + " " + e.URL
			wa, ok := writeMap[wkey]
			if !ok {
				wa = &writeAgg{method: e.Method, domain: e.Domain, url: e.URL, lastSeen: e.Timestamp, lastStatus: e.ResponseStatus}
				writeMap[wkey] = wa
			}
			wa.count++
			if !e.Timestamp.Before(wa.lastSeen) {
				wa.lastSeen = e.Timestamp
				wa.lastStatus = e.ResponseStatus
			}
		}

		// Estimated cost by provider.
		if e.Provider != "" {
			resp.Cost.TotalUSD += e.CostUSD
			pc, ok := providerCosts[e.Provider]
			if !ok {
				pc = &providerCost{Provider: e.Provider}
				providerCosts[e.Provider] = pc
			}
			pc.CostUSD += e.CostUSD
			pc.Requests++
		}

		// Compliance control-ID tally.
		for _, id := range e.Compliance {
			complianceCounts[id]++
		}
	}

	resp.Totals.UniqueDomains = len(domains)
	resp.Totals.UniqueEndpoints = len(endpoints)
	resp.Totals.Writes = len(writeMap)

	// New domains today / new denials in last 24h.
	for _, d := range domains {
		if d.firstSeen.After(dayAgo) {
			resp.Totals.NewDomainsToday++
			if d.firstIsDen {
				resp.Totals.NewDenials++
			}
		}
	}

	// Status timeline. For a finite range, bucket across the fixed [cutoff, now]
	// window so the x-axis spans the whole selection; otherwise bucket across
	// the events' own min..max span.
	if finite {
		resp.Timeline = timelineBucketsWindow(events, cutoff, now)
	} else {
		resp.Timeline = timelineBuckets(events)
	}

	// Methods sorted by count desc, then name.
	for m, c := range methodCounts {
		resp.Methods = append(resp.Methods, methodCount{Method: m, Count: c})
	}
	sort.Slice(resp.Methods, func(i, j int) bool {
		if resp.Methods[i].Count != resp.Methods[j].Count {
			return resp.Methods[i].Count > resp.Methods[j].Count
		}
		return resp.Methods[i].Method < resp.Methods[j].Method
	})

	// Protocols sorted by count desc, then name.
	for p, c := range protocolCounts {
		resp.Protocols = append(resp.Protocols, protocolCount{Protocol: p, Count: c})
	}
	sort.Slice(resp.Protocols, func(i, j int) bool {
		if resp.Protocols[i].Count != resp.Protocols[j].Count {
			return resp.Protocols[i].Count > resp.Protocols[j].Count
		}
		return resp.Protocols[i].Protocol < resp.Protocols[j].Protocol
	})

	// Top domains (top 12 by count).
	allDomains := make([]topDomain, 0, len(domains))
	for name, d := range domains {
		allDomains = append(allDomains, topDomain{
			Domain:    name,
			Count:     d.count,
			Endpoints: len(d.endpoints),
			Allowed:   d.allowed,
			Denied:    d.denied,
			LastSeen:  d.lastSeen.Format(time.RFC3339),
		})
	}
	sort.Slice(allDomains, func(i, j int) bool {
		if allDomains[i].Count != allDomains[j].Count {
			return allDomains[i].Count > allDomains[j].Count
		}
		return allDomains[i].Domain < allDomains[j].Domain
	})
	if len(allDomains) > 12 {
		allDomains = allDomains[:12]
	}
	resp.TopDomains = allDomains

	// Top endpoints (top 12 by count).
	allEndpoints := make([]topEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		allEndpoints = append(allEndpoints, topEndpoint{
			Method:     ep.method,
			URL:        ep.url,
			Domain:     ep.domain,
			Count:      ep.count,
			LastStatus: ep.lastStatus,
			LastSeen:   ep.lastSeen.Format(time.RFC3339),
		})
	}
	sort.Slice(allEndpoints, func(i, j int) bool {
		if allEndpoints[i].Count != allEndpoints[j].Count {
			return allEndpoints[i].Count > allEndpoints[j].Count
		}
		if allEndpoints[i].URL != allEndpoints[j].URL {
			return allEndpoints[i].URL < allEndpoints[j].URL
		}
		return allEndpoints[i].Method < allEndpoints[j].Method
	})
	if len(allEndpoints) > 12 {
		allEndpoints = allEndpoints[:12]
	}
	resp.TopEndpoints = allEndpoints

	// Blocked groups sorted by count desc, then domain.
	for name, b := range blocked {
		resp.Blocked = append(resp.Blocked, blockedGroup{
			Domain:    name,
			Count:     b.count,
			FirstSeen: b.firstSeen.Format(time.RFC3339),
			LastSeen:  b.lastSeen.Format(time.RFC3339),
		})
	}
	sort.Slice(resp.Blocked, func(i, j int) bool {
		if resp.Blocked[i].Count != resp.Blocked[j].Count {
			return resp.Blocked[i].Count > resp.Blocked[j].Count
		}
		return resp.Blocked[i].Domain < resp.Blocked[j].Domain
	})

	// Secrets grouped by ref, each with distinct destination domains (sorted).
	for ref, sa := range secretMap {
		doms := make([]string, 0, len(sa.domains))
		for d := range sa.domains {
			doms = append(doms, d)
		}
		sort.Strings(doms)
		resp.Secrets = append(resp.Secrets, secretUsage{Ref: ref, Count: sa.count, Domains: doms})
	}
	sort.Slice(resp.Secrets, func(i, j int) bool {
		if resp.Secrets[i].Count != resp.Secrets[j].Count {
			return resp.Secrets[i].Count > resp.Secrets[j].Count
		}
		return resp.Secrets[i].Ref < resp.Secrets[j].Ref
	})

	// Judge log: most-recent first, capped at 20. events arrive newest-first
	// from GetEvents, but we sort defensively to guarantee ordering.
	sort.SliceStable(judges, func(i, j int) bool {
		return judges[i].Time > judges[j].Time
	})
	if len(judges) > 20 {
		judges = judges[:20]
	}
	if judges != nil {
		resp.Judge = judges
	}

	// Writes (top 12 by count).
	allWrites := make([]writeEntry, 0, len(writeMap))
	for _, wa := range writeMap {
		allWrites = append(allWrites, writeEntry{
			Method:     wa.method,
			Domain:     wa.domain,
			URL:        wa.url,
			Count:      wa.count,
			LastStatus: wa.lastStatus,
		})
	}
	sort.Slice(allWrites, func(i, j int) bool {
		if allWrites[i].Count != allWrites[j].Count {
			return allWrites[i].Count > allWrites[j].Count
		}
		if allWrites[i].URL != allWrites[j].URL {
			return allWrites[i].URL < allWrites[j].URL
		}
		return allWrites[i].Method < allWrites[j].Method
	})
	if len(allWrites) > 12 {
		allWrites = allWrites[:12]
	}
	resp.Writes = allWrites

	// Estimated cost by provider, sorted by spend desc then name.
	for _, pc := range providerCosts {
		resp.Cost.ByProvider = append(resp.Cost.ByProvider, *pc)
	}
	sort.Slice(resp.Cost.ByProvider, func(i, j int) bool {
		if resp.Cost.ByProvider[i].CostUSD != resp.Cost.ByProvider[j].CostUSD {
			return resp.Cost.ByProvider[i].CostUSD > resp.Cost.ByProvider[j].CostUSD
		}
		return resp.Cost.ByProvider[i].Provider < resp.Cost.ByProvider[j].Provider
	})

	// Compliance control IDs, sorted by count desc then ID.
	for id, c := range complianceCounts {
		resp.Compliance = append(resp.Compliance, complianceTag{ControlID: id, Count: c})
	}
	sort.Slice(resp.Compliance, func(i, j int) bool {
		if resp.Compliance[i].Count != resp.Compliance[j].Count {
			return resp.Compliance[i].Count > resp.Compliance[j].Count
		}
		return resp.Compliance[i].ControlID < resp.Compliance[j].ControlID
	})

	writeJSON(w, resp)
}

// --- MCP view types ---

// mcpFieldView is one observed field path in a tool's request or response
// schema: its structural types, how many times it was seen, and the sensitivity
// classes it has ever carried. Value-free — paths and class tags only.
type mcpFieldView struct {
	Types       []string `json:"types"`
	SeenCount   int      `json:"seenCount"`
	Sensitivity []string `json:"sensitivity"`
}

// mcpToolView is one tool's combined row: identity from the inventory, call
// counts from mcp-tagged events, and the observed request/response schema with
// per-field sensitivity from the SchemaProfiler.
type mcpToolView struct {
	Tool           string                  `json:"tool"`
	Server         string                  `json:"server"` // MCP server domain(s) the tool was called on
	Present        bool                    `json:"present"`
	HasDescription bool                    `json:"hasDescription"`
	SchemaHash     string                  `json:"schemaHash"`
	FirstSeen      string                  `json:"firstSeen"`
	LastSeen       string                  `json:"lastSeen"`
	Calls          int                     `json:"calls"`
	Allowed        int                     `json:"allowed"`
	Denied         int                     `json:"denied"`
	Sensitive      []string                `json:"sensitive"`
	Findings       []string                `json:"findings"`
	RequestSchema  map[string]mcpFieldView `json:"requestSchema"`
	ResponseSchema map[string]mcpFieldView `json:"responseSchema"`
}

// mcpResponse is the payload for /dashboard/api/mcp.
type mcpResponse struct {
	Enabled bool          `json:"enabled"`
	Tools   []mcpToolView `json:"tools"`
}

// mcpAgg accumulates one tool's call counts and findings from mcp-tagged events.
type mcpAgg struct {
	calls    int
	allowed  int
	denied   int
	lastSeen time.Time
	findings map[string]struct{}
	servers  map[string]struct{} // MCP server domain(s) this tool was seen on
}

// handleMCP serves GET /dashboard/api/mcp: a per-tool view joining call counts
// (from mcp-tagged events), the gateway tool inventory, and the observed
// request/response schema with per-field sensitivity. It is metadata-only —
// every source is value-free, so nothing here can leak a tool argument or
// result. When no MCP provider is attached the schema/inventory sources are
// empty, but event-derived counts (if any) are still reported.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Inventory + observed schema source: a worker's own gateway, or — on the
	// control plane — the per-worker fleet store selected by ?proxy=.
	proxyID := r.URL.Query().Get("proxy")
	var (
		inv     []gateway.InventoryItem
		schema  map[string]mcp.ToolProfileView
		enabled bool
	)
	switch {
	case s.mcpFleet != nil:
		inv, schema = s.mcpFleet(proxyID)
		enabled = true
	case s.mcp != nil:
		inv, schema = s.mcp.Inventory(), s.mcp.SchemaSnapshot()
		enabled = true
	}

	// Counts + findings from mcp-tagged events, aggregated in-Go by tool. On the
	// control plane the proxy filter scopes counts to the selected worker.
	events, err := s.data.GetEvents(analytics.EventFilter{Protocol: "mcp", ProxyID: proxyID, Limit: 0})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	aggs := make(map[string]*mcpAgg)
	for _, e := range events {
		if e.Tool == "" {
			continue
		}
		a, ok := aggs[e.Tool]
		if !ok {
			a = &mcpAgg{findings: map[string]struct{}{}, servers: map[string]struct{}{}}
			aggs[e.Tool] = a
		}
		if e.Domain != "" {
			a.servers[e.Domain] = struct{}{}
		}
		a.calls++
		switch e.Decision {
		case "allow":
			a.allowed++
		case "deny":
			a.denied++
		}
		if e.Timestamp.After(a.lastSeen) {
			a.lastSeen = e.Timestamp
		}
		if e.Reason != "" {
			a.findings[e.Reason] = struct{}{}
		}
	}

	// Build the per-tool rows, keyed by tool name across all three sources.
	rows := make(map[string]*mcpToolView)
	row := func(tool string) *mcpToolView {
		v, ok := rows[tool]
		if !ok {
			v = &mcpToolView{
				Tool:           tool,
				Sensitive:      []string{},
				Findings:       []string{},
				RequestSchema:  map[string]mcpFieldView{},
				ResponseSchema: map[string]mcpFieldView{},
			}
			rows[tool] = v
		}
		return v
	}

	// Inventory (present-but-uncalled tools appear here with 0 calls).
	for _, it := range inv {
		v := row(it.Name)
		v.Present = true
		v.HasDescription = it.HasDescription
		v.SchemaHash = it.InputSchemaHash
		if it.Server != "" {
			v.Server = it.Server // the MCP server that declared this tool
		}
		if !it.FirstSeen.IsZero() {
			v.FirstSeen = it.FirstSeen.Format(time.RFC3339)
		}
		if !it.LastSeen.IsZero() {
			v.LastSeen = it.LastSeen.Format(time.RFC3339)
		}
	}

	// Counts + findings.
	for tool, a := range aggs {
		v := row(tool)
		v.Calls = a.calls
		v.Allowed = a.allowed
		v.Denied = a.denied
		if !a.lastSeen.IsZero() {
			ls := a.lastSeen.Format(time.RFC3339)
			// Prefer the most recent of inventory vs event last-seen.
			if v.LastSeen == "" || ls > v.LastSeen {
				v.LastSeen = ls
			}
		}
		findings := make([]string, 0, len(a.findings))
		for f := range a.findings {
			findings = append(findings, f)
		}
		sort.Strings(findings)
		v.Findings = findings

		// Fall back to the server(s) seen on this tool's events when the gateway
		// inventory didn't supply one (e.g. a tools/call with no prior tools/list).
		if v.Server == "" {
			servers := make([]string, 0, len(a.servers))
			for s := range a.servers {
				servers = append(servers, s)
			}
			sort.Strings(servers)
			v.Server = strings.Join(servers, ", ")
		}
	}

	// Observed schema + per-field sensitivity. Keys are "tool\x00direction".
	for key, prof := range schema {
		tool, dir, ok := splitProfileKey(key)
		if !ok {
			continue
		}
		v := row(tool)
		dst := v.RequestSchema
		if dir == string(mcp.DirResponse) {
			dst = v.ResponseSchema
		}
		sensitive := map[string]struct{}{}
		for path, fp := range prof.Fields {
			dst[path] = mcpFieldView{
				Types:       fp.Types,
				SeenCount:   fp.SeenCount,
				Sensitivity: fp.Sensitivity,
			}
			for _, c := range fp.Sensitivity {
				sensitive[c] = struct{}{}
			}
		}
		// Union the tool-level sensitive classes across request + response.
		merged := map[string]struct{}{}
		for _, c := range v.Sensitive {
			merged[c] = struct{}{}
		}
		for c := range sensitive {
			merged[c] = struct{}{}
		}
		classes := make([]string, 0, len(merged))
		for c := range merged {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		v.Sensitive = classes
	}

	tools := make([]mcpToolView, 0, len(rows))
	for _, v := range rows {
		tools = append(tools, *v)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Tool < tools[j].Tool })

	writeJSON(w, mcpResponse{
		Enabled: enabled,
		Tools:   tools,
	})
}

// splitProfileKey splits a SchemaSnapshot key of the form "tool\x00direction"
// into its parts. It returns ok=false for a malformed key.
func splitProfileKey(key string) (tool, direction string, ok bool) {
	i := strings.IndexByte(key, '\x00')
	if i < 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
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
