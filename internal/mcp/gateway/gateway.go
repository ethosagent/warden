// Package gateway is the MCP verdict engine: it ties the individual MCP
// analyzers (tool policy, schema profiling, declared-schema drift, poisoning,
// per-field scanning, and call-chain analysis) into a single OnRequest /
// OnResponse pair that returns a rich Verdict the proxy and analytics consume.
//
// It owns a bounded, thread-safe per-session registry (declared-schema store +
// call-chain analyzer + JSON-RPC id->tool correlation) and applies the
// off/monitor/enforce modes. Analysis is fail-open by default (an analyzer bug
// never takes down egress); fail-closed is opt-in. Every entry point is wrapped
// in panic recovery.
package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/scan"
)

// Action is the gateway's blocking decision.
type Action int

const (
	// Pass allows the message through.
	Pass Action = iota
	// Deny blocks the message; only ever returned in enforce mode.
	Deny
)

// Finding is one bounded, value-free analyzer observation. Detail is a short,
// bounded description and never carries a tool argument or result value.
type Finding struct {
	// Kind is the bounded finding category. One of: "mcp_tool_denied",
	// "mcp_poisoning", "mcp_schema_drift", "mcp_args_injection", "mcp_args_leak",
	// "mcp_args_pii", "mcp_chain_<pattern>", "mcp_result_injection",
	// "mcp_result_leak", "mcp_result_pii".
	Kind     string
	Severity string // "high"|"medium"|"low"
	Tool     string
	Path     string // field path when applicable, else ""
	Detail   string // SHORT, bounded — never a tool arg/result value
}

// ToolInfo is one tool's identity in a tools/list inventory.
type ToolInfo struct {
	Name            string
	HasDescription  bool
	InputSchemaHash string // sha256 hex of InputSchema
}

// InventoryItem is one tool retained across tools/list responses, with the
// first/last time the gateway observed it. It is content-free metadata: a tool
// name, a description-present flag, and a schema hash — never a description, an
// argument, or a result value.
type InventoryItem struct {
	Name            string
	HasDescription  bool
	InputSchemaHash string
	FirstSeen       time.Time
	LastSeen        time.Time
}

// Verdict is the gateway's full response for one message. Findings is always
// populated (for analytics) even when Action is Pass.
type Verdict struct {
	Action    Action     // Deny only in enforce mode for a blocking condition
	Reason    string     // the dominant Finding.Kind that caused a Deny (or "")
	Tool      string     // tool name for tools/call, else ""
	Method    string     // JSON-RPC method observed ("tools/call","tools/list",...)
	Findings  []Finding  // ALWAYS populated (for analytics), even when Action==Pass
	Inventory []ToolInfo // populated on a tools/list response (for persistence)
}

const (
	modeOff     = "off"
	modeMonitor = "monitor"
	modeEnforce = "enforce"

	maxSessions     = 1024
	sessionTTL      = 30 * time.Minute
	maxIDToToolSize = 256
)

// session holds the per-conversation analyzer state. All access is guarded by
// the Gateway mutex.
type session struct {
	schema      *mcp.SchemaStore
	baselineSet bool // whether schema baseline has been captured
	chain       *mcp.CallChainAnalyzer
	idToTool    map[string]string // JSON-RPC id -> tool, bounded
	idOrder     []string          // FIFO order of idToTool keys for bounded eviction
	lastSeen    time.Time
}

// Gateway is the MCP verdict engine. It is safe for concurrent use.
type Gateway struct {
	cfg      config.MCPConfig
	scanner  *scan.Scanner
	policy   *mcp.ToolPolicy
	profiler *mcp.SchemaProfiler
	log      *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session

	// inventory is the gateway-wide, cross-session tool catalog accumulated from
	// every tools/list response, keyed by tool name. Guarded by g.mu.
	inventory map[string]*InventoryItem

	now func() time.Time // injectable clock for tests; default time.Now
}

// New builds a Gateway from cfg. The scanner is owned by the caller (the proxy);
// in tests construct one via scan.NewScanner honoring cfg.Scan.PII.Phone. The
// shared tool policy and (optional) schema profiler are built here.
func New(cfg config.MCPConfig, scanner *scan.Scanner, log *slog.Logger) *Gateway {
	if log == nil {
		log = slog.Default()
	}
	policy := mcp.NewToolPolicy(cfg.Tools.Allow, cfg.Tools.Deny, toPerMinute(cfg.Tools.RateLimit))
	var profiler *mcp.SchemaProfiler
	if cfg.Scan.ProfileSchema {
		profiler = mcp.NewSchemaProfiler(0)
	}
	return &Gateway{
		cfg:       cfg,
		scanner:   scanner,
		policy:    policy,
		profiler:  profiler,
		log:       log,
		sessions:  make(map[string]*session),
		inventory: make(map[string]*InventoryItem),
		now:       time.Now,
	}
}

// toPerMinute converts the config "N/period" rate strings into the per-minute
// integer limits ToolPolicy expects. Invalid entries are skipped (config
// validation already rejects them); the conversion is intentionally tolerant.
func toPerMinute(rl map[string]string) map[string]int {
	if len(rl) == 0 {
		return nil
	}
	out := make(map[string]int, len(rl))
	for tool, raw := range rl {
		parts := strings.SplitN(raw, "/", 2)
		if len(parts) != 2 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || n < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(parts[1])) {
		case "second":
			out[tool] = n * 60
		case "minute":
			out[tool] = n
		case "hour":
			v := n / 60
			if v < 1 {
				v = 1
			}
			out[tool] = v
		}
	}
	return out
}

// disabled reports whether the gateway should no-op (return Pass immediately).
func (g *Gateway) disabled() bool {
	return !g.cfg.Enabled || g.cfg.Mode == modeOff
}

// failVerdict builds the fail-open / fail-closed verdict used on parse errors
// and recovered panics. method may be "".
func (g *Gateway) failVerdict(method, tool string) Verdict {
	v := Verdict{Action: Pass, Method: method, Tool: tool}
	if g.cfg.FailClosedOnError {
		v.Action = g.applyMode(true)
		if v.Action == Deny {
			v.Reason = "mcp_fail_closed"
		}
	}
	return v
}

// applyMode maps a blocking decision through the active mode: only enforce can
// produce a Deny.
func (g *Gateway) applyMode(blocking bool) Action {
	if blocking && g.cfg.Mode == modeEnforce {
		return Deny
	}
	return Pass
}

// session returns the session for key, lazily creating it and pruning the
// registry. Caller must hold g.mu and supply the current time (computed outside
// the lock so a panicking clock cannot strand the mutex).
func (g *Gateway) sessionLocked(key string, now time.Time) *session {
	if s, ok := g.sessions[key]; ok {
		s.lastSeen = now
		return s
	}
	g.pruneLocked(now)
	s := &session{
		schema:   mcp.NewSchemaStore(g.cfg.Schema.Pin),
		chain:    mcp.NewCallChainAnalyzer(g.chainWindow()),
		idToTool: make(map[string]string),
		lastSeen: now,
	}
	g.sessions[key] = s
	return s
}

func (g *Gateway) chainWindow() int {
	if g.cfg.Chain.WindowSize > 0 {
		return g.cfg.Chain.WindowSize
	}
	return 50
}

// pruneLocked evicts idle sessions and, if still over the cap, the
// least-recently-seen session. Caller must hold g.mu.
func (g *Gateway) pruneLocked(now time.Time) {
	for key, s := range g.sessions {
		if now.Sub(s.lastSeen) > sessionTTL {
			delete(g.sessions, key)
		}
	}
	for len(g.sessions) >= maxSessions {
		var oldestKey string
		var oldest time.Time
		first := true
		for key, s := range g.sessions {
			if first || s.lastSeen.Before(oldest) {
				oldestKey, oldest, first = key, s.lastSeen, false
			}
		}
		if oldestKey == "" {
			break
		}
		delete(g.sessions, oldestKey)
	}
}

// recordID stores a bounded id->tool mapping for response correlation. Caller
// must hold g.mu.
func (s *session) recordID(id, tool string) {
	if id == "" {
		return
	}
	if _, ok := s.idToTool[id]; !ok {
		s.idOrder = append(s.idOrder, id)
		for len(s.idOrder) > maxIDToToolSize {
			drop := s.idOrder[0]
			s.idOrder = s.idOrder[1:]
			delete(s.idToTool, drop)
		}
	}
	s.idToTool[id] = tool
}

// OnRequest analyzes one outbound MCP request body and returns a Verdict.
func (g *Gateway) OnRequest(sessionKey, method, url string, hdr http.Header, body []byte) (v Verdict) {
	if g.disabled() {
		return Verdict{Action: Pass}
	}
	defer func() {
		if r := recover(); r != nil {
			g.log.Error("mcp gateway OnRequest panic", "panic", r)
			v = g.failVerdict(method, "")
		}
	}()

	tc, err := mcp.ParseToolCall(body)
	if err != nil {
		// Malformed JSON-RPC: best-effort method, fail-open (or closed).
		return g.failVerdict(rpcMethod(body), "")
	}
	if tc == nil {
		// A valid MCP method that is not tools/call. Phase 1 acts on tools/call.
		return Verdict{Action: Pass, Method: rpcMethod(body)}
	}

	tool := tc.Name
	var findings []Finding
	blocking := false
	dominant := ""

	now := g.now() // outside the lock: a panicking clock cannot strand the mutex
	g.mu.Lock()
	s := g.sessionLocked(sessionKey, now)
	s.recordID(tc.ID, tool)
	g.mu.Unlock()

	// Tool policy (default-deny).
	allowed := g.policy.Evaluate(tool)
	if !allowed {
		findings = append(findings, Finding{
			Kind:     "mcp_tool_denied",
			Severity: "high",
			Tool:     tool,
			Detail:   "tool not permitted by policy",
		})
		blocking = true
		dominant = "mcp_tool_denied"
	}

	// Per-field argument scanning + schema profiling.
	if g.cfg.Scan.ToolArgs && g.profiler != nil {
		params := rawField(body, "params")
		for _, fd := range g.profiler.Observe(tool, mcp.DirRequest, params, g.scanner) {
			kind := argKind(fd.Category)
			if kind == "" {
				continue
			}
			findings = append(findings, Finding{
				Kind:     kind,
				Severity: fd.Severity,
				Tool:     tool,
				Path:     fd.Path,
				Detail:   "pattern " + fd.Pattern + " in tool argument",
			})
			if fd.Severity == "high" {
				blocking = true
				if dominant == "" {
					dominant = kind
				}
			}
		}
	}

	// Call-chain analysis (non-blocking in Phase 1; recorded only). The chain
	// analyzer is internally synchronized, so no g.mu is needed here.
	if g.cfg.Chain.Enabled {
		dets := s.chain.Record(mcp.CallRecord{ToolName: tool, Timestamp: now, Allowed: allowed})
		for _, d := range dets {
			findings = append(findings, Finding{
				Kind:     "mcp_chain_" + d.Pattern,
				Severity: "medium",
				Tool:     tool,
				Detail:   d.Detail,
			})
		}
	}

	action := g.applyMode(blocking)
	reason := ""
	if action == Deny {
		reason = dominant
	}
	return Verdict{
		Action:   action,
		Reason:   reason,
		Tool:     tool,
		Method:   tc.Method,
		Findings: findings,
	}
}

// OnResponse analyzes one inbound MCP response body and returns a Verdict.
func (g *Gateway) OnResponse(sessionKey string, status int, hdr http.Header, body []byte) (v Verdict) {
	if g.disabled() {
		return Verdict{Action: Pass}
	}
	defer func() {
		if r := recover(); r != nil {
			g.log.Error("mcp gateway OnResponse panic", "panic", r)
			v = g.failVerdict("", "")
		}
	}()

	id := rpcID(body)
	now := g.now() // outside the lock: a panicking clock cannot strand the mutex
	var findings []Finding
	var inventory []ToolInfo
	blocking := false
	dominant := ""

	if isToolListResult(body) {
		tools, err := mcp.ParseToolList(body)
		if err != nil {
			return g.failVerdict("tools/list", "")
		}
		for _, t := range tools {
			inventory = append(inventory, ToolInfo{
				Name:            t.Name,
				HasDescription:  t.Description != "",
				InputSchemaHash: hashSchema(t.InputSchema),
			})
		}

		g.mu.Lock()
		s := g.sessionLocked(sessionKey, now)
		firstList := !s.baselineSet
		if firstList {
			s.schema.CaptureBaseline(tools)
			s.baselineSet = true
		}
		g.recordInventoryLocked(inventory, now)
		g.mu.Unlock()

		// Declared-schema integrity: baseline-or-drift.
		if !firstList {
			for _, d := range s.schema.DetectDrift(tools) {
				findings = append(findings, Finding{
					Kind:     "mcp_schema_drift",
					Severity: "medium",
					Tool:     d.ToolName,
					Detail:   d.Type,
				})
				if d.Blocked {
					blocking = true
					if dominant == "" {
						dominant = "mcp_schema_drift"
					}
				}
			}
		}

		// Tool poisoning.
		for _, p := range mcp.DetectPoisoning(tools, g.scanner) {
			findings = append(findings, Finding{
				Kind:     "mcp_poisoning",
				Severity: "high",
				Tool:     p.ToolName,
				Detail:   p.Pattern,
			})
			blocking = true
			if dominant == "" {
				dominant = "mcp_poisoning"
			}
		}

		action := g.applyMode(blocking)
		reason := ""
		if action == Deny {
			reason = dominant
		}
		return Verdict{
			Action:    action,
			Reason:    reason,
			Method:    "tools/list",
			Findings:  findings,
			Inventory: inventory,
		}
	}

	// Generic result: correlate id -> tool and scan the result fields.
	tool := ""
	if id != "" {
		g.mu.Lock()
		s := g.sessionLocked(sessionKey, now)
		tool = s.idToTool[id]
		g.mu.Unlock()
	}
	if tool != "" && g.cfg.Scan.ToolResults && g.profiler != nil {
		result := rawField(body, "result")
		for _, fd := range g.profiler.Observe(tool, mcp.DirResponse, result, g.scanner) {
			kind := resultKind(fd.Category)
			if kind == "" {
				continue
			}
			findings = append(findings, Finding{
				Kind:     kind,
				Severity: fd.Severity,
				Tool:     tool,
				Path:     fd.Path,
				Detail:   "pattern " + fd.Pattern + " in tool result",
			})
			if fd.Severity == "high" {
				blocking = true
				if dominant == "" {
					dominant = kind
				}
			}
		}
	}

	action := g.applyMode(blocking)
	reason := ""
	if action == Deny {
		reason = dominant
	}
	return Verdict{
		Action:   action,
		Reason:   reason,
		Tool:     tool,
		Findings: findings,
	}
}

// MaxResponseScanBytes is the inline response-buffer cap. Defaults to 1 MiB when
// unset so the proxy never buffers an unbounded body.
func (g *Gateway) MaxResponseScanBytes() int {
	if g.cfg.MaxResponseScanBytes <= 0 {
		return 1 << 20
	}
	return g.cfg.MaxResponseScanBytes
}

// recordInventoryLocked merges a tools/list inventory into the gateway-wide
// catalog, stamping FirstSeen on first observation and refreshing LastSeen +
// the description/schema metadata on every subsequent list. Caller must hold
// g.mu.
func (g *Gateway) recordInventoryLocked(items []ToolInfo, now time.Time) {
	for _, it := range items {
		cur, ok := g.inventory[it.Name]
		if !ok {
			g.inventory[it.Name] = &InventoryItem{
				Name:            it.Name,
				HasDescription:  it.HasDescription,
				InputSchemaHash: it.InputSchemaHash,
				FirstSeen:       now,
				LastSeen:        now,
			}
			continue
		}
		cur.HasDescription = it.HasDescription
		cur.InputSchemaHash = it.InputSchemaHash
		cur.LastSeen = now
	}
}

// Inventory returns the gateway-wide tool catalog accumulated from every
// tools/list response, sorted by Name. The returned slice is a deep copy and
// shares no state with the gateway.
func (g *Gateway) Inventory() []InventoryItem {
	g.mu.Lock()
	defer g.mu.Unlock()

	out := make([]InventoryItem, 0, len(g.inventory))
	for _, it := range g.inventory {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SchemaSnapshot returns the observed per-tool schema profiles for the
// dashboard. Returns nil when profiling is disabled.
func (g *Gateway) SchemaSnapshot() map[string]mcp.ToolProfileView {
	if g.profiler == nil {
		return nil
	}
	return g.profiler.Snapshot()
}

// argKind maps a scan category to a request-side Finding kind.
func argKind(category string) string {
	switch category {
	case "credential_leak":
		return "mcp_args_leak"
	case "injection":
		return "mcp_args_injection"
	case "pii":
		return "mcp_args_pii"
	default:
		return ""
	}
}

// resultKind maps a scan category to a response-side Finding kind.
func resultKind(category string) string {
	switch category {
	case "credential_leak":
		return "mcp_result_leak"
	case "injection":
		return "mcp_result_injection"
	case "pii":
		return "mcp_result_pii"
	default:
		return ""
	}
}

// hashSchema returns the sha256 hex of the raw input schema (empty for none).
func hashSchema(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// rawField pulls a top-level raw JSON field out of a JSON-RPC envelope without
// re-decoding the whole message. Returns nil when absent or malformed.
func rawField(body []byte, field string) json.RawMessage {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	return env[field]
}

// rpcMethod best-effort extracts the JSON-RPC method from a request body.
func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	return env.Method
}

// rpcID best-effort extracts the JSON-RPC id (stringified) from a body.
func rpcID(body []byte) string {
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.ID == nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(env.ID, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(env.ID))
}

// isToolListResult reports whether body is a JSON-RPC result whose result object
// carries a "tools" array — i.e. a tools/list response.
func isToolListResult(body []byte) bool {
	var env struct {
		Result struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	if len(env.Result.Tools) == 0 {
		return false
	}
	var arr []json.RawMessage
	return json.Unmarshal(env.Result.Tools, &arr) == nil
}
