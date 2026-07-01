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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// "mcp_tool_condition", "mcp_poisoning", "mcp_schema_drift",
	// "mcp_args_injection", "mcp_args_leak", "mcp_args_pii",
	// "mcp_args_constraint", "mcp_args_too_large", "mcp_chain_<pattern>",
	// "mcp_result_injection", "mcp_result_leak", "mcp_result_pii".
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
	// Server is the MCP server host (e.g. "mcp.linear.app") that advertised this
	// tool, so the dashboard can attribute a tool to its MCP server.
	Server    string
	FirstSeen time.Time
	LastSeen  time.Time
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

// compiledFieldConstraint is a per-field constraint with its Match regexp
// precompiled once at New (never per request). re is nil when no match is set.
type compiledFieldConstraint struct {
	re        *regexp.Regexp
	maxLen    int
	required  bool
	forbidden bool
}

// compiledToolConstraints is one tool's precompiled argument constraints.
type compiledToolConstraints struct {
	maxArgsBytes int
	fields       map[string]compiledFieldConstraint
}

// compiledCondition is one tool's precompiled AllowWhen condition: the agent id
// gate and the time window parsed once into [startHour, endHour) (server local).
// A zero value (hasWindow false, agentID "") imposes no extra restriction.
type compiledCondition struct {
	agentID   string
	hasWindow bool
	startHour int
	endHour   int
}

// compiledScope is one task scope precompiled at New: the allowed tool-set as a
// membership set plus the per-tool argument constraints (reusing the same
// compiled constraint shape as the base Tools policy).
type compiledScope struct {
	id          string
	tools       map[string]struct{}
	constraints map[string]compiledToolConstraints
}

// compiledScopes holds the whole task-scope block precompiled at New. A nil
// *compiledScopes means no scoping is configured (unchanged behavior).
type compiledScopes struct {
	active     string            // global active scope id ("" = none)
	perAgent   map[string]string // agent id -> scope id override
	outOfScope string            // "deny" | "escalate" (escalate degrades to deny)
	byID       map[string]compiledScope
}

// activeFor resolves the scope enforced for agentID: the PerAgent override wins,
// else the global active scope. ok is false when no scope applies (no scoping,
// no selection, or a dangling reference — validation rejects the latter, so at
// runtime a miss simply means "unscoped").
func (cs *compiledScopes) activeFor(agentID string) (compiledScope, bool) {
	if cs == nil {
		return compiledScope{}, false
	}
	id := cs.perAgent[agentID]
	if id == "" {
		id = cs.active
	}
	if id == "" {
		return compiledScope{}, false
	}
	sc, ok := cs.byID[id]
	return sc, ok
}

// Store persists the gateway's tool inventory and observed schema profiles so
// they survive a proxy restart. It is defined here (not in the analytics
// package) so the gateway never imports analytics — the analytics package
// implements this interface, keeping the dependency one-directional.
//
// The schema map is keyed by "tool\x00direction" (the same key Snapshot/Restore
// on the profiler use).
type Store interface {
	LoadMCPInventory() ([]InventoryItem, error)
	SaveMCPInventory([]InventoryItem) error
	LoadMCPSchemas() (map[string]mcp.ToolProfileView, error) // key = "tool\x00direction"
	SaveMCPSchemas(map[string]mcp.ToolProfileView) error
}

// Option configures a Gateway at construction. Options are applied after the
// core fields are set so they can read cfg-derived state (e.g. the profiler).
type Option func(*Gateway)

// WithStore attaches a persistence Store. On New the gateway loads any
// persisted inventory and schema profiles (best-effort; load errors are logged
// and never fail startup) and starts a background flusher that writes back
// changes periodically and on Close.
func WithStore(s Store) Option {
	return func(g *Gateway) { g.store = s }
}

// WithAgentID sets the agent id this gateway fronts. Per-tool AllowWhen
// conditions whose agentId is set are matched against it; with no WithAgentID
// the id is empty and any agent-scoped condition denies.
func WithAgentID(id string) Option {
	return func(g *Gateway) { g.agentID = id }
}

// flushInterval is how often the background flusher writes dirty state back to
// the store.
const flushInterval = 15 * time.Second

// Gateway is the MCP verdict engine. It is safe for concurrent use.
type Gateway struct {
	cfg      config.MCPConfig
	scanner  scan.Scanner
	policy   *mcp.ToolPolicy
	profiler *mcp.SchemaProfiler
	log      *slog.Logger

	// constraints holds the per-tool argument constraints precompiled at New,
	// keyed by tool name. Read-only after construction; no lock needed.
	constraints map[string]compiledToolConstraints

	// conditions holds the per-tool AllowWhen conditions precompiled at New,
	// keyed by tool name. Read-only after construction; no lock needed.
	conditions map[string]compiledCondition

	// scopes holds the precompiled task-scope block (nil = no scoping). Read-only
	// after construction; no lock needed.
	scopes *compiledScopes

	// agentID identifies the agent this gateway fronts; set via WithAgentID and
	// matched against a tool condition's agent id. Read-only after construction.
	agentID string

	mu       sync.Mutex
	sessions map[string]*session

	// inventory is the gateway-wide, cross-session tool catalog accumulated from
	// every tools/list response, keyed by tool name. Guarded by g.mu.
	inventory map[string]*InventoryItem

	// store, when non-nil, persists inventory + schema across restarts. dirty is
	// set whenever inventory or schema state changes; the flusher goroutine
	// (started only when store != nil) writes back when dirty. done stops it, and
	// closeOnce makes Close idempotent.
	store     Store
	dirty     atomic.Bool
	done      chan struct{}
	closeOnce sync.Once

	now func() time.Time // injectable clock for tests; default time.Now
}

// New builds a Gateway from cfg. The scanner is owned by the caller (the proxy);
// in tests construct one via scan.NewScanner honoring cfg.Scan.PII.Phone. The
// shared tool policy and (optional) schema profiler are built here.
//
// Optional opts (e.g. WithStore) enable persistence: when a Store is attached
// the gateway loads any persisted inventory + schema on start and runs a
// background flusher. New stays backward-compatible — with no opts it behaves
// exactly as before and starts no goroutines.
func New(cfg config.MCPConfig, scanner scan.Scanner, log *slog.Logger, opts ...Option) *Gateway {
	if log == nil {
		log = slog.Default()
	}
	policy := mcp.NewToolPolicy(cfg.Tools.Allow, cfg.Tools.Deny, toPerMinute(cfg.Tools.RateLimit))
	var profiler *mcp.SchemaProfiler
	if cfg.Scan.ProfileSchema {
		profiler = mcp.NewSchemaProfiler(0)
	}
	g := &Gateway{
		cfg:         cfg,
		scanner:     scanner,
		policy:      policy,
		profiler:    profiler,
		log:         log,
		constraints: compileConstraints(cfg.Tools.Constraints),
		conditions:  compileConditions(cfg.Tools.Constraints),
		scopes:      compileScopes(cfg.Scopes),
		sessions:    make(map[string]*session),
		inventory:   make(map[string]*InventoryItem),
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(g)
	}
	if g.store != nil {
		g.loadFromStore()
		g.done = make(chan struct{})
		go g.flushLoop()
	}
	return g
}

// loadFromStore hydrates the inventory and profiler from the persisted store.
// It is best-effort: a load error is logged and skipped so a corrupt or empty
// store never blocks startup. Called once from New, before the flusher starts,
// so no lock is needed for the inventory map.
func (g *Gateway) loadFromStore() {
	if items, err := g.store.LoadMCPInventory(); err != nil {
		g.log.Warn("mcp gateway: load inventory failed; starting empty", "error", err)
	} else {
		for i := range items {
			it := items[i]
			g.inventory[it.Name] = &it
		}
	}
	if g.profiler != nil {
		if snap, err := g.store.LoadMCPSchemas(); err != nil {
			g.log.Warn("mcp gateway: load schemas failed; starting empty", "error", err)
		} else if len(snap) > 0 {
			g.profiler.Restore(snap)
		}
	}
}

// markDirty flags that persisted state has diverged from the store. Cheap and
// lock-free so hot paths (OnRequest/OnResponse) can call it freely. No-op when
// no store is attached.
func (g *Gateway) markDirty() {
	if g.store != nil {
		g.dirty.Store(true)
	}
}

// flushLoop writes dirty state back to the store on a fixed interval until Close
// signals done. Started only when a store is attached.
func (g *Gateway) flushLoop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-g.done:
			return
		case <-t.C:
			g.flush()
		}
	}
}

// flush persists the current inventory + schema snapshot when dirty, clearing
// the dirty flag first so a concurrent change after the snapshot re-marks it for
// the next cycle rather than being lost. No-op when no store is attached or
// nothing changed.
func (g *Gateway) flush() {
	if g.store == nil || !g.dirty.Swap(false) {
		return
	}
	if err := g.store.SaveMCPInventory(g.Inventory()); err != nil {
		g.log.Warn("mcp gateway: save inventory failed", "error", err)
		g.dirty.Store(true)
	}
	if g.profiler != nil {
		if err := g.store.SaveMCPSchemas(g.profiler.Snapshot()); err != nil {
			g.log.Warn("mcp gateway: save schemas failed", "error", err)
			g.dirty.Store(true)
		}
	}
}

// Close stops the background flusher and performs a final flush of any pending
// changes. It is safe to call multiple times and is a no-op when no store is
// attached (no goroutine was started). Always returns nil; flush errors are
// logged, not surfaced, so shutdown never fails on a persistence hiccup.
func (g *Gateway) Close() error {
	g.closeOnce.Do(func() {
		if g.done != nil {
			close(g.done)
		}
		g.flush()
	})
	return nil
}

// compileConstraints precompiles each per-tool argument constraint once. Match
// regexps are compiled here (config validation already proved they compile, so
// a compile error here is unexpected and that field is skipped rather than
// taking down construction). Returns nil when no constraints are configured.
func compileConstraints(cs map[string]config.MCPToolConstraints) map[string]compiledToolConstraints {
	if len(cs) == 0 {
		return nil
	}
	out := make(map[string]compiledToolConstraints, len(cs))
	for tool, tc := range cs {
		ctc := compiledToolConstraints{maxArgsBytes: tc.MaxArgsBytes}
		if len(tc.Fields) > 0 {
			ctc.fields = make(map[string]compiledFieldConstraint, len(tc.Fields))
			for field, fc := range tc.Fields {
				cfc := compiledFieldConstraint{
					maxLen:    fc.MaxLen,
					required:  fc.Required,
					forbidden: fc.Forbidden,
				}
				if fc.Match != "" {
					re, err := regexp.Compile(fc.Match)
					if err != nil {
						continue
					}
					cfc.re = re
				}
				ctc.fields[field] = cfc
			}
		}
		out[tool] = ctc
	}
	return out
}

// compileScopes precompiles the task-scope block once at New: each scope's tool
// list becomes a membership set and its per-tool constraints are compiled with
// the same compileConstraints used for the base Tools policy. Returns nil when no
// scoping is configured (scopes stays nil → unchanged behavior).
func compileScopes(sc *config.MCPScopesConfig) *compiledScopes {
	if sc == nil || len(sc.List) == 0 {
		return nil
	}
	out := &compiledScopes{
		active:     sc.ActiveScope,
		outOfScope: sc.OutOfScope,
		byID:       make(map[string]compiledScope, len(sc.List)),
	}
	if out.outOfScope == "" {
		out.outOfScope = "deny"
	}
	if len(sc.PerAgent) > 0 {
		out.perAgent = make(map[string]string, len(sc.PerAgent))
		for k, v := range sc.PerAgent {
			out.perAgent[k] = v
		}
	}
	for _, s := range sc.List {
		cs := compiledScope{
			id:          s.ID,
			tools:       make(map[string]struct{}, len(s.Tools)),
			constraints: compileConstraints(s.Constraints),
		}
		for _, t := range s.Tools {
			cs.tools[t] = struct{}{}
		}
		out.byID[s.ID] = cs
	}
	return out
}

// compileConditions precompiles each tool's AllowWhen condition once at New:
// the agent id is stored verbatim and the time window is parsed into start/end
// hours. Tools without an AllowWhen are omitted. Config validation already
// proved any time window is well-formed, so a parse failure here is unexpected
// and that window is dropped (treated as no window) rather than failing
// construction. Returns nil when no conditions are configured.
func compileConditions(cs map[string]config.MCPToolConstraints) map[string]compiledCondition {
	if len(cs) == 0 {
		return nil
	}
	out := make(map[string]compiledCondition)
	for tool, tc := range cs {
		if tc.AllowWhen == nil {
			continue
		}
		cc := compiledCondition{agentID: tc.AllowWhen.AgentID}
		if tc.AllowWhen.TimeWindow != "" {
			if start, end, ok := parseConditionWindow(tc.AllowWhen.TimeWindow); ok {
				cc.hasWindow = true
				cc.startHour = start
				cc.endHour = end
			}
		}
		out[tool] = cc
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseConditionWindow parses a "HH-HH" window into start/end hours. ok is false
// for a malformed window (config validation prevents this on the enforced path).
func parseConditionWindow(s string) (start, end int, ok bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 || start > 23 {
		return 0, 0, false
	}
	end, err = strconv.Atoi(parts[1])
	if err != nil || end < 0 || end > 23 {
		return 0, 0, false
	}
	return start, end, true
}

// hourInWindow reports whether hour falls in [start, end) (server local time),
// handling wrap-around (e.g. 22-06) the same way the domain policy does.
func hourInWindow(hour, start, end int) bool {
	if start <= end {
		return hour >= start && hour < end
	}
	// Wrap-around (e.g. 22-06 means 22:00-06:00).
	return hour >= start || hour < end
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

	// Conditional rule (AllowWhen): a tool the policy ALLOWED may be further
	// gated to a specific agent id and/or a server-local time window. It only
	// narrows — a tool the policy already denied is untouched. On failure the
	// tool is treated as denied for the downstream chain so the call-chain
	// analyzer sees the request the same way the policy decision did.
	if allowed {
		if cc, ok := g.conditions[tool]; ok {
			if detail, deny := g.conditionDenies(cc, now); deny {
				findings = append(findings, Finding{
					Kind:     "mcp_tool_condition",
					Severity: "high",
					Tool:     tool,
					Detail:   detail,
				})
				blocking = true
				if dominant == "" {
					dominant = "mcp_tool_condition"
				}
				allowed = false
			}
		}
	}

	// Task-scoped authorization (approve-once, enforce-continuously). When a scope
	// is active for this agent, a tool the base policy already ALLOWED must also be
	// in the scope's tool-set; otherwise it is out-of-scope. Scopes only NARROW: an
	// out-of-scope tool is denied (never re-permitted), and a tool the base policy
	// or a restriction already denied is untouched. outOfScope: escalate is
	// deferred (no approval channel) and degrades to deny, so the absence of an
	// approval mechanism can never widen access. An in-scope tool additionally
	// satisfies the scope's bundled arg constraints via the SAME evaluator as the
	// base policy. In monitor mode this only logs (applyMode never blocks).
	if allowed {
		if sc, ok := g.scopes.activeFor(g.agentID); ok {
			if _, in := sc.tools[tool]; !in {
				detail := "tool not in active scope " + sc.id
				if g.scopes.outOfScope == "escalate" {
					detail += " (escalate: no approval channel — denied)"
				}
				findings = append(findings, Finding{
					Kind:     "mcp_out_of_scope",
					Severity: "high",
					Tool:     tool,
					Detail:   detail,
				})
				blocking = true
				if dominant == "" {
					dominant = "mcp_out_of_scope"
				}
				allowed = false
			} else if ctc, ok := sc.constraints[tool]; ok {
				args := rawField(rawField(body, "params"), "arguments")
				if fs, fk := evalToolConstraints(ctc, tool, args); len(fs) > 0 {
					findings = append(findings, fs...)
					blocking = true
					if dominant == "" {
						dominant = fk
					}
				}
			}
		}
	}

	// Argument scanning. Two passes that are deduped by (category|pattern):
	//
	//  1. Per-field pass (only when the profiler is on): attributes each
	//     detection to its field Path and feeds schema learning. We always call
	//     Observe when the profiler exists because it also profiles shapes and
	//     learns the inventory-independent schema, not just scans.
	//  2. Whole-body pass (always when ToolArgs is on): scans the concatenated
	//     value set. This runs even with the profiler off — closing the gap where
	//     scan.toolArgs did nothing without profileSchema — and catches
	//     concatenation/base64 cases a strict per-field pass misses. Detections
	//     already attributed to a field are skipped so a single-field hit is not
	//     double-counted; genuinely cross-field detections carry an empty Path.
	if g.cfg.Scan.ToolArgs {
		params := rawField(body, "params")
		seen := map[string]bool{}
		if g.profiler != nil {
			g.markDirty()
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
				seen[fd.Category+"|"+fd.Pattern] = true
				applyScanSeverity(fd.Severity, kind, &blocking, &dominant)
			}
		}
		for _, d := range mcp.ScanToolArgs(params, g.scanner) {
			if seen[d.Category+"|"+d.Pattern] {
				continue
			}
			kind := argKind(d.Category)
			if kind == "" {
				continue
			}
			findings = append(findings, Finding{
				Kind:     kind,
				Severity: d.Severity,
				Tool:     tool,
				Path:     "",
				Detail:   "cross-field",
			})
			applyScanSeverity(d.Severity, kind, &blocking, &dominant)
		}
	}

	// Per-tool argument constraints (precompiled at New). Evaluated against the
	// parsed params after the policy/scan checks. Values are inspected
	// transiently (size, presence, regexp match, length) and never stored; a
	// Finding's Detail never contains the value.
	if ctc, ok := g.constraints[tool]; ok {
		args := rawField(rawField(body, "params"), "arguments")
		if fs, fk := evalToolConstraints(ctc, tool, args); len(fs) > 0 {
			findings = append(findings, fs...)
			blocking = true
			if dominant == "" {
				dominant = fk
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
		g.recordInventoryLocked(inventory, serverFromSessionKey(sessionKey), now)
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
	// Result scanning. Mirrors the request-side two-pass logic: a per-field pass
	// (profiler on) for Path attribution + schema learning, plus a whole-body
	// pass that always runs when ToolResults is on (so scanning works without the
	// profiler and catches cross-field/base64 cases), deduped by (category|pattern).
	if tool != "" && g.cfg.Scan.ToolResults {
		result := rawField(body, "result")
		seen := map[string]bool{}
		if g.profiler != nil {
			g.markDirty()
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
				seen[fd.Category+"|"+fd.Pattern] = true
				applyScanSeverity(fd.Severity, kind, &blocking, &dominant)
			}
		}
		for _, d := range mcp.ScanToolResult(result, g.scanner) {
			if seen[d.Category+"|"+d.Pattern] {
				continue
			}
			kind := resultKind(d.Category)
			if kind == "" {
				continue
			}
			findings = append(findings, Finding{
				Kind:     kind,
				Severity: d.Severity,
				Tool:     tool,
				Path:     "",
				Detail:   "cross-field",
			})
			applyScanSeverity(d.Severity, kind, &blocking, &dominant)
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
// serverFromSessionKey extracts the MCP server host from a session key of the
// form "agentID:domain". A hostname never contains a colon, so the substring
// after the LAST colon is the server host. Returns "" if there is no colon.
func serverFromSessionKey(key string) string {
	if i := strings.LastIndexByte(key, ':'); i >= 0 {
		return key[i+1:]
	}
	return ""
}

func (g *Gateway) recordInventoryLocked(items []ToolInfo, server string, now time.Time) {
	for _, it := range items {
		cur, ok := g.inventory[it.Name]
		if !ok {
			g.inventory[it.Name] = &InventoryItem{
				Name:            it.Name,
				HasDescription:  it.HasDescription,
				InputSchemaHash: it.InputSchemaHash,
				Server:          server,
				FirstSeen:       now,
				LastSeen:        now,
			}
			continue
		}
		cur.HasDescription = it.HasDescription
		cur.InputSchemaHash = it.InputSchemaHash
		if server != "" {
			cur.Server = server
		}
		cur.LastSeen = now
	}
	if len(items) > 0 {
		g.markDirty()
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

// applyScanSeverity applies the uniform blocking rule for a scan finding: a
// high-severity detection flips blocking on and, if no dominant kind is set yet,
// becomes the dominant reason. Shared by the per-field and whole-body passes so
// both sides enforce identically.
func applyScanSeverity(severity, kind string, blocking *bool, dominant *string) {
	if severity == "high" {
		*blocking = true
		if *dominant == "" {
			*dominant = kind
		}
	}
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

// conditionDenies reports whether an allowed tool's AllowWhen condition fails
// for the current agent / time. detail is a short, value-free phrase suitable
// for a Finding.Detail. now is server local time (the injectable clock).
func (g *Gateway) conditionDenies(cc compiledCondition, now time.Time) (detail string, deny bool) {
	if cc.agentID != "" && g.agentID != cc.agentID {
		return "agent not permitted", true
	}
	if cc.hasWindow && !hourInWindow(now.Hour(), cc.startHour, cc.endHour) {
		return "outside allowed time window", true
	}
	return "", false
}

// constraintFinding builds a value-free mcp_args_constraint Finding. detail is
// one of a small fixed set of phrases and never contains a field value.
// evalToolConstraints checks one tool's precompiled argument constraints against
// the raw arguments, returning any findings plus the kind of the FIRST blocking
// finding ("" when nothing blocked). Every constraint finding is high-severity
// (blocking). Values are inspected transiently (size, presence, regexp, length)
// and never stored — a Finding's Detail never carries the value. Shared verbatim
// by the base Tools policy and an active task scope so there is one constraint
// engine, not two.
func evalToolConstraints(ctc compiledToolConstraints, tool string, args json.RawMessage) (findings []Finding, firstKind string) {
	if ctc.maxArgsBytes > 0 && len(args) > ctc.maxArgsBytes {
		findings = append(findings, Finding{
			Kind:     "mcp_args_too_large",
			Severity: "high",
			Tool:     tool,
			Detail:   "params exceed maxArgsBytes",
		})
		firstKind = "mcp_args_too_large"
	}
	for field, fc := range ctc.fields {
		val, present, isString := topLevelField(args, field)
		if fc.required && !present {
			findings = append(findings, constraintFinding(tool, field, "required field missing"))
			if firstKind == "" {
				firstKind = "mcp_args_constraint"
			}
			continue
		}
		if fc.forbidden && present {
			findings = append(findings, constraintFinding(tool, field, "forbidden field present"))
			if firstKind == "" {
				firstKind = "mcp_args_constraint"
			}
			continue
		}
		if !present || !isString {
			continue
		}
		if fc.re != nil && !fc.re.MatchString(val) {
			findings = append(findings, constraintFinding(tool, field, "value violates constraint"))
			if firstKind == "" {
				firstKind = "mcp_args_constraint"
			}
			continue
		}
		if fc.maxLen > 0 && len(val) > fc.maxLen {
			findings = append(findings, constraintFinding(tool, field, "value exceeds maxLen"))
			if firstKind == "" {
				firstKind = "mcp_args_constraint"
			}
		}
	}
	return findings, firstKind
}

func constraintFinding(tool, field, detail string) Finding {
	return Finding{
		Kind:     "mcp_args_constraint",
		Severity: "high",
		Tool:     tool,
		Path:     field,
		Detail:   detail,
	}
}

// topLevelField reports the presence, string value, and string-ness of a
// top-level field in a JSON object. The value is returned transiently for an
// immediate regexp/length check by the caller and is never stored. present is
// true whenever the key exists (even for a non-string value); isString is true
// only when the value decodes as a JSON string (val holds it then).
func topLevelField(obj json.RawMessage, field string) (val string, present, isString bool) {
	if len(obj) == 0 {
		return "", false, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil {
		return "", false, false
	}
	raw, ok := m[field]
	if !ok {
		return "", false, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true, true
	}
	return "", true, false
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
