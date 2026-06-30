// Package controlplane implements the Warden control plane: a server that
// distributes allow/deny policy to data-plane workers and aggregates their
// analytics for a fleet dashboard.
//
// Boundary invariant: the control plane is policy + visibility ONLY. It never
// holds or serves secrets. The policy sent to workers is an explicit allow/deny
// wire type (policyWire), so a future field added to config.Policy can never
// accidentally leak across the boundary — the guarantee is structural, not a
// matter of struct tags.
package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/secrets"
)

// Config configures the control-plane server.
type Config struct {
	// PolicyPath is the YAML file whose allow/deny policy is served to workers.
	// It is re-read on each /policy request so edits propagate on the next poll.
	PolicyPath string
	// Token is the bearer token workers must present on /policy and
	// /central/ingest. Empty disables auth (development only).
	Token string
	// MaxEvents caps the in-memory central analytics store (0 = default).
	MaxEvents int
	// Logger receives lifecycle and policy-load logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// policyWire is the shape sent to workers: allow/deny policy plus the optional
// behavioral settings document. Secrets never appear here — Settings is the
// explicit, secret-free config.SettingsWire (env-name references only), so a
// value can never accidentally cross the boundary. Settings is omitempty so a
// control plane serving only allow/deny stays byte-identical to before (the
// "settings" key is simply absent → back-compatible).
type policyWire struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
	Settings  *config.SettingsWire    `json:"settings,omitempty"`
}

// Long-poll bounds and the external-edit re-read cadence.
const (
	minLongPollWait      = 1 * time.Second
	maxLongPollWait      = 60 * time.Second
	policyReloadInterval = 3 * time.Second
)

// Server is the control plane. It is safe for concurrent use.
type Server struct {
	cfg      Config
	central  *analytics.CentralStore
	registry *WorkerRegistry
	mcp      *mcpStore
	watch    *policyWatch
	writeMu  sync.Mutex // serializes policy edits
}

// New constructs a control-plane Server backed by an in-memory central store.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		cfg:      cfg,
		central:  analytics.NewCentralStore(cfg.MaxEvents),
		registry: NewWorkerRegistry(),
		mcp:      newMCPStore(),
		watch:    newPolicyWatch(),
	}
	s.refresh() // initial load so /policy and the dashboard have policy immediately
	return s
}

// Start launches the periodic re-read that catches EXTERNAL edits to the served
// policy file (editor edits refresh synchronously). It returns when ctx is done.
func (s *Server) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(policyReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refresh()
			}
		}
	}()
}

// policyWatch holds the current served policy + its ETag and broadcasts to
// blocked long-poll waiters when it changes. The broadcast is a close-and-replace
// channel: waiters grab the current channel, and a change closes it.
type policyWatch struct {
	mu   sync.Mutex
	wire policyWire
	etag string
	ok   bool // a good policy has been loaded at least once
	ch   chan struct{}
}

func newPolicyWatch() *policyWatch { return &policyWatch{ch: make(chan struct{})} }

// set updates the watched policy and wakes waiters only when the ETag changes.
func (w *policyWatch) set(wire policyWire, etag string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ok && etag == w.etag {
		return
	}
	w.wire, w.etag, w.ok = wire, etag, true
	close(w.ch)
	w.ch = make(chan struct{})
}

// snapshot returns the current policy, ETag, whether one has loaded, and a
// channel that closes when the policy next changes.
func (w *policyWatch) snapshot() (policyWire, string, bool, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.wire, w.etag, w.ok, w.ch
}

// refresh re-reads the policy file and updates the watch. On a read/parse error
// it logs and keeps the last good policy, so a mid-edit malformed file never
// breaks workers.
func (s *Server) refresh() {
	wire, err := s.loadPolicy()
	if err != nil {
		s.cfg.Logger.Warn("control plane: policy reload failed; keeping last-known-good", "error", err)
		return
	}
	s.watch.set(wire, etagFor(wire))
}

// etagFor is a short, stable content hash of the served policy. Because Settings
// is part of policyWire, the ETag automatically covers behavioral settings too:
// any settings change alters the marshaled bytes → a new ETag → long-poll wake.
func etagFor(wire policyWire) string {
	b, _ := json.Marshal(wire)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

// currentETag returns the ETag of the policy currently served (for the dashboard
// "version behind" hint). Empty until the first successful load.
func (s *Server) currentETag() string {
	_, etag, _, _ := s.watch.snapshot()
	return etag
}

// Handler returns the control plane's HTTP routes:
//
//	GET  /policy          — allow/deny policy for workers (bearer-auth)
//	POST /central/ingest  — fleet analytics ingest (bearer-auth)
//	     /dashboard/      — fleet dashboard over the aggregated store
//	GET  /healthz         — liveness
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/policy", s.handlePolicy)
	mux.HandleFunc("/control/heartbeat", s.handleHeartbeat)
	ingest := analytics.NewIngestHandler(s.central, s.cfg.Token)
	ingest.SetOnIngest(s.registry.SeenIngest) // track which workers are forwarding
	ingest.SetOnMCP(s.mcp.Update)             // store each worker's MCP snapshot
	mux.Handle("/central/ingest", ingest)

	// The fleet dashboard reads the aggregated central store. The control plane
	// holds no secrets, so it is given an empty secret provider and a
	// secret-free policy view; the dashboard's secrets panel is naturally empty.
	emptySecrets, _ := secrets.NewCache(secrets.NewEnvFetcher(map[string]string{}), 0, nil)
	wire, _, _, _ := s.watch.snapshot()
	dashPolicy := config.Policy{Allowlist: wire.Allowlist, Denylist: wire.Denylist}
	dash := dashboard.NewServer(s.central, dashPolicy, emptySecrets)
	// Policy panel reflects the live served policy (the watch), so edits show
	// immediately rather than a startup snapshot.
	dash.SetLivePolicy(func() config.Policy {
		w, _, _, _ := s.watch.snapshot()
		return config.Policy{Allowlist: w.Allowlist, Denylist: w.Denylist}
	})
	// Editing is enabled on the control plane only: persist edits to the served
	// policy file so workers pull them on their next poll.
	dash.SetPolicyWriter(s.writePolicy)
	// Behavioral settings editing (Phase 2b: the mcp block) is likewise a
	// control-plane-only capability: persist edits to the served file so workers
	// pull them on their next poll. The read side reflects the live watch.
	dash.SetSettingsWriter(s.writeSettings)
	dash.SetLiveSettings(func() *config.SettingsWire {
		w, _, _, _ := s.watch.snapshot()
		return w.Settings
	})
	// Per-worker MCP view (inventory + observed schema), selected by ?proxy=.
	dash.SetMCPFleet(s.mcp.For)
	// Connected-workers list for the fleet view, with a "behind" flag for any
	// worker whose policy version differs from what the CP currently serves.
	dash.SetWorkers(func() []dashboard.WorkerView {
		cur := s.currentETag()
		views := s.registry.Views()
		for i := range views {
			views[i].Behind = views[i].PolicyETag != "" && views[i].PolicyETag != cur
		}
		return views
	})
	mux.Handle("/dashboard/", dash.Handler())

	return mux
}

// handlePolicy serves the current allow/deny policy with ETag-based long-poll.
// A worker sends its current ETag in If-None-Match and an optional ?wait=:
//   - ETag differs   -> 200 with the new policy + ETag (immediate).
//   - ETag matches    -> block up to ?wait for a change, then 200 (changed) or
//     304 Not Modified (timeout). wait==0/absent returns immediately (plain poll).
//
// This is one of the ONLY three worker→CP interactions; the CP never calls the
// worker. A bad mid-edit file never breaks workers: the watch keeps last-good.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Token != "" {
		want := "Bearer " + s.cfg.Token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	// Register the worker as connected (it announces its id on the pull).
	s.registry.SeenPolicyPull(r.Header.Get(analytics.ProxyIDHeader))

	inm := trimETag(r.Header.Get("If-None-Match"))
	wait := parseWait(r.URL.Query().Get("wait"))

	for {
		wire, etag, ok, ch := s.watch.snapshot()
		if !ok {
			// No good policy has ever loaded (e.g. unreadable file at startup).
			http.Error(w, "policy unavailable", http.StatusInternalServerError)
			return
		}
		if etag != inm {
			w.Header().Set("ETag", `"`+etag+`"`)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(wire)
			return
		}
		if wait <= 0 {
			w.Header().Set("ETag", `"`+etag+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		timer := time.NewTimer(wait)
		select {
		case <-ch:
			timer.Stop() // policy changed — loop re-evaluates and serves it
		case <-timer.C:
			w.Header().Set("ETag", `"`+etag+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			timer.Stop()
			return
		}
	}
}

// handleHeartbeat records a worker liveness ping. Body: {"policyETag": "..."}.
// It is one of the three worker→CP interactions; the CP never calls the worker.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Token != "" {
		want := "Bearer " + s.cfg.Token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	var body struct {
		PolicyETag string `json:"policyETag"`
	}
	// Body is optional/tiny; ignore decode errors (heartbeat is best-effort).
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	s.registry.SeenHeartbeat(r.Header.Get(analytics.ProxyIDHeader), trimETag(body.PolicyETag))
	w.WriteHeader(http.StatusNoContent)
}

// parseWait parses the ?wait= long-poll duration, clamped to [min,max]; an
// absent/zero/invalid value means "respond immediately" (plain poll).
func parseWait(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0
	}
	if d < minLongPollWait {
		d = minLongPollWait
	}
	if d > maxLongPollWait {
		d = maxLongPollWait
	}
	return d
}

// trimETag normalizes an If-None-Match value to the bare tag (no quotes / weak prefix).
func trimETag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "W/")
	return strings.Trim(s, `"`)
}

// policyYAML is the policy sub-block written back when policy is edited from the
// dashboard: allow/deny only — never secrets, which the control plane does not
// hold.
type policyYAML struct {
	Allowlist []config.AllowlistEntry `yaml:"allowlist"`
	Denylist  []config.DenylistEntry  `yaml:"denylist"`
}

// writePolicy validates and atomically persists an edited allow/deny policy to
// the served file, so workers pull it on their next poll. It writes a temp file,
// validates it with the full config loader (rejecting an invalid edit), then
// renames it into place — so a bad edit never replaces a good policy.
//
// The CP config file may carry behavioral blocks (mcp/judge/observability/…)
// that the policy editor does not touch. To avoid silently deleting operator
// config, writePolicy round-trips the file through a top-level YAML map and
// rewrites ONLY the `policy` (and `logging`, when present) blocks, leaving every
// other block byte-for-byte intact.
func (s *Server) writePolicy(p config.Policy) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Load the current file as a top-level YAML map so unknown/behavioral blocks
	// (mcp, judge, agents, observability, advisory, central, audit, secrets, …)
	// survive the edit untouched. A missing/unreadable file starts from empty.
	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		// Best-effort: a malformed current file just means we rebuild the two
		// blocks we own; the loader validation below still guards the result.
		_ = yaml.Unmarshal(cur, &root)
	}

	// Replace the policy block with the edited allow/deny.
	var policyNode yaml.Node
	if err := policyNode.Encode(policyYAML{Allowlist: p.Allowlist, Denylist: p.Denylist}); err != nil {
		return fmt.Errorf("controlplane: encode policy block: %w", err)
	}
	root["policy"] = policyNode

	// Ensure a logging block exists (preserved from the current file when
	// present; otherwise default to info/json). The editor does not change it.
	if _, ok := root["logging"]; !ok {
		var logNode yaml.Node
		if err := logNode.Encode(map[string]string{"level": "info", "format": "json"}); err != nil {
			return fmt.Errorf("controlplane: encode logging block: %w", err)
		}
		root["logging"] = logNode
	}

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	// Update the watch immediately so any long-poll waiters wake and serve the
	// new policy now (rather than after the next periodic re-read).
	s.refresh()
	s.cfg.Logger.Info("control plane policy updated via dashboard",
		"allow", len(p.Allowlist), "deny", len(p.Denylist))
	return nil
}

// atomicWriteConfig marshals the top-level config map, writes it to a temp file
// in the policy file's directory, validates it with the full loader (so a bad
// edit can never replace a good config — default-deny is enforced here), then
// renames it into place. Callers refresh the watch afterward. The caller MUST
// hold s.writeMu.
func (s *Server) atomicWriteConfig(root map[string]yaml.Node) error {
	data, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("controlplane: marshal config: %w", err)
	}

	dir := filepath.Dir(s.cfg.PolicyPath)
	tmp, err := os.CreateTemp(dir, ".warden-policy-*.yaml")
	if err != nil {
		return fmt.Errorf("controlplane: create temp policy: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("controlplane: write temp policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("controlplane: close temp policy: %w", err)
	}
	// Validate the candidate with the full loader before it can replace the live
	// file (this enforces default-deny: an empty allowlist is rejected here).
	if _, err := config.NewLocalYAMLProvider(tmpName); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	if err := os.Rename(tmpName, s.cfg.PolicyPath); err != nil {
		return fmt.Errorf("controlplane: persist policy: %w", err)
	}
	return nil
}

// loadPolicy re-reads and validates the policy file, returning the allow/deny
// wire view. Re-reading per call keeps served policy fresh without a watcher.
func (s *Server) loadPolicy() (policyWire, error) {
	prov, err := config.NewLocalYAMLProvider(s.cfg.PolicyPath)
	if err != nil {
		return policyWire{}, err
	}
	p, err := prov.GetPolicy()
	if err != nil {
		return policyWire{}, err
	}
	// SettingsWireFromPolicy projects only the secret-free behavioral blocks and
	// returns nil when the config is pure allow/deny, so the "settings" key stays
	// absent in that case (back-compat).
	return policyWire{
		Allowlist: p.Allowlist,
		Denylist:  p.Denylist,
		Settings:  config.SettingsWireFromPolicy(p),
	}, nil
}

// writeSettings validates and atomically persists an edited behavioral settings
// document to the served config file, so workers pull the new settings on their
// next poll. It is the settings analogue of writePolicy: it round-trips the file
// through a top-level YAML map and rewrites ONLY the blocks this phase owns,
// preserving every other block (policy, logging, central, controlPlane, secrets,
// audit signing, …) byte-for-byte.
//
// This phase owns the `mcp`, `judge`, `agents`, `logging`, `cache`, and (nested)
// `audit.compliance` blocks. A nil/disabled in.MCP or in.Judge removes that block
// (the worker disables the feature); an empty in.Agents removes the agents list.
//
// logging/cache are top-level and ride the settingsBlocks table; compliance is
// nested at audit.compliance.enabled and is merged into the existing audit node
// separately (below) so local-only audit sub-keys (e.g. signedReceipts) survive.
// A nil in.Logging/in.CacheTTLSeconds/in.Compliance leaves the existing block
// untouched (logging is co-owned by writePolicy's default, so writeSettings must
// not delete it).
func (s *Server) writeSettings(in config.SettingsWire) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Load the current file as a top-level YAML map so policy/logging/secrets and
	// any block this phase does not own survive untouched. A missing/unreadable
	// file starts from empty (the loader validation below still guards the result).
	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		_ = yaml.Unmarshal(cur, &root)
	}

	// settingsBlocks is the per-block rewrite table. Each entry owns one top-level
	// key: it either encodes a replacement node (present) or removes the key
	// (absent). later phases append entries here (judge, observability, …) so a
	// new distributable block is a few lines, not a new code path.
	type blockEdit struct {
		key     string
		node    *yaml.Node // nil → delete the key
		present bool
	}
	settingsBlocks := []blockEdit{}

	// mcp: encode in.MCP → the on-disk mcp block, or delete it when MCP is absent
	// or disabled (so the worker turns MCP off).
	mcpEdit := blockEdit{key: "mcp"}
	if in.MCP != nil && in.MCP.Enabled {
		node, err := mcpSettingsNode(in.MCP)
		if err != nil {
			return fmt.Errorf("controlplane: encode mcp settings: %w", err)
		}
		mcpEdit.node, mcpEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, mcpEdit)

	// judge: encode in.Judge → the on-disk judge block, or delete it when the
	// judge is absent or disabled (so the worker turns the judge off).
	judgeEdit := blockEdit{key: "judge"}
	if in.Judge != nil && in.Judge.Enabled {
		node, err := judgeSettingsNode(in.Judge)
		if err != nil {
			return fmt.Errorf("controlplane: encode judge settings: %w", err)
		}
		judgeEdit.node, judgeEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, judgeEdit)

	// agents: encode the natural-language agent policies the judge consults, or
	// delete the key when none are configured.
	agentsEdit := blockEdit{key: "agents"}
	if len(in.Agents) > 0 {
		node, err := agentsSettingsNode(in.Agents)
		if err != nil {
			return fmt.Errorf("controlplane: encode agents settings: %w", err)
		}
		agentsEdit.node, agentsEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, agentsEdit)

	// observability: encode in.Observability → the on-disk observability block, or
	// delete it when observability is absent or disabled (so the worker turns OTel
	// off on its next restart).
	obsEdit := blockEdit{key: "observability"}
	if in.Observability != nil && in.Observability.Enabled {
		node, err := observabilitySettingsNode(in.Observability)
		if err != nil {
			return fmt.Errorf("controlplane: encode observability settings: %w", err)
		}
		obsEdit.node, obsEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, obsEdit)

	// logging: top-level `logging: {level, format}`. We OWN it only when the wire
	// carries a logging block; when in.Logging is nil we LEAVE any existing logging
	// block intact (do NOT delete it — writePolicy also maintains a default logging
	// block, and deleting it here would fight that). So logging joins the table only
	// in the present case; there is no delete branch for it.
	if in.Logging != nil {
		node, err := loggingSettingsNode(in.Logging)
		if err != nil {
			return fmt.Errorf("controlplane: encode logging settings: %w", err)
		}
		settingsBlocks = append(settingsBlocks, blockEdit{key: "logging", node: node, present: true})
	}

	// cache: the loader reads Policy.CacheTTLSeconds from top-level `cache: {ttl}`
	// (int seconds). Own it only when the wire sets a TTL; a nil leaves any existing
	// cache block untouched (no delete branch — same rationale as logging).
	if in.CacheTTLSeconds != nil {
		node, err := cacheSettingsNode(*in.CacheTTLSeconds)
		if err != nil {
			return fmt.Errorf("controlplane: encode cache settings: %w", err)
		}
		settingsBlocks = append(settingsBlocks, blockEdit{key: "cache", node: node, present: true})
	}

	for _, b := range settingsBlocks {
		if b.present {
			root[b.key] = *b.node
		} else {
			delete(root, b.key)
		}
	}

	// compliance is NESTED at audit.compliance.enabled, NOT a top-level key. The
	// `audit` block also carries LOCAL-ONLY sub-keys (e.g. signedReceipts key/log
	// paths) that the control plane must never clobber. So rather than replacing the
	// whole audit node (which the top-level table would do), we MERGE: decode the
	// existing audit node into a generic map, set only compliance.enabled, and
	// re-encode — every other audit sub-key survives byte-for-byte. A nil
	// in.Compliance leaves audit entirely untouched.
	if in.Compliance != nil {
		if err := mergeAuditCompliance(root, in.Compliance.Enabled); err != nil {
			return fmt.Errorf("controlplane: merge audit.compliance: %w", err)
		}
	}

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	// Wake long-poll waiters with the new settings now, like writePolicy.
	s.refresh()
	mode := "off"
	if in.MCP != nil && in.MCP.Enabled {
		mode = in.MCP.Mode
	}
	judge := "off"
	if in.Judge != nil && in.Judge.Enabled {
		judge = "on"
	}
	logging := "unchanged"
	if in.Logging != nil {
		logging = in.Logging.Level
	}
	compliance := "unchanged"
	if in.Compliance != nil {
		if in.Compliance.Enabled {
			compliance = "on"
		} else {
			compliance = "off"
		}
	}
	observability := "off"
	if in.Observability != nil && in.Observability.Enabled {
		observability = "on"
	}
	s.cfg.Logger.Info("control plane settings updated via dashboard",
		"mcp", mode, "judge", judge, "agents", len(in.Agents),
		"logging", logging, "compliance", compliance, "observability", observability)
	return nil
}

// loggingSettingsNode encodes a wire Logging block into a YAML node matching the
// on-disk `logging: {level, format}` shape. The loader normalizes empty
// level/format to info/json, so omitempty here is harmless: an unset field simply
// falls back to the loader default rather than writing a zero value.
func loggingSettingsNode(s *config.LoggingSettings) (*yaml.Node, error) {
	type loggingYAML struct {
		Level  string `yaml:"level,omitempty"`
		Format string `yaml:"format,omitempty"`
	}
	var node yaml.Node
	if err := node.Encode(loggingYAML{Level: s.Level, Format: s.Format}); err != nil {
		return nil, err
	}
	return &node, nil
}

// cacheSettingsNode encodes a secret-cache TTL into a YAML node matching the
// on-disk `cache: {ttl}` shape the loader reads for Policy.CacheTTLSeconds (int
// seconds). ttl is written unconditionally because the caller only reaches here
// when the wire explicitly set CacheTTLSeconds — including an explicit 0, which
// the loader treats as "use default"; that is the operator's intent, preserved.
func cacheSettingsNode(ttlSeconds int) (*yaml.Node, error) {
	type cacheYAML struct {
		TTL int `yaml:"ttl"`
	}
	var node yaml.Node
	if err := node.Encode(cacheYAML{TTL: ttlSeconds}); err != nil {
		return nil, err
	}
	return &node, nil
}

// mergeAuditCompliance sets audit.compliance.enabled in the top-level config map
// WITHOUT clobbering any other audit sub-key (notably the local-only
// signedReceipts key/log paths). It decodes the existing audit node into a
// generic map, overwrites only the compliance sub-block, and re-encodes — so
// every sibling audit field round-trips byte-for-byte. When no audit node exists
// yet, a fresh one carrying only compliance is created.
func mergeAuditCompliance(root map[string]yaml.Node, enabled bool) error {
	audit := map[string]yaml.Node{}
	if existing, ok := root["audit"]; ok {
		// Best-effort decode: a malformed audit node just means we rebuild it with
		// compliance only; the loader validation in atomicWriteConfig still guards.
		_ = existing.Decode(&audit)
	}
	var compNode yaml.Node
	if err := compNode.Encode(map[string]bool{"enabled": enabled}); err != nil {
		return err
	}
	audit["compliance"] = compNode
	var auditNode yaml.Node
	if err := auditNode.Encode(audit); err != nil {
		return err
	}
	root["audit"] = auditNode
	return nil
}

// mcpYAML mirrors the on-disk `mcp:` block (config.rawMCP). It is the encoder
// counterpart of the loader's raw type: the boolean sub-block fields use pointers
// so an explicit false (e.g. scan.toolArgs=false, which the loader defaults to
// true when absent) round-trips instead of being silently dropped or re-defaulted.
type mcpYAML struct {
	Enabled              bool           `yaml:"enabled"`
	Mode                 string         `yaml:"mode,omitempty"`
	FailClosedOnError    bool           `yaml:"failClosedOnError,omitempty"`
	MaxResponseScanBytes int            `yaml:"maxResponseScanBytes,omitempty"`
	Tools                *mcpToolsYAML  `yaml:"tools,omitempty"`
	Schema               *mcpSchemaYAML `yaml:"schema,omitempty"`
	Scan                 *mcpScanYAML   `yaml:"scan,omitempty"`
	Chain                *mcpChainYAML  `yaml:"chain,omitempty"`
}

type mcpToolsYAML struct {
	Allow       []string                             `yaml:"allow,omitempty"`
	Deny        []string                             `yaml:"deny,omitempty"`
	RateLimit   map[string]string                    `yaml:"rateLimit,omitempty"`
	Constraints map[string]config.MCPToolConstraints `yaml:"constraints,omitempty"`
}

type mcpSchemaYAML struct {
	Pin bool `yaml:"pin"`
}

type mcpScanYAML struct {
	ToolArgs      *bool           `yaml:"toolArgs,omitempty"`
	ToolResults   *bool           `yaml:"toolResults,omitempty"`
	ProfileSchema *bool           `yaml:"profileSchema,omitempty"`
	PII           *mcpScanPIIYAML `yaml:"pii,omitempty"`
}

type mcpScanPIIYAML struct {
	Phone bool `yaml:"phone"`
}

type mcpChainYAML struct {
	Enabled    *bool    `yaml:"enabled,omitempty"`
	WindowSize *int     `yaml:"windowSize,omitempty"`
	Patterns   []string `yaml:"patterns,omitempty"`
}

// mcpSettingsNode encodes a wire MCP block into a YAML node matching the on-disk
// `mcp:` shape. It projects the WIRE settings (not a fully-defaulted MCPConfig)
// so that sub-blocks the operator never set stay ABSENT on disk and the loader
// applies its own defaults — emitting a fully-defaulted block would instead write
// concrete values (e.g. chain.windowSize=0) that fail loader validation. The
// scalar fields and any sub-block the operator DID set are written explicitly,
// with pointers where an explicit zero/false must survive the round-trip rather
// than be re-defaulted by the loader.
func mcpSettingsNode(s *config.MCPSettings) (*yaml.Node, error) {
	raw := mcpYAML{
		Enabled:              s.Enabled,
		Mode:                 s.Mode,
		FailClosedOnError:    s.FailClosedOnError,
		MaxResponseScanBytes: s.MaxResponseScanBytes,
	}
	if s.Schema != nil {
		raw.Schema = &mcpSchemaYAML{Pin: s.Schema.Pin}
	}
	if s.Scan != nil {
		raw.Scan = &mcpScanYAML{
			ToolArgs:      boolPtr(s.Scan.ToolArgs),
			ToolResults:   boolPtr(s.Scan.ToolResults),
			ProfileSchema: boolPtr(s.Scan.ProfileSchema),
			PII:           &mcpScanPIIYAML{Phone: s.Scan.PIIPhone},
		}
	}
	if s.Chain != nil {
		raw.Chain = &mcpChainYAML{
			Enabled:    boolPtr(s.Chain.Enabled),
			WindowSize: intPtr(s.Chain.WindowSize),
			Patterns:   s.Chain.Patterns,
		}
	}
	if s.Tools != nil &&
		(len(s.Tools.Allow) > 0 || len(s.Tools.Deny) > 0 ||
			len(s.Tools.RateLimit) > 0 || len(s.Tools.Constraints) > 0) {
		// Reuse the wire→config tool mapping so allow/deny/rate/constraints stay in
		// one place; the on-disk constraint shape matches config.MCPToolConstraints.
		tools := config.MCPConfigFromSettings(s).Tools
		raw.Tools = &mcpToolsYAML{
			Allow:       tools.Allow,
			Deny:        tools.Deny,
			RateLimit:   tools.RateLimit,
			Constraints: tools.Constraints,
		}
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return nil, err
	}
	return &node, nil
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// judgeYAML mirrors the on-disk `judge:` block (config.rawJudge). Durations live
// on disk as Go duration STRINGS ("5s", "30s", "5m"), and the loader treats an
// empty/absent duration string — and a zero maxFailures — as "apply the default".
// So this encoder writes a duration field ONLY when the wire carries a positive
// value: emitting "0s" or maxFailures:0 would override the loader's defaults with
// concrete zeros (the same defaults-vs-zero gotcha solved for the mcp block). The
// circuitBreaker/cache sub-blocks are pointers so they stay ABSENT when the wire
// has no tuning, leaving the loader free to apply its defaults.
type judgeYAML struct {
	Enabled        bool              `yaml:"enabled"`
	Provider       string            `yaml:"provider,omitempty"`
	Model          string            `yaml:"model,omitempty"`
	BaseURL        string            `yaml:"baseURL,omitempty"`
	APIKeyEnv      string            `yaml:"apiKeyEnv,omitempty"`
	Timeout        string            `yaml:"timeout,omitempty"`
	RateLimit      string            `yaml:"rateLimit,omitempty"`
	CircuitBreaker *judgeCircuitYAML `yaml:"circuitBreaker,omitempty"`
	Cache          *judgeCacheYAML   `yaml:"cache,omitempty"`
}

type judgeCircuitYAML struct {
	MaxFailures int    `yaml:"maxFailures,omitempty"`
	Cooldown    string `yaml:"cooldown,omitempty"`
}

type judgeCacheYAML struct {
	TTL string `yaml:"ttl,omitempty"`
}

// agentYAML mirrors one on-disk `agents:` list item (config.rawAgent).
type agentYAML struct {
	ID     string `yaml:"id"`
	Policy string `yaml:"policy,omitempty"`
}

// secondsToDuration renders a positive whole-second count as a Go duration string
// the loader's time.ParseDuration accepts ("30s"), or "" when n<=0 so the field is
// omitted and the loader applies its own default.
func secondsToDuration(n int) string {
	if n <= 0 {
		return ""
	}
	return (time.Duration(n) * time.Second).String()
}

// judgeSettingsNode encodes a wire Judge block into a YAML node matching the
// on-disk `judge:` shape. It projects the WIRE settings (not a fully-defaulted
// JudgeConfig): timeout/cache/circuit-breaker fields are written only when the
// wire carries a positive value, so unset tuning stays ABSENT on disk and the
// loader applies its documented defaults rather than zero values.
func judgeSettingsNode(s *config.JudgeSettings) (*yaml.Node, error) {
	raw := judgeYAML{
		Enabled:   s.Enabled,
		Provider:  s.Provider,
		Model:     s.Model,
		BaseURL:   s.BaseURL,
		APIKeyEnv: s.APIKeyEnv,
		RateLimit: s.RateLimit,
		Timeout:   secondsToDuration(s.TimeoutSeconds),
	}
	if ttl := secondsToDuration(s.CacheTTLSeconds); ttl != "" {
		raw.Cache = &judgeCacheYAML{TTL: ttl}
	}
	if s.CircuitBreaker != nil {
		cd := secondsToDuration(s.CircuitBreaker.CooldownSeconds)
		if s.CircuitBreaker.MaxFailures != 0 || cd != "" {
			raw.CircuitBreaker = &judgeCircuitYAML{
				MaxFailures: s.CircuitBreaker.MaxFailures,
				Cooldown:    cd,
			}
		}
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return nil, err
	}
	return &node, nil
}

// agentsSettingsNode encodes the wire agent list into a YAML node matching the
// on-disk `agents:` list shape (id + policy text). Order is preserved.
func agentsSettingsNode(in []config.AgentSettings) (*yaml.Node, error) {
	out := make([]agentYAML, 0, len(in))
	for _, a := range in {
		out = append(out, agentYAML{ID: a.ID, Policy: a.Policy})
	}
	var node yaml.Node
	if err := node.Encode(out); err != nil {
		return nil, err
	}
	return &node, nil
}

// observabilityYAML mirrors the on-disk `observability:` block
// (config.rawObservability). The wire ObservabilitySettings FLATTENS
// metricsEnabled/otlpEndpoint, but on disk they NEST under `metrics:`, so this
// encoder re-nests them. serviceName/otlpEndpoint/resourceAttributes are
// omitempty so an unset value stays ABSENT and the loader applies its default
// (serviceName→"warden"). metrics.enabled is a POINTER and written
// unconditionally: the loader defaults it to true when the block is present, so
// emitting it explicitly is the only way an operator's explicit false survives
// the round-trip rather than being silently re-defaulted to true.
type observabilityYAML struct {
	Enabled            bool                  `yaml:"enabled"`
	ServiceName        string                `yaml:"serviceName,omitempty"`
	Metrics            *observabilityMetrics `yaml:"metrics,omitempty"`
	ResourceAttributes map[string]string     `yaml:"resourceAttributes,omitempty"`
}

type observabilityMetrics struct {
	Enabled      *bool  `yaml:"enabled"`
	OTLPEndpoint string `yaml:"otlpEndpoint,omitempty"`
}

// observabilitySettingsNode encodes a wire Observability block into a YAML node
// matching the on-disk `observability:` shape. The caller only reaches here when
// observability is enabled; the metrics sub-block is always emitted so the
// flattened metricsEnabled/otlpEndpoint round-trip (metrics.enabled as a pointer
// so an explicit false is not re-defaulted to true by the loader).
func observabilitySettingsNode(s *config.ObservabilitySettings) (*yaml.Node, error) {
	raw := observabilityYAML{
		Enabled:     s.Enabled,
		ServiceName: s.ServiceName,
		Metrics: &observabilityMetrics{
			Enabled:      boolPtr(s.MetricsEnabled),
			OTLPEndpoint: s.OTLPEndpoint,
		},
		ResourceAttributes: s.ResourceAttributes,
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return nil, err
	}
	return &node, nil
}
