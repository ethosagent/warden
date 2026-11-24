package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The agent registry admin API's control-plane half (W-P2-AREG-02): the
// adapter from agentreg.Store to dashboard.AgentRegistry. It owns what needs
// the caller's identity (the actor, the owner of a new agent), the admin audit
// annotation, the post-write policy refresh and the in-memory counters kept for
// W-P5-RETN-06. Roles, CSRF and the audit row itself are the authz table and
// the audit middleware (authz.go). Nothing here logs, annotates or hashes a
// JWK: the audit details carry field names, key ids, groups and the status.

// auditTargetAgents is the admin audit target (and state hasher name) of the
// registry.
const auditTargetAgents = "agents"

// agentRef is the admin audit target_ref of an agent.
func agentRef(id string) string { return "agent:" + id }

// Registry write actions and outcomes, the labels of
// warden_cp_agent_registry_writes_total{action,outcome}.
const (
	agentActionCreate  = "create"
	agentActionUpdate  = "update"
	agentActionDisable = "disable"
	agentActionEnable  = "enable"

	agentOutcomeOK       = "ok"
	agentOutcomeInvalid  = "invalid"
	agentOutcomeNotFound = "not_found"
	agentOutcomeExists   = "exists"
	agentOutcomeKeyInUse = "key_in_use"
	agentOutcomeConflict = "conflict"
	agentOutcomeFull     = "full"
	agentOutcomeError    = "error"
)

// AgentWriteKey labels one warden_cp_agent_registry_writes_total series.
type AgentWriteKey struct{ Action, Outcome string }

// agentMetrics counts registry writes in memory.
type agentMetrics struct {
	mu     sync.Mutex
	writes map[AgentWriteKey]uint64
}

func (m *agentMetrics) inc(action, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writes == nil {
		m.writes = map[AgentWriteKey]uint64{}
	}
	m.writes[AgentWriteKey{action, outcome}]++
}

// AgentRegistryWrites returns warden_cp_agent_registry_writes_total{action,
// outcome}, kept in memory for W-P5-RETN-06.
func (s *Server) AgentRegistryWrites() map[AgentWriteKey]uint64 {
	s.agentMetrics.mu.Lock()
	defer s.agentMetrics.mu.Unlock()
	out := make(map[AgentWriteKey]uint64, len(s.agentMetrics.writes))
	for k, v := range s.agentMetrics.writes {
		out[k] = v
	}
	return out
}

// AgentRegistryCounts returns warden_cp_agents{status}: the number of agents
// per status, read from the registry (empty without one).
func (s *Server) AgentRegistryCounts(ctx context.Context) map[string]int {
	out := map[string]int{string(agentreg.StatusActive): 0, string(agentreg.StatusDisabled): 0}
	if s.agents == nil {
		return out
	}
	list, err := s.agents.List(ctx)
	if err != nil {
		s.cfg.Logger.Warn("agent registry: count failed", "error", err)
		return out
	}
	for _, a := range list {
		out[string(a.Status)]++
	}
	return out
}

// initAgentStore builds the registry store on the state DB unless one was
// injected (Config.AgentStore). Without either there is no registry and the
// routes answer 503 state_dir_required.
func (s *Server) initAgentStore() {
	if s.cfg.AgentStore != nil {
		s.agents = s.cfg.AgentStore
		return
	}
	if s.cfg.State == nil {
		return
	}
	s.agents = agentregsqlite.New(s.cfg.State, agentregsqlite.WithClock(s.cfg.Clock), agentregsqlite.WithLogger(s.cfg.Logger))
}

// agentWatcher is the optional part of a Store that notices another process's
// writes (the SQLite store's data_version poll); Run starts it.
type agentWatcher interface {
	Watch(ctx context.Context, interval time.Duration)
}

// agentRegistryAPI adapts an agentreg.Store to the dashboard's AgentRegistry.
type agentRegistryAPI struct {
	store   agentreg.Store
	logger  *slog.Logger
	refresh func()
	metrics *agentMetrics
}

var _ dashboard.AgentRegistry = agentRegistryAPI{}

func (agentRegistryAPI) Ready() error { return nil }

func (a agentRegistryAPI) List(ctx context.Context) ([]dashboard.AgentView, error) {
	list, err := a.store.List(ctx)
	if err != nil {
		return nil, a.unexpected("list", "", err)
	}
	out := make([]dashboard.AgentView, 0, len(list))
	for _, ag := range list {
		out = append(out, agentView(ag))
	}
	return out, nil
}

func (a agentRegistryAPI) Get(ctx context.Context, id string) (dashboard.AgentView, error) {
	ag, err := a.store.Get(ctx, id)
	if err != nil {
		return dashboard.AgentView{}, a.mapErr("get", id, err)
	}
	return agentView(ag), nil
}

func (a agentRegistryAPI) Create(ctx context.Context, in dashboard.AgentInput) (dashboard.AgentView, error) {
	adminaudit.Annotate(ctx, agentRef(in.ID), map[string]string{adminaudit.DetailOp: agentActionCreate})
	ag := agentFromInput(in)
	// The caller owns what they register. The owner is informational: it is
	// never an authorization input.
	if p, ok := PrincipalFrom(ctx); ok {
		ag.OwnerIss, ag.OwnerSub, ag.OwnerEmail = p.Iss, p.Sub, p.Email
	}
	out, err := a.store.Create(ctx, ag, blockActor(ctx))
	if err != nil {
		return dashboard.AgentView{}, a.failed(agentActionCreate, in.ID, err)
	}
	a.metrics.inc(agentActionCreate, agentOutcomeOK)
	adminaudit.Annotate(ctx, agentRef(out.ID), map[string]string{
		adminaudit.DetailOp:          agentActionCreate,
		adminaudit.DetailKidsAdded:   joinAudit(kids(out)),
		adminaudit.DetailGroupsAdded: joinAudit(out.AllowedGroups),
		adminaudit.DetailStatusTo:    string(out.Status),
	})
	a.refresh()
	return agentView(out), nil
}

func (a agentRegistryAPI) Update(ctx context.Context, id string, revision int64, in dashboard.AgentInput) (dashboard.AgentView, error) {
	adminaudit.Annotate(ctx, agentRef(id), map[string]string{adminaudit.DetailOp: agentActionUpdate})
	// The current row is read for the owner (an edit keeps it) and the audit
	// diff only. The compare-and-swap token is the revision the client sent,
	// never this read's: Store.Update refuses a stale one.
	cur, err := a.store.Get(ctx, id)
	if err != nil {
		return dashboard.AgentView{}, a.failed(agentActionUpdate, id, err)
	}
	ag := agentFromInput(in)
	ag.ID = id
	ag.OwnerIss, ag.OwnerSub, ag.OwnerEmail = cur.OwnerIss, cur.OwnerSub, cur.OwnerEmail
	ag.Revision = revision
	out, err := a.store.Update(ctx, ag, blockActor(ctx))
	if err != nil {
		return dashboard.AgentView{}, a.failed(agentActionUpdate, id, err)
	}
	a.metrics.inc(agentActionUpdate, agentOutcomeOK)
	addedK, removedK := diffSets(kids(cur), kids(out))
	addedG, removedG := diffSets(cur.AllowedGroups, out.AllowedGroups)
	adminaudit.Annotate(ctx, agentRef(id), map[string]string{
		adminaudit.DetailOp:            agentActionUpdate,
		adminaudit.DetailChanged:       strings.Join(changedFields(cur, out), ","),
		adminaudit.DetailKidsAdded:     joinAudit(addedK),
		adminaudit.DetailKidsRemoved:   joinAudit(removedK),
		adminaudit.DetailGroupsAdded:   joinAudit(addedG),
		adminaudit.DetailGroupsRemoved: joinAudit(removedG),
	})
	a.refresh()
	return agentView(out), nil
}

func (a agentRegistryAPI) SetEnabled(ctx context.Context, id string, enabled bool, revision int64) (dashboard.AgentView, error) {
	action, to := agentActionDisable, agentreg.StatusDisabled
	if enabled {
		action, to = agentActionEnable, agentreg.StatusActive
	}
	adminaudit.Annotate(ctx, agentRef(id), map[string]string{adminaudit.DetailOp: action})
	cur, err := a.store.Get(ctx, id)
	if err != nil {
		return dashboard.AgentView{}, a.failed(action, id, err)
	}
	out, err := a.store.SetStatus(ctx, id, to, revision, blockActor(ctx))
	if err != nil {
		return dashboard.AgentView{}, a.failed(action, id, err)
	}
	a.metrics.inc(action, agentOutcomeOK)
	adminaudit.Annotate(ctx, agentRef(id), map[string]string{
		adminaudit.DetailOp:         action,
		adminaudit.DetailStatusFrom: string(cur.Status),
		adminaudit.DetailStatusTo:   string(out.Status),
	})
	a.refresh()
	return agentView(out), nil
}

// failed counts a failed write by its outcome and maps the error.
func (a agentRegistryAPI) failed(action, id string, err error) error {
	a.metrics.inc(action, agentOutcome(err))
	return a.mapErr(action, id, err)
}

func agentOutcome(err error) string {
	switch {
	case errors.Is(err, agentreg.ErrInvalid):
		return agentOutcomeInvalid
	case errors.Is(err, agentreg.ErrNotFound):
		return agentOutcomeNotFound
	case errors.Is(err, agentreg.ErrAlreadyExists):
		return agentOutcomeExists
	case errors.Is(err, agentreg.ErrKeyInUse):
		return agentOutcomeKeyInUse
	case errors.Is(err, agentreg.ErrConflict):
		return agentOutcomeConflict
	case errors.Is(err, agentreg.ErrRegistryFull):
		return agentOutcomeFull
	}
	return agentOutcomeError
}

// mapErr maps a store error to the dashboard's. An unmapped error is logged
// (store errors carry an id, never a key document) and returned bare, which the
// handler answers with a fixed 500.
func (a agentRegistryAPI) mapErr(op, id string, err error) error {
	var ie *agentreg.InvalidError
	switch {
	case errors.As(err, &ie):
		return &dashboard.AgentInvalidError{Field: ie.Field, Reason: ie.Reason}
	case errors.Is(err, agentreg.ErrNotFound):
		return dashboard.ErrAgentNotFound
	case errors.Is(err, agentreg.ErrAlreadyExists):
		return dashboard.ErrAgentExists
	case errors.Is(err, agentreg.ErrKeyInUse):
		return dashboard.ErrAgentKeyInUse
	case errors.Is(err, agentreg.ErrConflict):
		return dashboard.ErrAgentConflict
	case errors.Is(err, agentreg.ErrRegistryFull):
		return dashboard.ErrAgentFull
	}
	return a.unexpected(op, id, err)
}

func (a agentRegistryAPI) unexpected(op, id string, err error) error {
	a.logger.Error("agent registry request failed", "op", op, "agent", id, "error", err)
	return err
}

// agentRegistryNoState answers every route with state_dir_required: a control
// plane without --state-dir has no registry.
type agentRegistryNoState struct{}

var _ dashboard.AgentRegistry = agentRegistryNoState{}

func (agentRegistryNoState) Ready() error { return dashboard.ErrAgentStateRequired }
func (agentRegistryNoState) List(context.Context) ([]dashboard.AgentView, error) {
	return nil, dashboard.ErrAgentStateRequired
}

func (agentRegistryNoState) Get(context.Context, string) (dashboard.AgentView, error) {
	return dashboard.AgentView{}, dashboard.ErrAgentStateRequired
}

func (agentRegistryNoState) Create(context.Context, dashboard.AgentInput) (dashboard.AgentView, error) {
	return dashboard.AgentView{}, dashboard.ErrAgentStateRequired
}

func (agentRegistryNoState) Update(context.Context, string, int64, dashboard.AgentInput) (dashboard.AgentView, error) {
	return dashboard.AgentView{}, dashboard.ErrAgentStateRequired
}

func (agentRegistryNoState) SetEnabled(context.Context, string, bool, int64) (dashboard.AgentView, error) {
	return dashboard.AgentView{}, dashboard.ErrAgentStateRequired
}

// wireAgents hands the dashboard the registry seam (the stub when there is no
// state DB) and registers the audit hasher of the "agents" target.
func (s *Server) wireAgents(dash *dashboard.Server) {
	if s.agents == nil {
		dash.SetAgentRegistry(agentRegistryNoState{})
		return
	}
	dash.SetAgentRegistry(agentRegistryAPI{store: s.agents, logger: s.cfg.Logger, refresh: s.refresh, metrics: &s.agentMetrics})
	s.RegisterStateHasher(auditTargetAgents, s.agentsStateHash)
}

// agentsStateHash is the keyed hash of every agent's identity-relevant state:
// id, status, revision, key thumbprints, groups and scopes. No key document is
// in it, and no time (so it moves only when an admin changes something).
func (s *Server) agentsStateHash(ctx context.Context) (string, error) {
	list, err := s.agents.List(ctx)
	if err != nil {
		return "", err
	}
	type row struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Status   string   `json:"status"`
		Revision int64    `json:"revision"`
		JKTs     []string `json:"jkts"`
		Groups   []string `json:"groups"`
		Scopes   []string `json:"scopes"`
	}
	rows := make([]row, 0, len(list))
	for _, a := range list {
		rows = append(rows, row{
			ID: a.ID, Name: a.DisplayName, Status: string(a.Status), Revision: a.Revision,
			JKTs: agentreg.Thumbprints(a), Groups: a.AllowedGroups, Scopes: a.AllowedScopes,
		})
	}
	return s.stateHashJSON(auditTargetAgents, rows)
}

func agentFromInput(in dashboard.AgentInput) agentreg.Agent {
	ag := agentreg.Agent{ID: in.ID, DisplayName: in.DisplayName, AllowedGroups: in.AllowedGroups, AllowedScopes: in.AllowedScopes}
	for _, raw := range in.Keys {
		ag.Keys = append(ag.Keys, agentreg.Key{JWK: raw})
	}
	return ag
}

func agentView(a agentreg.Agent) dashboard.AgentView {
	v := dashboard.AgentView{
		ID: a.ID, DisplayName: a.DisplayName,
		OwnerIss: a.OwnerIss, OwnerSub: a.OwnerSub, OwnerEmail: a.OwnerEmail,
		Keys:          make([]dashboard.AgentKeyView, 0, len(a.Keys)),
		AllowedGroups: nonNilStrings(a.AllowedGroups), AllowedScopes: nonNilStrings(a.AllowedScopes),
		Status: string(a.Status), Revision: a.Revision,
		CreatedAt: rfc3339(a.CreatedAt), CreatedBy: a.CreatedBy,
		UpdatedAt: rfc3339(a.UpdatedAt), UpdatedBy: a.UpdatedBy,
	}
	for _, k := range a.Keys {
		kv := dashboard.AgentKeyView{KID: k.KID, Alg: k.Alg, JKT: k.JKT}
		// The store returns validated keys, so the parse cannot fail; a key
		// that did would show its ids with an empty document, never raw bytes.
		if j, err := k.PublicJWK(); err == nil {
			kv.JWK = dashboard.KeyJWK{Kty: j.Kty, Crv: j.Crv, X: j.X, Y: j.Y, Kid: j.Kid, Alg: j.Alg, Use: j.Use}
		}
		v.Keys = append(v.Keys, kv)
	}
	return v
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func kids(a agentreg.Agent) []string {
	out := make([]string, 0, len(a.Keys))
	for _, k := range a.Keys {
		out = append(out, k.KID)
	}
	return out
}

// diffSets returns what is in after and not before (added) and in before and
// not after (removed), each sorted.
func diffSets(before, after []string) (added, removed []string) {
	in := func(set []string, v string) bool {
		for _, s := range set {
			if s == v {
				return true
			}
		}
		return false
	}
	for _, v := range after {
		if !in(before, v) {
			added = append(added, v)
		}
	}
	for _, v := range before {
		if !in(after, v) {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// changedFields names, in the API's member names, the editable fields whose
// value differs between before and after.
func changedFields(before, after agentreg.Agent) []string {
	var out []string
	if before.DisplayName != after.DisplayName {
		out = append(out, "displayName")
	}
	if a, r := diffSets(agentreg.Thumbprints(before), agentreg.Thumbprints(after)); len(a)+len(r) > 0 {
		out = append(out, "keys")
	} else if strings.Join(kids(before), ",") != strings.Join(kids(after), ",") {
		out = append(out, "keys")
	}
	if a, r := diffSets(before.AllowedGroups, after.AllowedGroups); len(a)+len(r) > 0 {
		out = append(out, "allowedGroups")
	}
	if a, r := diffSets(before.AllowedScopes, after.AllowedScopes); len(a)+len(r) > 0 {
		out = append(out, "allowedScopes")
	}
	return out
}

// joinAudit renders a list as one audit detail value: comma separated, with
// anything outside printable ASCII replaced (Annotate drops a value that has
// it) and cut at a whole element when the list would not fit one detail.
func joinAudit(in []string) string {
	var b strings.Builder
	for i, s := range in {
		s = strings.Map(func(r rune) rune {
			if r < 0x20 || r > 0x7e {
				return '?'
			}
			return r
		}, s)
		if b.Len()+len(s)+1 > adminaudit.MaxDetailValueLen-8 {
			b.WriteString(",...")
			break
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s)
	}
	return b.String()
}
