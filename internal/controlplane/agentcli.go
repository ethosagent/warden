package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Admin audit vocabulary of the agent registry's writes: one target, one
// action per kind of write, and a details allowlist (changed field names, kids
// and groups added or removed, status from/to) that never carries a JWK
// coordinate. The admin API (W-P2-AREG-02) uses the same names.
const (
	auditTargetAgents  = "agents"
	actionAgentCreate  = "agent.create"
	actionAgentUpdate  = "agent.update"
	actionAgentDisable = "agent.disable"
	actionAgentEnable  = "agent.enable"
)

// maxAgentJWKFileBytes bounds a --jwk-file read: a JWKS of two keys is well
// under 1 KiB, so anything larger is not a key file.
const maxAgentJWKFileBytes = 64 << 10

// The offline agent registry commands (`warden control-plane agent ...`).
// cmd/proxy only parses flags and maps errors to exit codes (rule C1); the
// logic is here. Writes go through the same agentreg.Store and validator as
// the admin API, so a running control plane serves them as soon as its store's
// data_version watch sees the commit (about 2 seconds).

// AgentChange is the operator's requested edit of an agent. Nil pointer and
// nil slice mean "leave as it is" (update); register takes them as given.
type AgentChange struct {
	DisplayName *string
	Groups      []string
	Scopes      []string
	// SetGroups and SetScopes distinguish an explicit empty list from absent.
	SetGroups bool
	SetScopes bool
	// Keys replaces the whole key set when non-nil.
	Keys []agentreg.Key
}

// ReadAgentJWKFiles loads every --jwk-file: each is one public JWK object or a
// JWKS ({"keys":[...]}) as `warden identity enroll` prints. The keys of all
// files are returned in order, so a validation error's keys[i] path indexes
// that list. Errors name the file, never its content.
func ReadAgentJWKFiles(paths []string) ([]agentreg.Key, error) {
	var out []agentreg.Key
	for _, p := range paths {
		raws, err := readAgentJWKFile(p)
		if err != nil {
			return nil, err
		}
		for _, r := range raws {
			out = append(out, agentreg.Key{JWK: r})
		}
	}
	return out, nil
}

func readAgentJWKFile(path string) ([]json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--jwk-file: cannot read %s", path)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAgentJWKFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("--jwk-file: cannot read %s", path)
	}
	if len(data) > maxAgentJWKFileBytes {
		return nil, fmt.Errorf("--jwk-file: %s is over %d bytes", path, maxAgentJWKFileBytes)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return nil, fmt.Errorf("--jwk-file: %s is not a JSON object (want a public JWK or a JWKS)", path)
	}
	list, isSet := doc["keys"]
	if !isSet {
		return []json.RawMessage{data}, nil
	}
	var members []json.RawMessage
	if err := json.Unmarshal(list, &members); err != nil || len(members) == 0 {
		return nil, fmt.Errorf("--jwk-file: %s has a keys member that is not a non-empty array", path)
	}
	return members, nil
}

// RunAgentRegister creates the agent and appends one agent.create admin audit
// row. The audit recorder opens first, so a missing or mismatching audit key
// aborts before anything is written.
func RunAgentRegister(ctx context.Context, stateDir, keyFile string, a agentreg.Agent, notice io.Writer) (agentreg.Agent, error) {
	h, err := openAgentCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return agentreg.Agent{}, err
	}
	defer h.close()
	got, err := h.store.Create(ctx, a, adminaudit.CLIActor())
	if err != nil {
		return agentreg.Agent{}, err
	}
	if err := h.record(ctx, actionAgentCreate, got.ID, agentAuditDetails(agentreg.Agent{}, got)); err != nil {
		return agentreg.Agent{}, fmt.Errorf("agent %s was registered but its admin audit row was not appended: %w", got.ID, err)
	}
	return got, nil
}

// RunAgentUpdate applies change to the agent id if revision is still the stored
// one, and appends one agent.update admin audit row. revision is the one the
// operator read (the compare-and-swap token), not a fresh read.
func RunAgentUpdate(ctx context.Context, stateDir, keyFile, id string, revision int64, change AgentChange, notice io.Writer) (agentreg.Agent, error) {
	h, err := openAgentCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return agentreg.Agent{}, err
	}
	defer h.close()
	cur, err := h.store.Get(ctx, id)
	if err != nil {
		return agentreg.Agent{}, err
	}
	next := cur
	if change.DisplayName != nil {
		next.DisplayName = *change.DisplayName
	}
	if change.SetGroups {
		next.AllowedGroups = change.Groups
	}
	if change.SetScopes {
		next.AllowedScopes = change.Scopes
	}
	if change.Keys != nil {
		next.Keys = change.Keys
	}
	next.Revision = revision
	got, err := h.store.Update(ctx, next, adminaudit.CLIActor())
	if err != nil {
		return agentreg.Agent{}, err
	}
	if err := h.record(ctx, actionAgentUpdate, got.ID, agentAuditDetails(cur, got)); err != nil {
		return agentreg.Agent{}, fmt.Errorf("agent %s was updated but its admin audit row was not appended: %w", got.ID, err)
	}
	return got, nil
}

// RunAgentSetStatus disables or enables the agent id if revision is still the
// stored one, and appends one agent.disable or agent.enable admin audit row.
func RunAgentSetStatus(ctx context.Context, stateDir, keyFile, id string, status agentreg.Status, revision int64, notice io.Writer) (agentreg.Agent, error) {
	h, err := openAgentCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return agentreg.Agent{}, err
	}
	defer h.close()
	cur, err := h.store.Get(ctx, id)
	if err != nil {
		return agentreg.Agent{}, err
	}
	got, err := h.store.SetStatus(ctx, id, status, revision, adminaudit.CLIActor())
	if err != nil {
		return agentreg.Agent{}, err
	}
	action := actionAgentEnable
	if status == agentreg.StatusDisabled {
		action = actionAgentDisable
	}
	if err := h.record(ctx, action, got.ID, agentAuditDetails(cur, got)); err != nil {
		return agentreg.Agent{}, fmt.Errorf("agent %s was changed but its admin audit row was not appended: %w", got.ID, err)
	}
	return got, nil
}

// ListAgentsOffline returns every agent, ordered by id, opening the database
// read-only. A state dir whose database predates the registry has none.
func ListAgentsOffline(ctx context.Context, stateDir string) ([]agentreg.Agent, error) {
	db, err := cpstate.OpenReadOnly(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if !slices.Contains(db.Applied(), agentregsqlite.MigrationID) {
		return nil, nil
	}
	return agentregsqlite.New(db).List(ctx)
}

// agentCLI is the open handles of one writing command.
type agentCLI struct {
	rec      adminaudit.Recorder
	store    *agentregsqlite.Store
	closeAll func()
}

func (h *agentCLI) close() { h.closeAll() }

// record appends the audit row of one write; a nil recorder (audit never
// enabled here) is a no-op.
func (h *agentCLI) record(ctx context.Context, action, id string, details map[string]string) error {
	if h.rec == nil {
		return nil
	}
	_, err := h.rec.Record(ctx, adminaudit.Input{
		Action: action, Target: auditTargetAgents, TargetRef: "agent:" + id,
		Details: details, Outcome: adminaudit.OutcomeOK,
	})
	return err
}

func openAgentCLI(ctx context.Context, stateDir, keyFile string, notice io.Writer) (*agentCLI, error) {
	if stateDir == "" {
		return nil, errors.New("agent: --state-dir is required")
	}
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("agent: --state-dir %s is not a directory", stateDir)
	}
	rec, closeAudit, err := adminaudit.OpenForCLI(ctx, stateDir, keyFile, StateMigrations())
	if err != nil {
		return nil, fmt.Errorf("admin audit: %w", err)
	}
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	if rec == nil && notice != nil {
		_, _ = fmt.Fprintln(notice, "warning: admin audit is not enabled in "+stateDir+"; no audit row appended")
	}
	return &agentCLI{rec: rec, store: agentregsqlite.New(db), closeAll: func() {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
	}}, nil
}

// agentAuditDetails is the details allowlist of an agent write: the names of
// the changed fields, the kids and groups added and removed, and the status
// from/to. before is the zero Agent for a create. Nothing from a JWK but its
// kid appears.
func agentAuditDetails(before, after agentreg.Agent) map[string]string {
	d := map[string]string{}
	var changed []string
	if before.DisplayName != after.DisplayName {
		changed = append(changed, "display_name")
	}
	bk, ak := agentKIDs(before), agentKIDs(after)
	if !slices.Equal(bk, ak) || !slices.Equal(agentJKTs(before), agentJKTs(after)) {
		changed = append(changed, "keys")
	}
	if added, removed := diffSets(bk, ak); len(added) > 0 || len(removed) > 0 {
		setDetail(d, "kids_added", added)
		setDetail(d, "kids_removed", removed)
	}
	bg, ag := sortedCopy(before.AllowedGroups), sortedCopy(after.AllowedGroups)
	if added, removed := diffSets(bg, ag); len(added) > 0 || len(removed) > 0 {
		changed = append(changed, "allowed_groups")
		setDetail(d, "groups_added", added)
		setDetail(d, "groups_removed", removed)
	}
	if !slices.Equal(sortedCopy(before.AllowedScopes), sortedCopy(after.AllowedScopes)) {
		changed = append(changed, "allowed_scopes")
	}
	if before.Status != after.Status {
		changed = append(changed, "status")
		d["status_from"] = string(before.Status)
		d["status_to"] = string(after.Status)
	}
	if len(changed) > 0 {
		d["fields"] = strings.Join(changed, ",")
	}
	return d
}

func agentKIDs(a agentreg.Agent) []string {
	out := make([]string, 0, len(a.Keys))
	for _, k := range a.Keys {
		out = append(out, k.KID)
	}
	sort.Strings(out)
	return out
}

func agentJKTs(a agentreg.Agent) []string { return agentreg.Thumbprints(a) }

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}

// diffSets returns the members only in after (added) and only in before
// (removed); both inputs are sorted.
func diffSets(before, after []string) (added, removed []string) {
	for _, v := range after {
		if !slices.Contains(before, v) {
			added = append(added, v)
		}
	}
	for _, v := range before {
		if !slices.Contains(after, v) {
			removed = append(removed, v)
		}
	}
	return added, removed
}

func setDetail(d map[string]string, name string, vals []string) {
	if len(vals) > 0 {
		d[name] = strings.Join(vals, ",")
	}
}
