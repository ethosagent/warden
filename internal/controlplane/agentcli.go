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

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/cpstate"
)

// maxAgentJWKFileBytes bounds a --jwk-file read: a JWKS of two keys is well
// under 1 KiB, so anything larger is not a key file.
const maxAgentJWKFileBytes = 64 << 10

// The offline agent registry commands (`warden control-plane agent ...`).
// cmd/proxy only parses flags and maps errors to exit codes (rule C1); the
// logic is here. Writes go through the same agentreg.Store and validator as
// the admin API. A write is visible to a running control plane within one
// data_version poll of its store (2 seconds); how fast policy serving then
// carries it to workers is the policy wire's (W-P2-AREG-04).

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

// An agent write that cannot be audited is undone, like RunBlockAdd: no agent
// change stands without its audit entry. The store has no Delete, so the undo
// is the closest state it can reach: a registered agent is disabled, an update
// is reverted to the previous fields and a status change is flipped back, each
// as a further revision. The undo runs on context.WithoutCancel so an
// interrupt cannot leave the change standing.

// RunAgentRegister creates the agent and appends one agent.create admin audit
// row. The audit recorder opens first, so a missing or mismatching audit key
// aborts before anything is written. If the append still fails the agent is
// disabled again (ids are never reused, so the row stays).
func RunAgentRegister(ctx context.Context, stateDir, keyFile string, a agentreg.Agent, notice io.Writer) (agentreg.Agent, error) {
	h, err := openAgentCLI(ctx, stateDir, keyFile, notice, false)
	if err != nil {
		return agentreg.Agent{}, err
	}
	defer h.close()
	return h.register(ctx, a)
}

func (h *agentCLI) register(ctx context.Context, a agentreg.Agent) (agentreg.Agent, error) {
	actor := adminaudit.CLIActor()
	got, err := h.store.Create(ctx, a, actor)
	if err != nil {
		return agentreg.Agent{}, err
	}
	auditErr := h.record(ctx, AgentActionCreate, got.ID, AgentAuditDetails(nil, got))
	if auditErr == nil {
		return got, nil
	}
	if _, undoErr := h.store.SetStatus(context.WithoutCancel(ctx), got.ID, agentreg.StatusDisabled, got.Revision, actor); undoErr != nil {
		return agentreg.Agent{}, fmt.Errorf("agent %s was registered but its admin audit row was not appended (%v) and it could not be disabled again: %w", got.ID, auditErr, undoErr)
	}
	return agentreg.Agent{}, fmt.Errorf("admin audit: %w; agent %s was registered then disabled again (ids are never reused: pick a new id)", auditErr, got.ID)
}

// RunAgentUpdate applies change to the agent id if revision is still the stored
// one, and appends one agent.update admin audit row. revision is the one the
// operator read (the compare-and-swap token), not a fresh read. If the append
// fails the previous fields and keys are restored.
func RunAgentUpdate(ctx context.Context, stateDir, keyFile, id string, revision int64, change AgentChange, notice io.Writer) (agentreg.Agent, error) {
	h, err := openAgentCLI(ctx, stateDir, keyFile, notice, true)
	if err != nil {
		return agentreg.Agent{}, err
	}
	defer h.close()
	return h.update(ctx, id, revision, change)
}

func (h *agentCLI) update(ctx context.Context, id string, revision int64, change AgentChange) (agentreg.Agent, error) {
	actor := adminaudit.CLIActor()
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
	got, err := h.store.Update(ctx, next, actor)
	if err != nil {
		return agentreg.Agent{}, err
	}
	auditErr := h.record(ctx, AgentActionUpdate, got.ID, AgentAuditDetails(&cur, got))
	if auditErr == nil {
		return got, nil
	}
	back := cur
	back.Revision = got.Revision
	if _, undoErr := h.store.Update(context.WithoutCancel(ctx), back, actor); undoErr != nil {
		return agentreg.Agent{}, fmt.Errorf("agent %s was updated but its admin audit row was not appended (%v) and the update could not be reverted: %w", got.ID, auditErr, undoErr)
	}
	return agentreg.Agent{}, fmt.Errorf("admin audit: %w; the update was reverted", auditErr)
}

// RunAgentSetStatus disables or enables the agent id if revision is still the
// stored one, and appends one agent.disable or agent.enable admin audit row. If
// the append fails the previous status is restored.
func RunAgentSetStatus(ctx context.Context, stateDir, keyFile, id string, status agentreg.Status, revision int64, notice io.Writer) (agentreg.Agent, error) {
	h, err := openAgentCLI(ctx, stateDir, keyFile, notice, true)
	if err != nil {
		return agentreg.Agent{}, err
	}
	defer h.close()
	return h.setStatus(ctx, id, status, revision)
}

func (h *agentCLI) setStatus(ctx context.Context, id string, status agentreg.Status, revision int64) (agentreg.Agent, error) {
	actor := adminaudit.CLIActor()
	cur, err := h.store.Get(ctx, id)
	if err != nil {
		return agentreg.Agent{}, err
	}
	got, err := h.store.SetStatus(ctx, id, status, revision, actor)
	if err != nil {
		return agentreg.Agent{}, err
	}
	action := AgentActionEnable
	if status == agentreg.StatusDisabled {
		action = AgentActionDisable
	}
	auditErr := h.record(ctx, action, got.ID, AgentAuditDetails(&cur, got))
	if auditErr == nil {
		return got, nil
	}
	if _, undoErr := h.store.SetStatus(context.WithoutCancel(ctx), id, cur.Status, got.Revision, actor); undoErr != nil {
		return agentreg.Agent{}, fmt.Errorf("agent %s was changed to %s but its admin audit row was not appended (%v) and the change could not be reverted: %w", got.ID, status, auditErr, undoErr)
	}
	return agentreg.Agent{}, fmt.Errorf("admin audit: %w; the status change was reverted", auditErr)
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
		Action: action, Target: AgentAuditTarget, TargetRef: AgentAuditRef(id),
		Details: details, Outcome: adminaudit.OutcomeOK,
	})
	return err
}

// openAgentCLI opens the audit recorder and the registry store. mustExist
// refuses a state dir with no database (update, disable, enable) instead of
// creating one, as RunBlockRemove does.
func openAgentCLI(ctx context.Context, stateDir, keyFile string, notice io.Writer, mustExist bool) (*agentCLI, error) {
	if stateDir == "" {
		return nil, errors.New("agent: --state-dir is required")
	}
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("agent: --state-dir %s is not a directory", stateDir)
	}
	if mustExist {
		if _, err := os.Stat(filepath.Join(stateDir, adminaudit.StateDBFileName)); err != nil {
			return nil, fmt.Errorf("%w: no control-plane state db in %s", agentreg.ErrNotFound, stateDir)
		}
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
