package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The offline API key commands (`warden control-plane api-key list|revoke`),
// W-P2-APIK-05. cmd/proxy only parses flags and maps errors to exit codes (rule
// C1); the logic is here. The commands use the apikeys.Store only: this process
// has no Index and no Run, so nothing here can authenticate a key. A running
// control plane notices a revoke on its next data_version poll (2 seconds) and
// refuses the key from then on. They never create a key and take no state-dir
// lock (a revoke must work while the control plane runs), like the worker-token
// CLI. Nothing printed, logged or audited here carries a secret or a hash: the
// Store has no method that returns either.

// Admin audit vocabulary of an offline revoke. The actions are the ones the
// console routes write (authz.go), so a revoke reads the same in the log
// whichever way it was made; the auth method (cli) tells them apart.
const (
	apiKeyAuditTarget      = auditTargetAPIKeys
	apiKeyAuditRevoke      = "api_key.revoke"
	apiKeyAuditRevokeOwner = "api_key.revoke_owner"
	apiKeyAuditOwnerRef    = "api_key:owner"
	apiKeyOpRevoke         = "revoke"
	apiKeyOpRevokeOwner    = "revoke_owner"
)

// ErrNoAPIKeyTable: the state dir's database has no api_keys table, so no key
// was ever created there (console.apiKeys was never enabled).
var ErrNoAPIKeyTable = errors.New("no API keys in this state dir (console.apiKeys was never enabled here)")

// ListAPIKeysOffline returns every key of the state dir's database, oldest
// first, opening it read-only. A database that never held API keys has none.
func ListAPIKeysOffline(ctx context.Context, stateDir string) ([]apikeys.Key, error) {
	if stateDir == "" {
		return nil, errors.New("api-key: --state-dir is required")
	}
	path := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("api-key: no control-plane state db in %s", stateDir)
	}
	db, err := cpstate.OpenReadOnly(ctx, path, StateMigrations())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if !slices.Contains(db.Applied(), sqlitestore.MigrationID) {
		return nil, nil
	}
	st, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry()})
	if err != nil {
		return nil, err
	}
	return st.List(ctx, apikeys.ListFilter{})
}

// APIKeyRevokeTarget names what to revoke: one key by ID, or every key of an
// owner by OwnerSub. Exactly one is set.
type APIKeyRevokeTarget struct {
	ID       string
	OwnerSub string
}

// APIKeyRevokeResult is what a revoke did.
type APIKeyRevokeResult struct {
	// Revoked lists the ids of the keys this call revoked, sorted.
	Revoked []string
	// Already reports a --id target that was revoked before: nothing changed
	// and no audit row was appended.
	Already bool
	// Audited is false when admin audit was never enabled in the state dir, so
	// no audit row exists.
	Audited bool
}

// RunAPIKeyRevoke revokes the key (or every unrevoked key of the owner) through
// the Store, stamping revoked_by with cli:<os user>, and appends one admin
// audit row for the call. The audit recorder opens first, so a missing or
// mismatching audit key aborts before anything is revoked. A revoke is never
// undone for a failed audit append (an operator killing a leaked key must not
// have it revived): the error then says the keys are revoked and unaudited.
func RunAPIKeyRevoke(ctx context.Context, stateDir, keyFile string, t APIKeyRevokeTarget, notice io.Writer) (APIKeyRevokeResult, error) {
	if (t.ID == "") == (t.OwnerSub == "") {
		return APIKeyRevokeResult{}, errors.New("api-key revoke: give exactly one of --id and --owner-sub")
	}
	h, err := openAPIKeyCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return APIKeyRevokeResult{}, err
	}
	defer h.close()
	actor := adminaudit.CLIActor()
	if t.ID != "" {
		return h.revokeID(ctx, t.ID, actor)
	}
	return h.revokeOwner(ctx, t.OwnerSub, actor)
}

func (h *apiKeyCLI) revokeID(ctx context.Context, id, actor string) (APIKeyRevokeResult, error) {
	k, err := h.store.Get(ctx, id)
	if err != nil {
		return APIKeyRevokeResult{}, err
	}
	if !k.RevokedAt.IsZero() {
		return APIKeyRevokeResult{Already: true}, nil
	}
	if err := h.store.Revoke(ctx, id, actor); err != nil {
		return APIKeyRevokeResult{}, err
	}
	// Revoke is idempotent and does not say whether it changed the row. If
	// another process revoked the key between the Get and the Revoke, it holds
	// that revoker's name: this call changed nothing, so it writes no audit row.
	if now, err := h.store.Get(ctx, id); err != nil {
		return APIKeyRevokeResult{}, err
	} else if now.RevokedBy != actor {
		return APIKeyRevokeResult{Already: true}, nil
	}
	res := APIKeyRevokeResult{Revoked: []string{id}, Audited: h.rec != nil}
	return res, h.record(ctx, apiKeyAuditRevoke, apiKeyRef(id), map[string]string{
		adminaudit.DetailOp:        apiKeyOpRevoke,
		adminaudit.DetailAPIKeyID:  id,
		adminaudit.DetailScopes:    strings.Join(scopeNames(k.Scopes), ","),
		adminaudit.DetailExpiresAt: rfc3339(k.ExpiresAt),
	}, res.Revoked)
}

func (h *apiKeyCLI) revokeOwner(ctx context.Context, sub, actor string) (APIKeyRevokeResult, error) {
	keys, err := h.store.List(ctx, apikeys.ListFilter{OwnerSub: sub})
	if err != nil {
		return APIKeyRevokeResult{}, err
	}
	issuers := map[string]bool{}
	var ids []string
	for _, k := range keys {
		if k.RevokedAt.IsZero() {
			issuers[k.OwnerIss] = true
			ids = append(ids, k.ID)
		}
	}
	if len(keys) == 0 {
		return APIKeyRevokeResult{}, fmt.Errorf("no API keys for owner %s", sub)
	}
	if len(ids) == 0 {
		return APIKeyRevokeResult{Already: true}, nil
	}
	sort.Strings(ids)
	var revokeErr error
	for iss := range issuers {
		if _, err := h.store.RevokeByOwner(ctx, iss, sub, actor); err != nil {
			revokeErr = errors.Join(revokeErr, err)
		}
	}
	// Report what is revoked now, not what was planned: a partial failure must
	// not claim keys that stayed live.
	after, err := h.store.List(ctx, apikeys.ListFilter{OwnerSub: sub})
	if err != nil {
		return APIKeyRevokeResult{}, errors.Join(revokeErr, err)
	}
	var done []string
	for _, k := range after {
		if !k.RevokedAt.IsZero() && slices.Contains(ids, k.ID) {
			done = append(done, k.ID)
		}
	}
	sort.Strings(done)
	res := APIKeyRevokeResult{Revoked: done, Audited: h.rec != nil}
	if len(done) > 0 {
		auditErr := h.record(ctx, apiKeyAuditRevokeOwner, apiKeyAuditOwnerRef, map[string]string{
			adminaudit.DetailOp:    apiKeyOpRevokeOwner,
			adminaudit.DetailCount: fmt.Sprintf("%d", len(done)),
		}, done)
		revokeErr = errors.Join(revokeErr, auditErr)
	}
	return res, revokeErr
}

// apiKeyCLI is the open handles of one revoke.
type apiKeyCLI struct {
	rec      adminaudit.Recorder
	store    apikeys.Store
	closeAll func()
}

func (h *apiKeyCLI) close() { h.closeAll() }

// record appends the audit row of a revoke; a nil recorder (audit never
// enabled here) is a no-op. A failed append leaves the keys revoked.
func (h *apiKeyCLI) record(ctx context.Context, action, ref string, details map[string]string, ids []string) error {
	if h.rec == nil {
		return nil
	}
	_, err := h.rec.Record(ctx, adminaudit.Input{
		Action: action, Target: apiKeyAuditTarget, TargetRef: ref,
		Details: details, Outcome: adminaudit.OutcomeOK,
	})
	if err != nil {
		return fmt.Errorf("admin audit: %w; the key(s) %s are revoked but no audit row was appended", err, strings.Join(ids, ", "))
	}
	return nil
}

// openAPIKeyCLI opens the audit recorder and the key store. The database must
// already exist and already hold the api_keys table: a revoke never creates
// either, and never applies the (feature-gated) migration.
func openAPIKeyCLI(ctx context.Context, stateDir, keyFile string, notice io.Writer) (*apiKeyCLI, error) {
	if stateDir == "" {
		return nil, errors.New("api-key: --state-dir is required")
	}
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("api-key: --state-dir %s is not a directory", stateDir)
	}
	path := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("api-key: no control-plane state db in %s", stateDir)
	}
	// Probe before opening for write: a state dir that never held keys is left
	// untouched.
	ro, err := cpstate.OpenReadOnly(ctx, path, StateMigrations())
	if err != nil {
		return nil, err
	}
	has := slices.Contains(ro.Applied(), sqlitestore.MigrationID)
	_ = ro.Close()
	if !has {
		return nil, ErrNoAPIKeyTable
	}
	rec, closeAudit, err := adminaudit.OpenForCLI(ctx, stateDir, keyFile, StateMigrations())
	if err != nil {
		return nil, fmt.Errorf("admin audit: %w", err)
	}
	db, err := cpstate.Open(ctx, path, StateMigrations())
	if err != nil {
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	st, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry()})
	if err != nil {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	if rec == nil && notice != nil {
		_, _ = fmt.Fprintln(notice, "warning: admin audit is not enabled in "+stateDir+"; no audit row appended")
	}
	return &apiKeyCLI{rec: rec, store: st, closeAll: func() {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
	}}, nil
}

// revokeAPIKeysInState revokes every unrevoked key of the database db through
// the Store, as by on clk (nil: real time), and returns how many it revoked. A database without the
// api_keys table has none. Restore uses it on the staged copy before the swap.
func revokeAPIKeysInState(ctx context.Context, db *cpstate.DB, by string, clk clock.Clock) (int, error) {
	// Applied() lists only what this Open applied, so ask the schema itself; a
	// failed query aborts (only "no table" means no keys).
	var tables int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='api_keys'").Scan(&tables); err != nil {
		return 0, fmt.Errorf("look for the api_keys table: %w", err)
	}
	if tables == 0 {
		return 0, nil
	}
	st, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry(), Clock: clk})
	if err != nil {
		return 0, err
	}
	keys, err := st.List(ctx, apikeys.ListFilter{})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		if !k.RevokedAt.IsZero() {
			continue
		}
		if err := st.Revoke(ctx, k.ID, by); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
