// Package agentreg is the domain of the control plane's registry of agents:
// which agents exist, which public keys authenticate them and which user
// groups may delegate to them. It holds the Agent type, the Store port and the
// validators every consumer shares (the admin API, the policy wire, the token
// service). It does no I/O: the SQLite implementation lives in
// internal/agentreg/adapters/sqlite and the conformance suite in
// internal/agentreg/agentregtest.
//
// Rows are never deleted and ids are never reused, so audit rows and token
// references stay resolvable; an agent is switched off with SetStatus. Key
// parsing and RFC 7638 thumbprints come from internal/keys, so the registry,
// the token service and workers compute the same jkt for one key.
//
// Errors and logs carry an agent id, a kid and at most a thumbprint prefix,
// never a key document or a user-supplied value.
package agentreg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ethosagent/warden/internal/keys"
)

// Status is an agent's lifecycle state.
type Status string

// The two statuses. A disabled agent keeps its row and its keys; consumers
// deny everything for it.
const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

// Valid reports whether s is one of the two statuses.
func (s Status) Valid() bool { return s == StatusActive || s == StatusDisabled }

// Key is one public key an agent authenticates with.
type Key struct {
	// KID is the key id the agent puts in its JWT header; unique within the
	// agent. Empty on input means the thumbprint.
	KID string `json:"kid"`
	// JKT is the RFC 7638 thumbprint, unique across the whole registry.
	// Computed by Validate; whatever the caller sets is overwritten.
	JKT string `json:"jkt"`
	// Alg is "EdDSA" (OKP/Ed25519) or "ES256" (EC/P-256), derived from the
	// key type by Validate.
	Alg string `json:"alg"`
	// JWK is the public key document. On input it is the raw JSON the
	// operator supplied (so private and hazardous members are caught); after
	// Validate it is the canonical document: kty, crv, x, y, kid, alg, use.
	JWK json.RawMessage `json:"jwk"`
}

// PublicJWK decodes the key's canonical document. Validate must have run
// (the store always returns validated keys).
func (k Key) PublicJWK() (keys.JWK, error) {
	j, err := keys.ParseJWK(k.JWK)
	if err != nil {
		return keys.JWK{}, fmt.Errorf("agentreg: key %q: %w", k.KID, err)
	}
	return j, nil
}

// Agent is one registered agent. There is deliberately no identity-mode or
// environments field: the per-agent identity mode lives in the P1 settings
// field, so there is one source of truth for it.
type Agent struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	// OwnerIss, OwnerSub and OwnerEmail identify the human who registered the
	// agent, as the IdP asserted them. Informational; not an authorization
	// input.
	OwnerIss   string `json:"owner_iss,omitempty"`
	OwnerSub   string `json:"owner_sub,omitempty"`
	OwnerEmail string `json:"owner_email,omitempty"`
	// Keys holds 1 or 2 keys (two during a rotation).
	Keys []Key `json:"keys"`
	// AllowedGroups are the user groups that may delegate to this agent,
	// normalized like policy rule groups. Non-empty for an active agent.
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	// AllowedScopes are the scopes a delegation to this agent may carry.
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	Status        Status   `json:"status"`
	// Revision starts at 1 and increments on every Update and SetStatus. It
	// is the compare-and-swap token: callers pass the revision they read.
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// Thumbprints is the one projection of an agent's key thumbprints: sorted,
// so equal key sets give equal output. The policy wire (W-P2-AREG-04) and the
// token service both use it.
func Thumbprints(a Agent) []string {
	if len(a.Keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(a.Keys))
	for _, k := range a.Keys {
		out = append(out, k.JKT)
	}
	sort.Strings(out)
	return out
}

// Errors returned by a Store. Branch with errors.Is.
var (
	// ErrInvalid wraps every validation failure; the concrete error is an
	// *InvalidError naming the field path.
	ErrInvalid = errors.New("agentreg: invalid agent")
	// ErrNotFound is returned for an unknown agent id.
	ErrNotFound = errors.New("agentreg: agent not found")
	// ErrAlreadyExists is returned by Create for an id that is registered.
	// Ids are never reused, so this holds for disabled agents too.
	ErrAlreadyExists = errors.New("agentreg: agent already exists")
	// ErrConflict is returned by Update and SetStatus when the revision the
	// caller read is no longer the stored one. Re-read and retry.
	ErrConflict = errors.New("agentreg: stale revision")
	// ErrKeyInUse is returned when a key thumbprint is already bound to
	// another agent: a key authenticates exactly one agent.
	ErrKeyInUse = errors.New("agentreg: key already bound to another agent")
	// ErrRegistryFull is returned by Create at config.MaxRegisteredAgents.
	ErrRegistryFull = errors.New("agentreg: registry is full")
)

// InvalidError is a validation failure. Field is the path of the offending
// field (for example "keys[0].crv" or "allowed_scopes[3]"); Reason is a fixed
// phrase. Neither ever contains the submitted value.
type InvalidError struct {
	Field  string
	Reason string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrInvalid.Error(), e.Field, e.Reason)
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Invalid builds the *InvalidError for field with a fixed reason phrase. A
// Store implementation uses it for the failures only it can see; the reason
// must never contain a submitted value.
func Invalid(field, reason string) error { return &InvalidError{Field: field, Reason: reason} }

// Store is the agent registry port. Implementations are safe for concurrent
// use. The SQLite store is the P2 implementation; agentregtest.Run is the
// conformance suite any other (the P5 Postgres store) must pass.
//
// actor is the admin id recorded in created_by/updated_by; it must be
// non-empty. Every write validates (Validate) before touching storage and runs
// in one transaction.
type Store interface {
	// Create registers a. Status defaults to active; Revision, CreatedAt and
	// UpdatedAt are set by the store (Revision 1). It returns the stored agent.
	// Errors: ErrInvalid, ErrAlreadyExists, ErrKeyInUse, ErrRegistryFull.
	Create(ctx context.Context, a Agent, actor string) (Agent, error)
	// Get returns the agent with id, or ErrNotFound.
	Get(ctx context.Context, id string) (Agent, error)
	// List returns every agent, disabled ones included, ordered by id.
	List(ctx context.Context) ([]Agent, error)
	// Update replaces a.ID's display name, owner, keys, groups and scopes
	// (the whole mutable document; Status is not touched) if a.Revision is
	// still the stored revision. a.Revision is the compare-and-swap token: a
	// caller must set it from what the client saw (the admin API, AREG-02,
	// from If-Match), never from a fresh read of its own, or the check is
	// void. Errors: ErrInvalid, ErrNotFound, ErrConflict, ErrKeyInUse.
	Update(ctx context.Context, a Agent, actor string) (Agent, error)
	// SetStatus changes only the status, if revision is still the stored one.
	// Enabling an agent with no allowed groups is ErrInvalid. Setting the
	// status it already has still bumps the revision.
	SetStatus(ctx context.Context, id string, status Status, revision int64, actor string) (Agent, error)
}
