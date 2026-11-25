package apikeys

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/ethosagent/warden/internal/config"
)

// Scope names one capability a key can hold, in "resource:verb" form. A key's
// scopes are fixed at creation.
type Scope string

// Sentinels for the control plane's route table. Neither is a grantable scope:
// they have no colon, so they can never collide with a registered one, and
// ParseScopes and Lookup reject them.
const (
	// ScopeNone marks a route no API key may reach.
	ScopeNone Scope = "none"
	// ScopeSelf marks a route any valid key may reach (introspection of itself).
	ScopeSelf Scope = "self"
)

var scopeRe = regexp.MustCompile(`^[a-z][a-z0-9]*:[a-z][a-z0-9]*$`)

// Errors from the scope registry.
var (
	ErrUnknownScope   = errors.New("apikeys: unknown scope")
	ErrDuplicateScope = errors.New("apikeys: duplicate scope")
	ErrNoScopes       = errors.New("apikeys: at least one scope is required")
	ErrInvalidScope   = errors.New("apikeys: invalid scope name or role")
)

// Registry holds the scopes a control plane knows and the minimum console role
// each needs. It is built once at assembly (NewP2Registry for the scopes P2
// ships; later features Register theirs before the registry is shared) and
// passed to the Store, so there is no package-level registry.
type Registry struct {
	mu     sync.RWMutex
	scopes map[Scope]config.Role
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{scopes: map[Scope]config.Role{}} }

// NewP2Registry returns a registry holding the scopes Phase 2 ships.
func NewP2Registry() *Registry {
	r := NewRegistry()
	for _, e := range []struct {
		s    Scope
		role config.Role
	}{
		{"policy:read", config.RoleViewer},
		{"settings:read", config.RoleViewer},
		{"traffic:read", config.RoleViewer},
		{"audit:read", config.RoleViewer},
		{"policy:draft", config.RoleEditor},
		{"policy:write", config.RoleEditor},
		{"adminaudit:read", config.RoleAdmin},
		{"agents:read", config.RoleAdmin},
		{"agents:write", config.RoleAdmin},
		{"workers:admin", config.RoleAdmin},
	} {
		if err := r.Register(e.s, e.role); err != nil {
			panic(err) // a programming error in the table above
		}
	}
	return r
}

// ReservedRole returns the minimum role a reserved scope must be registered
// at: mcp:read viewer and mcp:write editor (P4 MCP registry), grants:read
// viewer (W-P4-DGR-06) and grants:write admin (W-P4-DGR-07). The names are
// unknown to ParseScopes until their feature registers them, so a key cannot be
// minted for a capability that does not exist yet; reserving the name and role
// stops another feature claiming it with a different meaning.
func ReservedRole(s Scope) (config.Role, bool) {
	switch s {
	case "mcp:read", "grants:read":
		return config.RoleViewer, true
	case "mcp:write":
		return config.RoleEditor, true
	case "grants:write":
		return config.RoleAdmin, true
	}
	return 0, false
}

// Reserved reports whether s is a name held for a later feature.
func Reserved(s Scope) bool {
	_, ok := ReservedRole(s)
	return ok
}

// Register adds s to the registry with the minimum console role a key owner
// must hold for a key to use it. The name must look like "resource:verb" and
// the role must be one of the three console roles; a scope registers once.
func (r *Registry) Register(s Scope, minRole config.Role) error {
	if !scopeRe.MatchString(string(s)) {
		return fmt.Errorf("%w: %q is not resource:verb", ErrInvalidScope, string(s))
	}
	if minRole < config.RoleViewer || minRole > config.RoleAdmin {
		return fmt.Errorf("%w: role for %q", ErrInvalidScope, string(s))
	}
	if want, ok := ReservedRole(s); ok && want != minRole {
		return fmt.Errorf("%w: %q is reserved at role %s", ErrInvalidScope, string(s), want)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.scopes[s]; dup {
		return fmt.Errorf("%w: %q already registered", ErrDuplicateScope, string(s))
	}
	r.scopes[s] = minRole
	return nil
}

// Lookup returns the minimum role for a registered scope. ScopeNone, ScopeSelf
// and reserved-but-unregistered scopes report false.
func (r *Registry) Lookup(s Scope) (config.Role, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.scopes[s]
	return role, ok
}

// Registered returns every registered scope, sorted by name.
func (r *Registry) Registered() []Scope {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Scope, 0, len(r.scopes))
	for s := range r.scopes {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseScopes converts requested scope names to Scopes. It rejects an empty
// list, an unknown or reserved name, a sentinel and a duplicate, naming the
// offender. Order is preserved.
func (r *Registry) ParseScopes(names []string) ([]Scope, error) {
	if len(names) == 0 {
		return nil, ErrNoScopes
	}
	out := make([]Scope, 0, len(names))
	seen := make(map[Scope]struct{}, len(names))
	for _, n := range names {
		s := Scope(n)
		if _, ok := r.Lookup(s); !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownScope, n)
		}
		if _, dup := seen[s]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateScope, n)
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

// MaxRole returns the highest minimum role among scopes (the least privileged
// console role that may hold all of them), or 0 for an empty list.
func (r *Registry) MaxRole(scopes []Scope) config.Role {
	var max config.Role
	for _, s := range scopes {
		if role, ok := r.Lookup(s); ok && role > max {
			max = role
		}
	}
	return max
}
