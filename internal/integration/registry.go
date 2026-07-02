package integration

import (
	"fmt"
	"sort"
	"sync"
)

// registry maps a stable type key to a factory. It mirrors stdlib driver
// registries (database/sql, image): registration is a package-init side effect
// and a duplicate type is a programming error, so Register panics.
var (
	registryMu sync.RWMutex
	registry   = map[string]func() Integration{}
)

// Register makes an integration type available under typ. It panics on a nil
// factory or a duplicate type, mirroring stdlib driver registries. Call it from
// an integration package's init().
func Register(typ string, factory func() Integration) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if factory == nil {
		panic("integration: Register factory is nil")
	}
	if _, dup := registry[typ]; dup {
		panic(fmt.Sprintf("integration: Register called twice for type %q", typ))
	}
	registry[typ] = factory
}

// newInstance constructs a fresh integration for typ, or (nil, false) if the
// type is not registered.
func newInstance(typ string) (Integration, bool) {
	registryMu.RLock()
	factory, ok := registry[typ]
	registryMu.RUnlock()
	if !ok {
		return nil, false
	}
	return factory(), true
}

// registeredTypes returns the sorted set of registered type keys (validation /
// tests / error messages).
func registeredTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
