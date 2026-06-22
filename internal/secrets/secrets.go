// Package secrets defines the SecretProvider interface and a provider-agnostic
// in-memory cache. Phase 1 ships only the ENV provider; Vault/AWS/GCP are later
// drop-in implementations of the same interface.
//
// Core invariant: real secret values live in memory only, are never persisted
// to disk, and are never logged. Observability references a secret by hash,
// last-4, or version via Reference — never the raw value.
package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// SecretProvider resolves a placeholder the agent holds into the real secret
// and supports a manual refresh. Implementations are swappable behind this
// interface (ENV in phase 1; Vault/AWS/GCP later).
type SecretProvider interface {
	GetSecret(placeholder string) (string, error)
	RefreshSecrets() error
}

// ErrUnknownPlaceholder is returned when a placeholder has no mapping.
var ErrUnknownPlaceholder = errors.New("secrets: unknown placeholder")

// Fetcher loads the raw value for a single placeholder from a backing source.
// The ENV provider is one Fetcher; Vault/AWS/GCP implement the same signature.
type Fetcher interface {
	Fetch(placeholder string) (string, error)
}

// EnvFetcher resolves placeholders from environment variables using a
// placeholder→envVar mapping (e.g. openai_secret_001 → OPENAI_API_KEY).
type EnvFetcher struct {
	mapping map[string]string
}

// NewEnvFetcher builds an EnvFetcher from a placeholder→envVar map.
func NewEnvFetcher(mapping map[string]string) *EnvFetcher {
	m := make(map[string]string, len(mapping))
	for k, v := range mapping {
		m[k] = v
	}
	return &EnvFetcher{mapping: m}
}

// Fetch returns the current value of the env var mapped to placeholder.
func (f *EnvFetcher) Fetch(placeholder string) (string, error) {
	envVar, ok := f.mapping[placeholder]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownPlaceholder, placeholder)
	}
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return "", fmt.Errorf("secrets: env var %q not set for placeholder %q", envVar, placeholder)
	}
	return val, nil
}

// placeholders returns the set of known placeholder names.
func (f *EnvFetcher) placeholders() []string {
	out := make([]string, 0, len(f.mapping))
	for k := range f.mapping {
		out = append(out, k)
	}
	return out
}

// entry is a single cached secret with its fetch time.
type entry struct {
	value     string
	fetchedAt time.Time
}

// Cache is the provider-agnostic in-memory secret cache implementing the
// documented semantics:
//   - prefetch all mapped secrets on startup,
//   - configurable TTL; on expiry refresh silently,
//   - silent-refresh failure keeps the stale value (requests keep flowing),
//   - manual RefreshSecrets drops the cache and hard-fails until a successful
//     refetch.
//
// Cache implements SecretProvider.
type Cache struct {
	fetcher Fetcher
	ttl     time.Duration
	keys    []string

	mu      sync.RWMutex
	entries map[string]entry
	// healthy is false after a failed manual refresh; requests hard-fail until
	// a subsequent refresh succeeds.
	healthy bool

	now func() time.Time
}

var _ SecretProvider = (*Cache)(nil)

// NewCache builds a cache over fetcher with the given TTL and the set of
// placeholders to prefetch. It performs the startup prefetch; a prefetch
// failure is returned so startup can fail loudly.
func NewCache(fetcher Fetcher, ttl time.Duration, placeholders []string) (*Cache, error) {
	c := &Cache{
		fetcher: fetcher,
		ttl:     ttl,
		keys:    append([]string(nil), placeholders...),
		entries: make(map[string]entry),
		now:     time.Now,
	}
	if err := c.RefreshSecrets(); err != nil {
		return nil, err
	}
	return c, nil
}

// GetSecret returns the real value for placeholder, refreshing silently if the
// cached value has expired. On a silent-refresh failure the stale value is
// returned. If the last manual refresh failed (cache unhealthy), it hard-fails.
func (c *Cache) GetSecret(placeholder string) (string, error) {
	c.mu.RLock()
	healthy := c.healthy
	e, ok := c.entries[placeholder]
	c.mu.RUnlock()

	if !healthy {
		return "", fmt.Errorf("secrets: cache unhealthy after failed manual refresh")
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownPlaceholder, placeholder)
	}

	if c.now().Sub(e.fetchedAt) < c.ttl {
		return e.value, nil
	}

	// Expired: refresh this entry silently. On failure keep the stale value.
	val, err := c.fetcher.Fetch(placeholder)
	if err != nil {
		return e.value, nil
	}
	c.mu.Lock()
	c.entries[placeholder] = entry{value: val, fetchedAt: c.now()}
	c.mu.Unlock()
	return val, nil
}

// RefreshSecrets drops the cache and refetches all mapped secrets. On any
// failure the cache is marked unhealthy and the error is returned so requests
// hard-fail until a successful refresh.
func (c *Cache) RefreshSecrets() error {
	fresh := make(map[string]entry, len(c.keys))
	for _, k := range c.keys {
		val, err := c.fetcher.Fetch(k)
		if err != nil {
			c.mu.Lock()
			c.entries = make(map[string]entry)
			c.healthy = false
			c.mu.Unlock()
			return fmt.Errorf("secrets: manual refresh failed for %q: %w", k, err)
		}
		fresh[k] = entry{value: val, fetchedAt: c.now()}
	}
	c.mu.Lock()
	c.entries = fresh
	c.healthy = true
	c.mu.Unlock()
	return nil
}

// Reference is a non-sensitive descriptor of a secret used in logs. It carries
// enough to identify which secret was used without exposing the raw value.
type Reference struct {
	// SHA256 is the full hex SHA-256 of the secret value.
	SHA256 string
	// Last4 is the last four characters of the secret (or fewer if shorter).
	Last4 string
	// Length is the secret length in bytes.
	Length int
}

// String renders a compact, log-safe reference. It never includes the raw
// value.
func (r Reference) String() string {
	return fmt.Sprintf("sha256:%s last4:%s len:%d", short(r.SHA256), r.Last4, r.Length)
}

// short truncates a hex digest for compact logging.
func short(hexDigest string) string {
	if len(hexDigest) <= 12 {
		return hexDigest
	}
	return hexDigest[:12]
}

// Ref builds a log-safe Reference for a raw secret value. The raw value never
// leaves this function; callers receive only the reference.
func Ref(value string) Reference {
	sum := sha256.Sum256([]byte(value))
	last4 := value
	if len(value) > 4 {
		last4 = value[len(value)-4:]
	}
	return Reference{
		SHA256: hex.EncodeToString(sum[:]),
		Last4:  last4,
		Length: len(value),
	}
}
