package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
)

// clientSecretReadTimeout bounds one consent.store read of a client secret.
const clientSecretReadTimeout = 10 * time.Second

// ErrNotClientSecretKey is returned for a key outside oauth-clients/.
var ErrNotClientSecretKey = errors.New("controlplane: key is not an oauth client secret key")

// ClientSecretResolver implements oauthbroker.SecretResolver over consent.store
// (W-P3-BRKR-06). It reads ONLY oauth-clients/<id> keys, so the broker seam
// cannot be pointed at a user grant (users/...) or an IdP refresh token (idp/...).
// It never touches the distributed secretStore: it holds the CP-only user
// credential store alone.
//
// Each call applies its own timeout. A store failure is returned as its Go type
// only, never its text, so nothing a backend echoes can reach a log.
type ClientSecretResolver struct {
	store   secrets.SecretStore
	timeout time.Duration
}

// NewClientSecretResolver returns a resolver over the consent.store st (the
// store NewUserStore built). A nil st is a programming error and the resolver
// then reports every read as unavailable.
func NewClientSecretResolver(st secrets.SecretStore) *ClientSecretResolver {
	return &ClientSecretResolver{store: st, timeout: clientSecretReadTimeout}
}

// ResolveSecret reads the client secret stored at key (oauth-clients/<id>).
func (r *ClientSecretResolver) ResolveSecret(ctx context.Context, key string) (string, error) {
	id, ok := strings.CutPrefix(key, secrets.ClientSecretPrefix)
	if !ok || !secrets.ValidProviderID(id) {
		return "", ErrNotClientSecretKey
	}
	if r == nil || r.store == nil {
		return "", errors.New("consent.store is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	v, err := r.store.Get(ctx, key)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("consent.store read of %s: %w", key, ctx.Err())
		}
		return "", fmt.Errorf("consent.store read of %s failed (%T)", key, err)
	}
	return v, nil
}
