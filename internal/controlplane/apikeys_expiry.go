package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/integration"
)

// API key expiry warnings (W-P2-APIK-05). Once an hour a job lists the keys
// that expire within 7 days and publishes one api_key_expiring Finding per key,
// so a CI job's key does not lapse unnoticed. It reads through the Store (the
// Index is not needed) and runs only with console.apiKeys.enabled. A Finding
// carries the key id, name, owner email and expiry, never a secret or a hash:
// the Store returns neither.
const (
	// findingAPIKeyExpiring is the rule id and the DedupKey prefix.
	findingAPIKeyExpiring = "api_key_expiring"
	// apiKeyExpiryInterval is how often the job scans.
	apiKeyExpiryInterval = time.Hour
	// apiKeyExpiryWindow is how far ahead of expiry a key is reported.
	apiKeyExpiryWindow = 7 * 24 * time.Hour
)

// scanExpiringAPIKeys publishes a Finding for every unrevoked key expiring
// within the warning window that this process has not reported yet, and returns
// how many it published. A key revoked or already expired is not listed by the
// Store's ExpiresBefore filter.
func (s *Server) scanExpiringAPIKeys(ctx context.Context) (int, error) {
	st := s.cfg.APIKeyStore
	if st == nil {
		return 0, nil
	}
	now := s.cfg.Clock.Now()
	keys, err := st.List(ctx, apikeys.ListFilter{ExpiresBefore: now.Add(apiKeyExpiryWindow)})
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		s.publishFinding(apiKeyExpiringFinding(k, now))
	}
	return len(keys), nil
}

// apiKeyExpiringFinding is the medium Finding for one expiring key. The owner's
// email is evidence for the operator; the Subject carries only the opaque sub.
func apiKeyExpiringFinding(k apikeys.Key, now time.Time) integration.Finding {
	left := k.ExpiresAt.Sub(now).Round(time.Hour)
	return integration.Finding{
		RuleID:   findingAPIKeyExpiring,
		Category: "security",
		Severity: integration.SevMedium,
		Subject:  integration.Subject{Tool: "api_keys", User: k.OwnerSub},
		Summary:  fmt.Sprintf("API key %q expires in %s: replace it before CI or scripts using it start failing", k.Name, left),
		Evidence: integration.Evidence(fmt.Sprintf("key_id=%s name=%q owner_email=%q expires_at=%s",
			k.ID, k.Name, k.OwnerEmail, rfc3339(k.ExpiresAt))),
		DedupKey: findingAPIKeyExpiring + ":" + k.ID,
		Ts:       now,
	}
}

// runAPIKeyExpiry scans once at start and then every apiKeyExpiryInterval of
// the control plane's clock until ctx is cancelled, then closes done. A failed
// scan is logged and retried at the next tick.
func (s *Server) runAPIKeyExpiry(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	for {
		if _, err := s.scanExpiringAPIKeys(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Error("api_key_expiry_scan_failed", "error", err)
		}
		t := s.cfg.Clock.NewTimer(apiKeyExpiryInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C():
		}
	}
}
