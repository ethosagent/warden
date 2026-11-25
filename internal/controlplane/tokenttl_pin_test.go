package controlplane

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/tokensvc"
)

// TestWardenTokenTTLPinned: the longest token lifetime a worker honours is the
// longest the control plane will mint. If the mint cap grows, workers must
// follow it in the same change.
func TestWardenTokenTTLPinned(t *testing.T) {
	worker, svc, cfg := identity.MaxWardenTokenTTL, tokensvc.MaxTTL, config.MaxTokenServiceTTL
	if worker != svc {
		t.Errorf("identity.MaxWardenTokenTTL %v != tokensvc.MaxTTL %v", worker, svc)
	}
	if worker != cfg {
		t.Errorf("identity.MaxWardenTokenTTL %v != config.MaxTokenServiceTTL %v", worker, cfg)
	}
}
