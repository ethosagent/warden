package controlplane

import (
	"slices"
	"sync"

	"github.com/ethosagent/warden/internal/config"
)

// The fail-open guard of identity challenge mode (#558). A worker that does not
// know the `challenge` mode rejects the settings and keeps its previous config,
// which in practice means it keeps allowing callers it should be challenging.
// The control plane cannot stop that, so it makes it visible: while the served
// settings turn challenge on, every connected worker whose heartbeat caps lack
// identity/challenge-v1 is flagged in the fleet view and logged once per ETag.

// challengeFlags caches whether the served ETag turns challenge mode on and
// remembers the ETag each worker was last logged for.
type challengeFlags struct {
	mu       sync.Mutex
	etag     string
	served   bool
	computed bool
	logged   map[string]string // proxy id -> etag the lack was logged for
}

// challengeServedWire reports whether w's settings put any agent in challenge
// mode: the identity block's default, or an agent's own override.
func challengeServedWire(w policyWire) bool {
	if w.Settings == nil {
		return false
	}
	if id := w.Settings.Identity; id != nil && id.DefaultMode == config.IdentityModeChallenge {
		return true
	}
	for _, a := range w.Settings.Agents {
		if a.Identity == config.IdentityModeChallenge {
			return true
		}
	}
	return false
}

// challengeServed reports whether the served policy turns challenge mode on,
// recomputed only when the ETag changes. False before the first load.
func (s *Server) challengeServed() bool {
	on, _ := s.challengeServedETag()
	return on
}

func (s *Server) challengeServedETag() (bool, string) {
	wire, etag, ok, _ := s.policy.snapshot()
	if !ok {
		return false, ""
	}
	s.cf.mu.Lock()
	defer s.cf.mu.Unlock()
	if !s.cf.computed || s.cf.etag != etag {
		s.cf.etag, s.cf.served, s.cf.computed = etag, challengeServedWire(wire), true
	}
	return s.cf.served, etag
}

// noteIdentityChallenge logs worker_lacks_identity_challenge once per worker per
// ETag while challenge mode is served and caps lack identity/challenge-v1. The
// line carries the proxy id only.
func (s *Server) noteIdentityChallenge(proxyID string, caps []string) {
	if proxyID == "" || slices.Contains(caps, config.CapIdentityChallengeV1) {
		return
	}
	on, etag := s.challengeServedETag()
	if !on {
		return
	}
	s.cf.mu.Lock()
	if s.cf.logged == nil || len(s.cf.logged) >= maxGroupPolicyLogMarks {
		s.cf.logged = make(map[string]string)
	}
	seen := s.cf.logged[proxyID] == etag
	s.cf.logged[proxyID] = etag
	s.cf.mu.Unlock()
	if seen {
		return
	}
	s.cfg.Logger.Warn("worker_lacks_identity_challenge", "proxy_id", proxyID)
}
