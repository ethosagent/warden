package controlplane

import (
	"slices"
	"sync"

	"github.com/ethosagent/warden/internal/config"
)

// maxGroupPolicyLogMarks bounds the per-worker log marks; past it the map is
// reset, which at worst repeats a log line.
const maxGroupPolicyLogMarks = 10000

// groupPolicyFlags caches the scoped-rule count of the served ETag (computed
// once per ETag) and remembers the ETag each worker was last logged for.
type groupPolicyFlags struct {
	mu       sync.Mutex
	etag     string
	entries  int
	computed bool
	logged   map[string]string // proxy id -> etag the lack was logged for
}

// scopedEntries returns the number of identity-scoped rules in the served
// policy, recomputed only when the ETag changes. 0 before the first load.
func (s *Server) scopedEntries() int {
	n, _ := s.scopedEntriesETag()
	return n
}

func (s *Server) scopedEntriesETag() (int, string) {
	wire, etag, ok, _ := s.policy.snapshot()
	if !ok {
		return 0, ""
	}
	s.gp.mu.Lock()
	defer s.gp.mu.Unlock()
	if !s.gp.computed || s.gp.etag != etag {
		s.gp.etag, s.gp.entries, s.gp.computed = etag, scopedEntryCount(wire), true
	}
	return s.gp.entries, etag
}

// noteGroupPolicy logs worker_lacks_grouppolicy once per worker per ETag when
// the served policy has scoped rules and caps lack grouppolicy/v1. The line
// carries the proxy id and the count, never group names.
func (s *Server) noteGroupPolicy(proxyID string, caps []string) {
	if proxyID == "" || slices.Contains(caps, config.CapGroupPolicyV1) {
		return
	}
	n, etag := s.scopedEntriesETag()
	if n == 0 {
		return
	}
	s.gp.mu.Lock()
	if s.gp.logged == nil || len(s.gp.logged) >= maxGroupPolicyLogMarks {
		s.gp.logged = make(map[string]string)
	}
	seen := s.gp.logged[proxyID] == etag
	s.gp.logged[proxyID] = etag
	s.gp.mu.Unlock()
	if seen {
		return
	}
	s.cfg.Logger.Warn("worker_lacks_grouppolicy", "proxy_id", proxyID, "scoped_entries", n)
}
