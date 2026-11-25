package security

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// workerBootLogs restarts w (stopped by the caller) and returns what the
// worker logged while booting.
func workerBootLogs(t *testing.T, s *Stack, w *Worker) string {
	t.Helper()
	mark := s.LogMark()
	s.RestartWorker(t, w)
	return s.LogsSince(mark)
}

// restartBoth stops and restarts every worker with the control plane down.
func restartBoth(t *testing.T, s *Stack) {
	t.Helper()
	for _, w := range s.Workers {
		seq := float64(s.CachedBundleValue(t, w).Seq)
		s.StopWorker(t, w)
		logs := workerBootLogs(t, s, w)
		if !strings.Contains(logs, "bundle loaded from cache") {
			t.Fatalf("%s did not boot from its bundle cache:\n%s", w.Name, tail(logs, 1500))
		}
		s.AwaitWorkerSeq(t, w, seq)
	}
}

// flipPayloadByte changes one character of the envelope's payload member to
// another valid base64url character: the payload no longer matches its
// signature.
func flipPayloadByte(raw []byte) []byte {
	return mutateEnvelope(raw, func(m map[string]json.RawMessage) {
		var payload string
		if err := json.Unmarshal(m["payload"], &payload); err != nil {
			panic("security: decode the payload member: " + err.Error())
		}
		b := []byte(payload)
		i := len(b) / 2
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		m["payload"], _ = json.Marshal(string(b))
	})
}

// deniesEverything is what a worker with no verified bundle answers: nothing
// is accepted, whatever credential it is shown.
func deniesEverything(prefix string) []Case {
	one := func(name, key string) Case {
		return Case{
			Name: prefix + name,
			Path: PathWorker,
			Attack: func(t testing.TB, s *Stack) Observed {
				return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, key))))
			},
			WantStatus: http.StatusForbidden,
			WantDeny:   "policy_no_match",
		}
	}
	return []Case{one("a token that was valid", keyDegU1), one("a token of a blocked user", keyDegU2)}
}

// cachedStack is degradedStack with user-2 blocked and agent-b disabled, and
// every worker's bundle cache holding the bundle that carries both. It returns
// the stack and agent-a's worker.
func cachedStack(t *testing.T) (*Stack, *Worker) {
	t.Helper()
	s := degradedStack(t, StackOptions{})
	cutOff(t, s)
	// The cache follows the applied bundle: wait until it holds the one that
	// carries the block and the disabled agent.
	for _, w := range s.Workers {
		w := w
		// The gauge follows the worker's clock, so the wait advances it.
		s.EventuallyAdvance(w.Name+"'s cache to hold the applied bundle", time.Second, func() bool {
			return float64(s.CachedBundleValue(t, w).Seq) == s.WorkerSeq(t, w)
		})
	}
	return s, s.Worker("agent-a")
}

// degradedTamperedCache: a worker restarted with the CP down and a bundle cache
// with one byte changed refuses it, starts fail-closed and denies all traffic;
// the control plane's return heals it.
func degradedTamperedCache(t *testing.T) {
	s, wa := cachedStack(t)
	s.StopCP(t)
	s.StopWorker(t, wa)
	s.WriteBundleCache(t, wa, flipPayloadByte(s.CachedBundle(t, wa)))
	logs := workerBootLogs(t, s, wa)
	if !strings.Contains(logs, "cached bundle rejected (bad_signature)") || !strings.Contains(logs, "FAIL-CLOSED") {
		t.Errorf("the worker did not refuse the tampered cache and start fail-closed:\n%s", tail(logs, 1500))
	}
	if v, _ := s.TryMetric(wa, "warden_bundle_seq", nil); v != 0 {
		t.Errorf("warden_bundle_seq = %v after refusing the cache, want 0", v)
	}
	Run(t, s, "worker", deniesEverything("tampered cache: "))

	// The control plane's return heals the worker that refused its cache: it
	// pulls the signed bundle and enforces it again, block and all.
	s.RestartCP(t)
	s.AwaitWorkerSeq(t, wa, 1)
	Run(t, s, "worker", enforcedCases("healed: ")[:3])
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}

// jwksUnavailable is a Warden token shown to a worker whose verified bundle
// carries no token keys: the worker cannot verify any Warden token, so in
// require mode it refuses every one.
var jwksUnavailable = Case{
	Name:   "a bundle without token keys verifies no Warden token",
	Path:   PathWorker,
	Covers: []string{CoverIdentity("jwks_unavailable")},
	Attack: func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyDegU1))))
	},
	WantStatus: http.StatusProxyAuthRequired,
	WantHeader: map[string]string{"Proxy-Authenticate": `Basic realm="warden"`},
	WantBody:   "identity_required",
	WantResult: "unverified", WantReason: "jwks_unavailable",
	WantDeny: "identity_required",
}

// degradedWorkerRestart restarts workers while the control plane is down,
// with controlPlane.stateDir set: the bundle cache is the only thing a worker
// has. A valid cache is re-verified against the pins and enforced; a cache with
// one byte changed, one older than controlPlane.bundleCacheMaxAge, or none at
// all leaves the worker denying everything. The control plane's return heals it.
func degradedWorkerRestart(t *testing.T) {
	s, wa := cachedStack(t)
	// The bundle signing key lives in the control plane's state, so the stale
	// cache is signed while the control plane is up: the same bundle as the
	// worker's cache, issued 25 hours ago and still unexpired.
	stale := s.CachedBundleValue(t, wa)
	stale.IssuedAt = s.Clock.Now().UTC().Add(-25 * time.Hour)
	stale.ExpiresAt = s.Clock.Now().UTC().Add(time.Hour)
	staleCache := Sign(t, stale, nil, s.BundleSigner(t))
	// A bundle the control plane signed once for a state without token keys
	// (an earlier seq than the cache's, so the control plane's own bundle
	// replaces it): signed now for the same reason as the stale cache.
	noKeys := s.CachedBundleValue(t, wa)
	noKeys.TokenIssuer = ""
	noKeys.Seq--
	noKeysCache := Sign(t, noKeys, nil, s.BundleSigner(t))
	s.StopCP(t)

	t.Run("a valid cache is enforced", func(t *testing.T) {
		restartBoth(t, s)
		Run(t, s, "worker", enforcedCases("valid cache: "))
		terminatedAndMCPStillServe(t, s, "valid cache: ")
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	// A cache issued longer ago than controlPlane.bundleCacheMaxAge (24h) is
	// refused even though its signature and its expiry are fine: a restart
	// cannot bring back a very old block list.
	t.Run("a cache older than bundleCacheMaxAge is refused", func(t *testing.T) {
		s.StopWorker(t, wa)
		s.WriteBundleCache(t, wa, staleCache)
		logs := workerBootLogs(t, s, wa)
		if !strings.Contains(logs, "cached bundle is older than bundleCacheMaxAge") || !strings.Contains(logs, "FAIL-CLOSED") {
			t.Errorf("the worker did not refuse the old cache and start fail-closed:\n%s", tail(logs, 1500))
		}
		Run(t, s, "worker", deniesEverything("old cache: "))
	})

	// A cache that verifies but carries no token keys: the worker enforces its
	// policy and verifies no Warden token (jwks_unavailable), so in require
	// mode nothing passes until a bundle with keys arrives.
	t.Run("a cache without token keys verifies no token", func(t *testing.T) {
		s.StopWorker(t, wa)
		s.WriteBundleCache(t, wa, noKeysCache)
		logs := workerBootLogs(t, s, wa)
		if !strings.Contains(logs, "bundle loaded from cache") || !strings.Contains(logs, `"tokenIssuerSet":false`) {
			t.Errorf("the worker did not boot from the cache without token keys:\n%s", tail(logs, 1500))
		}
		Run(t, s, "worker", []Case{jwksUnavailable})
		s.RestartCP(t)
		s.EventuallyAdvance("the worker to pull the control plane's bundle with token keys", time.Second, func() bool {
			return s.ConnectStatus(t, wa, UpstreamHost, scratchToken(s, keyDegU1)) == http.StatusOK
		})
		s.StopCP(t)
	})

	// Without a cache the worker stays fail-closed, as before the cache existed.
	t.Run("no cache stays fail-closed", func(t *testing.T) {
		s.StopWorker(t, wa)
		s.DropBundleCache(t, wa)
		logs := workerBootLogs(t, s, wa)
		if !strings.Contains(logs, `"bundleCache":"empty"`) || !strings.Contains(logs, "FAIL-CLOSED") {
			t.Errorf("the worker did not start fail-closed without a cache:\n%s", tail(logs, 1500))
		}
		Run(t, s, "worker", deniesEverything("no cache: "))
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})
}

// degradedRollbackFloor: the last-known-good cache is also the
// boot rollback floor. A worker restarted with the control plane up, whose
// cache is newer than what the control plane serves (a control plane restored
// from an old backup, or an attacker's replay in front of it), refuses the
// older bundle as a rollback and keeps enforcing the cached one: here a cache
// that has dropped the upstream from the allowlist.
func degradedRollbackFloor(t *testing.T) {
	s := degradedStack(t, StackOptions{})
	wa := s.Worker("agent-a")
	s.EventuallyAdvance("the cache to hold the applied bundle", time.Second, func() bool {
		return float64(s.CachedBundleValue(t, wa).Seq) == s.WorkerSeq(t, wa)
	})
	newer := s.CachedBundleValue(t, wa)
	newer.Seq += 50
	newer.PolicyVersion += 50
	newer.IssuedAt = s.Clock.Now().UTC()
	newer.ExpiresAt = newer.IssuedAt.Add(time.Hour)
	var pol map[string]json.RawMessage
	if err := json.Unmarshal(newer.Policy, &pol); err != nil {
		t.Fatalf("security: decode the policy: %v", err)
	}
	pol["allowlist"] = json.RawMessage(`[{"domain":"` + EvilHost + `"}]`)
	var err error
	if newer.Policy, err = json.Marshal(pol); err != nil {
		t.Fatalf("security: encode the policy: %v", err)
	}
	cache := Sign(t, newer, nil, s.BundleSigner(t))
	token := scratchToken(s, keyDegU1)
	if got := s.ConnectStatus(t, wa, UpstreamHost, token); got != http.StatusOK {
		t.Fatalf("the upstream before the restart = %d, want 200", got)
	}

	s.StopWorker(t, wa)
	s.WriteBundleCache(t, wa, cache)
	logs := workerBootLogs(t, s, wa)
	if strings.Contains(logs, "starting FAIL-CLOSED") {
		t.Fatalf("the worker did not boot from the newer cache:\n%s", tail(logs, 1500))
	}

	rolledBack := func() float64 {
		v, _ := s.TryMetric(wa, "warden_bundle_rejected_total", map[string]string{"reason": "rollback"})
		return v
	}
	s.EventuallyAdvance("the worker to refuse the older bundle of the control plane as a rollback", time.Second, func() bool { return rolledBack() > 0 })
	if got := s.WorkerSeq(t, wa); got != float64(newer.Seq) {
		t.Errorf("warden_bundle_seq = %v, want the cached %d", got, newer.Seq)
	}
	Run(t, s, "worker", []Case{{
		Name: "the older bundle's allowlist does not come back",
		Path: PathWorker,
		Attack: func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, token)))
		},
		WantStatus: http.StatusForbidden,
		WantResult: "valid", WantDeny: "policy_no_match",
	}})
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}
