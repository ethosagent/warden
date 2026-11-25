package security

import (
	"net/http"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
)

// Binding cases (W-P2-SECT-03): a Warden token is bound to the agent it was
// minted for and to that agent's registered key, and the worker re-checks both
// against the bundle it holds now on every request. The stack runs identity in
// challenge mode (the strictest mode config validation allows today), so a
// refused credential is a 407 challenge on CONNECT and a 403 identity_required
// on an open terminated tunnel.

const (
	keyTokA = "binding.token-a"
	keyTokB = "binding.token-b"
	keyTunA = "binding.tunnel-a"
)

func scratchToken(s *Stack, key string) string {
	tok, _ := s.Get(key).(string)
	return tok
}

// challenged is the expectation of a CONNECT the worker refuses on the identity
// reason: a 407 challenge, one verify count, one identity_required deny, and
// nothing at the upstream.
func challenged(reason string) Case {
	return Case{
		Path:             PathWorker,
		WantStatus:       http.StatusProxyAuthRequired,
		WantHeader:       map[string]string{"Proxy-Authenticate": `Basic realm="warden"`},
		WantBody:         "identity_required",
		WantResult:       "invalid",
		WantReason:       reason,
		WantDeny:         "identity_required",
		WantUpstreamHits: 0,
	}
}

// crossAgentCases: agent-b's valid token presented on agent-a's worker, on each
// transport. The signature verifies; the binding refuses it (agent_mismatch).
var crossAgentCases = func() []Case {
	var out []Case
	for _, tr := range Transports {
		tr := tr
		c := challenged("agent_mismatch")
		c.Name = "agent-b's token on agent-a's worker over " + string(tr)
		c.Covers = []string{CoverIdentity("agent_mismatch")}
		c.Attack = func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("agent-a"), Via(tr, scratchToken(s, keyTokB))))
		}
		out = append(out, c)
	}
	return out
}()

// unboundWorkerCases: a worker with no central.agentID serves agent:<port>,
// which no registry lists, so it refuses every token in the bundle's registry.
var unboundWorkerCases = func() []Case {
	var out []Case
	for _, k := range []string{keyTokA, keyTokB} {
		k := k
		c := challenged("agent_unregistered")
		c.Name = "a worker without an agent id refuses " + map[string]string{keyTokA: "agent-a", keyTokB: "agent-b"}[k] + "'s token"
		c.Covers = []string{CoverIdentity("agent_unregistered")}
		c.Worker = "worker-unbound"
		c.Attack = func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("worker-unbound"), Via(TransportConnect, scratchToken(s, k))))
		}
		out = append(out, c)
	}
	return out
}()

// rotatedKeyCases: after agent-a's registry key is replaced, a token minted
// with the old key (whose verify result the worker had cached) is refused with
// cnf_mismatch on a new CONNECT. A tunnel that was already open is closed
// instead (TestBinding/cnf_rotated_open_tunnel).
var rotatedKeyCases = func() []Case {
	rotate := func(t testing.TB, s *Stack) {
		w := s.Worker("agent-a")
		seq := s.BundleSeq(t, w)
		s.Put("binding.agent-a", s.RotateAgentKey(t, s.Get("binding.agent-a").(*Agent), fakes.NewAgentKey(t, "agent-a-key-2"), "eng"))
		s.AwaitBundle(t, w, seq)
	}
	newConnect := challenged("cnf_mismatch")
	newConnect.Name = "a cached token whose key was rotated out, on a new CONNECT"
	newConnect.Covers = []string{CoverIdentity("cnf_mismatch")}
	newConnect.Setup = rotate
	newConnect.Attack = func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyTokA))))
	}

	return []Case{newConnect}
}()

// bindingStack boots a stack with agent-a and agent-b registered and returns
// the agents and a token of each (minted for user-1 and user-2).
func bindingStack(t *testing.T, opts StackOptions) (*Stack, *Agent, *Agent) {
	t.Helper()
	s := StartStack(t, opts)
	a := agentSetup(t, s, "agent-a")
	b := agentSetup(t, s, "agent-b")
	s.Put("binding.agent-a", a)
	s.Put(keyTokA, s.MintWardenToken(t, a, "user-1", "eng"))
	s.Put(keyTokB, s.MintWardenToken(t, b, "user-2", "eng"))
	return s, a, b
}

// bindingWorkerControl is the worker category's positive control: each agent's own
// token is accepted on its own worker over every transport.
func bindingWorkerControl(s *Stack) func(t *testing.T) {
	return func(t *testing.T) {
		for _, p := range []struct{ agent, key string }{{"agent-a", keyTokA}, {"agent-b", keyTokB}} {
			for _, tr := range Transports {
				hits := s.Upstream.Hits()
				if r := s.Do(t, s.Worker(p.agent), Via(tr, scratchToken(s, p.key))); r.Status != http.StatusOK {
					t.Fatalf("%s over %s: status %d, want 200 (%s)", p.agent, tr, r.Status, tail(r.Body, 200))
				}
				if got := s.Upstream.Hits() - hits; got != 1 {
					t.Fatalf("%s over %s: %d upstream hits, want 1", p.agent, tr, got)
				}
			}
		}
	}
}

func TestBinding(t *testing.T) {
	t.Run("agent_mismatch", func(t *testing.T) {
		s, _, _ := bindingStack(t, StackOptions{})
		s.PositiveControl(t, "worker", bindingWorkerControl(s))
		Run(t, s, "worker", crossAgentCases)
	})
	t.Run("agent_unregistered", func(t *testing.T) {
		s, _, _ := bindingStack(t, StackOptions{UnboundWorker: true})
		unbound := s.Worker("worker-unbound")
		s.Eventually("the unbound worker to enforce identity mode require", func() bool {
			return s.probeConnect(unbound) == http.StatusProxyAuthRequired
		})
		s.PositiveControl(t, "worker", bindingWorkerControl(s))
		Run(t, s, "worker", unboundWorkerCases)
	})
	t.Run("cnf_rotated", func(t *testing.T) {
		// Each case starts from its own stack: the first one rotates the key.
		for _, c := range rotatedKeyCases {
			c := c
			s, _, _ := bindingStack(t, StackOptions{})
			s.PositiveControl(t, "worker", bindingWorkerControl(s))
			Run(t, s, "worker", []Case{c})
		}
	})

	// A terminated tunnel opened before the key was rotated out is no longer
	// answered with a per-request 403: the post-apply re-check (W-P2-WBND-09)
	// closes it as soon as the rotated bundle lands.
	t.Run("cnf_rotated_open_tunnel", func(t *testing.T) {
		s, a, _ := bindingStack(t, StackOptions{})
		s.PositiveControl(t, "worker", bindingWorkerControl(s))
		w := s.Worker("agent-a")
		tun := s.OpenTunnel(t, w, TransportTerminated, scratchToken(s, keyTokA))
		if tun.Open.Status != http.StatusOK || tun.MustGet(t).Status != http.StatusOK {
			t.Fatalf("the tunnel did not serve before the rotation: %d", tun.Open.Status)
		}
		hits := s.Upstream.Hits()
		seq := s.BundleSeq(t, w)
		s.RotateAgentKey(t, a, fakes.NewAgentKey(t, "agent-a-key-2"), "eng")
		s.AwaitBundle(t, w, seq)
		s.Eventually("the open tunnel to be closed by the post-apply re-check", tun.Closed)
		if got := s.Upstream.Hits() - hits; got != 0 {
			t.Errorf("%d upstream hits after the rotation, want 0", got)
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	// A raw tunnel (a worker with no CA) is opaque, so the worker binds it at
	// CONNECT only. Require mode registers it in the session registry (W-P2-WBND-09,
	// #270) and the post-apply re-check cuts it when the agent's key is rotated
	// out, instead of leaving it to run until the token's exp. A new CONNECT with
	// the same token is refused too, which proves the bundle reached the worker.
	t.Run("raw_tunnel_cut_on_key_rotation", func(t *testing.T) {
		s, a, _ := bindingStack(t, StackOptions{NoCA: true})
		s.PositiveControl(t, "worker", func(t *testing.T) {
			tun := s.OpenTunnel(t, s.Worker("agent-a"), TransportConnect, scratchToken(s, keyTokA))
			if tun.Open.Status != http.StatusOK {
				t.Fatalf("the raw tunnel did not open: %d %s", tun.Open.Status, tun.Open.Body)
			}
			if r := tun.MustGet(t); r.Status != http.StatusOK {
				t.Fatalf("a request through the raw tunnel = %d, want 200", r.Status)
			}
		})
		tun := s.OpenTunnel(t, s.Worker("agent-a"), TransportConnect, scratchToken(s, keyTokA))
		if tun.Open.Status != http.StatusOK || tun.MustGet(t).Status != http.StatusOK {
			t.Fatalf("the raw tunnel did not serve before the cut: %d", tun.Open.Status)
		}
		w := s.Worker("agent-a")
		seq := s.BundleSeq(t, w)
		s.RotateAgentKey(t, a, fakes.NewAgentKey(t, "agent-a-key-2"), "eng")
		s.AwaitBundle(t, w, seq)
		s.Run1(t, challenged("cnf_mismatch"), "a new CONNECT with the rotated-out key's token on a worker without a CA", func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, w, Via(TransportConnect, scratchToken(s, keyTokA))))
		})
		s.Eventually("the open raw tunnel to be closed by the post-apply re-check", tun.Closed)
		if r, err := tun.Get(t); err == nil && r.Status == http.StatusOK {
			t.Errorf("a request on the raw tunnel after the key rotation = %d, want the tunnel cut", r.Status)
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})
}

// TestStolenTokenSamePort_KnownGap records a known gap that is accepted in P2: a
// token is a bearer credential. cnf.jkt names the agent's registered key but
// nothing proves the presenter holds it, so a token replayed from another
// client on the same agent's port is accepted until it expires. Proof of
// possession is a P2 non-goal (docs/roadmap/features/identity-enforcement.md,
// line 19). The test stays active and asserts today's behaviour; it flips to
// expect a refusal when a proof-of-possession binding (DPoP or an mTLS-bound
// cnf) lands and the worker verifies it.
func TestStolenTokenSamePort_KnownGap(t *testing.T) {
	s, _, _ := bindingStack(t, StackOptions{})
	s.PositiveControl(t, "worker", bindingWorkerControl(s))
	stolen := scratchToken(s, keyTokA)
	hits := s.Upstream.Hits()
	for i := 0; i < 2; i++ {
		if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, stolen)); r.Status != http.StatusOK {
			t.Errorf("replay %d of a token on its own agent's port = %d, want 200 (no proof of possession in P2)", i, r.Status)
		}
	}
	if got := s.Upstream.Hits() - hits; got != 2 {
		t.Errorf("%d upstream hits, want 2", got)
	}
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}
