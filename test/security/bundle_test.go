package security

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
)

// Malicious signed bundles (W-P2-SECT-04). A pinned worker is served hostile
// envelopes through a TamperProxy, so its real RemoteProvider and bundle.Verify
// are what reject them. After every rejection the worker keeps its
// last-known-good policy: the bundle seq gauge does not move, a host only the
// hostile bundle allows stays denied, and a host the policy allows still gets
// through. The rejection is counted with its reason and the next heartbeat
// carries it to the control plane's fleet view.

// evilDenied is what a worker answers a CONNECT its policy does not allow.
const evilDenied = http.StatusForbidden

// armFn arms the proxy with a hostile response built from the applied bundle.
type armFn func(t testing.TB, s *Stack, tp *TamperProxy, base bundle.Bundle)

// bundleAttack arms a hostile response, drives the worker until it has rejected
// it, and asserts the invariants every rejection shares. It returns what the
// attacker gets by trying the host only the hostile bundle allows. extra, when
// set, runs after the shared assertions.
func bundleAttack(t testing.TB, s *Stack, reason string, arm armFn, extra func(t testing.TB, s *Stack, w *Worker)) Observed {
	t.Helper()
	w := s.Worker("agent-a")
	tp := w.Tamper
	base := s.DecodeBundle(t, tp.Latest())
	seq := s.WorkerSeq(t, w)
	served := tp.Served()
	rejected := func() float64 {
		v, _ := s.TryMetric(w, "warden_bundle_rejected_total", map[string]string{"reason": reason})
		return v
	}
	before := rejected()

	arm(t, s, tp, base)
	s.EventuallyAdvance("the worker to reject the "+reason+" bundle", time.Second, func() bool {
		return tp.Served() > served && rejected() > before
	})

	if got := s.WorkerSeq(t, w); got != seq {
		t.Errorf("warden_bundle_seq = %v after the %s bundle, want %v", got, reason, seq)
	}
	// The next heartbeat carries the reason to the control plane.
	s.EventuallyAdvance("the heartbeat to report lastRejectReason "+reason, time.Second, func() bool {
		v, ok := s.FleetWorker(t, w)
		return ok && v.LastRejectReason == reason
	})
	tok := s.FreshToken(t, "agent-a")
	if got := s.ConnectStatus(t, w, UpstreamHost, tok); got != http.StatusOK {
		t.Errorf("a host the last-known-good policy allows = %d after the %s bundle, want 200", got, reason)
	}
	if extra != nil {
		extra(t, s, w)
	}
	return Observed{Status: s.ConnectStatus(t, w, EvilHost, tok)}
}

// hostile is a bundle derived from the applied one that allows EvilHost, with
// its time window valid at the shared clock and seq above the applied one.
func (s *Stack) hostile(t testing.TB, base bundle.Bundle) bundle.Bundle {
	t.Helper()
	b := base
	b.Seq = base.Seq + 1
	b.PolicyVersion = base.PolicyVersion + 1
	b.IssuedAt = s.Clock.Now().UTC()
	b.ExpiresAt = b.IssuedAt.Add(time.Hour)
	b.Policy = PolicyAllowing(t, base.Policy, EvilHost, nil)
	return b
}

// signedEnvelope builds an envelope over an arbitrary payload map, signed by
// sg over the exact signing input: for the cases bundle.Sign refuses to build
// (a format version it does not know).
func signedEnvelope(t testing.TB, payload map[string]any, sg keys.Signer) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("security: encode a payload: %v", err)
	}
	in := append([]byte(bundle.SigningPrefix), 0)
	in = append(in, raw...)
	sig, err := sg.Sign(context.Background(), in)
	if err != nil {
		t.Fatalf("security: sign a payload: %v", err)
	}
	env, err := json.Marshal(bundle.Envelope{
		Payload:    base64.RawURLEncoding.EncodeToString(raw),
		Signatures: []bundle.Signature{{KID: sg.KID(), Sig: base64.RawURLEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		t.Fatalf("security: encode an envelope: %v", err)
	}
	return env
}

func bundleCase(name, reason string, arm armFn) Case {
	return Case{
		Name:   name,
		Path:   PathBundle,
		Covers: []string{CoverBundle(reason)},
		Attack: func(t testing.TB, s *Stack) Observed {
			return bundleAttack(t, s, reason, arm, nil)
		},
		WantStatus: evilDenied,
		WantReason: reason,
	}
}

// replacing arms the plan f builds.
func replacing(f func(t testing.TB, s *Stack, base bundle.Bundle) Plan) armFn {
	return func(t testing.TB, s *Stack, tp *TamperProxy, base bundle.Bundle) { tp.Replace(f(t, s, base)) }
}

// signedBy arms a hostile bundle (see hostile) that f then adjusts, signed by
// the control plane's own pinned bundle key, so it reaches the check f targets.
func signedBy(f func(b *bundle.Bundle, s *Stack)) armFn {
	return replacing(func(t testing.TB, s *Stack, base bundle.Bundle) Plan {
		b := s.hostile(t, base)
		f(&b, s)
		return Plan{Body: Sign(t, b, nil, s.BundleSigner(t))}
	})
}

// preBlockRollback replays the envelope the worker held before a user was
// blocked: a rollback that would unblock them. It runs first, while the user's
// token (minted before the block) is still valid.
var preBlockRollback = Case{
	Name:   "rollback pre-block",
	Path:   PathBundle,
	Covers: []string{CoverBundle("rollback")},
	Attack: func(t testing.TB, s *Stack) Observed {
		pre, _ := s.KV("preblock")
		return bundleAttack(t, s, "rollback", func(t testing.TB, s *Stack, tp *TamperProxy, _ bundle.Bundle) {
			tp.Replace(Plan{Body: pre.([]byte)})
		}, func(t testing.TB, s *Stack, w *Worker) {
			victim, _ := s.KV("victim")
			if got := s.ConnectStatus(t, w, UpstreamHost, victim.(string)); got == http.StatusOK {
				t.Errorf("the blocked user got %d after the pre-block envelope was replayed, want a denial", got)
			}
		})
	},
	WantStatus: evilDenied,
	WantReason: "rollback",
}

// bundleCases is one case per bundle.Reason (and invalid_policy), plus the
// variants the ticket names: the legacy wire to a pinned worker, an envelope
// signed with the token key, and the pre-block envelope replayed.
func bundleCases() []Case {
	return []Case{
		preBlockRollback,
		bundleCase("malformed", "malformed", replacing(func(testing.TB, *Stack, bundle.Bundle) Plan { return Plan{Body: []byte("{not json")} })),
		bundleCase("too large", "too_large", replacing(func(testing.TB, *Stack, bundle.Bundle) Plan {
			return Plan{Body: bytes.Repeat([]byte("a"), bundle.MaxEnvelopeBytes+1)}
		})),
		bundleCase("unsupported format", "unsupported_format", replacing(func(t testing.TB, s *Stack, base bundle.Bundle) Plan {
			raw, err := json.Marshal(s.hostile(t, base))
			if err != nil {
				t.Fatalf("security: encode a bundle: %v", err)
			}
			payload := map[string]any{}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatalf("security: decode a bundle: %v", err)
			}
			payload["typ"] = "warden-bundle-v2"
			return Plan{Body: signedEnvelope(t, payload, s.BundleSigner(t))}
		})),
		bundleCase("legacy downgrade", "unsigned", replacing(func(t testing.TB, _ *Stack, base bundle.Bundle) Plan {
			// The unsigned policy wire an older control plane serves, with a
			// host the signed policy never allowed.
			return Plan{ContentType: "application/json", Body: PolicyAllowing(t, base.Policy, EvilHost, nil)}
		})),
		bundleCase("no signatures", "unsigned", replacing(func(t testing.TB, s *Stack, base bundle.Bundle) Plan {
			raw := Sign(t, s.hostile(t, base), nil, s.BundleSigner(t))
			return Plan{Body: mutateEnvelope(raw, func(m map[string]json.RawMessage) { m["signatures"] = json.RawMessage("[]") })}
		})),
		bundleCase("token key signature", "unknown_kid", replacing(func(t testing.TB, s *Stack, base bundle.Bundle) Plan {
			return Plan{Body: Sign(t, s.hostile(t, base), nil, s.signerFor(t, keys.PurposeToken))}
		})),
		bundleCase("unpinned key", "unknown_kid", replacing(func(t testing.TB, s *Stack, base bundle.Bundle) Plan {
			return Plan{Body: Sign(t, s.hostile(t, base), nil, UnpinnedSigner(t))}
		})),
		bundleCase("bad signature", "bad_signature", func(t testing.TB, _ *Stack, tp *TamperProxy, _ bundle.Bundle) {
			tp.Mutate(func(raw []byte) []byte {
				return mutateEnvelope(raw, func(m map[string]json.RawMessage) {
					var payload string
					if err := json.Unmarshal(m["payload"], &payload); err != nil {
						t.Fatalf("security: decode the payload member: %v", err)
					}
					// One flipped payload character, still valid base64url.
					b := []byte(payload)
					i := len(b) / 2
					if b[i] == 'A' {
						b[i] = 'B'
					} else {
						b[i] = 'A'
					}
					m["payload"], _ = json.Marshal(string(b))
				})
			})
		}),
		bundleCase("issuer mismatch", "issuer_mismatch", signedBy(func(b *bundle.Bundle, _ *Stack) { b.CPID = "cp_00000000000000000000000000000000" })),
		bundleCase("credential mismatch", "credential_mismatch", func(t testing.TB, s *Stack, tp *TamperProxy, _ bundle.Bundle) {
			s.Track("planted credential", "planted-secret-access-key-0001")
			tp.Mutate(func(raw []byte) []byte {
				// The signed payload commits to no credential; a sidecar riding
				// along must not be accepted.
				return mutateEnvelope(raw, func(m map[string]json.RawMessage) {
					m["credentials"] = json.RawMessage(`{"accessKeyId":"AKIAPLANTED000000001","secretAccessKey":"planted-secret-access-key-0001"}`)
				})
			})
		}),
		bundleCase("rollback", "rollback", func(t testing.TB, _ *Stack, tp *TamperProxy, base bundle.Bundle) {
			seen := tp.Relayed()
			if len(seen) == 0 || seen[0].Seq >= base.Seq {
				t.Fatalf("security: the first envelope the worker saw (seq %d) is not older than the applied one (%d)", firstSeq(seen), base.Seq)
			}
			tp.Replay(0)
		}),
		// Same seq as the applied bundle, different content.
		bundleCase("equivocation", "equivocation", signedBy(func(b *bundle.Bundle, _ *Stack) { b.Seq-- })),
		bundleCase("expired", "expired", signedBy(func(b *bundle.Bundle, s *Stack) {
			b.IssuedAt = s.Clock.Now().UTC().Add(-26 * time.Hour)
			b.ExpiresAt = b.IssuedAt.Add(time.Hour)
		})),
		bundleCase("future", "future", signedBy(func(b *bundle.Bundle, s *Stack) {
			b.IssuedAt = s.Clock.Now().UTC().Add(time.Hour)
			b.ExpiresAt = b.IssuedAt.Add(24 * time.Hour)
		})),
		bundleCase("invalid policy", config.BundleReasonInvalidPolicy, replacing(func(t testing.TB, s *Stack, base bundle.Bundle) Plan {
			b := s.hostile(t, base)
			// Validly signed, but an allowlist entry with groups is not one a
			// worker can enforce on the unscoped list.
			b.Policy = PolicyAllowing(t, base.Policy, EvilHost, map[string]any{"groups": []string{"eng"}})
			return Plan{Body: Sign(t, b, nil, s.BundleSigner(t))}
		})),
	}
}

func firstSeq(seen []Relayed) int64 {
	if len(seen) == 0 {
		return 0
	}
	return seen[0].Seq
}

// TestMaliciousBundle serves every kind of hostile bundle to a pinned worker.
func TestMaliciousBundle(t *testing.T) {
	s := StartStack(t, StackOptions{CPEndpoint: tamperAgentA, PinBundleIssuer: true})
	a := agentSetup(t, s, "agent-a")
	agentSetup(t, s, "agent-b")
	w := s.Worker("agent-a")

	s.PositiveControl(t, "bundle", func(t *testing.T) {
		if seq := s.WorkerSeq(t, w); seq <= 1 {
			t.Fatalf("warden_bundle_seq = %v, want above 1 (agent registration published newer bundles)", seq)
		}
		if r := s.Do(t, w, Via(TransportConnect, s.FreshToken(t, "agent-a"))); r.Status != http.StatusOK {
			t.Fatalf("a valid request through the pinned worker = %d, want 200", r.Status)
		}
		if got := s.ConnectStatus(t, w, EvilHost, s.FreshToken(t, "agent-a")); got != evilDenied {
			t.Fatalf("the host only a hostile bundle allows = %d before any attack, want %d", got, evilDenied)
		}
	})

	// The block-list story for the pre-block rollback: the user's token exists
	// before the block, the envelope is kept, then the block is published.
	s.SetKV("victim", s.MintWardenToken(t, a, "victim", "eng"))
	s.SetKV("preblock", append([]byte(nil), w.Tamper.Latest()...))
	seq := s.WorkerSeq(t, w)
	if r := s.AdminSession(t).Do(t, http.MethodPost, "/dashboard/api/blocked-users", map[string]any{"sub": "victim", "reason": "incident"}); r.Status != http.StatusCreated {
		t.Fatalf("security: block a user = %d %s", r.Status, r.Body)
	}
	s.EventuallyAdvance("the worker to apply the block list", time.Second, func() bool { return s.WorkerSeq(t, w) > seq })

	Run(t, s, "bundle", bundleCases())
}
