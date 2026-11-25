package worker

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

var bundleStart = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// bundleCP is a minimal signed-bundle control plane: it serves one envelope
// under one ETag, answers 304 to a matching If-None-Match after a short hold,
// and records every If-None-Match.
type bundleCP struct {
	mu   sync.Mutex
	body []byte
	etag string
	inm  []string
}

func (c *bundleCP) set(body []byte, etag string) {
	c.mu.Lock()
	c.body, c.etag = body, etag
	c.mu.Unlock()
}

func (c *bundleCP) seen(inm string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.inm {
		if v == inm {
			return true
		}
	}
	return false
}

func (c *bundleCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	body, etag := c.body, c.etag
	c.inm = append(c.inm, r.Header.Get("If-None-Match"))
	c.mu.Unlock()
	if r.Header.Get("If-None-Match") == `"`+etag+`"` {
		time.Sleep(5 * time.Millisecond) // a held poll
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	_, _ = w.Write(body)
}

func signedProvider(t *testing.T, clk *clocktest.Fake) (*config.RemoteProvider, *bundleCP, func(seq int64, domain string, tamper bool) []byte) {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	cp := &bundleCP{}
	srv := httptest.NewTLSServer(cp)
	t.Cleanup(srv.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	rp, err := config.NewRemoteProvider(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rp.CloseIdleConnections)
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatal(err)
	}
	if err := rp.SetBundleTrust(config.BundleTrust{
		Pins: []keys.JWK{pin}, Skew: time.Minute, Now: clk.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}); err != nil {
		t.Fatal(err)
	}
	mk := func(seq int64, domain string, tamper bool) []byte {
		raw, err := bundle.Sign(context.Background(), bundle.Bundle{
			Seq: seq, PolicyVersion: seq, IssuedAt: bundleStart, ExpiresAt: bundleStart.Add(time.Hour), CPID: "cp",
			Policy: json.RawMessage(`{"allowlist":[{"domain":"` + domain + `"}]}`),
		}, nil, sg)
		if err != nil {
			t.Fatal(err)
		}
		if tamper {
			var env bundle.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			p := []byte(env.Payload)
			p[len(p)/2] ^= 1
			env.Payload = string(p)
			raw, _ = json.Marshal(env)
		}
		return raw
	}
	return rp, cp, mk
}

// TestLongPollSignedBundleKeepsLastKnownGood: a worker on seq 5 is served a
// tampered seq 6. The evaluator is not touched again, and the next long-poll
// carries the rejected ETag, so the bad bundle is not downloaded twice.
func TestLongPollSignedBundleKeepsLastKnownGood(t *testing.T) {
	clk := clocktest.NewFake(bundleStart.Add(time.Minute))
	rp, cp, mk := signedProvider(t, clk)
	cp.set(mk(5, "a.example.com", false), "e5")
	ev := &recordingEvaluator{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		longPollControlPlane(ctx, clk, rp, ev, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	replaced := func() int { ev.mu.Lock(); defer ev.mu.Unlock(); return len(ev.replaced) }
	await(t, 5*time.Second, "seq 5 to be applied", func() bool { return replaced() == 1 })

	cp.set(mk(6, "b.example.com", true), "e6bad")
	await(t, 5*time.Second, "the rejected ETag on the next long-poll", func() bool {
		clk.Advance(time.Second) // the loop's backoff after a rejection
		return cp.seen(`"e6bad"`)
	})
	if n := replaced(); n != 1 {
		t.Fatalf("evaluator replaced %d times, want 1 (the tampered bundle must not apply)", n)
	}
	if b, ok := rp.Bundle(); !ok || b.Seq != 5 {
		t.Fatalf("Bundle() = %+v, %v, want seq 5", b, ok)
	}
	if st := rp.BundleStatus(); st.LastRejectReason != "bad_signature" {
		t.Fatalf("status = %+v", st)
	}
}

// expiryClient is a ControlPlaneClient whose bundle state the test sets.
type expiryClient struct {
	fakeControlPlaneClient
	mu2    sync.Mutex
	status config.BundleStatus
}

func (c *expiryClient) BundleStatus() config.BundleStatus {
	c.mu2.Lock()
	defer c.mu2.Unlock()
	return c.status
}

func (c *expiryClient) set(s config.BundleStatus) {
	c.mu2.Lock()
	c.status = s
	c.mu2.Unlock()
}

func TestEnforceBundleExpiry(t *testing.T) {
	good := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.example.com"}}}
	expired := config.BundleStatus{Enabled: true, Applied: true, Seq: 5, Expired: true, Expiry: config.BundleExpiryDeny}

	run := func(t *testing.T, st config.BundleStatus) (*clocktest.Fake, *expiryClient, *recordingEvaluator, *recordingEvaluator) {
		t.Helper()
		clk := clocktest.NewFake(bundleStart)
		cp := &expiryClient{}
		cp.policy = good
		cp.set(st)
		raw, restore := &recordingEvaluator{}, &recordingEvaluator{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			enforceBundleExpiry(ctx, clk, cp, raw, restore, slog.New(slog.NewTextHandler(io.Discard, nil)))
			close(done)
		}()
		t.Cleanup(func() { cancel(); <-done })
		await(t, 2*time.Second, "the expiry loop to arm", func() bool { return clk.PendingTimers() == 1 })
		return clk, cp, raw, restore
	}
	count := func(e *recordingEvaluator) int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.replaced) }
	tick := func(t *testing.T, clk *clocktest.Fake, cond func() bool) {
		t.Helper()
		await(t, 2*time.Second, "the expiry check", func() bool {
			clk.Advance(bundleExpiryInterval)
			return cond()
		})
	}

	t.Run("deny swaps in deny-all once and restores when valid again", func(t *testing.T) {
		clk, cp, raw, restore := run(t, expired)
		tick(t, clk, func() bool { return count(raw) == 1 })
		raw.mu.Lock()
		if len(raw.replaced[0].Allowlist) != 0 {
			t.Fatal("the deny policy allows something")
		}
		raw.mu.Unlock()
		clk.Advance(bundleExpiryInterval)
		clk.Advance(bundleExpiryInterval)
		if n := count(raw); n != 1 {
			t.Fatalf("deny-all applied %d times, want once", n)
		}
		cp.set(config.BundleStatus{Enabled: true, Applied: true, Seq: 5, Expiry: config.BundleExpiryDeny}) // refreshed
		tick(t, clk, func() bool { return count(restore) == 1 })
		restore.mu.Lock()
		defer restore.mu.Unlock()
		if restore.replaced[0].Allowlist[0].Domain != "a.example.com" {
			t.Fatalf("restored %+v", restore.replaced[0])
		}
	})

	t.Run("keep never touches the evaluator", func(t *testing.T) {
		st := expired
		st.Expiry = config.BundleExpiryKeep
		clk, _, raw, restore := run(t, st)
		for i := 0; i < 3; i++ {
			clk.Advance(bundleExpiryInterval)
			await(t, 2*time.Second, "re-arm", func() bool { return clk.PendingTimers() == 1 })
		}
		if count(raw)+count(restore) != 0 {
			t.Fatal("keep mode replaced the policy")
		}
	})

	t.Run("a worker without a verified bundle is left alone", func(t *testing.T) {
		clk, _, raw, _ := run(t, config.BundleStatus{Enabled: true, Expired: true, Expiry: config.BundleExpiryDeny})
		clk.Advance(bundleExpiryInterval)
		await(t, 2*time.Second, "re-arm", func() bool { return clk.PendingTimers() == 1 })
		if count(raw) != 0 {
			t.Fatal("deny-all without an applied bundle")
		}
	})
}
