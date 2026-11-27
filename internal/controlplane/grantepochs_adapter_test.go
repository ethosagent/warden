package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
)

type stubEpochBumper struct{ err error }

func (b stubEpochBumper) Bump(context.Context, string) error { return b.err }

// TestGrantEpochAdapter: a bump through the adapter wakes a held bundle long
// poll, the woken bundle's userGrantEpochs holds the user key (never a sub) at a
// higher epoch, and the log line carries only the 8-character key prefix.
func TestGrantEpochAdapter(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{cfg: puOn()}, nil, nil)
	alice := puUserKey(t, "alice-sub")
	_, ch := h.ps.watch.bundleSnapshot()
	before := h.latest(t)

	b := h.s.GrantEpochBumper()
	if err := b.Bump(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("the bump did not wake the long poll within 1s")
	}
	h.bundleResp(t)
	for name, raw := range h.sections(t) {
		if bytes.Contains(raw, []byte("alice")) {
			t.Errorf("a subject is in the decoded %s section", name)
		}
	}
	got := h.epochs(t)
	if got[alice] <= before.Seq {
		t.Fatalf("userGrantEpochs = %v, want %s above %d", got, alice, before.Seq)
	}
	first := got[alice]
	if err := b.Bump(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	if again := h.epochs(t)[alice]; again <= first {
		t.Errorf("a retry bump gave epoch %d, want above %d", again, first)
	}

	logs := h.logs.String()
	if !strings.Contains(logs, `"msg":"grant_epoch_bumped"`) || !strings.Contains(logs, `"key_prefix":"`+alice[:8]+`"`) {
		t.Errorf("no grant_epoch_bumped line with the key prefix:\n%s", logs)
	}
	if strings.Contains(logs, alice) || strings.Contains(logs, "alice-sub") {
		t.Errorf("the log holds the full user key or the sub:\n%s", logs)
	}
}

// TestGrantEpochAdapterWorkersWithoutCap: of two connected workers, only the one
// without usersecrets/v1 is listed; the fleet view flags the same worker.
func TestGrantEpochAdapterWorkersWithoutCap(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{cfg: puOn("agent-a")}, nil, nil)
	h.s.registry.SeenHeartbeat("w-new", "x", []string{config.CapUserSecretsV1}, "agent-a", "attribute", WorkerBundle{})
	h.s.registry.SeenHeartbeat("w-old", "x", []string{config.CapBlocklistV1}, "agent-a", "attribute", WorkerBundle{})

	out := oauthbroker.BumpGrantEpoch(context.Background(), h.s.GrantEpochBumper(), h.s.GrantWorkerCaps(), config.CapUserSecretsV1, puUserKey(t, "alice"))
	if out.Status != oauthbroker.EpochOK || out.Partial() || !slices.Equal(out.WorkersWithoutCap, []string{"w-old"}) {
		t.Fatalf("outcome = %+v, want ok and only w-old", out)
	}

	views := h.s.registry.Views()
	FlagNoUserSecrets(views, h.ps.servedPerUserAgents())
	for _, v := range views {
		if want := v.ProxyID == "w-old"; v.NoUserSecrets != want {
			t.Errorf("worker %s NoUserSecrets = %v, want %v", v.ProxyID, v.NoUserSecrets, want)
		}
	}
}

// TestGrantEpochAdapterFleetFlag: the flag needs a served mapping for the
// worker's agent; with per-user secrets off, or for another agent, nothing is
// flagged.
func TestGrantEpochAdapterFleetFlag(t *testing.T) {
	on := newPerUserBundleHarness(t, &puBlock{cfg: puOn("agent-a")}, nil, nil)
	on.s.registry.SeenHeartbeat("w-a", "x", nil, "agent-a", "attribute", WorkerBundle{})
	on.s.registry.SeenHeartbeat("w-b", "x", nil, "agent-b", "attribute", WorkerBundle{})
	on.s.registry.SeenHeartbeat("w-none", "x", nil, "", "attribute", WorkerBundle{})
	views := on.s.registry.Views()
	FlagNoUserSecrets(views, on.ps.servedPerUserAgents())
	for _, v := range views {
		if want := v.ProxyID == "w-a"; v.NoUserSecrets != want {
			t.Errorf("worker %s NoUserSecrets = %v, want %v", v.ProxyID, v.NoUserSecrets, want)
		}
	}

	off := newPerUserBundleHarness(t, &puBlock{}, nil, nil)
	off.s.registry.SeenHeartbeat("w-a", "x", nil, "agent-a", "attribute", WorkerBundle{})
	views = off.s.registry.Views()
	FlagNoUserSecrets(views, off.ps.servedPerUserAgents())
	if views[0].NoUserSecrets {
		t.Error("a worker is flagged with per-user secrets off")
	}
}

// TestGrantEpochAdapterFailingStore: a failing epoch store is reported as
// epoch failed (partial), never swallowed, and ErrEpochNotPublished survives so
// the caller knows the epoch is recorded; without signed bundles the adapter
// fails instead of reporting success.
func TestGrantEpochAdapterFailingStore(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{cfg: puOn()}, nil, nil)
	h.fk.mu.Lock()
	h.fk.failSign = true
	h.fk.mu.Unlock()
	out := oauthbroker.BumpGrantEpoch(context.Background(), h.s.GrantEpochBumper(), h.s.GrantWorkerCaps(), config.CapUserSecretsV1, puUserKey(t, "alice"))
	if out.Status != oauthbroker.EpochFailed || !out.Partial() || !errors.Is(out.Err, ErrEpochNotPublished) {
		t.Fatalf("outcome = %+v, want failed with ErrEpochNotPublished", out)
	}
	if strings.Contains(h.logs.String(), `"msg":"grant_epoch_bumped"`) {
		t.Error("grant_epoch_bumped was logged for a bump that did not publish")
	}

	if err := h.s.GrantEpochBumper().Bump(context.Background(), "not-a-user-key"); !errors.Is(err, ErrInvalidGrantUserKey) {
		t.Errorf("Bump(bad key) = %v, want ErrInvalidGrantUserKey", err)
	}

	noBundles := New(Config{PolicyPath: overlayFixture(t)})
	if err := noBundles.GrantEpochBumper().Bump(context.Background(), puUserKey(t, "alice")); !errors.Is(err, ErrGrantEpochsUnavailable) {
		t.Errorf("Bump without bundles = %v, want ErrGrantEpochsUnavailable", err)
	}

	custom := oauthbroker.BumpGrantEpoch(context.Background(), stubEpochBumper{err: errors.New("boom")}, nil, config.CapUserSecretsV1, "k")
	if custom.Status != oauthbroker.EpochFailed || custom.Err == nil || custom.WorkersWithoutCap != nil {
		t.Errorf("stub outcome = %+v", custom)
	}
	if skipped := oauthbroker.BumpGrantEpoch(context.Background(), nil, nil, config.CapUserSecretsV1, "k"); skipped.Status != oauthbroker.EpochSkipped || !skipped.Partial() {
		t.Errorf("nil bumper outcome = %+v, want skipped", skipped)
	}
}

// TestGrantEpochAdapterNoConsent: with per-user secrets off, building the
// adapters and bumping through them changes neither the /policy body, its ETag
// nor the publish log.
func TestGrantEpochAdapterNoConsent(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{}, nil, nil)
	before := h.get(t, "", "")
	rows := len(h.publishRows(t))
	if err := h.s.GrantEpochBumper().Bump(context.Background(), puUserKey(t, "alice")); !errors.Is(err, ErrPerUserSecretsOff) {
		t.Fatalf("Bump with per-user secrets off = %v, want ErrPerUserSecretsOff", err)
	}
	_ = h.s.GrantWorkerCaps().WorkersWithoutCap(config.CapUserSecretsV1)
	after := h.get(t, "", "")
	if before.code != http.StatusOK || after.code != before.code || !bytes.Equal(before.body, after.body) || before.hdr.Get("ETag") != after.hdr.Get("ETag") {
		t.Error("/policy changed")
	}
	if len(h.publishRows(t)) != rows {
		t.Error("a bump with the feature off appended a publish row")
	}
	if _, ok := h.sections(t)[bundle.SectionUserGrantEpochs]; ok {
		t.Error("the bundle gained a userGrantEpochs section")
	}
}

// TestGrantEpochAdapterOffIsSkipped: with bundles on but per-user secrets off
// the bump publishes nothing, so the revoke reports epoch skipped (partial) and
// logs no grant_epoch_bumped line.
func TestGrantEpochAdapterOffIsSkipped(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{}, nil, nil)
	out := oauthbroker.BumpGrantEpoch(context.Background(), h.s.GrantEpochBumper(), h.s.GrantWorkerCaps(), config.CapUserSecretsV1, puUserKey(t, "alice"))
	if out.Status != oauthbroker.EpochSkipped || !out.Partial() || !errors.Is(out.Err, ErrPerUserSecretsOff) {
		t.Fatalf("outcome = %+v, want skipped, partial", out)
	}
	if strings.Contains(h.logs.String(), "grant_epoch_bumped") {
		t.Error("grant_epoch_bumped logged although nothing was published")
	}
}

// TestGrantEpochAdapterFilterBeforeBound: workers_without_cap applies the
// fleet-flag filter (serves a mapped agent, cap missing) before the registry's
// bound, so one relevant worker is listed among many irrelevant old ones.
func TestGrantEpochAdapterFilterBeforeBound(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{cfg: puOn("agent-a")}, nil, nil)
	for i := 0; i < maxWorkersWithoutCap+10; i++ {
		h.s.registry.SeenHeartbeat(fmt.Sprintf("a-other-%03d", i), "x", nil, "agent-other", "attribute", WorkerBundle{})
	}
	h.s.registry.SeenHeartbeat("z-relevant", "x", nil, "agent-a", "attribute", WorkerBundle{})
	h.s.registry.SeenHeartbeat("z-capable", "x", []string{config.CapUserSecretsV1}, "agent-a", "attribute", WorkerBundle{})
	got := h.s.GrantWorkerCaps().WorkersWithoutCap(config.CapUserSecretsV1)
	if !slices.Equal(got, []string{"z-relevant"}) {
		t.Errorf("workers_without_cap = %v, want only z-relevant", got)
	}
	off := newPerUserBundleHarness(t, &puBlock{}, nil, nil)
	off.s.registry.SeenHeartbeat("w", "x", nil, "agent-a", "attribute", WorkerBundle{})
	if got := off.s.GrantWorkerCaps().WorkersWithoutCap(config.CapUserSecretsV1); len(got) != 0 {
		t.Errorf("listed %v with per-user secrets off", got)
	}
}

// TestGrantEpochAdapterFleetViewDoesNotBlock: the served-agents snapshot is read
// without refreshMu, so the fleet view never waits behind a refresh or a Bump.
func TestGrantEpochAdapterFleetViewDoesNotBlock(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{cfg: puOn("agent-a")}, nil, nil)
	h.ps.refreshMu.Lock()
	done := make(chan map[string]bool, 1)
	go func() { done <- h.ps.servedPerUserAgents() }()
	select {
	case got := <-done:
		if !got["agent-a"] {
			t.Errorf("served agents = %v", got)
		}
	case <-time.After(5 * time.Second):
		h.ps.refreshMu.Unlock()
		t.Fatal("servedPerUserAgents blocked behind refreshMu")
	}
	h.ps.refreshMu.Unlock()
}
