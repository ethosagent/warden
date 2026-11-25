package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

func wireAgents(t *testing.T, body []byte) []config.RegisteredAgent {
	t.Helper()
	var w policyWire
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatal(err)
	}
	return w.RegisteredAgents
}

func registerAgent(t *testing.T, store agentreg.Store, id string) agentreg.Agent {
	t.Helper()
	a, err := store.Create(context.Background(), agentreg.Agent{
		ID: id, DisplayName: "Display " + id, OwnerEmail: "owner@corp.example",
		Keys:          []agentreg.Key{{JWK: agentregtest.Ed25519JWK(t, id)}},
		AllowedGroups: []string{"warden-agents"}, AllowedScopes: []string{"scope-x"},
	}, "t")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// An empty registry, and a control plane with no state dir, serve exactly the
// bytes and ETag of a build without the feature.
func TestPolicyWireRegisteredAgents_EmptyIsByteIdentical(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	withState := New(Config{PolicyPath: path, State: openPolicyState(t), Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	noState := New(Config{PolicyPath: path, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	b1, e1 := servePolicyOnce(t, withState.policy)
	b2, e2 := servePolicyOnce(t, noState.policy)
	if string(b1) != string(b2) || e1 != e2 {
		t.Fatalf("empty registry changed /policy:\n%s (%s)\n%s (%s)", b1, e1, b2, e2)
	}
	const golden = `{"allowlist":[{"domain":"api.openai.com","port":0}],"denylist":[{"domain":"evil.example.com","port":0}]}`
	if string(b1) != golden+"\n" {
		t.Fatalf("body = %q, want the pre-change golden %q", b1, golden)
	}
}

// The wire carries id, status and thumbprints, sorted by id, and nothing else
// from the registry.
func TestPolicyWireRegisteredAgents_ServesOnlyWhatWorkersNeed(t *testing.T) {
	s := blockServer(t, nil, nil)
	a := registerAgent(t, s.agents, "zeta")
	registerAgent(t, s.agents, "alpha")
	s.policy.Refresh()
	body, _ := servePolicyOnce(t, s.policy)
	got := wireAgents(t, body)
	if len(got) != 2 || got[0].ID != "alpha" || got[1].ID != "zeta" || got[1].Status != "active" ||
		len(got[1].JKT) != 1 || got[1].JKT[0] != a.Keys[0].JKT {
		t.Fatalf("registeredAgents = %+v", got)
	}
	for _, leak := range []string{"owner@corp.example", "warden-agents", "scope-x", "Display", `"x"`, `"kty"`, `"kid"`, "display", "owner"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("wire carries %q: %s", leak, body)
		}
	}
	// A worker decodes it with the shared validator.
	if err := config.ValidateRegisteredAgents(got); err != nil {
		t.Fatal(err)
	}
}

// An admin disable wakes a held long-poll within 1s with a new ETag.
func TestLongPollWakesOnAgentWrite(t *testing.T) {
	s := blockServer(t, nil, nil)
	a := registerAgent(t, s.agents, "claude-code")
	s.policy.Refresh()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	_, _, etag := getPolicy(t, ts.URL+"/policy", nil)

	type result struct {
		code int
		body []byte
		etag string
		at   time.Time
	}
	done := make(chan result, 1)
	go func() {
		code, body, e := getPolicy(t, ts.URL+"/policy?wait=5s", map[string]string{"If-None-Match": etag})
		done <- result{code, body, e, time.Now()}
	}()
	start := time.Now()
	if _, err := s.agents.SetStatus(context.Background(), "claude-code", agentreg.StatusDisabled, a.Revision, "t"); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh() // what the admin API's write does
	select {
	case r := <-done:
		got := wireAgents(t, r.body)
		if r.code != http.StatusOK || r.etag == etag || len(got) != 1 || got[0].Status != "disabled" {
			t.Fatalf("long-poll = %d etag %s (was %s) agents %+v", r.code, r.etag, etag, got)
		}
		if d := r.at.Sub(start); d > time.Second {
			t.Errorf("long-poll woke after %s, want within 1s", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll waiter not woken by the disable")
	}
}

// A write by another handle on the database (the offline CLI), with no Watch
// running at all, is served by the next policy reload: the overlay re-checks
// data_version itself, so the 3s reload tick alone bounds the delay.
func TestPolicyWireRegisteredAgents_ReloadSeesOtherHandleWithoutWatch(t *testing.T) {
	s := blockServer(t, nil, nil)
	a := registerAgent(t, s.agents, "claude-code")
	s.policy.Refresh()
	b0, e0 := servePolicyOnce(t, s.policy)
	if got := wireAgents(t, b0); len(got) != 1 || got[0].Status != "active" {
		t.Fatalf("before = %+v", got)
	}

	other, err := cpstate.Open(context.Background(), s.cfg.State.Path(), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	cli := agentregsqlite.New(other)
	if _, err := cli.SetStatus(context.Background(), "claude-code", agentreg.StatusDisabled, a.Revision, "cli:t"); err != nil {
		t.Fatal(err)
	}

	s.policy.Refresh() // one reload tick
	b1, e1 := servePolicyOnce(t, s.policy)
	if got := wireAgents(t, b1); len(got) != 1 || got[0].Status != "disabled" || e1 == e0 {
		t.Fatalf("after one reload: agents %+v etag %s (was %s)", got, e1, e0)
	}
}

type flakyAgents struct {
	agentreg.Store
	fail atomic.Bool
}

func (f *flakyAgents) List(ctx context.Context) ([]agentreg.Agent, error) {
	if f.fail.Load() {
		return nil, errors.New("agentreg: boom user-secret-value")
	}
	return f.Store.List(ctx)
}

// A registry read error keeps the last-known-good wire and ETag, and logs one
// agentreg_load_failed line per episode that carries no entry values.
func TestPolicyWireRegisteredAgents_StoreErrorKeepsETag(t *testing.T) {
	s := blockServer(t, nil, nil)
	registerAgent(t, s.agents, "claude-code")
	var logs strings.Builder
	lg := slog.New(slog.NewJSONHandler(&logs, nil))
	flaky := &flakyAgents{Store: s.agents}
	ps := newPolicyServer(s.cfg.PolicyPath, "", lg, s.registry)
	if err := ps.addOverlay(agentRegistryOverlay(flaky, &agentLoadReporter{logger: lg})); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()
	b0, e0 := servePolicyOnce(t, ps)

	flaky.fail.Store(true)
	for range 3 {
		ps.Refresh()
	}
	b1, e1 := servePolicyOnce(t, ps)
	if string(b0) != string(b1) || e0 != e1 {
		t.Fatalf("a store error changed the served wire:\n%s\n%s", b0, b1)
	}
	if n := strings.Count(logs.String(), agentLoadFailedMsg); n != 1 {
		t.Errorf("%d %s lines for one episode, want 1", n, agentLoadFailedMsg)
	}
	flaky.fail.Store(false)
	ps.Refresh()
	if _, e2 := servePolicyOnce(t, ps); e2 != e0 {
		t.Errorf("etag after recovery = %s, want %s", e2, e0)
	}
}

// In versioned mode a disable appends exactly one publish_log row with reason
// agent_registry, registry data never enters a stored version, and a rollback
// to a version from before the disable leaves the agent disabled.
func TestPolicyWireRegisteredAgents_VersionedRollbackAndPublishLog(t *testing.T) {
	ctx := context.Background()
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	createVersions(t, s, 2)
	a := registerAgent(t, s.agents, "claude-code")
	s.policy.Refresh()
	before := publishLog(t, s)

	if _, err := s.agents.SetStatus(ctx, "claude-code", agentreg.StatusDisabled, a.Revision, "t"); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()
	after := publishLog(t, s)
	if len(after) != len(before)+1 || after[len(after)-1].Reason != agentRegistryOverlayName {
		t.Fatalf("publish_log %d -> %d rows, last %+v; want one agent_registry row", len(before), len(after), after[len(after)-1])
	}

	v1, err := s.versions.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	head := mustHead(t, s.versions)
	if _, _, err := s.versions.Create(ctx, v1.Doc, testAuthor, "rollback to v1", SourceRollback, head); err != nil {
		t.Fatal(err)
	}
	body, _ := servePolicyOnce(t, s.policy)
	if got := wireAgents(t, body); len(got) != 1 || got[0].Status != "disabled" {
		t.Fatalf("after rollback: %+v, want the agent still disabled", got)
	}
	hv, err := s.versions.Get(ctx, mustHead(t, s.versions))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(hv.Doc); strings.Contains(string(b), "registeredAgents") || strings.Contains(string(b), "claude-code") {
		t.Errorf("registry data in a stored version: %s", b)
	}
}

// config cannot import agentreg, so its jkt cap is a copy of agentreg.MaxKeys;
// drift would make every Refresh fail validation.
func TestPolicyWireRegisteredAgents_JKTCapMatchesMaxKeys(t *testing.T) {
	if agentreg.MaxKeys != config.MaxRegisteredAgentJKT {
		t.Fatalf("agentreg.MaxKeys = %d, config.MaxRegisteredAgentJKT = %d", agentreg.MaxKeys, config.MaxRegisteredAgentJKT)
	}
}

// TestWorkerCapsAcceptedByControlPlane: every capability a worker advertises,
// the require cap included, survives the control plane's capability filter, so
// the console sees the literal the worker sent.
func TestWorkerCapsAcceptedByControlPlane(t *testing.T) {
	in := config.WorkerCaps()
	if !slices.Contains(in, config.CapIdentityRequireV1) {
		t.Fatalf("WorkerCaps() = %v lacks %s", in, config.CapIdentityRequireV1)
	}
	got := normalizeCaps(in)
	if len(got) != len(in) {
		t.Fatalf("normalizeCaps(%v) = %v, dropped a capability", in, got)
	}
}
