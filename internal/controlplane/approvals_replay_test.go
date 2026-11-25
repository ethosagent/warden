package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policyeval"
)

func replayEvent(domain, decision, urlPath string) analytics.AggregatedEvent {
	return analytics.AggregatedEvent{Event: analytics.Event{
		Timestamp: time.Now(), Domain: domain, Port: 443, Protocol: "https", Method: "GET",
		URL: "https://" + domain + urlPath, Decision: decision,
	}, ProxyID: "p1"}
}

func waitSettled(t *testing.T, svc *approvals.Service, id string) approvals.Replay {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, ok, err := svc.LatestReplay(context.Background(), id, 0)
		if err != nil {
			t.Fatal(err)
		}
		if ok && r.Status.Settled() {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("replay of %s never settled: %+v", id, r)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A draft that adds a deny for a domain the base allows replays as a
// changed_to_deny group; events the base also denies (DLP, user_blocked) are
// not changes; and the stored result carries no url key, path or query.
func TestReplayPolicyDraftAgainstFleetEvents(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := srv.central.StoreAggregatedEvent(replayEvent("api.openai.com", "allow", "/v1/chat?key=secretish&n=1")); err != nil {
			t.Fatal(err)
		}
	}
	// Recorded as denied by something the replay does not model; both policies
	// allow the domain, so it must not show up as changed_to_allow.
	if err := srv.central.StoreAggregatedEvent(replayEvent("api.openai.com", "deny", "/v1/other")); err != nil {
		t.Fatal(err)
	}
	if err := srv.central.StoreAggregatedEvent(replayEvent("other.example.com", "allow", "/a/b")); err != nil {
		t.Fatal(err)
	}

	_, hd, err := srv.headDoc(ctx)
	if err != nil {
		t.Fatal(err)
	}
	doc := draftDoc(hd)
	doc.Denylist = append(slices.Clone(doc.Denylist), config.DenylistEntry{Domain: "api.openai.com"})
	d, err := srv.Approvals().CreateDraft(ctx, approvals.TargetPolicy, doc, draftAuthor, approvals.Provenance{Message: "deny"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Approvals().Submit(ctx, d.ID, d.Revision, draftAuthor.Sub); err != nil {
		t.Fatal(err)
	}
	r := waitSettled(t, srv.Approvals(), d.ID)
	if r.Status != approvals.ReplayDone || r.BaseVersion != 1 || r.EventsScanned != 6 {
		t.Fatalf("replay = %+v", r)
	}
	var res policyeval.CompareResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.ChangedToAllow) != 0 {
		t.Errorf("changed_to_allow = %+v, want none", res.ChangedToAllow)
	}
	// The 4 allows and the recorded deny all change from allow to deny: the
	// recorded decision is not what is compared.
	if len(res.ChangedToDeny) != 1 || res.ChangedToDeny[0].Domain != "api.openai.com" || res.ChangedToDeny[0].Port != 443 || res.ChangedToDeny[0].Count != 5 {
		t.Errorf("changed_to_deny = %+v", res.ChangedToDeny)
	}
	if res.Events != 6 || res.Agreed != 1 {
		t.Errorf("events %d agreed %d, want 6 and 1 (other.example.com is denied by both)", res.Events, res.Agreed)
	}
	raw := string(r.Result)
	if strings.Contains(raw, `"url"`) || strings.Contains(raw, "/") || strings.Contains(raw, "?") || strings.Contains(raw, "secretish") {
		t.Errorf("stored result leaks request detail: %s", raw)
	}

	// A re-run is allowed once, and the old replay stays.
	if _, err := srv.Approvals().Replay(ctx, d.ID); err != nil {
		t.Errorf("Replay: %v", err)
	}
}

func TestReplayZeroEventsUnavailableAndBaseMissing(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := context.Background()
	d := pendingDraft(t, srv, 1, "new.example.com")
	if _, err := srv.Approvals().Replay(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if r := waitSettled(t, srv.Approvals(), d.ID); r.Status != approvals.ReplayUnavailable {
		t.Errorf("replay with no events = %+v, want unavailable", r)
	}

	// A base version the store does not hold fails with a stable code.
	runner := policyReplayRunner{versions: srv.versions, scan: func(context.Context, time.Time, int, func(analytics.Event) error) error { return nil }}
	d.BaseVersion = 99
	_, err := runner.Run(ctx, approvals.ReplayRequest{Draft: d})
	var re *approvals.ReplayError
	if !asReplayError(err, &re) || re.Code != "base_unavailable" {
		t.Errorf("Run with a missing base = %v, want base_unavailable", err)
	}
	d.Target = approvals.TargetAgents
	if _, err := runner.Run(ctx, approvals.ReplayRequest{Draft: d}); !asReplayError(err, &re) || re.Code != "unsupported_target" {
		t.Errorf("Run for a non-policy target = %v", err)
	}
}

func asReplayError(err error, target **approvals.ReplayError) bool { return errors.As(err, target) }
