package analytics

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func actEvent(proxy, domain, act, typ string, ts time.Time) AggregatedEvent {
	e := aggEvent(proxy, "worker-agent", domain, "allow", ts)
	e.UserSub, e.IdentityStatus = "sub-1", "valid"
	e.UserAct, e.IdentityTokenType = act, typ
	return e
}

// An old fleet DB opens with user_act and identity_token_type added (and the
// (user_act, ts) index), existing rows keep empty defaults, and a second open
// is a no-op (W-P2-WBND-08).
func TestFleetMigrateUserAct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.db")
	createLegacyFleetDB(t, path)

	s, err := NewFleetSQLiteStore(path, 0, 0)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	for _, c := range []string{"user_act", "identity_token_type"} {
		if ok, err := s.columnPresent(c); err != nil || !ok {
			t.Errorf("column %s not added (err %v)", c, err)
		}
	}
	var idx int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_user_act_ts'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("index count=%d err=%v", idx, err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil || len(got) != 1 || got[0].Domain != "legacy.example" || got[0].UserAct != "" || got[0].IdentityTokenType != "" {
		t.Fatalf("legacy row lost or wrong defaults: %+v %v", got, err)
	}
	if err := s.StoreAggregatedEvent(actEvent("proxy-a", "new.example", "a1", "warden", time.Unix(9000, 0))); err != nil {
		t.Fatalf("store after migrate: %v", err)
	}
	_ = s.Close()

	s2, err := NewFleetSQLiteStore(path, 0, 0)
	if err != nil {
		t.Fatalf("second open must be a no-op: %v", err)
	}
	defer func() { _ = s2.Close() }()
	got, err = s2.GetEvents(EventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("rows after reopen: %d %v", len(got), err)
	}
}

// user_act and identity_token_type travel worker -> ingest -> fleet store and
// come back from GetEvents and GetAggregatedEvents; an event without them
// stores empty defaults without error.
func TestIngestCarriesUserAct(t *testing.T) {
	fleet := newFleetStore(t, 0, 0)
	srv := newIngestServer(t, NewIngestHandler(fleet, StaticTokenAuthorizer("")))
	rs, err := NewHTTPRemoteStore(srv.URL, "", "proxy-1", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	local := newTestStore(t, 0)
	ev := attributedEvent()
	ev.UserAct, ev.IdentityTokenType = "a1", "warden"
	plain := Event{Timestamp: time.Now(), Domain: "plain.example", Decision: "allow"}
	for _, e := range []Event{ev, plain} {
		if err := local.StoreEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewSyncWorker(local, rs, "proxy-1", 5, 100, time.Hour).SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	got, err := fleet.GetEvents(EventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("GetEvents: %v %v", got, err)
	}
	agg, err := fleet.GetAggregatedEvents(AggregatedFilter{})
	if err != nil || len(agg) != 2 {
		t.Fatalf("GetAggregatedEvents: %v %v", agg, err)
	}
	flat := []Event{agg[0].Event, agg[1].Event}
	for name, evs := range map[string][]Event{"GetEvents": got, "GetAggregatedEvents": flat} {
		for _, e := range evs {
			switch e.Domain {
			case "api.openai.com":
				if e.UserAct != "a1" || e.IdentityTokenType != "warden" {
					t.Errorf("%s lost the agent fields: %+v", name, e)
				}
			case "plain.example":
				if e.UserAct != "" || e.IdentityTokenType != "" {
					t.Errorf("%s: an event without the fields has act %q type %q", name, e.UserAct, e.IdentityTokenType)
				}
			default:
				t.Errorf("%s: unexpected event %q", name, e.Domain)
			}
		}
	}
}

// The act filter selects exactly one agent's events on the fleet store (both
// read paths) and the in-memory central store; an empty filter changes nothing
// and a hostile value matches nothing.
func TestFleetFilterByAct(t *testing.T) {
	now := time.Now()
	evs := []AggregatedEvent{
		actEvent("p1", "one.example", "a1", "warden", now),
		actEvent("p1", "two.example", "a2", "warden", now.Add(time.Second)),
		actEvent("p1", "idp.example", "", "idp", now.Add(2*time.Second)),
	}
	fleet := newFleetStore(t, 0, 0)
	central := NewCentralStore(0)
	for _, e := range evs {
		if err := fleet.StoreAggregatedEvent(e); err != nil {
			t.Fatal(err)
		}
		if err := central.StoreAggregatedEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	domains := func(es []Event) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.Domain)
		}
		return out
	}
	for name, st := range map[string]interface {
		GetEvents(EventFilter) ([]Event, error)
		GetAggregatedEvents(AggregatedFilter) ([]AggregatedEvent, error)
	}{"fleet": fleet, "central": central} {
		got, err := st.GetEvents(EventFilter{Act: "a1"})
		if err != nil || strings.Join(domains(got), ",") != "one.example" {
			t.Errorf("%s GetEvents act=a1 = %v %v", name, domains(got), err)
		}
		agg, err := st.GetAggregatedEvents(AggregatedFilter{EventFilter: EventFilter{Act: "a2"}})
		if err != nil || len(agg) != 1 || agg[0].Domain != "two.example" {
			t.Errorf("%s GetAggregatedEvents act=a2 = %v %v", name, agg, err)
		}
		all, err := st.GetEvents(EventFilter{})
		if err != nil || len(all) != 3 {
			t.Errorf("%s no filter = %d %v, want 3", name, len(all), err)
		}
		none, err := st.GetEvents(EventFilter{Act: "x' OR '1'='1"})
		if err != nil || len(none) != 0 {
			t.Errorf("%s hostile act = %v %v", name, none, err)
		}
	}
}

// The only identity-token data the fleet store keeps is the agent id and the
// token type: no event field or fleet column can carry token content.
func TestFleetStoresNoRawToken(t *testing.T) {
	typ := reflect.TypeOf(AggregatedEvent{})
	var walk func(t reflect.Type)
	walk = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.Anonymous {
				walk(f.Type)
				continue
			}
			l := strings.ToLower(f.Name + " " + f.Tag.Get("json"))
			if (strings.Contains(l, "token") && f.Name != "IdentityTokenType" && f.Name != "UserTokenProvider" && f.Name != "UserTokenRetried") || strings.Contains(l, "jwt") || strings.Contains(l, "bearer") {
				t.Errorf("event field %s can carry token content", f.Name)
			}
		}
	}
	walk(typ)

	s := newFleetStore(t, 0, 0)
	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid, nn, pk int
			n, ty       string
			d           any
		)
		if err := rows.Scan(&cid, &n, &ty, &nn, &d, &pk); err != nil {
			t.Fatal(err)
		}
		l := strings.ToLower(n)
		if (strings.Contains(l, "token") && n != "identity_token_type" && n != "user_token_provider" && n != "user_token_retried") || strings.Contains(l, "jwt") || strings.Contains(l, "bearer") {
			t.Errorf("fleet column %q can carry token content", n)
		}
	}
	if err := s.StoreAggregatedEvent(actEvent("p1", "x.example", "a1", "warden", time.Now())); err != nil {
		t.Fatal(err)
	}
	var act, tt string
	if err := s.db.QueryRow(`SELECT user_act, identity_token_type FROM events`).Scan(&act, &tt); err != nil || act != "a1" || tt != "warden" {
		t.Fatalf("stored act %q type %q err %v", act, tt, err)
	}
}
