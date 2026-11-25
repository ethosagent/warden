package controlplane

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

func fleetHasColumn(t *testing.T, path, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid, nn, pk int
			n, ty       string
			d           sql.NullString
		)
		if err := rows.Scan(&cid, &n, &ty, &nn, &d, &pk); err != nil {
			t.Fatal(err)
		}
		if n == name {
			return true
		}
	}
	return false
}

// A fleet DB from before the agent fields opens with both columns added, its
// rows intact, and a second open is a no-op (W-P2-WBND-08).
func TestFleetMigrateUserAct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_uid TEXT, proxy_id TEXT NOT NULL DEFAULT '',
 agent_id TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL, domain TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', decision TEXT NOT NULL DEFAULT '',
 response_status INTEGER NOT NULL DEFAULT 0, secret_ref TEXT NOT NULL DEFAULT '', judge_reason TEXT NOT NULL DEFAULT '',
 tool TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', cost_usd REAL NOT NULL DEFAULT 0,
 provider TEXT NOT NULL DEFAULT '', compliance TEXT NOT NULL DEFAULT '');
INSERT INTO events (proxy_id, ts, domain, decision) VALUES ('p', 5000, 'old.example', 'allow');`)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s, err := analytics.NewFleetSQLiteStore(path, 0, 0)
		if err != nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		got, err := s.GetEvents(analytics.EventFilter{})
		_ = s.Close()
		if err != nil || len(got) != 1 || got[0].Domain != "old.example" || got[0].UserAct != "" {
			t.Fatalf("open %d: rows %+v err %v", i+1, got, err)
		}
	}
	for _, c := range []string{"user_act", "identity_token_type"} {
		if !fleetHasColumn(t, path, c) {
			t.Errorf("column %s missing", c)
		}
	}
}

// An event ingested through the control plane's /central/ingest with
// user_act=a1 and identity_token_type=warden is returned with both by the fleet
// store; one without them stores empty defaults.
func TestIngestCarriesUserAct(t *testing.T) {
	store, err := analytics.NewFleetSQLiteStore(filepath.Join(t.TempDir(), "fleet.db"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ts := httptest.NewServer(New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Store: store}).Handler())
	defer ts.Close()

	now := time.Now().UTC()
	postIngest(t, ts.URL, "proxy-1", []analytics.Event{
		{Timestamp: now, Domain: "bound.example", Decision: "allow", UserSub: "u1", IdentityStatus: "valid", UserAct: "a1", IdentityTokenType: "warden"},
		{Timestamp: now.Add(time.Second), Domain: "plain.example", Decision: "allow"},
	})
	got, err := store.GetEvents(analytics.EventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("GetEvents: %v %v", got, err)
	}
	for _, e := range got {
		wantAct, wantTyp := "", ""
		if e.Domain == "bound.example" {
			wantAct, wantTyp = "a1", "warden"
		}
		if e.UserAct != wantAct || e.IdentityTokenType != wantTyp {
			t.Errorf("%s: act %q type %q, want %q %q", e.Domain, e.UserAct, e.IdentityTokenType, wantAct, wantTyp)
		}
	}
}
