package webauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/webauth"
)

var (
	consoleTable = webauth.SessionTable{Name: "sessions", MigrationID: "sessions/0001", AuthMethod: true}
	portalTable  = webauth.SessionTable{Name: "portal_sessions", MigrationID: "portal_sessions/0001"}
)

func TestSessionTables(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, consoleTable.Migrations(), portalTable.Migrations())
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	console := webauth.NewSessionStore(db.SQL(), consoleTable, time.Hour, 12*time.Hour, clock)
	portal := webauth.NewSessionStore(db.SQL(), portalTable, 30*time.Minute, 8*time.Hour, clock)

	in := webauth.SessionInput{Iss: "https://idp.example", Sub: "alice", Email: "Alice@Example.com", Groups: []string{"staff"}, AuthMethod: "oidc"}
	craw, _, err := console.Create(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	praw, psess, err := portal.Create(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if psess.AuthMethod != "" || psess.ExpiresAt != now.Add(8*time.Hour) {
		t.Fatalf("portal session = %+v", psess)
	}

	// Each store sees only its own table.
	if _, live, _ := portal.Lookup(ctx, craw); live {
		t.Fatal("the portal store sees a console session")
	}
	if _, live, _ := console.Lookup(ctx, praw); live {
		t.Fatal("the console store sees a portal session")
	}
	cs, live, err := console.Lookup(ctx, craw)
	if err != nil || !live || cs.AuthMethod != "oidc" {
		t.Fatalf("console lookup = %+v %v %v", cs, live, err)
	}
	ps, live, err := portal.Lookup(ctx, praw)
	if err != nil || !live || ps.Sub != "alice" || ps.Email != "Alice@Example.com" || len(ps.Groups) != 1 {
		t.Fatalf("portal lookup = %+v %v %v", ps, live, err)
	}
	for name, st := range map[string]*webauth.SessionStore{"console": console, "portal": portal} {
		if l, err := st.List(ctx); err != nil || len(l) != 1 {
			t.Fatalf("%s List = %d rows %v, want 1", name, len(l), err)
		}
	}
	countRows := func(table string) int {
		var n int
		if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Revocation on one table leaves the other alone.
	if n, err := portal.DeleteByEmail(ctx, "alice@example.com"); err != nil || n != 1 {
		t.Fatalf("portal DeleteByEmail = %d %v", n, err)
	}
	if countRows("sessions") != 1 || countRows("portal_sessions") != 0 {
		t.Fatal("DeleteByEmail crossed tables")
	}
	praw, _, _ = portal.Create(ctx, in)
	if n, err := console.DeleteBySub(ctx, "alice"); err != nil || n != 1 {
		t.Fatalf("console DeleteBySub = %d %v", n, err)
	}
	if _, live, _ := portal.Lookup(ctx, praw); !live {
		t.Fatal("a console DeleteBySub ended a portal session")
	}

	// The portal's shorter idle limit applies to its table only; with no
	// auth_method column, the sweep uses the plain idle rule.
	craw, _, _ = console.Create(ctx, in)
	now = now.Add(45 * time.Minute)
	if n, err := portal.SweepExpired(ctx); err != nil || n != 1 {
		t.Fatalf("portal sweep = %d %v, want 1", n, err)
	}
	if n, err := console.SweepExpired(ctx); err != nil || n != 0 {
		t.Fatalf("console sweep = %d %v, want 0", n, err)
	}
	if _, live, _ := console.Lookup(ctx, craw); !live {
		t.Fatal("the console session idled out on the portal's limit")
	}
	if ok, err := console.Touch(ctx, craw); err != nil || !ok {
		t.Fatalf("console touch = %v %v", ok, err)
	}
}

// The console's table is generated exactly as the sessions/0001 migration was
// written before the move.
func TestSessionTableConsoleSQL(t *testing.T) {
	const want = `CREATE TABLE sessions (
  id_hash      TEXT PRIMARY KEY,
  iss          TEXT NOT NULL,
  sub          TEXT NOT NULL,
  email        TEXT NOT NULL,
  groups_json  TEXT NOT NULL,
  auth_method  TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX sessions_expires_at ON sessions (expires_at);
CREATE INDEX sessions_sub ON sessions (sub);`
	m := consoleTable.Migrations()
	if len(m) != 1 || m[0].ID != "sessions/0001" || m[0].SQL != want {
		t.Fatalf("console migration = %+v", m)
	}
}

func TestSessionTableRejectsBadName(t *testing.T) {
	for _, name := range []string{"", "Sessions", "sessions; DROP TABLE x", "1sessions", "a-b"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("table %q accepted", name)
				}
			}()
			webauth.NewSessionStore(nil, webauth.SessionTable{Name: name}, time.Hour, time.Hour, nil)
		}()
	}
}

func TestSessionBreakglassIdleExempt(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, consoleTable.Migrations())
	now := time.Unix(1_800_000_000, 0)
	st := webauth.NewSessionStore(db.SQL(), consoleTable, time.Minute, time.Hour, func() time.Time { return now })
	raw, _, err := st.Create(ctx, webauth.SessionInput{Sub: "bg", AuthMethod: webauth.AuthMethodBreakglass})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Minute)
	if n, _ := st.SweepExpired(ctx); n != 0 {
		t.Fatal("a break-glass session idled out")
	}
	if _, live, _ := st.Lookup(ctx, raw); !live {
		t.Fatal("a break-glass session is not live past the idle limit")
	}
}
