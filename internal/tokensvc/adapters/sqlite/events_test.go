package sqlite_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
)

func openEvents(t *testing.T, path string) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), path, sqlite.EventMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func eventRows(t *testing.T, db *cpstate.DB) []map[string]any {
	t.Helper()
	rows, err := db.SQL().Query(`SELECT ts, outcome, reason, agent_id, sub_hmac, sid, jti, kid, exp, scope FROM token_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]any
	for rows.Next() {
		var ts, exp int64
		var outcome, reason, agent, sub, sid, jti, kid, scope string
		if err := rows.Scan(&ts, &outcome, &reason, &agent, &sub, &sid, &jti, &kid, &exp, &scope); err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]any{"ts": ts, "outcome": outcome, "reason": reason, "agent": agent, "sub": sub, "sid": sid, "jti": jti, "kid": kid, "exp": exp, "scope": scope})
	}
	return out
}

func TestEventsRecordRowAndLine(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db := openEvents(t, path)
	var logs bytes.Buffer
	ev := sqlite.NewEvents(db, slog.New(slog.NewJSONHandler(&logs, nil)))
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	issued := tokensvc.Event{
		TS: at, Outcome: tokensvc.OutcomeIssued, AgentID: "agent-1", IdPIss: "https://idp", Sub: "user-secret-sub",
		SID: "wts_1", JTI: "jti-1", KID: "kid-1", Exp: at.Add(15 * time.Minute), Scope: "read",
	}
	if err := ev.Record(ctx, issued); err != nil {
		t.Fatal(err)
	}
	denied := tokensvc.Event{TS: at, Outcome: tokensvc.OutcomeDenied, Reason: tokensvc.ReasonUserBlocked, AgentID: "agent-1"}
	if err := ev.Record(ctx, denied); err != nil {
		t.Fatal(err)
	}
	rows := eventRows(t, db)
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	r := rows[0]
	sub, _ := r["sub"].(string)
	if len(sub) != 64 || strings.Contains(sub, "user-secret-sub") || r["sid"] != "wts_1" || r["exp"] != at.Add(15*time.Minute).Unix() || r["scope"] != "read" {
		t.Errorf("issued row = %v", r)
	}
	if rows[1]["sub"] != "" || rows[1]["reason"] != "user_blocked" {
		t.Errorf("a denial before the subject verified has a sub_hmac: %v", rows[1])
	}

	var line map[string]any
	first, _, _ := strings.Cut(logs.String(), "\n")
	if err := json.Unmarshal([]byte(first), &line); err != nil {
		t.Fatal(err)
	}
	if line["msg"] != "token_exchange" || line["schema"] != tokensvc.EventSchema || line["sub"] != sub || line["agent"] != "agent-1" ||
		line["sid"] != "wts_1" || line["jti"] != "jti-1" || line["kid"] != "kid-1" || line["outcome"] != "issued" {
		t.Errorf("log line = %v", line)
	}
	if strings.Contains(logs.String(), "user-secret-sub") {
		t.Error("the raw subject reached the log")
	}

	// The pseudonym is stable across a restart on the same database (the salt
	// is stored) and differs per user and per IdP.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2 := openEvents(t, path)
	ev2 := sqlite.NewEvents(db2, nil)
	if err := ev2.Record(ctx, issued); err != nil {
		t.Fatal(err)
	}
	other := issued
	other.Sub = "someone-else"
	other2 := issued
	other2.IdPIss = "https://other-idp"
	for _, e := range []tokensvc.Event{other, other2} {
		if err := ev2.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	rows = eventRows(t, db2)
	if rows[2]["sub"] != sub {
		t.Error("the pseudonym changed across a restart")
	}
	if rows[3]["sub"] == sub || rows[4]["sub"] == sub || rows[3]["sub"] == rows[4]["sub"] {
		t.Error("different users share a pseudonym")
	}
	var salts int
	if err := db2.SQL().QueryRow(`SELECT COUNT(*) FROM token_event_salt`).Scan(&salts); err != nil || salts != 1 {
		t.Errorf("salt rows = %d, %v; want 1", salts, err)
	}
}

func TestEventsFailureWritesNoLine(t *testing.T) {
	db := openEvents(t, filepath.Join(t.TempDir(), "warden-cp.db"))
	var logs bytes.Buffer
	ev := sqlite.NewEvents(db, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err := ev.Record(context.Background(), tokensvc.Event{TS: time.Now(), Outcome: tokensvc.OutcomeIssued, AgentID: "a", IdPIss: "i", Sub: "s"})
	if err == nil {
		t.Fatal("Record succeeded on a closed database")
	}
	if logs.Len() != 0 {
		t.Errorf("a line was logged for a row that was not written: %s", logs.String())
	}
}

func TestEventsPurge(t *testing.T) {
	ctx := context.Background()
	db := openEvents(t, filepath.Join(t.TempDir(), "warden-cp.db"))
	ev := sqlite.NewEvents(db, nil)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		if err := ev.Record(ctx, tokensvc.Event{TS: base.Add(time.Duration(i) * time.Hour), Outcome: tokensvc.OutcomeDenied, Reason: tokensvc.ReasonReplay, AgentID: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := ev.Purge(ctx, base.Add(2*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("Purge = %d, %v; want 2", n, err)
	}
	if rows := eventRows(t, db); len(rows) != 2 {
		t.Fatalf("%d rows left, want 2", len(rows))
	}
}
