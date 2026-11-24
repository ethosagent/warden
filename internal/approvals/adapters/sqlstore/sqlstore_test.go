package sqlstore_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The behaviour of the store (transitions, races, expiry, redaction) is
// exercised through the domain API in internal/approvals' tests; this covers the
// adapter's own surface: the migration contract and the default clock and
// logger.

func TestMigrationsAreOptional(t *testing.T) {
	migs := sqlstore.Migrations()
	if len(migs) != 3 || migs[0].ID != sqlstore.MigrationID || migs[1].ID != sqlstore.ReplayMigrationID || migs[2].ID != sqlstore.MetaMigrationID ||
		!migs[0].Optional || !migs[1].Optional || !migs[2].Optional {
		t.Fatalf("Migrations() ids = %s %s %s, want Optional %s, %s and %s", migs[0].ID, migs[1].ID, migs[len(migs)-1].ID,
			sqlstore.MigrationID, sqlstore.ReplayMigrationID, sqlstore.MetaMigrationID)
	}
	for i, m := range cpstate.Enable(migs, sqlstore.EnabledMigrationIDs()...) {
		if m.Optional {
			t.Errorf("Enable left migration %d (%s) optional", i, m.ID)
		}
	}
}

func TestStoreDefaultsAndCreate(t *testing.T) {
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "warden-cp.db"), cpstate.Enable(sqlstore.Migrations(), sqlstore.MigrationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st := sqlstore.New(db.SQL(), nil, nil)

	nd := approvals.NewDraft{
		Target: approvals.TargetBlockedUsers, TargetRef: "email:a@example.com", BaseVersion: 2,
		Author: approvals.Author{Sub: "ada", Kind: "oidc"}, Source: approvals.SourceAPI,
		Provenance: approvals.Provenance{Source: approvals.SourceAPI, Ref: "req-1"},
		DocJSON:    json.RawMessage(`{"remove":"a@example.com"}`), DocSHA256: "abc",
		Classification: json.RawMessage(`{"widening":true}`), RequiredRole: "admin",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	d, err := st.Create(ctx, nd, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.Target != approvals.TargetBlockedUsers || d.TargetRef != "email:a@example.com" || d.Source != approvals.SourceAPI ||
		d.Provenance.Ref != "req-1" || d.RequiredRole != "admin" || string(d.Classification) != `{"widening":true}` {
		t.Fatalf("draft = %+v", d)
	}
	for _, bad := range []approvals.NewDraft{
		{Target: "nope", Source: approvals.SourceAPI, Author: nd.Author, DocJSON: nd.DocJSON, DocSHA256: "x"},
		{Target: approvals.TargetPolicy, Source: "nope", Author: nd.Author, DocJSON: nd.DocJSON, DocSHA256: "x"},
		{Target: approvals.TargetPolicy, Source: approvals.SourceAPI, DocJSON: nd.DocJSON, DocSHA256: "x"},
	} {
		if _, err := st.Create(ctx, bad, 0); err == nil {
			t.Errorf("Create(%+v) accepted an invalid draft", bad)
		}
	}
	if _, _, err := st.RecordDecision(ctx, d.ID, approvals.DecisionInput{Revision: 1, DocSHA256: "abc", Decision: approvals.DecisionEmergency, Approver: nd.Author}); err == nil {
		t.Error("RecordDecision accepted an emergency decision (that is APPR-07's own path)")
	}
}

func TestApprovalsMeta(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	// Never enabled: no table, nothing is created by a disabled write.
	off, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "off.db"), sqlstore.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = off.Close() }()
	if err := sqlstore.WriteMeta(ctx, off.SQL(), sqlstore.Meta{}, now); err != nil {
		t.Fatalf("disabled WriteMeta = %v, want nil", err)
	}
	if _, found, err := sqlstore.ReadMeta(ctx, off.SQL()); err != nil || found {
		t.Fatalf("ReadMeta on a database that never enabled approvals = %v, %v", found, err)
	}
	if err := sqlstore.WriteMeta(ctx, off.SQL(), sqlstore.Meta{Enabled: true}, now); err == nil {
		t.Error("enabled WriteMeta without the table succeeded")
	}

	db, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "on.db"), cpstate.Enable(sqlstore.Migrations(), sqlstore.EnabledMigrationIDs()...))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, found, _ := sqlstore.ReadMeta(ctx, db.SQL()); found {
		t.Error("ReadMeta found a row before any write")
	}
	want := sqlstore.Meta{Enabled: true, DraftTTL: 90 * time.Minute, MaxOpenDrafts: 7}
	if err := sqlstore.WriteMeta(ctx, db.SQL(), want, now); err != nil {
		t.Fatal(err)
	}
	if got, found, err := sqlstore.ReadMeta(ctx, db.SQL()); err != nil || !found || got != want {
		t.Fatalf("ReadMeta = %+v, %v, %v; want %+v", got, found, err, want)
	}
	if err := sqlstore.WriteMeta(ctx, db.SQL(), sqlstore.Meta{}, now); err != nil {
		t.Fatal(err)
	}
	if got, found, _ := sqlstore.ReadMeta(ctx, db.SQL()); !found || got.Enabled {
		t.Errorf("after disable ReadMeta = %+v, %v", got, found)
	}
}
