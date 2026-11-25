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
	if len(migs) != 2 || migs[0].ID != sqlstore.MigrationID || migs[1].ID != sqlstore.ReplayMigrationID || !migs[0].Optional || !migs[1].Optional {
		t.Fatalf("Migrations() = %+v, want Optional %s and %s", migs, sqlstore.MigrationID, sqlstore.ReplayMigrationID)
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
