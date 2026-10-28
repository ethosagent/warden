package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The admin audit log API on the control plane (W-P1-AAUD-03): the dashboard
// routes over a real adminaudit store, behind the oidc role table.

// openDashAuditStore opens a writing store with its key at dir/name and the
// shared HMAC key beside it, optionally starting a new segment on that key.
func openDashAuditStore(t *testing.T, db *cpstate.DB, dir, name string, newSegment bool) *adminaudit.Store {
	t.Helper()
	keyFile := filepath.Join(dir, name)
	o := adminaudit.OpenOptions{KeyFile: keyFile}
	if newSegment {
		signer, err := audit.LoadOrCreateSigner(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		o.NewSegment = audit.KeyID(signer.PubKey())
	}
	store, err := adminaudit.Open(context.Background(), db, o)
	if err != nil {
		t.Fatalf("adminaudit.Open: %v", err)
	}
	return store
}

// recordDashAudit appends n admin rows.
func recordDashAudit(t *testing.T, store *adminaudit.Store, n int) {
	t.Helper()
	for i := range n {
		_, err := store.Record(context.Background(), adminaudit.Input{
			Actor:     adminaudit.Actor{Sub: fmt.Sprintf("user-%d", i%3), Email: fmt.Sprintf("user%d@example.com", i%3)},
			ActorRole: "admin", AuthMethod: adminaudit.AuthMethodOIDC, Action: "policy.write", Target: "policy",
			Outcome: adminaudit.OutcomeOK, HTTPStatus: http.StatusOK, RequestID: fmt.Sprintf("req-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func newDashAuditEnv(t *testing.T, db *cpstate.DB, store *adminaudit.Store) *auditEnv {
	t.Helper()
	return newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken, db: db, store: store})
}

type dashAuditList struct {
	Entries    []dashboard.AdminAuditEntry `json:"entries"`
	NextCursor int64                       `json:"nextCursor"`
}

func getDashAuditList(t *testing.T, e *auditEnv, raw, target string) dashAuditList {
	t.Helper()
	rec := e.send(raw, "", http.MethodGet, target, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", target, rec.Code, rec.Body)
	}
	var out dashAuditList
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func countDashAuditRows(t *testing.T, db *cpstate.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM admin_audit").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAdminAuditAPIRoles: over 120 stored rows an admin pages 50, 50 and 20
// entries newest first with no duplicates, each naming its actor from the side
// table and none carrying a signature; viewers and editors get 403 on the list
// and verify but may read the public keys; no session gets 401; and none of
// these reads or refusals adds a row to the chain.
func TestAdminAuditAPIRoles(t *testing.T) {
	db := openAuditDB(t)
	store := openDashAuditStore(t, db, t.TempDir(), "cp-audit.key", false)
	recordDashAudit(t, store, 119) // + genesis = 120
	e := newDashAuditEnv(t, db, store)
	admin := e.session(t, groupAdmin)

	var sizes []int
	seen := map[int64]bool{}
	last, cursor := int64(1<<62), int64(0)
	for page := 0; page < 5; page++ {
		target := "/dashboard/api/admin-audit?limit=50"
		if cursor > 0 {
			target += fmt.Sprintf("&cursor=%d", cursor)
		}
		resp := getDashAuditList(t, e, admin, target)
		sizes = append(sizes, len(resp.Entries))
		for _, en := range resp.Entries {
			if en.Seq >= last || seen[en.Seq] {
				t.Fatalf("seq %d after %d", en.Seq, last)
			}
			seen[en.Seq], last = true, en.Seq
			if en.Seq > 1 && (en.ActorSub == "" || !strings.HasSuffix(en.ActorEmail, "@example.com") || en.ActorID == en.ActorSub) {
				t.Errorf("seq %d actor = %q %q %q", en.Seq, en.ActorID, en.ActorSub, en.ActorEmail)
			}
			if len(en.EntryHash) != 64 || len(en.PrevHash) != 64 || en.KeyID != store.KeyID() || en.Time == "" {
				t.Errorf("seq %d hashes %q %q key %q time %q", en.Seq, en.EntryHash, en.PrevHash, en.KeyID, en.Time)
			}
		}
		if cursor = resp.NextCursor; cursor == 0 {
			break
		}
	}
	if fmt.Sprint(sizes) != "[50 50 20]" || len(seen) != 120 {
		t.Fatalf("page sizes %v, %d distinct; want [50 50 20], 120", sizes, len(seen))
	}
	if raw := e.send(admin, "", http.MethodGet, "/dashboard/api/admin-audit?limit=3", "").Body.String(); strings.Contains(raw, "ignature") {
		t.Errorf("list exposes the signature: %s", raw)
	}
	// The actor filter takes a sub (hashed with the store's key).
	for _, en := range getDashAuditList(t, e, admin, "/dashboard/api/admin-audit?actor=user-1&limit=200").Entries {
		if en.ActorSub != "user-1" {
			t.Fatalf("actor filter returned %q", en.ActorSub)
		}
	}

	for _, group := range []string{groupViewer, groupEditor} {
		raw := e.session(t, group)
		if rec := e.send(raw, "", http.MethodGet, "/dashboard/api/admin-audit", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s list = %d, want 403", group, rec.Code)
		}
		if rec := e.send(raw, "", http.MethodPost, "/dashboard/api/admin-audit/verify", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s verify = %d, want 403", group, rec.Code)
		}
		if rec := e.send(raw, "", http.MethodGet, "/dashboard/api/admin-audit/pubkey", ""); rec.Code != http.StatusOK {
			t.Errorf("%s pubkey = %d, want 200", group, rec.Code)
		}
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/admin-audit"},
		{http.MethodPost, "/dashboard/api/admin-audit/verify"},
		{http.MethodGet, "/dashboard/api/admin-audit/pubkey"},
	} {
		if rec := e.send("", "", c.method, c.path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d, want 401", c.method, c.path, rec.Code)
		}
	}
	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/admin-audit/verify", ""); rec.Code != http.StatusOK {
		t.Fatalf("admin verify = %d %s", rec.Code, rec.Body)
	}
	if n := countDashAuditRows(t, db); n != 120 {
		t.Errorf("admin_audit rows = %d after reads, refusals and verify; want 120 (read-only routes)", n)
	}
}

// TestAdminAuditVerifyStore: verify over the real store reports every row on
// an untouched chain and the tampered row 7 after an edit; an anchor that no
// longer matches fails too.
func TestAdminAuditVerifyStore(t *testing.T) {
	db := openAuditDB(t)
	store := openDashAuditStore(t, db, t.TempDir(), "cp-audit.key", false)
	recordDashAudit(t, store, 11)
	e := newDashAuditEnv(t, db, store)
	admin := e.session(t, groupAdmin)
	verify := func(body string) dashboard.AdminAuditVerifyResult {
		t.Helper()
		rec := e.send(admin, "", http.MethodPost, "/dashboard/api/admin-audit/verify", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("verify = %d %s", rec.Code, rec.Body)
		}
		var res dashboard.AdminAuditVerifyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := verify("")
	if !res.OK || res.Checked != 12 || res.HeadSeq != 12 || len(res.HeadHash) != 64 || res.LastVerifiedSeq != 12 {
		t.Fatalf("untouched = %+v, want ok with 12 checked", res)
	}
	if res := verify(`{"anchor":{"seq":12,"hash":"` + res.HeadHash + `"}}`); !res.OK {
		t.Fatalf("matching anchor = %+v", res)
	}
	if res := verify(`{"anchor":{"seq":12,"hash":"` + strings.Repeat("00", 32) + `"}}`); res.OK || res.FirstBadSeq != 12 {
		t.Fatalf("stale anchor = %+v, want a failure at 12", res)
	}
	if _, err := db.SQL().Exec("UPDATE admin_audit SET target = 'settings' WHERE seq = 7"); err != nil {
		t.Fatal(err)
	}
	if res := verify(""); res.OK || res.FirstBadSeq != 7 || res.Reason != adminaudit.ReasonEntryHash {
		t.Fatalf("tampered = %+v, want ok:false at 7", res)
	}
	if !strings.Contains(e.log.String(), "admin audit chain verification failed") {
		t.Error("a failed verification is not logged")
	}
}

// TestAdminAuditPubKeys: the pubkey route lists the genesis key, and after a
// manual segment_start both keys, each matching the key_id its rows carry.
func TestAdminAuditPubKeys(t *testing.T) {
	db := openAuditDB(t)
	dir := t.TempDir()
	storeA := openDashAuditStore(t, db, dir, "a.key", false)
	recordDashAudit(t, storeA, 2)

	pubkeys := func(e *auditEnv) []dashboard.AdminAuditKey {
		t.Helper()
		rec := e.send(e.session(t, groupViewer), "", http.MethodGet, "/dashboard/api/admin-audit/pubkey", "")
		var out struct {
			Alg  string                    `json:"alg"`
			Keys []dashboard.AdminAuditKey `json:"keys"`
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("pubkey = %d %s", rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Alg != "ed25519" {
			t.Fatalf("pubkey body %s: %v", rec.Body, err)
		}
		return out.Keys
	}
	keys := pubkeys(newDashAuditEnv(t, db, storeA))
	if len(keys) != 1 || keys[0].KeyID != storeA.KeyID() || keys[0].FirstSeq != 1 || keys[0].PublicKey == "" {
		t.Fatalf("genesis keys = %+v, want one key %s", keys, storeA.KeyID())
	}

	storeB := openDashAuditStore(t, db, dir, "b.key", true)
	recordDashAudit(t, storeB, 2)
	e := newDashAuditEnv(t, db, storeB)
	keys = pubkeys(e)
	if len(keys) != 2 || keys[0].KeyID != storeA.KeyID() || keys[1].KeyID != storeB.KeyID() || keys[1].FirstSeq != 4 || keys[0].PublicKey == keys[1].PublicKey {
		t.Fatalf("keys after segment_start = %+v", keys)
	}
	byID := map[string]int64{keys[0].KeyID: keys[0].FirstSeq, keys[1].KeyID: keys[1].FirstSeq}
	for _, en := range getDashAuditList(t, e, e.session(t, groupAdmin), "/dashboard/api/admin-audit").Entries {
		want := storeA.KeyID()
		if en.Seq >= byID[storeB.KeyID()] {
			want = storeB.KeyID()
		}
		if en.KeyID != want {
			t.Errorf("seq %d key_id %s, want %s", en.Seq, en.KeyID, want)
		}
	}
}

// TestAdminAuditNotWiredOnCP: with admin audit disabled the three routes are
// 404 for an admin in oidc mode and for anyone in none mode.
func TestAdminAuditNotWiredOnCP(t *testing.T) {
	e := newAuthzEnv(t)
	admin := e.session(t, groupAdmin)
	none := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Console: config.ConsoleConfig{}}).Handler()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/admin-audit"},
		{http.MethodPost, "/dashboard/api/admin-audit/verify"},
		{http.MethodGet, "/dashboard/api/admin-audit/pubkey"},
	} {
		if rec := e.do(admin, c.method, c.path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("oidc admin %s %s = %d, want 404", c.method, c.path, rec.Code)
		}
		if rec := dashWrite(t, none, c.method, c.path, "Bearer "+dashTestToken); rec.Code != http.StatusNotFound {
			t.Errorf("none mode %s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}
