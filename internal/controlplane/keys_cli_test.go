package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
)

// openKeysStateDir runs a control plane with keys and the admin audit enabled
// once, so the state dir holds the state database, the signing_keys table, a
// first key set and an audit chain — everything the keys CLI opens.
func openKeysStateDir(t *testing.T) string {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeKeysPolicy(t, keysEnabledYAML+"console:\n  adminAudit:\n    enabled: true\n")
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	return stateDir
}

// backdateNextPublish moves purpose's next key's publish_at behind its
// prepublish window, so a real-time non-emergency rotation may promote it.
func backdateNextPublish(t *testing.T, stateDir, purpose string) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.SQL().Exec(`UPDATE signing_keys SET publish_at = publish_at - ? WHERE purpose = ? AND state = 'next'`,
		int64(time.Hour/time.Second), purpose); err != nil {
		t.Fatal(err)
	}
}

// cliAuditRow is one admin_audit row's identity columns. actor_id is the
// recorder's pseudonym of the actor sub, so assertions compare ids against
// each other, never against a literal subject.
type cliAuditRow struct {
	actorID    string
	authMethod string
	targetRef  string
}

// keyAuditRows returns the admin audit rows with action, seq order.
func keyAuditRows(t *testing.T, stateDir, action string) []cliAuditRow {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT actor_id, auth_method, target_ref FROM admin_audit WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []cliAuditRow
	for rows.Next() {
		var r cliAuditRow
		if err := rows.Scan(&r.actorID, &r.authMethod, &r.targetRef); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// systemActorID returns the boot generation's actor id: what the system's own
// key events are pseudonymized to.
func systemActorID(t *testing.T, stateDir string) string {
	t.Helper()
	rows := keyAuditRows(t, stateDir, keys.ActionGenerated)
	if len(rows) == 0 {
		t.Fatal("no keys.generated rows to read the system actor from")
	}
	return rows[0].actorID
}

// TestKeysCLIOpenRefuses: the keys CLI opens only a state dir whose control
// plane has run with keys enabled, and read-only opens create nothing.
func TestKeysCLIOpenRefuses(t *testing.T) {
	ctx := context.Background()
	opt := KeysCLIOptions{}
	if _, err := OpenKeysOffline(ctx, "", opt); err == nil || !strings.Contains(err.Error(), "--state-dir") {
		t.Errorf("empty state dir err = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "none")
	if _, err := OpenKeysOfflineReadOnly(ctx, missing, opt); err == nil || !strings.Contains(err.Error(), "no control plane state database") {
		t.Errorf("missing state db err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(missing, adminaudit.StateDBFileName)); !os.IsNotExist(err) {
		t.Errorf("a read-only open created %s: %v", adminaudit.StateDBFileName, err)
	}
	// The control plane ran here without keys: a database, but no
	// signing_keys table.
	stateDir := filepath.Join(t.TempDir(), "state")
	runCP(t, Params{ConfigPath: writeKeysPolicy(t, ""), StateDir: stateDir})
	if _, err := OpenKeysOfflineReadOnly(ctx, stateDir, opt); err == nil || !strings.Contains(err.Error(), "signing_keys") {
		t.Errorf("state dir without signing_keys err = %v", err)
	}
}

// TestKeysCLIListAndJWKSOffline: list and export read the stored rows without
// a running control plane and carry public members only.
func TestKeysCLIListAndJWKSOffline(t *testing.T) {
	ctx := context.Background()
	o, err := OpenKeysOfflineReadOnly(ctx, openKeysStateDir(t), KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	all, err := o.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("list = %d rows, want an active and a next for token and bundle", len(all))
	}
	tok, err := o.Rows(ctx, keys.PurposeToken)
	if err != nil || len(tok) != 2 {
		t.Fatalf("token rows = %v err %v, want 2", tok, err)
	}
	doc, err := o.JWKS(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("jwks = %d keys, want the active and next key", len(doc.Keys))
	}
	for _, k := range doc.Keys {
		if k.Kid != tok[0].KID && k.Kid != tok[1].KID {
			t.Errorf("jwks kid %s is not one of the stored rows", k.Kid)
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"d"`) || strings.Contains(string(out), "PRIVATE") {
		t.Errorf("jwks leaks private members: %s", out)
	}
}

// TestKeysCLIRotateToken: a rotation promotes the published next key, retires
// the old key and appends one cli audit row naming the request.
func TestKeysCLIRotateToken(t *testing.T) {
	ctx := context.Background()
	stateDir := openKeysStateDir(t)
	backdateNextPublish(t, stateDir, keys.PurposeToken)
	o, err := OpenKeysOffline(ctx, stateDir, KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if !o.AuditEnabled() {
		t.Fatal("the state dir's admin audit chain was not picked up")
	}
	before, err := o.Rows(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	var oldActive, oldNext keys.Record
	for _, r := range before {
		switch r.State {
		case keys.StateActive:
			oldActive = r
		case keys.StateNext:
			oldNext = r
		}
	}
	res, err := o.Rotate(ctx, keys.PurposeToken, false)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if res.KID != oldNext.KID || res.Emergency {
		t.Errorf("rotate result = %+v, want the published next key %s", res, oldNext.KID)
	}
	after, err := o.Rows(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	states := map[keys.State]string{}
	for _, r := range after {
		states[r.State] = r.KID
	}
	if states[keys.StateActive] != oldNext.KID {
		t.Errorf("active after the rotation = %s, want the promoted %s", states[keys.StateActive], oldNext.KID)
	}
	if states[keys.StateRetired] != oldActive.KID {
		t.Errorf("the old active key did not retire: %+v", after)
	}
	if states[keys.StateNext] == "" || states[keys.StateNext] == oldNext.KID {
		t.Errorf("no fresh next key: %+v", after)
	}
	// The bundle purpose is untouched, and the request row is the CLI's: one
	// cli-authenticated row naming the purpose, with an actor distinct from
	// the system's and shared by this rotation's own transition rows.
	bundle, err := o.Rows(ctx, keys.PurposeBundle)
	if err != nil || len(bundle) != 2 {
		t.Fatalf("bundle rows = %v err %v, want 2 untouched", bundle, err)
	}
	req := keyAuditRows(t, stateDir, actionKeysRotate)
	if len(req) != 1 {
		t.Fatalf("keys.rotate_requested rows = %d, want 1", len(req))
	}
	if req[0].authMethod != adminaudit.AuthMethodCLI || req[0].targetRef != "keys:"+keys.PurposeToken {
		t.Errorf("rotate request row = %+v, want auth_method cli and target_ref keys:token", req[0])
	}
	if req[0].actorID == systemActorID(t, stateDir) {
		t.Errorf("the CLI rotation is attributed to the system actor %s", req[0].actorID)
	}
	for _, r := range keyAuditRows(t, stateDir, keys.ActionActivated) {
		if r.actorID != req[0].actorID {
			t.Errorf("activated row actor %s != the request's %s", r.actorID, req[0].actorID)
		}
	}
}

// TestKeysCLIRotateBundleIsStaged: the bundle purpose is never rotated through
// the CLI — the refusal names the next key to pin, and emergency does not
// bypass it.
func TestKeysCLIRotateBundleIsStaged(t *testing.T) {
	ctx := context.Background()
	o, err := OpenKeysOffline(ctx, openKeysStateDir(t), KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	before, err := o.Rows(ctx, keys.PurposeBundle)
	if err != nil {
		t.Fatal(err)
	}
	var next string
	for _, r := range before {
		if r.State == keys.StateNext {
			next = r.KID
		}
	}
	for _, emergency := range []bool{false, true} {
		_, err := o.Rotate(ctx, keys.PurposeBundle, emergency)
		var staged *StagedRotationError
		if !errors.As(err, &staged) {
			t.Fatalf("rotate bundle (emergency %t) = %v, want a staged refusal", emergency, err)
		}
		if staged.NextKID != next || !strings.Contains(err.Error(), next) {
			t.Errorf("refusal = %v, want it to pin next key %s", err, next)
		}
	}
	after, err := o.Rows(ctx, keys.PurposeBundle)
	if err != nil || len(after) != len(before) {
		t.Fatalf("a refused rotation changed the rows: %v -> %v (err %v)", before, after, err)
	}
}

// TestKeysCLIRotateAuditFailure: an audit append that fails after the rotation
// is reported, not rolled back.
func TestKeysCLIRotateAuditFailure(t *testing.T) {
	ctx := context.Background()
	o, err := OpenKeysOffline(ctx, openKeysStateDir(t), KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	o.rec = cliFailRecorder{}
	res, err := o.Rotate(ctx, keys.PurposeToken, true)
	if err == nil || !strings.Contains(err.Error(), "applied but the admin audit append failed") {
		t.Fatalf("rotate with a failing audit = %v, want the applied-but-unaudited error", err)
	}
	after, err := o.Rows(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after {
		if r.State == keys.StateActive && r.KID != res.KID {
			t.Errorf("active = %s, want the rotated-in %s", r.KID, res.KID)
		}
	}
}

// TestKeysCLIReset: reset refuses while the instance lock is held and
// otherwise replaces the purpose, appending one cli audit row.
func TestKeysCLIReset(t *testing.T) {
	ctx := context.Background()
	stateDir := openKeysStateDir(t)
	o, err := OpenKeysOffline(ctx, stateDir, KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	release, err := cpstate.AcquireDirLock(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Reset(ctx, keys.PurposeToken); err == nil || !strings.Contains(err.Error(), "control plane is running") {
		t.Fatalf("reset under the lock = %v, want the running-control-plane refusal", err)
	}
	before, err := o.Rows(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	res, err := o.Reset(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if res.Removed != len(before) || res.KID == "" {
		t.Errorf("reset result = %+v, want %d rows removed and a fresh active key", res, len(before))
	}
	after, err := o.Rows(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after {
		for _, old := range before {
			if r.KID == old.KID {
				t.Errorf("kid %s survived the reset", old.KID)
			}
		}
	}
	req := keyAuditRows(t, stateDir, actionKeysReset)
	if len(req) != 1 {
		t.Fatalf("keys.reset rows = %d, want 1", len(req))
	}
	if req[0].authMethod != adminaudit.AuthMethodCLI || req[0].targetRef != "keys:"+keys.PurposeToken {
		t.Errorf("reset request row = %+v, want auth_method cli and target_ref keys:token", req[0])
	}
	if req[0].actorID == systemActorID(t, stateDir) {
		t.Errorf("the CLI reset is attributed to the system actor %s", req[0].actorID)
	}
	// The fresh keys the reset generated are the operator's, not the system's.
	var cliGenerated int
	for _, r := range keyAuditRows(t, stateDir, keys.ActionGenerated) {
		if r.actorID == req[0].actorID {
			cliGenerated++
		}
	}
	if cliGenerated != 2 {
		t.Errorf("keys.generated rows by the operator = %d, want the fresh active and next", cliGenerated)
	}
}

// TestKeysCLIMissingAuditKeyRefuses: a state dir with an audit chain but a
// lost signing key fails at open, before anything is written.
func TestKeysCLIMissingAuditKeyRefuses(t *testing.T) {
	ctx := context.Background()
	stateDir := openKeysStateDir(t)
	if err := os.Remove(filepath.Join(stateDir, adminaudit.DefaultKeyFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKeysOffline(ctx, stateDir, KeysCLIOptions{}); err == nil || !strings.Contains(err.Error(), "admin audit") {
		t.Errorf("open without the audit key = %v, want an admin audit failure", err)
	}
}
