package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// Key rotation (W-P2-KEYS-06): with the control plane running the offline
// rotation is refused ("control plane is running", nothing written); stopped,
// it appends one audit.key_rotated handover signed by the old key, puts the
// new key at the key file and keeps the old one beside it as
// <key>.<key_id>.key.retired. The control plane then starts on the new key,
// signs the next row with it and the chain verifies end to end, while the
// retired key fails the startup check naming the key that holds the chain.
// The offline verify and the export list both keys of the history; no key
// material reaches the logs.

func adminAuditKeyRotation(t *testing.T, h *harness.H) {
	ctx := context.Background()
	dir := h.AdminAuditStateDir()
	keyFile := adminaudit.DefaultKeyPath(dir)
	h.Upstream("api.example.com")

	// The running control plane holds the state dir: refused, nothing written.
	if _, err := adminaudit.RotateKeyFile(ctx, dir, "", controlplane.StateMigrations()); !errors.Is(err, adminaudit.ErrControlPlaneRunning) ||
		!strings.Contains(err.Error(), "control plane is running") {
		t.Fatalf("rotate-key against the running control plane = %v, want 'control plane is running'", err)
	}
	rows := h.AdminAuditRows()
	if len(rows) != 1 || rows[0].Action != adminaudit.ActionGenesis {
		t.Fatalf("admin_audit after the refused rotation = %+v, want the genesis row only", rows)
	}
	oldPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	oldID := rows[0].KeyID

	h.CP().Stop()

	res, err := adminaudit.RotateKeyFile(ctx, dir, "", controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	if res.Recovered || res.Seq != 2 || res.OldKeyID != oldID || res.NewKeyID == oldID {
		t.Fatalf("RotateKeyFile = %+v, want a fresh handover at seq 2 from %s", res, oldID)
	}

	// The files: the new key at the key file, the old one retired beside it
	// (mode 0600, byte for byte), no parked rotation temp left.
	newPEM, err := os.ReadFile(keyFile)
	if err != nil || bytes.Equal(newPEM, oldPEM) {
		t.Fatalf("the key file after the rotation: %v (replaced=%v)", err, !bytes.Equal(newPEM, oldPEM))
	}
	retiredPEM, err := os.ReadFile(res.RetiredPath)
	if err != nil || !bytes.Equal(retiredPEM, oldPEM) {
		t.Fatalf("the retired key file: %v (kept=%v)", err, bytes.Equal(retiredPEM, oldPEM))
	}
	if fi, err := os.Stat(res.RetiredPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("retired key file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".rotate-") {
			t.Errorf("the rotation left %s behind", e.Name())
		}
	}

	// The handover row: system-written by the old key, carrying both key ids
	// and the new public key, no key material.
	rows = h.AdminAuditRows()
	if len(rows) != 2 || rows[1].Action != adminaudit.ActionKeyRotated || rows[1].KeyID != oldID ||
		rows[1].AuthMethod != adminaudit.AuthMethodSystem {
		t.Fatalf("admin_audit = %+v, want the key_rotated handover written by %s", rows, oldID)
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(rows[1].Details), &d); err != nil {
		t.Fatalf("key_rotated details %q: %v", rows[1].Details, err)
	}
	if d["old_key_id"] != oldID || d["new_key_id"] != res.NewKeyID || d["new_public_key"] == "" {
		t.Errorf("key_rotated details = %v, want old %s, new %s and a public key", d, oldID, res.NewKeyID)
	}

	// Offline: the rotated chain verifies and both keys are in the rotation
	// history; the export's keys record carries both and verifies with no
	// database at the pre-rotation anchor.
	st, closeFn, err := adminaudit.OpenReadOnly(ctx, dir, controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = closeFn() }()
	vr, err := st.VerifyAll(ctx, adminaudit.VerifyOptions{})
	if err != nil || !vr.OK || vr.Checked != 2 {
		t.Fatalf("offline verify of the rotated chain = %+v, %v", vr, err)
	}
	keys, err := st.PubKeys(ctx)
	if err != nil || len(keys) != 2 || keys[0].KeyID != oldID || keys[0].FirstSeq != 1 ||
		keys[1].KeyID != res.NewKeyID || keys[1].FirstSeq != 2 {
		t.Fatalf("PubKeys = %+v (%v), want %s at seq 1 then %s at seq 2", keys, err, oldID, res.NewKeyID)
	}
	if keys[1].PublicKey != d["new_public_key"] {
		t.Errorf("PubKeys lists public key %q, the handover declared %q", keys[1].PublicKey, d["new_public_key"])
	}
	out := filepath.Join(t.TempDir(), "admin-audit.jsonl")
	if er, err := st.ExportFile(ctx, out, adminaudit.ExportOptions{}); err != nil || er.Keys != 2 || er.Entries != 2 {
		t.Fatalf("ExportFile = %+v, %v", er, err)
	}
	anchor := &adminaudit.Anchor{Seq: vr.HeadSeq, Hash: vr.HeadHash}
	if ve, err := adminaudit.VerifyExport(out, adminaudit.VerifyExportOptions{Anchor: anchor}); err != nil || !ve.OK || ve.Checked != 2 {
		t.Fatalf("VerifyExport = %+v, %v", ve, err)
	}

	// The retired key fails the startup check, naming the key that holds the
	// chain now, and writes nothing.
	db, err := cpstate.Open(ctx, filepath.Join(dir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminaudit.Open(ctx, db, adminaudit.OpenOptions{KeyFile: res.RetiredPath})
	_ = db.Close()
	if !errors.Is(err, adminaudit.ErrKeyIDMismatch) || !strings.Contains(err.Error(), res.NewKeyID) {
		t.Fatalf("startup with the retired key = %v, want a key_id mismatch naming %s", err, res.NewKeyID)
	}
	if rows = h.AdminAuditRows(); len(rows) != 2 {
		t.Fatalf("the refused startup wrote rows: %+v", rows)
	}

	// The control plane starts on the new key and serves with it.
	h.CP().Start()
	var enabled map[string]any
	h.Eventually("the startup line naming the new key_id", func() bool {
		for _, line := range strings.Split(h.Logs(), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "admin audit enabled" {
				enabled = rec
			}
		}
		return enabled != nil && enabled["key_id"] == res.NewKeyID
	})
	if enabled["public_key"] == "" {
		t.Error("the startup line carries no public_key")
	}
	if status, _ := get(t, h, "https://api.example.com/v1/models", nil); status != http.StatusOK {
		t.Fatalf("allowed request after the rotation = %d, want 200", status)
	}

	// The next system write is signed with the new key: one external config
	// edit, one config.external_change row.
	_ = h.EditControlPlaneConfig(func(body string) string { return body + "\n# key rotated\n" })
	h.EventuallyWithin(15*time.Second, "the external-change row after the rotation", func() bool {
		for _, r := range h.AdminAuditRows() {
			if r.Action == externalChangeAction {
				return true
			}
		}
		return false
	})
	rows = h.AdminAuditRows()
	if last := rows[len(rows)-1]; last.Action != externalChangeAction || last.KeyID != res.NewKeyID ||
		last.AuthMethod != adminaudit.AuthMethodSystem {
		t.Errorf("post-rotation row = %+v, want %s signed by %s", last, externalChangeAction, res.NewKeyID)
	}
	if vr, err := st.VerifyAll(ctx, adminaudit.VerifyOptions{}); err != nil || !vr.OK || vr.Checked != 3 {
		t.Errorf("verify after the post-rotation write = %+v, %v, want 3 checked", vr, err)
	}

	if strings.Contains(h.Logs(), "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
}
