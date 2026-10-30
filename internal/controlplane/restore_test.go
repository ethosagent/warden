package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

// restoreSrc builds a stopped CP state dir (cp db, alert db, fleet db and
// config.yaml) and returns a backup set of all four. With audit, the CP db
// holds a signed chain whose keys sit in the state dir.
func restoreSrc(t *testing.T, audit bool) (state, set string) {
	t.Helper()
	ctx := context.Background()
	state = t.TempDir()
	db, err := cpstate.Open(ctx, filepath.Join(state, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	if audit {
		s, err := adminaudit.Open(ctx, db, adminaudit.OpenOptions{KeyFile: adminaudit.DefaultKeyPath(state)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Record(ctx, adminaudit.Input{
			ActorRole: "admin", AuthMethod: adminaudit.AuthMethodOIDC, Action: "policy.update",
			Target: "policy", Outcome: adminaudit.OutcomeOK,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	alerts, err := integration.NewStore(filepath.Join(state, "warden-alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = alerts.Close()
	fleet, err := analytics.NewFleetSQLiteStore(filepath.Join(state, "warden-fleet.db"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = fleet.Close()
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("policy:\n  allowlist: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := RunOfflineBackup(ctx, OfflineBackupParams{
		StateDir: state, Version: "v-test",
		Backup: BackupConfig{Dir: filepath.Join(t.TempDir(), "b"), Include: []string{BackupCP, BackupAlerts, BackupConfigKey, BackupFleet}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return state, res.Path
}

func restoreManifestEdit(t *testing.T, set string, rehash bool, edit func(*BackupManifest)) {
	t.Helper()
	path := filepath.Join(set, BackupManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(&m)
	if rehash {
		for i, f := range m.Files {
			b, err := os.ReadFile(filepath.Join(set, f.Name))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			m.Files[i].SHA256, m.Files[i].Size = hex.EncodeToString(sum[:]), int64(len(b))
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyRestoreSet(t *testing.T, set string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "set")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(set)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(set, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestRunRestoreAllFiles(t *testing.T) {
	state, set := restoreSrc(t, true)
	dst := filepath.Join(t.TempDir(), "new-state") // does not exist yet
	other := t.TempDir()                           // --analytics-db and --alerts-db elsewhere
	for _, k := range []string{adminaudit.DefaultKeyPath(state), adminaudit.DefaultHMACKeyPath(adminaudit.DefaultKeyPath(state))} {
		b, err := os.ReadFile(k)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, filepath.Base(k)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := RunRestore(context.Background(), RestoreParams{
		From: set, StateDir: dst,
		AnalyticsDB: filepath.Join(other, "fleet.db"), AlertsDB: filepath.Join(other, "alerts.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyChecked || !res.Audited || res.WardenVersion != "v-test" || res.PreRestoreDir != "" || len(res.Files) != 4 {
		t.Errorf("result = %+v", res)
	}
	for _, p := range []string{
		filepath.Join(dst, "warden-cp.db"), filepath.Join(dst, "config.yaml"),
		filepath.Join(other, "fleet.db"), filepath.Join(other, "alerts.db"),
	} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v, want a 0600 file", p, fi, err)
		}
	}
	for _, d := range []string{dst, other} {
		if left, _ := filepath.Glob(filepath.Join(d, ".restore-*")); len(left) != 0 {
			t.Errorf("staging left in %s: %v", d, left)
		}
	}
}

// A set from a state dir that never had admin audit restores with no audit row.
func TestRunRestoreWithoutAuditChain(t *testing.T) {
	_, set := restoreSrc(t, false)
	dst := t.TempDir()
	res, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res.Audited {
		t.Error("Audited = true with no chain")
	}
}

// With a chain and no key at the target, the files are in place and the
// failure is reported as unaudited.
func TestRunRestoreUnaudited(t *testing.T) {
	_, set := restoreSrc(t, true)
	dst := t.TempDir()
	res, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: dst})
	if !errors.Is(err, ErrRestoreUnaudited) {
		t.Fatalf("err = %v, want ErrRestoreUnaudited", err)
	}
	if len(res.Files) == 0 {
		t.Error("the applied files are not reported")
	}
	if _, err := os.Stat(filepath.Join(dst, "warden-cp.db")); err != nil {
		t.Errorf("files are not in place: %v", err)
	}
}

func TestRunRestoreRefusals(t *testing.T) {
	_, set := restoreSrc(t, true)
	cases := []struct {
		name string
		edit func(t *testing.T, set string)
		want string
	}{
		{"no files", func(t *testing.T, s string) {
			restoreManifestEdit(t, s, false, func(m *BackupManifest) { m.Files = nil })
		}, "lists no files"},
		{"duplicate name", func(t *testing.T, s string) {
			restoreManifestEdit(t, s, false, func(m *BackupManifest) { m.Files = append(m.Files, m.Files[0]) })
		}, "twice"},
		{"negative size", func(t *testing.T, s string) {
			restoreManifestEdit(t, s, false, func(m *BackupManifest) { m.Files[0].Size = -1 })
		}, "negative size"},
		{"missing file", func(t *testing.T, s string) {
			if err := os.Remove(filepath.Join(s, "config.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "manifest mismatch: config.yaml"},
		{"symlinked file", func(t *testing.T, s string) {
			p := filepath.Join(s, "config.yaml")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/hostname", p); err != nil {
				t.Fatal(err)
			}
		}, "manifest mismatch: config.yaml"},
		{"size differs", func(t *testing.T, s string) {
			restoreManifestEdit(t, s, false, func(m *BackupManifest) {
				for i := range m.Files {
					if m.Files[i].Name == "config.yaml" {
						m.Files[i].Size++
					}
				}
			})
		}, "manifest mismatch: config.yaml"},
		{"corrupt database", func(t *testing.T, s string) {
			if err := os.WriteFile(filepath.Join(s, "warden-alerts.db"), []byte("not a database at all, only text"), 0o600); err != nil {
				t.Fatal(err)
			}
			restoreManifestEdit(t, s, true, func(*BackupManifest) {})
		}, "integrity_check failed for warden-alerts.db"},
		{"manifest schema newer", func(t *testing.T, s string) {
			restoreManifestEdit(t, s, false, func(m *BackupManifest) { m.SchemaVersion = len(StateMigrations()) + 3 })
		}, "is newer than this binary supports"},
		{"broken audit chain", func(t *testing.T, s string) {
			db, err := cpstate.Open(context.Background(), filepath.Join(s, "warden-cp.db"), StateMigrations())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.SQL().Exec("UPDATE admin_audit SET target_ref = 'forged' WHERE seq = 2"); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			restoreManifestEdit(t, s, true, func(*BackupManifest) {})
		}, "admin audit chain does not verify at seq 2"},
		{"unknown migration", func(t *testing.T, s string) {
			db, err := cpstate.Open(context.Background(), filepath.Join(s, "warden-cp.db"), StateMigrations())
			if err != nil {
				t.Fatal(err)
			}
			// The same count as this binary, but an ID it does not register.
			if _, err := db.SQL().Exec("UPDATE schema_migrations SET id = 'other/0001' WHERE id = (SELECT id FROM schema_migrations LIMIT 1)"); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			restoreManifestEdit(t, s, true, func(*BackupManifest) {})
		}, "backup warden-cp.db"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := copyRestoreSet(t, set)
			c.edit(t, s)
			dst := t.TempDir()
			_, err := RunRestore(context.Background(), RestoreParams{From: s, StateDir: dst, Force: true})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
			ents, _ := os.ReadDir(dst)
			for _, e := range ents {
				if e.Name() != cpstate.LockFileName {
					t.Errorf("refused restore left %s in the target", e.Name())
				}
			}
		})
	}

	t.Run("targets collide", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "same.db")
		_, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: t.TempDir(), AnalyticsDB: p, AlertsDB: p})
		if err == nil || !strings.Contains(err.Error(), "would both restore to") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing arguments", func(t *testing.T) {
		if _, err := RunRestore(context.Background(), RestoreParams{}); err == nil {
			t.Fatal("RunRestore with no arguments succeeded")
		}
	})
	t.Run("state dir is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: f}); err == nil {
			t.Fatal("restore into a file succeeded")
		}
	})
	t.Run("no manifest and a manifest that is not JSON", func(t *testing.T) {
		if _, err := RunRestore(context.Background(), RestoreParams{From: t.TempDir(), StateDir: t.TempDir()}); err == nil {
			t.Fatal("restore of an empty directory succeeded")
		}
		s := copyRestoreSet(t, set)
		if err := os.WriteFile(filepath.Join(s, BackupManifestName), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := RunRestore(context.Background(), RestoreParams{From: s, StateDir: t.TempDir()}); err == nil {
			t.Fatal("restore with a broken manifest succeeded")
		}
	})
	t.Run("running control plane", func(t *testing.T) {
		dst := t.TempDir()
		release, err := cpstate.AcquireDirLock(dst)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = release() }()
		if _, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: dst}); !errors.Is(err, ErrRestoreRunning) {
			t.Fatalf("err = %v, want ErrRestoreRunning", err)
		}
	})
}

// Staging and pre-restore names are never reused: a leftover from an earlier
// run in the same second moves the stamp on.
func TestRestoreStampSkipsTaken(t *testing.T) {
	state := t.TempDir()
	now := mustTime(t, "2026-01-02T03:04:05Z")
	tg := []*restoreTarget{{path: filepath.Join(state, "warden-cp.db")}}
	if err := os.Mkdir(filepath.Join(state, restoreStagePrefix+now.Format(BackupSetLayout)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, restorePrePrefix+now.Add(time.Second).Format(BackupSetLayout)), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := restoreStamp(now, state, tg); !got.Equal(now.Add(2 * time.Second)) {
		t.Errorf("stamp = %v, want two seconds on", got)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRunRestoreAuditKeyFingerprint(t *testing.T) {
	state, set := restoreSrc(t, true)
	keyFile := adminaudit.DefaultKeyPath(state)
	signer, err := audit.LoadOrCreateSigner(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	withFP := func(fp string) string {
		s := copyRestoreSet(t, set)
		restoreManifestEdit(t, s, false, func(m *BackupManifest) { m.AuditKeyFingerprint = fp })
		return s
	}
	fresh := func() string { return t.TempDir() }

	// Another key at the target.
	other := filepath.Join(t.TempDir(), "other.key")
	if _, err := audit.LoadOrCreateSigner(other); err != nil {
		t.Fatal(err)
	}
	if _, err := RunRestore(context.Background(), RestoreParams{From: withFP(audit.KeyID(signer.PubKey())), StateDir: fresh(), AuditKeyFile: other}); !errors.Is(err, ErrRestoreKey) {
		t.Fatalf("mismatching key: err = %v, want ErrRestoreKey", err)
	}
	// An unparsable key file.
	junk := filepath.Join(t.TempDir(), "junk.key")
	if err := os.WriteFile(junk, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunRestore(context.Background(), RestoreParams{From: withFP("00"), StateDir: fresh(), AuditKeyFile: junk}); !errors.Is(err, ErrRestoreKey) {
		t.Fatalf("junk key: err = %v, want ErrRestoreKey", err)
	}
	// No key file, with and without the override.
	missing := filepath.Join(t.TempDir(), "absent.key")
	if _, err := RunRestore(context.Background(), RestoreParams{From: withFP("00"), StateDir: fresh(), AuditKeyFile: missing}); !errors.Is(err, ErrRestoreKey) {
		t.Fatalf("missing key: err = %v, want ErrRestoreKey", err)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("the check created the key file")
	}
	// The matching key restores and appends.
	dst := fresh()
	res, err := RunRestore(context.Background(), RestoreParams{From: withFP(audit.KeyID(signer.PubKey())), StateDir: dst, AuditKeyFile: keyFile})
	if err != nil || !res.Audited || !res.KeyChecked {
		t.Fatalf("matching key: %+v, %v", res, err)
	}
	// With --new-audit-key a key that does not own the chain restores but
	// cannot append: applied, unaudited.
	dst2 := fresh()
	res, err = RunRestore(context.Background(), RestoreParams{From: withFP("00"), StateDir: dst2, AuditKeyFile: other, NewAuditKey: true})
	if !errors.Is(err, ErrRestoreUnaudited) || !res.NewAuditKey {
		t.Fatalf("new key that does not own the chain: %+v, %v", res, err)
	}
}

// existingTarget returns a state dir that already holds old files.
func existingTarget(t *testing.T, state string) string {
	t.Helper()
	dst := t.TempDir()
	for _, k := range []string{adminaudit.DefaultKeyPath(state), adminaudit.DefaultHMACKeyPath(adminaudit.DefaultKeyPath(state))} {
		b, err := os.ReadFile(k)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, filepath.Base(k)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for n, c := range map[string]string{"warden-cp.db": "OLD", "warden-cp.db-wal": "OLD-WAL", "warden-cp.db-shm": "OLD-SHM", "config.yaml": "old: 1\n"} {
		if err := os.WriteFile(filepath.Join(dst, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestRunRestoreForceKeepsOldFiles(t *testing.T) {
	state, set := restoreSrc(t, true)
	dst := existingTarget(t, state)
	if _, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: dst}); !errors.Is(err, ErrRestoreNotEmpty) {
		t.Fatalf("err = %v, want ErrRestoreNotEmpty", err)
	}
	res, err := RunRestore(context.Background(), RestoreParams{From: set, StateDir: dst, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{"warden-cp.db": "OLD", "warden-cp.db-wal": "OLD-WAL", "warden-cp.db-shm": "OLD-SHM", "config.yaml": "old: 1\n"} {
		if got, err := os.ReadFile(filepath.Join(res.PreRestoreDir, n)); err != nil || string(got) != want {
			t.Errorf("pre-restore %s = %q, %v", n, got, err)
		}
	}
}

func TestRunRestoreRollsBack(t *testing.T) {
	state, set := restoreSrc(t, true)
	errBoom := errors.New("boom")
	snapshot := func(dir string) map[string]string {
		out := map[string]string{}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.Name() == cpstate.LockFileName {
				continue
			}
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			out[e.Name()] = string(b)
		}
		return out
	}
	for name, fail := range map[string]func(oldpath, newpath string) bool{
		"moving the second file aside": func(o, _ string) bool { return strings.HasSuffix(o, "warden-cp.db-wal") },
		"placing the first file": func(o, _ string) bool {
			return strings.HasSuffix(o, "warden-cp.db") && strings.Contains(o, ".restore-")
		},
		"placing the last file": func(o, _ string) bool { return strings.HasSuffix(o, "config.yaml") && strings.Contains(o, ".restore-") },
	} {
		t.Run(name, func(t *testing.T) {
			dst := existingTarget(t, state)
			before := snapshot(dst)
			_, err := RunRestore(context.Background(), RestoreParams{
				From: set, StateDir: dst, Force: true,
				Ops: RestoreOps{Rename: func(o, n string) error {
					if fail(o, n) {
						return errBoom
					}
					return os.Rename(o, n)
				}},
			})
			if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("err = %v", err)
			}
			after := snapshot(dst)
			if len(after) != len(before) {
				t.Errorf("files after = %v, before = %v", after, before)
			}
			for k, v := range before {
				if after[k] != v {
					t.Errorf("%s = %q, want %q", k, after[k], v)
				}
			}
		})
	}
}

// A set written by an older binary (fewer migrations) restores and is brought
// up to this binary's schema.
func TestRunRestoreOlderSet(t *testing.T) {
	ctx := context.Background()
	state := t.TempDir()
	// Feature-gated (Optional) migrations are not applied by a plain Open, so
	// the version a restore reaches is the count of the always-on ones.
	var all []cpstate.Migration
	for _, m := range StateMigrations() {
		if !m.Optional {
			all = append(all, m)
		}
	}
	old, err := cpstate.Open(ctx, filepath.Join(state, "warden-cp.db"), all[:len(all)-1])
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := old.SchemaVersion(ctx); v != len(all)-1 {
		t.Fatalf("old schema version = %d", v)
	}
	_ = old.Close()
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("policy:\n  allowlist: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := RunOfflineBackup(ctx, OfflineBackupParams{
		StateDir: state, Backup: BackupConfig{Dir: filepath.Join(t.TempDir(), "b"), Include: []string{BackupCP, BackupConfigKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if _, err := RunRestore(ctx, RestoreParams{From: res.Path, StateDir: dst}); err != nil {
		t.Fatal(err)
	}
	db, err := cpstate.OpenReadOnly(ctx, filepath.Join(dst, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if v, _ := db.SchemaVersion(ctx); v != len(all) {
		t.Errorf("restored schema version = %d, want %d", v, len(all))
	}
}
