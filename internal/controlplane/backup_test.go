package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

var testBackupT0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// fileSource is a backupSource that writes fixed bytes (or fails).
type fileSource struct {
	data  string
	err   error
	calls atomic.Int32
	hook  func()
}

func (f *fileSource) BackupTo(_ context.Context, dst string) error {
	f.calls.Add(1)
	if f.hook != nil {
		f.hook()
	}
	if f.err != nil {
		return f.err
	}
	return os.WriteFile(dst, []byte(f.data), 0o600)
}

type recReporter struct {
	mu      sync.Mutex
	failed  []string
	errs    []error
	success []string
}

func (r *recReporter) BackupFailed(db string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed, r.errs = append(r.failed, db), append(r.errs, err)
}

func (r *recReporter) BackupSucceeded(set string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.success = append(r.success, set)
}

func plentyFree(string) (uint64, error) { return 1 << 40, nil }

func testBackupConfig(t *testing.T) BackupConfig {
	t.Helper()
	return BackupConfig{Dir: filepath.Join(t.TempDir(), "backups"), Interval: 24 * time.Hour, Keep: 7, Include: []string{"cp", "alerts", "config", "fleet"}}
}

func testServedConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("policy:\n  allowlist: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeDeps(t *testing.T, clk *clocktest.Fake) BackupDeps {
	t.Helper()
	return BackupDeps{
		CP:         BackupStore{Source: &fileSource{data: "cp"}},
		Alerts:     BackupStore{Source: &fileSource{data: "alerts"}},
		Fleet:      BackupStore{Source: &fileSource{data: "fleet"}},
		ConfigPath: testServedConfig(t),
		Version:    "v-test", Clock: clk, FreeBytes: plentyFree,
		SchemaVersion: func(context.Context) (int, error) { return 7, nil },
		Logger:        slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
}

func readManifest(t *testing.T, dir, set string) BackupManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, set, BackupManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m BackupManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sha(t *testing.T, path string) (string, int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), int64(len(b))
}

func integrityOK(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var res string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil || res != "ok" {
		t.Fatalf("integrity_check %s = %q, %v", filepath.Base(path), res, err)
	}
}

func TestBackup_ConsistentUnderWrites(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cpDB, err := cpstate.Open(ctx, filepath.Join(root, "warden-cp.db"), []cpstate.Migration{{ID: "t/0001", SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY, v TEXT)"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cpDB.Close() }()
	alerts, err := integration.NewStore(filepath.Join(root, "warden-alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = alerts.Close() }()
	fleet, err := analytics.NewFleetSQLiteStore(filepath.Join(root, "warden-fleet.db"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fleet.Close() }()

	var next atomic.Int64
	var committed atomic.Int64
	stop := make(chan struct{})
	errc := make(chan error, 8)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				n := next.Add(1)
				var err error
				switch w % 3 {
				case 0:
					_, err = cpDB.SQL().ExecContext(ctx, "INSERT INTO t1 (id, v) VALUES (?, 'w')", n)
				case 1:
					_, err = alerts.UpsertAlert(integration.Alert{
						ID: fmt.Sprintf("a%d", n), DedupKey: fmt.Sprintf("dk%d", n), Category: "reliability",
						Severity: integration.SevCritical, Summary: "s", Status: integration.StatusFiring, Count: 1,
						FirstSeen: time.Unix(1700000000, 0), LastSeen: time.Unix(1700000000, 0),
					})
				default:
					err = fleet.StoreAggregatedEvent(analytics.AggregatedEvent{
						Event:   analytics.Event{Timestamp: time.Unix(1700000000+n, 0), Domain: fmt.Sprintf("d%d.example.com", n), Port: 443, Protocol: "https", Decision: "allow"},
						ProxyID: "p1", AgentID: "a1",
					})
				}
				if err != nil {
					errc <- err
					return
				}
				committed.Add(1)
			}
		}()
	}
	for deadline := time.Now().Add(30 * time.Second); committed.Load() < 50; time.Sleep(time.Millisecond) {
		select {
		case err := <-errc:
			t.Fatalf("writer failed before the backup: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("writers did not commit 50 rows in 30s")
		}
	}

	cfg := testBackupConfig(t)
	deps := fakeDeps(t, clocktest.NewFake(testBackupT0))
	deps.CP, deps.Alerts, deps.Fleet = BackupStore{Source: cpDB, Path: cpDB.Path()}, BackupStore{Source: alerts}, BackupStore{Source: fleet}
	deps.SchemaVersion = cpDB.SchemaVersion
	res, err := NewBackupRunner(cfg, deps).RunOnce(ctx)
	close(stop)
	wg.Wait()
	close(errc)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	for e := range errc {
		t.Errorf("writer failed during the backup: %v", e)
	}

	m := readManifest(t, cfg.Dir, res.Set)
	if len(m.Files) != 4 || m.SchemaVersion != 1 {
		t.Fatalf("manifest = %+v, want 4 files and schema_version 1", m)
	}
	for _, f := range m.Files {
		p := filepath.Join(res.Path, f.Name)
		if sum, size := sha(t, p); sum != f.SHA256 || size != f.Size {
			t.Errorf("%s: manifest sha/size %s/%d, file %s/%d", f.Name, f.SHA256, f.Size, sum, size)
		}
		if strings.HasSuffix(f.Name, ".db") {
			integrityOK(t, p)
		}
	}
}

func TestBackup_Prune(t *testing.T) {
	clk := clocktest.NewFake(testBackupT0)
	cfg := testBackupConfig(t)
	cfg.Keep = 3
	deps := fakeDeps(t, clk)
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mkSet := func(at time.Time) string {
		n := at.Format(BackupSetLayout)
		if err := os.MkdirAll(filepath.Join(cfg.Dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.Dir, n, BackupManifestName), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i := 1; i <= 5; i++ {
		mkSet(testBackupT0.Add(-time.Duration(i) * 24 * time.Hour))
	}
	oldTmp := filepath.Join(cfg.Dir, backupTmpPrefix+testBackupT0.Add(-30*time.Hour).Format(BackupSetLayout))
	freshTmp := filepath.Join(cfg.Dir, backupTmpPrefix+testBackupT0.Add(-time.Hour).Format(BackupSetLayout))
	mtimeTmp := filepath.Join(cfg.Dir, backupTmpPrefix+"legacy")
	for _, d := range []string{oldTmp, freshTmp, mtimeTmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(mtimeTmp, testBackupT0.Add(-48*time.Hour), testBackupT0.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(cfg.Dir, "notes.txt")
	unrelatedDir := filepath.Join(cfg.Dir, "20260101T000000Z.old")
	incomplete := filepath.Join(cfg.Dir, "20200101T000000Z") // set-named, no manifest
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{unrelatedDir, incomplete} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	res, err := NewBackupRunner(cfg, deps).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sets, _ := listBackupSets(cfg.Dir)
	if len(sets) != 3 || sets[0].name != res.Set {
		t.Fatalf("sets after prune = %v, want the new set and the 2 newest older ones", sets)
	}
	for _, gone := range []string{oldTmp, mtimeTmp} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived pruning", filepath.Base(gone))
		}
	}
	for _, kept := range []string{freshTmp, unrelated, unrelatedDir, incomplete} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was touched: %v", filepath.Base(kept), err)
		}
	}
}

func TestBackup_PruneNeverDeletesNewest(t *testing.T) {
	cfg := testBackupConfig(t)
	cfg.Keep = 1
	r := NewBackupRunner(cfg, fakeDeps(t, clocktest.NewFake(testBackupT0)))
	r.cfg.Keep = 0 // a bad value must not delete everything
	res, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sets, _ := listBackupSets(cfg.Dir); len(sets) != 1 || sets[0].name != res.Set {
		t.Fatalf("sets = %v", sets)
	}
}

func TestBackup_Schedule(t *testing.T) {
	setup := func(t *testing.T, age time.Duration) (*BackupRunner, *fileSource, *clocktest.Fake, BackupConfig) {
		t.Helper()
		clk := clocktest.NewFake(testBackupT0)
		cfg := testBackupConfig(t)
		deps := fakeDeps(t, clk)
		cp := deps.CP.Source.(*fileSource)
		if age > 0 {
			n := testBackupT0.Add(-age).Format(BackupSetLayout)
			if err := os.MkdirAll(filepath.Join(cfg.Dir, n), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cfg.Dir, n, BackupManifestName), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return NewBackupRunner(cfg, deps), cp, clk, cfg
	}
	eventually := func(t *testing.T, what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out: %s", what)
			}
			time.Sleep(time.Millisecond)
		}
	}

	t.Run("overdue runs at startup", func(t *testing.T) {
		r, cp, _, _ := setup(t, 25*time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		r.Start(ctx)
		defer func() { cancel(); r.Wait() }()
		eventually(t, "startup backup", func() bool { return cp.calls.Load() == 1 })
	})
	t.Run("no set runs at startup", func(t *testing.T) {
		r, cp, _, _ := setup(t, 0)
		ctx, cancel := context.WithCancel(context.Background())
		r.Start(ctx)
		defer func() { cancel(); r.Wait() }()
		eventually(t, "startup backup", func() bool { return cp.calls.Load() == 1 })
	})
	t.Run("fresh set waits for set time plus interval", func(t *testing.T) {
		r, cp, clk, _ := setup(t, 2*time.Hour)
		if got, want := r.untilNext(), 22*time.Hour; got != want {
			t.Fatalf("untilNext = %s, want %s", got, want)
		}
		ctx, cancel := context.WithCancel(context.Background())
		r.Start(ctx)
		defer func() { cancel(); r.Wait() }()
		eventually(t, "timer armed", func() bool { return clk.PendingTimers() == 1 })
		clk.Advance(21 * time.Hour)
		if cp.calls.Load() != 0 {
			t.Fatal("ran before set time + interval")
		}
		clk.Advance(time.Hour)
		eventually(t, "scheduled backup", func() bool { return cp.calls.Load() == 1 })
		// The next one is a full interval after the set just written.
		eventually(t, "re-armed", func() bool { return clk.PendingTimers() == 1 && r.Status().LastSet != "" })
		clk.Advance(24 * time.Hour)
		eventually(t, "second scheduled backup", func() bool { return cp.calls.Load() == 2 })
	})
	t.Run("status reflects the newest set after a restart", func(t *testing.T) {
		r, _, _, _ := setup(t, 2*time.Hour)
		r.loadStatus()
		if st := r.Status(); st.LastSet == "" || !st.LastSuccessAt.Equal(testBackupT0.Add(-2*time.Hour)) {
			t.Fatalf("status = %+v", st)
		}
	})
	t.Run("a failed run retries sooner than the interval", func(t *testing.T) {
		r, cp, clk, _ := setup(t, 0)
		cp.err = errors.New("disk on fire")
		ctx, cancel := context.WithCancel(context.Background())
		r.Start(ctx)
		defer func() { cancel(); r.Wait() }()
		eventually(t, "first attempt", func() bool { return cp.calls.Load() == 1 })
		eventually(t, "retry timer", func() bool { return clk.PendingTimers() == 1 })
		clk.Advance(time.Hour)
		eventually(t, "retry", func() bool { return cp.calls.Load() == 2 })
	})
}

func TestBackup_MemoryProviderSkipsFleet(t *testing.T) {
	cfg := testBackupConfig(t)
	deps := fakeDeps(t, clocktest.NewFake(testBackupT0))
	deps.Fleet = BackupStore{Reason: "analytics provider is memory"}
	res, err := NewBackupRunner(cfg, deps).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, cfg.Dir, res.Set)
	if len(m.Skipped) != 1 || m.Skipped[0].Name != "warden-fleet.db" || m.Skipped[0].Reason == "" {
		t.Fatalf("skipped = %+v", m.Skipped)
	}
	if _, err := os.Stat(filepath.Join(res.Path, "warden-fleet.db")); err == nil {
		t.Fatal("fleet DB copied although absent")
	}
}

func TestBackup_NotIncludedSourcesAreNotListed(t *testing.T) {
	cfg := testBackupConfig(t)
	cfg.Include = []string{"cp"}
	res, err := NewBackupRunner(cfg, fakeDeps(t, clocktest.NewFake(testBackupT0))).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, cfg.Dir, res.Set)
	if len(m.Files) != 1 || m.Files[0].Name != "warden-cp.db" || len(m.Skipped) != 0 {
		t.Fatalf("manifest = %+v", m)
	}
}

func TestBackup_NoOverlap(t *testing.T) {
	cfg := testBackupConfig(t)
	deps := fakeDeps(t, clocktest.NewFake(testBackupT0))
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	deps.CP.Source.(*fileSource).hook = func() { once.Do(func() { close(entered); <-release }) }
	r := NewBackupRunner(cfg, deps)
	done := make(chan error, 1)
	go func() { _, err := r.RunOnce(context.Background()); done <- err }()
	<-entered
	if _, err := r.RunOnce(context.Background()); !errors.Is(err, ErrBackupInProgress) {
		t.Fatalf("second RunOnce = %v, want ErrBackupInProgress", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	// Released; a run in the same second takes the next set name.
	second, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce after release: %v", err)
	}
	if sets, _ := listBackupSets(cfg.Dir); len(sets) != 2 || sets[0].name != second.Set {
		t.Fatalf("sets = %v, want two distinct sets", sets)
	}
}

func TestBackup_FreeSpaceRefused(t *testing.T) {
	cfg := testBackupConfig(t)
	deps := fakeDeps(t, clocktest.NewFake(testBackupT0))
	rep := &recReporter{}
	deps.Reporter = rep
	deps.CP = BackupStore{Source: deps.CP.Source, Path: writeTemp(t, 1000)}
	deps.FreeBytes = func(string) (uint64, error) { return 1100, nil } // 1.1x < 1.2x
	_, err := NewBackupRunner(cfg, deps).RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "insufficient free space") {
		t.Fatalf("RunOnce = %v, want insufficient free space", err)
	}
	ents, _ := os.ReadDir(cfg.Dir)
	if len(ents) != 0 {
		t.Fatalf("backup dir holds %d entries after a refused run, want none", len(ents))
	}
	if deps.CP.Source.(*fileSource).calls.Load() != 0 {
		t.Fatal("a store was copied despite the refusal")
	}
	if len(rep.failed) != 1 {
		t.Fatalf("reporter failures = %v", rep.failed)
	}

	deps.FreeBytes = func(string) (uint64, error) { return 1300, nil } // enough
	if _, err := NewBackupRunner(cfg, deps).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce with enough space: %v", err)
	}
}

func writeTemp(t *testing.T, n int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.db")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBackup_DiskFree(t *testing.T) {
	if free, err := diskFree(t.TempDir()); err != nil || free == 0 {
		t.Fatalf("diskFree = %d, %v", free, err)
	}
}

func TestBackup_Modes(t *testing.T) {
	cfg := testBackupConfig(t)
	res, err := NewBackupRunner(cfg, fakeDeps(t, clocktest.NewFake(testBackupT0))).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(res.Path)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("set dir mode = %v, %v; want 0700", fi.Mode().Perm(), err)
	}
	ents, _ := os.ReadDir(res.Path)
	if len(ents) != 5 { // 3 dbs, config, manifest
		t.Fatalf("set holds %d files, want 5", len(ents))
	}
	for _, e := range ents {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", e.Name(), info.Mode().Perm())
		}
	}
}

func TestBackup_Manifest(t *testing.T) {
	clk := clocktest.NewFake(testBackupT0)
	cfg := testBackupConfig(t)
	deps := fakeDeps(t, clk)
	deps.AuditKeyID = "key-abc"
	deps.Fleet = BackupStore{Reason: "analytics provider is memory"}
	var res BackupResult
	deps.CP.Source.(*fileSource).hook = func() { clk.Advance(3 * time.Second) }
	res, err := NewBackupRunner(cfg, deps).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := testBackupT0.Format(BackupSetLayout); res.Set != want {
		t.Errorf("set = %s, want %s", res.Set, want)
	}
	raw, _ := os.ReadFile(filepath.Join(res.Path, BackupManifestName))
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"format", "warden_version", "schema_version", "audit_key_fingerprint", "created_at", "finished_at", "files", "skipped", "not_included"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("manifest has no %q", k)
		}
	}
	m := readManifest(t, cfg.Dir, res.Set)
	if m.Format != "warden.cp.backup.v1" || m.WardenVersion != "v-test" || m.SchemaVersion != 7 || m.AuditKeyFingerprint != "key-abc" {
		t.Errorf("manifest = %+v", m)
	}
	if !m.CreatedAt.Equal(testBackupT0) || !m.FinishedAt.Equal(testBackupT0.Add(3*time.Second)) || m.CreatedAt.Location() != time.UTC {
		t.Errorf("created %v finished %v", m.CreatedAt, m.FinishedAt)
	}
	if got := fmt.Sprint(m.NotIncluded); got != "[cp-audit.key IdP storage secret backend]" {
		t.Errorf("not_included = %s", got)
	}
	names := []string{}
	for _, f := range m.Files {
		names = append(names, f.Name)
		if sum, size := sha(t, filepath.Join(res.Path, f.Name)); sum != f.SHA256 || size != f.Size {
			t.Errorf("%s: sha/size mismatch", f.Name)
		}
	}
	if fmt.Sprint(names) != "[warden-cp.db warden-alerts.db config.yaml]" {
		t.Errorf("files = %v", names)
	}
	if cfgSum, _ := sha(t, deps.ConfigPath); m.Files[2].SHA256 != cfgSum {
		t.Error("config.yaml in the set differs from the served config")
	}

	// Audit disabled: the fingerprint is omitted.
	deps.AuditKeyID = ""
	clk.Advance(time.Hour)
	res, err = NewBackupRunner(cfg, deps).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(res.Path, BackupManifestName))
	if strings.Contains(string(raw), "audit_key_fingerprint") {
		t.Error("audit_key_fingerprint present with admin audit off")
	}
}

func TestBackup_Atomic(t *testing.T) {
	clk := clocktest.NewFake(testBackupT0)
	cfg := testBackupConfig(t)
	r := NewBackupRunner(cfg, fakeDeps(t, clk))
	r.beforeRename = func() error {
		// The manifest exists in the tmp dir, yet no set is visible.
		if sets, _ := listBackupSets(cfg.Dir); len(sets) != 0 {
			t.Errorf("a set is visible before the rename: %v", sets)
		}
		ents, _ := os.ReadDir(cfg.Dir)
		if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), backupTmpPrefix) {
			t.Errorf("backup dir = %v, want only the .tmp- dir", ents)
		}
		return errors.New("injected failure")
	}
	if _, err := r.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("RunOnce = %v", err)
	}
	if sets, _ := listBackupSets(cfg.Dir); len(sets) != 0 {
		t.Fatalf("a set exists after the failure: %v", sets)
	}
	ents, _ := os.ReadDir(cfg.Dir)
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), backupTmpPrefix) {
			t.Errorf("unexpected entry %s", e.Name())
		}
	}
	// A failure inside a copy never publishes either.
	r2 := NewBackupRunner(cfg, fakeDeps(t, clk))
	r2.deps.Alerts = BackupStore{Source: &fileSource{err: errors.New("boom")}}
	if _, err := r2.RunOnce(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	if sets, _ := listBackupSets(cfg.Dir); len(sets) != 0 {
		t.Fatalf("set after copy failure: %v", sets)
	}
}

func TestBackup_ReporterCalledOnFailure(t *testing.T) {
	var logs bytes.Buffer
	cfg := testBackupConfig(t)
	deps := fakeDeps(t, clocktest.NewFake(testBackupT0))
	deps.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	rep := &recReporter{}
	deps.Reporter = rep
	deps.Alerts = BackupStore{Source: &fileSource{err: errors.New(strings.Repeat("e", 500))}}
	r := NewBackupRunner(cfg, deps)
	if _, err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	if len(rep.failed) != 1 || rep.failed[0] != "alerts" || len(rep.success) != 0 {
		t.Fatalf("reporter failed=%v success=%v", rep.failed, rep.success)
	}
	st := r.Status()
	if st.LastError == "" || len(st.LastError) > 200 || !st.LastSuccessAt.IsZero() {
		t.Fatalf("status = %+v", st)
	}
	if !strings.Contains(logs.String(), `"msg":"cp_backup"`) || !strings.Contains(logs.String(), `"level":"ERROR"`) || !strings.Contains(logs.String(), `"db":"alerts"`) {
		t.Errorf("failure not logged: %s", logs.String())
	}

	// A good run clears LastError and reports success; a nil reporter is fine.
	deps.Alerts = BackupStore{Source: &fileSource{data: "a"}}
	r2 := NewBackupRunner(cfg, deps)
	r2.stat.LastError = "old"
	res, err := r2.RunOnce(context.Background())
	if err != nil || r2.Status().LastError != "" || r2.Status().LastSet != res.Set || len(rep.success) != 1 {
		t.Fatalf("after success: %v %+v %v", err, r2.Status(), rep.success)
	}
	deps.Reporter = nil
	deps.Alerts = BackupStore{Source: &fileSource{err: errors.New("x")}}
	if _, err := NewBackupRunner(cfg, deps).RunOnce(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
}

// A failing backup never stops the control plane serving /policy.
func TestBackup_ReporterCalledOnFailure_CPKeepsServing(t *testing.T) {
	// The backup dir sits under a regular file, so every run fails (as root too).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocker, "backups")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rep := &recReporter{}
	failed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, &bytes.Buffer{}, Params{
			ConfigPath: writePolicyFile(t, "api.openai.com"), StateDir: filepath.Join(t.TempDir(), "state"),
			AnalyticsProvider: "memory", Listener: ln, OnReady: func(a string) { ready <- a },
			Backup:         BackupConfig{Dir: dir, Interval: 24 * time.Hour, Keep: 3, Include: DefaultBackupInclude},
			BackupReporter: &notifyReporter{recReporter: rep, failed: failed},
		})
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("not ready")
	}
	select {
	case <-failed:
	case <-time.After(10 * time.Second):
		t.Fatal("backup failure not reported")
	}
	resp, err := http.Get("http://" + addr + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /policy = %d", resp.StatusCode)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

type notifyReporter struct {
	*recReporter
	failed chan struct{}
}

func (n *notifyReporter) BackupFailed(db string, err error) {
	n.recReporter.BackupFailed(db, err)
	select {
	case n.failed <- struct{}{}:
	default:
	}
}

func TestBackup_RunBacksUpAndStops(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backups")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, &bytes.Buffer{}, Params{
			ConfigPath: writePolicyFile(t, "api.openai.com"), StateDir: filepath.Join(t.TempDir(), "state"),
			AnalyticsProvider: "memory", Listener: ln, OnReady: func(a string) { ready <- a },
			Version: "v-run",
			Backup:  BackupConfig{Dir: dir, Interval: 24 * time.Hour, Keep: 3, Include: DefaultBackupInclude},
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("not ready")
	}
	var sets []backupSet
	for deadline := time.Now().Add(10 * time.Second); len(sets) == 0 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		sets, _ = listBackupSets(dir)
	}
	if len(sets) != 1 {
		t.Fatalf("sets = %v, want the startup backup", sets)
	}
	m := readManifest(t, dir, sets[0].name)
	if m.WardenVersion != "v-run" || m.SchemaVersion < 1 || m.AuditKeyFingerprint != "" {
		t.Errorf("manifest = %+v", m)
	}
	var names []string
	for _, f := range m.Files {
		names = append(names, f.Name)
		integrityPath := filepath.Join(dir, sets[0].name, f.Name)
		if strings.HasSuffix(f.Name, ".db") {
			integrityOK(t, integrityPath)
		}
	}
	if fmt.Sprint(names) != "[warden-cp.db warden-alerts.db config.yaml]" {
		t.Errorf("files = %v", names)
	}
	if len(m.Skipped) != 0 {
		t.Errorf("skipped = %+v (fleet is not in the default include)", m.Skipped)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func TestBackupConfig_Validate(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "backups")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	ok := BackupConfig{Dir: other, Interval: 24 * time.Hour, Keep: 7, Include: DefaultBackupInclude}
	with := func(f func(*BackupConfig)) BackupConfig { c := ok; f(&c); return c }
	for _, c := range []struct {
		name  string
		cfg   BackupConfig
		state string
		flag  string // "" = valid
	}{
		{"valid", ok, state, ""},
		{"off", BackupConfig{Interval: 24 * time.Hour, Keep: 7, Include: DefaultBackupInclude}, "", ""},
		{"no state dir", ok, "", "--backup-dir"},
		{"equal", with(func(c *BackupConfig) { c.Dir = state }), state, "--backup-dir"},
		{"equal unclean", with(func(c *BackupConfig) { c.Dir = state + "/./" }), state, "--backup-dir"},
		{"inside", with(func(c *BackupConfig) { c.Dir = filepath.Join(state, "b", "c") }), state, "--backup-dir"},
		{"inside via symlink", with(func(c *BackupConfig) { c.Dir = filepath.Join(link, "b") }), state, "--backup-dir"},
		{"sibling with shared prefix", with(func(c *BackupConfig) { c.Dir = state + "-backups" }), state, ""},
		{"interval", with(func(c *BackupConfig) { c.Interval = 30 * time.Minute }), state, "--backup-interval"},
		{"keep", with(func(c *BackupConfig) { c.Keep = 0 }), state, "--backup-keep"},
		{"include bogus", with(func(c *BackupConfig) { c.Include = []string{"bogus"} }), state, "--backup-include"},
		{"include empty", with(func(c *BackupConfig) { c.Include = nil }), state, "--backup-include"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate(c.state)
			switch {
			case c.flag == "" && err != nil:
				t.Fatalf("Validate = %v, want nil", err)
			case c.flag != "" && (err == nil || !strings.Contains(err.Error(), c.flag)):
				t.Fatalf("Validate = %v, want an error naming %s", err, c.flag)
			}
		})
	}
}

func TestBackupConfig_Defaults(t *testing.T) {
	c := BackupConfig{Dir: "x"}.withDefaults()
	if c.Interval != 24*time.Hour || c.Keep != 7 || !c.Has("cp") || !c.Has("alerts") || !c.Has("config") || c.Has("fleet") || !c.Enabled() {
		t.Fatalf("defaults = %+v", c)
	}
}
