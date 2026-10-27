package integration

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
)

func openBackupCopy(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open copy: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestBackupTo_ConsistentUnderWrites(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		if err := insertRow(s, int64(i)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var next atomic.Int64
	next.Store(1000)
	var committed atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errc := make(chan error, 8)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := insertRow(s, next.Add(1)); err != nil {
					errc <- err
					return
				}
				committed.Add(1)
			}
		}()
	}
	for committed.Load() < 20 {
		time.Sleep(time.Millisecond)
	}
	before := committed.Load()
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := s.BackupTo(ctx, dst); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	close(stop)
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatalf("writer failed during backup: %v", err)
	}

	cp := openBackupCopy(t, dst)
	var res string
	if err := cp.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil || res != "ok" {
		t.Fatalf("integrity_check = %q, %v", res, err)
	}
	var n int64
	if err := cp.QueryRow("SELECT count(*) FROM alerts").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n < 20+before {
		t.Fatalf("copy has %d rows, want at least %d (seed + committed before the call)", n, 20+before)
	}
}

func TestBackupTo_Destination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()

	existing := filepath.Join(dir, "exists.db")
	if err := os.WriteFile(existing, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupTo(ctx, existing); !errors.Is(err, cpstate.ErrBackupDestExists) {
		t.Fatalf("existing dst: err = %v, want ErrBackupDestExists", err)
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me" {
		t.Fatalf("existing dst modified: %q", b)
	}
	missing := filepath.Join(dir, "nodir", "copy.db")
	if err := s.BackupTo(ctx, missing); err == nil {
		t.Fatal("missing parent: want error")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatalf("missing parent was created: %v", err)
	}
	if err := s.BackupTo(ctx, ""); err == nil {
		t.Fatal("empty dst: want error")
	}
}

func TestBackupTo_Cancel(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := s.BackupTo(ctx, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("dst left behind: %v", err)
	}
}

func TestBackupTo_Mode(t *testing.T) {
	s := newTestStore(t)
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := s.BackupTo(context.Background(), dst); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func insertRow(s *Store, i int64) error {
	id := "a" + strconv.FormatInt(i, 10)
	_, err := s.UpsertAlert(sampleAlert(id, "dk-"+id, SevCritical, time.Unix(1700000000, 0)))
	return err
}
