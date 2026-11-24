package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// seedWorkerCerts creates a state dir with two live certificates for worker-1
// and one for worker-2, and returns it.
func seedWorkerCerts(t *testing.T) string {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	if out, errs, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "seed", "--state-dir", stateDir); code != 0 {
		t.Fatalf("bootstrap the state dir: %d %s %s", code, out, errs)
	}
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st, err := controlplane.NewEnrollmentStore(db, controlplane.EnrollmentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, r := range []controlplane.CertRecord{
		{Serial: "aa01", WorkerID: "worker-1"}, {Serial: "aa02", WorkerID: "worker-1"}, {Serial: "bb01", WorkerID: "worker-2"},
	} {
		r.SPKISHA256, r.IssuerKID, r.IssuedVia, r.IssuedAt, r.NotAfter = "spki"+r.Serial, "kid", controlplane.CertIssuedViaEnroll, now, now.Add(24*time.Hour)
		if err := st.RecordCert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	return stateDir
}

func revokedSerials(t *testing.T, stateDir string) string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT serial FROM worker_certs WHERE revoked_at IS NOT NULL ORDER BY serial`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

// TestControlPlaneWorkerRevokeCmd: revoke --serial takes one certificate, revoke
// --id the rest, a repeat changes nothing, and an unknown worker exits 2.
func TestControlPlaneWorkerRevokeCmd(t *testing.T) {
	stateDir := seedWorkerCerts(t)
	base := []string{"control-plane", "worker", "revoke", "--state-dir", stateDir}

	stdout, stderr, code := runWarden(t, append(base, "--id", "worker-1", "--serial", "AA01")...)
	if code != 0 || !strings.Contains(stdout, "revoked 1 certificate(s) and 0 unused enrollment token(s) of worker-1") {
		t.Fatalf("revoke --serial = %d %q %q", code, stdout, stderr)
	}
	if got := revokedSerials(t, stateDir); got != "aa01" {
		t.Fatalf("revoked = %q, want aa01", got)
	}
	stdout, stderr, code = runWarden(t, append(base, "--id", "worker-1")...)
	if code != 0 || !strings.Contains(stdout, "revoked 1 certificate(s)") {
		t.Fatalf("revoke --id = %d %q %q", code, stdout, stderr)
	}
	if got := revokedSerials(t, stateDir); got != "aa01,aa02" {
		t.Fatalf("revoked = %q, want aa01,aa02 (worker-2 untouched)", got)
	}
	stdout, _, code = runWarden(t, append(base, "--id", "worker-1")...)
	if code != 0 || !strings.Contains(stdout, "no change") {
		t.Errorf("repeat = %d %q, want no change", code, stdout)
	}
	if _, _, code := runWarden(t, append(base, "--id", "nobody")...); code != 2 {
		t.Errorf("unknown worker exit = %d, want 2", code)
	}
	// A serial that is another worker's is not found, and revokes nothing.
	if _, _, code := runWarden(t, append(base, "--id", "worker-1", "--serial", "bb01")...); code != 2 {
		t.Errorf("foreign serial exit = %d, want 2", code)
	}
	if _, _, code := runWarden(t, append(base, "--id", "worker-2", "--serial", "zz")...); code == 0 {
		t.Error("a non-hex serial exited 0")
	}
	if got := revokedSerials(t, stateDir); got != "aa01,aa02" {
		t.Errorf("revoked = %q after refused calls", got)
	}
	// No state database: an error, and nothing is created.
	if _, _, code := runWarden(t, "control-plane", "worker", "revoke", "--id", "w", "--state-dir", filepath.Join(t.TempDir(), "none")); code == 0 {
		t.Error("revoke with no state database exited 0")
	}
}
