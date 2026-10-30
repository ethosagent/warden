package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The verified restore (W-P1-OPS1-04) loads a backup set written by the runner
// of backup.go into a stopped control plane's state dir. It takes the state-dir
// lock first, checks the whole set in a staging directory next to each target
// and only then swaps: nothing in the target changes unless every check
// passed, and the files it replaces are kept under <state-dir>/pre-restore-<ts>.

const (
	// RestoreAuditAction is the admin audit action of a completed restore.
	RestoreAuditAction = "cp.restore"

	restoreStagePrefix = ".restore-"
	restorePrePrefix   = "pre-restore-"
	restoreMaxManifest = 4 << 20

	restoreCPDB     = "warden-cp.db"
	restoreAlertsDB = "warden-alerts.db"
	restoreFleetDB  = "warden-fleet.db"
	restoreConfig   = "config.yaml"
)

// restoreNames is the allowlist of manifest file names. A manifest never
// chooses where a file lands: the name selects one of the four targets.
var restoreNames = []string{restoreCPDB, restoreAlertsDB, restoreFleetDB, restoreConfig}

// Errors RunRestore returns, matched with errors.Is. Their text is the
// operator-facing message.
var (
	ErrRestoreRunning   = errors.New("control plane is running; stop it before restoring")
	ErrRestoreFormat    = errors.New("unsupported backup format")
	ErrRestoreManifest  = errors.New("manifest mismatch")
	ErrRestoreNotEmpty  = errors.New("target state dir is not empty; pass --force")
	ErrRestoreKey       = errors.New("audit key fingerprint does not match the backup")
	ErrRestoreUnaudited = errors.New("restore is applied but unaudited")
)

// RestoreOps is the file-operation seam of RunRestore; tests replace Rename to
// fail a step. Nil fields use the OS.
type RestoreOps struct {
	// Rename moves a file on the way in and when files are set aside. A
	// rollback always uses os.Rename.
	Rename func(oldpath, newpath string) error
}

// RestoreParams are the inputs of `warden control-plane restore`.
type RestoreParams struct {
	// From is the backup set directory (holding manifest.json); StateDir the
	// CP's --state-dir.
	From, StateDir string
	// AnalyticsDB and AlertsDB are the CP's --analytics-db and --alerts-db
	// ("" = <state-dir>/warden-fleet.db and a sibling of it named
	// warden-alerts.db).
	AnalyticsDB, AlertsDB string
	// AuditKeyFile is --admin-audit-key-file ("" = <state-dir>/cp-audit.key).
	AuditKeyFile string
	// Force allows replacing existing target files; NewAuditKey allows a
	// target audit key whose fingerprint differs from the manifest's.
	Force, NewAuditKey bool
	Clock              clock.Clock
	Ops                RestoreOps
}

// RestoreResult is what a completed restore did.
type RestoreResult struct {
	CreatedAt     time.Time // the backup's created_at
	WardenVersion string    // the version that wrote the backup
	Files         []string  // restored file names, in manifest order
	PreRestoreDir string    // where replaced files went; "" when nothing was replaced
	NewAuditKey   bool
	// KeyChecked is false when the audit key fingerprint was not compared: the
	// manifest records none (an offline backup never opens the audit store) or
	// NewAuditKey was set.
	KeyChecked bool
	// Audited is false when the restored state has no admin audit chain
	// (so no cp.restore row was appended).
	Audited bool
}

// restoreTarget is one file the restore places.
type restoreTarget struct {
	name   string // manifest name
	path   string // final path
	stage  string // staged copy
	sha    string // expected sha256 from the manifest
	size   int64
	isDB   bool
	placed bool
}

// RunRestore restores the backup set p.From into p.StateDir. It holds the
// state-dir lock for its whole run (ErrRestoreRunning when held). Any failed
// check leaves the target byte-for-byte unchanged and removes the staging
// directories. A failure after the files are in place is ErrRestoreUnaudited.
func RunRestore(ctx context.Context, p RestoreParams) (RestoreResult, error) {
	if p.From == "" || p.StateDir == "" {
		return RestoreResult{}, errors.New("--from and --state-dir are required")
	}
	clk := p.Clock
	if clk == nil {
		clk = clock.Real()
	}
	if fi, err := os.Stat(p.StateDir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
			return RestoreResult{}, fmt.Errorf("create --state-dir: %w", err)
		}
	} else if err != nil || !fi.IsDir() {
		return RestoreResult{}, fmt.Errorf("--state-dir %s is not a directory", p.StateDir)
	}
	release, err := cpstate.AcquireDirLock(p.StateDir)
	if errors.Is(err, cpstate.ErrLocked) {
		return RestoreResult{}, ErrRestoreRunning
	}
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() { _ = release() }()

	m, manifestSum, err := readRestoreManifest(p.From)
	if err != nil {
		return RestoreResult{}, err
	}
	targets, err := restoreTargets(p, m)
	if err != nil {
		return RestoreResult{}, err
	}

	ts := restoreStamp(clk.Now().UTC(), p.StateDir, targets)
	stages, err := makeStaging(ts, targets)
	defer func() {
		for _, d := range stages {
			_ = os.RemoveAll(d)
		}
	}()
	if err != nil {
		return RestoreResult{}, err
	}

	// Every check below runs on the staged copies; the target is untouched.
	if err := stageAndHash(p.From, targets); err != nil {
		return RestoreResult{}, err
	}
	for _, t := range targets {
		if !t.isDB {
			continue
		}
		if err := cpstate.IntegrityCheck(ctx, t.stage); err != nil {
			return RestoreResult{}, fmt.Errorf("integrity_check failed for %s: %w", t.name, err)
		}
	}
	keyFile := p.AuditKeyFile
	if keyFile == "" {
		keyFile = adminaudit.DefaultKeyPath(p.StateDir)
	}
	for _, t := range targets {
		if t.name != restoreCPDB {
			continue
		}
		if err := checkStagedState(ctx, t.stage, m); err != nil {
			return RestoreResult{}, err
		}
	}
	keyChecked := m.AuditKeyFingerprint != "" && !p.NewAuditKey
	if keyChecked {
		if err := checkAuditKeyFingerprint(keyFile, m.AuditKeyFingerprint); err != nil {
			return RestoreResult{}, err
		}
	}
	if !p.Force {
		for _, t := range targets {
			if _, err := os.Lstat(t.path); err == nil {
				return RestoreResult{}, ErrRestoreNotEmpty
			}
		}
	}
	for _, t := range targets {
		if t.name == restoreCPDB {
			if err := clearConsoleSessions(ctx, t.stage); err != nil {
				return RestoreResult{}, err
			}
		}
	}

	pre, err := applyRestore(p, ts, targets)
	if err != nil {
		return RestoreResult{}, err
	}

	res := RestoreResult{CreatedAt: m.CreatedAt, WardenVersion: m.WardenVersion, PreRestoreDir: pre, NewAuditKey: p.NewAuditKey, KeyChecked: keyChecked}
	for _, t := range targets {
		res.Files = append(res.Files, t.name)
	}
	if !slices.Contains(res.Files, restoreCPDB) {
		return res, nil
	}
	audited, err := recordRestore(ctx, p, keyFile, manifestSum, m)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrRestoreUnaudited, err)
	}
	res.Audited = audited
	return res, nil
}

// readRestoreManifest reads and validates <from>/manifest.json: the format,
// that every file name is on the allowlist (no path separator, no "..", no
// repeats), and that the set lists something. It returns the manifest and the
// sha256 of its bytes.
func readRestoreManifest(from string) (BackupManifest, string, error) {
	var m BackupManifest
	f, err := os.Open(filepath.Join(from, BackupManifestName))
	if err != nil {
		return m, "", fmt.Errorf("read backup manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, restoreMaxManifest+1))
	if err != nil {
		return m, "", fmt.Errorf("read backup manifest: %w", err)
	}
	if len(raw) > restoreMaxManifest {
		return m, "", errors.New("backup manifest is too large")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, "", fmt.Errorf("parse backup manifest: %w", err)
	}
	if m.Format != BackupFormat {
		return m, "", fmt.Errorf("%w %q (this binary reads %s)", ErrRestoreFormat, m.Format, BackupFormat)
	}
	seen := map[string]bool{}
	for _, bf := range m.Files {
		if !slices.Contains(restoreNames, bf.Name) {
			return m, "", fmt.Errorf("manifest lists %q: refused (not one of %s)", bf.Name, strings.Join(restoreNames, ", "))
		}
		if seen[bf.Name] {
			return m, "", fmt.Errorf("manifest lists %s twice", bf.Name)
		}
		seen[bf.Name] = true
		if bf.Size < 0 {
			return m, "", fmt.Errorf("manifest lists %s with a negative size", bf.Name)
		}
	}
	if len(m.Files) == 0 {
		return m, "", errors.New("backup set lists no files")
	}
	sum := sha256.Sum256(raw)
	return m, hex.EncodeToString(sum[:]), nil
}

// restoreTargets maps the manifest's files to their target paths, defaulting
// the databases as the CP resolves them.
func restoreTargets(p RestoreParams, m BackupManifest) ([]*restoreTarget, error) {
	fleet := p.AnalyticsDB
	if fleet == "" {
		fleet = filepath.Join(p.StateDir, restoreFleetDB)
	}
	alerts := p.AlertsDB
	if alerts == "" {
		alerts = filepath.Join(filepath.Dir(fleet), restoreAlertsDB)
	}
	paths := map[string]string{
		restoreCPDB:     filepath.Join(p.StateDir, restoreCPDB),
		restoreAlertsDB: alerts,
		restoreFleetDB:  fleet,
		restoreConfig:   filepath.Join(p.StateDir, restoreConfig),
	}
	var out []*restoreTarget
	used := map[string]string{}
	for _, bf := range m.Files {
		path := filepath.Clean(paths[bf.Name])
		if prev, ok := used[path]; ok {
			return nil, fmt.Errorf("%s and %s would both restore to %s; check --analytics-db and --alerts-db", prev, bf.Name, path)
		}
		used[path] = bf.Name
		out = append(out, &restoreTarget{
			name: bf.Name, path: path, sha: strings.ToLower(bf.SHA256), size: bf.Size,
			isDB: strings.HasSuffix(bf.Name, ".db"),
		})
	}
	return out, nil
}

// restoreStamp is the timestamp of the staging and pre-restore directory
// names: now, moved on by seconds while any of those names is taken.
func restoreStamp(now time.Time, stateDir string, targets []*restoreTarget) time.Time {
	for {
		name := now.Format(BackupSetLayout)
		taken := exists(filepath.Join(stateDir, restorePrePrefix+name))
		for _, t := range targets {
			taken = taken || exists(filepath.Join(filepath.Dir(t.path), restoreStagePrefix+name))
		}
		if !taken {
			return now
		}
		now = now.Add(time.Second)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// makeStaging creates .restore-<ts> (0700) beside each distinct target
// directory so the final rename stays on one filesystem. It returns every
// directory it created, also when it fails part way.
func makeStaging(ts time.Time, targets []*restoreTarget) ([]string, error) {
	var made []string
	byDir := map[string]string{}
	for _, t := range targets {
		dir := filepath.Dir(t.path)
		stage, ok := byDir[dir]
		if !ok {
			stage = filepath.Join(dir, restoreStagePrefix+ts.Format(BackupSetLayout))
			if err := os.Mkdir(stage, 0o700); err != nil {
				return made, fmt.Errorf("create staging directory for %s: %w", t.name, err)
			}
			byDir[dir] = stage
			made = append(made, stage)
		}
		t.stage = filepath.Join(stage, t.name)
	}
	return made, nil
}

// stageAndHash copies each manifest file from the set into its staging path
// (created exclusively, 0600) while hashing, and compares the sha256 and size
// with the manifest. A set file that is not a regular file (a symlink, say)
// is a mismatch.
func stageAndHash(from string, targets []*restoreTarget) error {
	for _, t := range targets {
		src := filepath.Join(from, t.name)
		fi, err := os.Lstat(src)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s (missing or not a regular file)", ErrRestoreManifest, t.name)
		}
		in, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("%w: %s (%v)", ErrRestoreManifest, t.name, err)
		}
		n, sum, err := copyHashing(t.stage, in)
		_ = in.Close()
		if err != nil {
			return fmt.Errorf("stage %s: %w", t.name, err)
		}
		if n != t.size || sum != t.sha {
			return fmt.Errorf("%w: %s", ErrRestoreManifest, t.name)
		}
	}
	return nil
}

func copyHashing(dst string, src io.Reader) (int64, string, error) {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), src)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// supportedSchemaVersion is the schema version a state database holding the
// applied migration IDs could have on this binary: every always-on migration
// plus the feature-gated (Optional) ones the file has applied. An Optional
// migration the file never applied does not count, or one unregistered
// future migration would hide behind it.
func supportedSchemaVersion(applied []string) int {
	have := make(map[string]bool, len(applied))
	for _, id := range applied {
		have[id] = true
	}
	n := 0
	for _, m := range StateMigrations() {
		if !m.Optional || have[m.ID] {
			n++
		}
	}
	return n
}

// checkStagedState vets the staged warden-cp.db: its schema version must not
// exceed this binary's, every migration it holds must be one this binary
// knows, and a non-empty admin audit chain must verify (the keys come from the
// chain itself).
func checkStagedState(ctx context.Context, staged string, m BackupManifest) error {
	lenient, err := cpstate.OpenReadOnlyWith(ctx, staged, StateMigrations(), cpstate.ReadOnlyOptions{AllowNewer: func(string) bool { return true }})
	if err != nil {
		return fmt.Errorf("backup warden-cp.db: %w", err)
	}
	got, err := lenient.SchemaVersion(ctx)
	known := supportedSchemaVersion(lenient.Applied())
	_ = lenient.Close()
	if err != nil {
		return fmt.Errorf("backup warden-cp.db: %w", err)
	}
	got = max(got, m.SchemaVersion)
	if got > known {
		return fmt.Errorf("backup schema_version %d is newer than this binary supports (%d)", got, known)
	}
	db, err := cpstate.OpenReadOnly(ctx, staged, StateMigrations())
	if err != nil {
		return fmt.Errorf("backup warden-cp.db: %w", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := restoreAuditRows(ctx, db.SQL())
	if err != nil {
		return fmt.Errorf("backup warden-cp.db: %w", err)
	}
	if rows == 0 {
		return nil
	}
	res, err := adminaudit.NewStore(db, adminaudit.Options{}).VerifyAll(ctx, adminaudit.VerifyOptions{})
	if err != nil {
		return fmt.Errorf("verify the backup's admin audit chain: %w", err)
	}
	if !res.OK {
		return fmt.Errorf("the backup's admin audit chain does not verify at seq %d (%s)", res.FirstBadSeq, res.Reason)
	}
	return nil
}

// auditRows counts the admin_audit rows (0 when the table does not exist).
func restoreAuditRows(ctx context.Context, db *sql.DB) (int, error) {
	if !tableExists(ctx, db, "admin_audit") {
		return 0, nil
	}
	var n int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM (SELECT 1 FROM admin_audit LIMIT 1)").Scan(&n)
	return n, err
}

func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name = ?", name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// checkAuditKeyFingerprint compares the key file's fingerprint (its key_id)
// with the manifest's. The file is only read: a missing one is never created.
func checkAuditKeyFingerprint(keyFile, want string) error {
	if _, err := os.Stat(keyFile); err != nil {
		return fmt.Errorf("%w: cannot read the audit key file %s; put the key with fingerprint %s there or pass --new-audit-key",
			ErrRestoreKey, keyFile, want)
	}
	s, err := audit.LoadOrCreateSigner(keyFile)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreKey, err)
	}
	if got := audit.KeyID(s.PubKey()); got != want {
		return fmt.Errorf("%w: the key at %s has fingerprint %s but the backup was taken with %s; restore that key or pass --new-audit-key",
			ErrRestoreKey, keyFile, got, want)
	}
	return nil
}

// clearConsoleSessions empties sessions and oidc_pending in the staged
// warden-cp.db (whichever exist), so cookies issued before the backup stop
// working. It opens the file with the full migration list, which also brings
// an older set's schema up to date, then checkpoints so the file is
// self-contained before it is renamed into place.
func clearConsoleSessions(ctx context.Context, staged string) error {
	db, err := cpstate.Open(ctx, staged, StateMigrations())
	if err != nil {
		return fmt.Errorf("prepare restored warden-cp.db: %w", err)
	}
	defer func() { _ = db.Close() }()
	for _, tbl := range []string{"sessions", "oidc_pending"} {
		if !tableExists(ctx, db.SQL(), tbl) {
			continue
		}
		if _, err := db.SQL().ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			return fmt.Errorf("clear %s in the restored warden-cp.db: %w", tbl, err)
		}
	}
	if _, err := db.SQL().ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint the restored warden-cp.db: %w", err)
	}
	return nil
}

type movedFile struct{ from, to string }

// applyRestore moves the replaced files (database, -wal, -shm and config) into
// <state-dir>/pre-restore-<ts>/ and renames the staged files into place. When
// a step fails it undoes what it did and names the pre-restore directory. It
// returns that directory ("" when nothing was moved).
func applyRestore(p RestoreParams, ts time.Time, targets []*restoreTarget) (string, error) {
	rename := p.Ops.Rename
	if rename == nil {
		rename = os.Rename
	}
	pre := filepath.Join(p.StateDir, restorePrePrefix+ts.Format(BackupSetLayout))
	var moved []movedFile
	made := false
	undo := func(cause error) error {
		var errs []error
		for _, t := range targets {
			if t.placed {
				if err := os.Remove(t.path); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		}
		for i := len(moved) - 1; i >= 0; i-- {
			if err := os.Rename(moved[i].to, moved[i].from); err != nil {
				errs = append(errs, err)
			}
		}
		if made && len(errs) == 0 {
			_ = os.Remove(pre) // empty again: the target is exactly as found
		}
		if len(errs) > 0 {
			return fmt.Errorf("restore failed: %w; rolling back also failed (%v): the replaced files are in %s", cause, errors.Join(errs...), pre)
		}
		return fmt.Errorf("restore failed and was rolled back (the replaced files are back in place; pre-restore directory %s): %w", pre, cause)
	}

	for _, t := range targets {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if suffix != "" && !t.isDB {
				continue
			}
			src := t.path + suffix
			if !exists(src) {
				continue
			}
			if !made {
				if err := os.Mkdir(pre, 0o700); err != nil {
					return "", undo(fmt.Errorf("create %s: %w", pre, err))
				}
				made = true
			}
			dst := filepath.Join(pre, filepath.Base(src))
			if exists(dst) {
				return "", undo(fmt.Errorf("%s already exists", dst))
			}
			if err := rename(src, dst); err != nil {
				return "", undo(fmt.Errorf("move %s aside: %w", src, err))
			}
			moved = append(moved, movedFile{from: src, to: dst})
		}
	}
	for _, t := range targets {
		if err := rename(t.stage, t.path); err != nil {
			return "", undo(fmt.Errorf("place %s: %w", t.name, err))
		}
		t.placed = true
		if err := os.Chmod(t.path, 0o600); err != nil {
			return "", undo(fmt.Errorf("chmod %s: %w", t.name, err))
		}
	}
	for _, d := range uniqueDirs(targets, p.StateDir) {
		_ = syncDir(d) // best effort: the renames are already visible
	}
	if !made {
		return "", nil
	}
	return pre, nil
}

func uniqueDirs(targets []*restoreTarget, extra string) []string {
	dirs := []string{extra}
	for _, t := range targets {
		if d := filepath.Dir(t.path); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// recordRestore appends the cp.restore row through the admin audit store. It
// reports false (and appends nothing) when the restored state has no admin
// audit chain.
func recordRestore(ctx context.Context, p RestoreParams, keyFile, manifestSum string, m BackupManifest) (bool, error) {
	rec, closeFn, err := adminaudit.OpenForCLI(ctx, p.StateDir, keyFile, StateMigrations())
	if err != nil {
		return false, err
	}
	if rec == nil {
		return false, nil
	}
	defer func() { _ = closeFn() }()
	_, err = rec.Record(ctx, adminaudit.Input{
		Action:  RestoreAuditAction,
		Target:  manifestSum,
		Outcome: adminaudit.OutcomeOK,
		Details: map[string]string{
			"new_audit_key":  fmt.Sprintf("%t", p.NewAuditKey),
			"set_created_at": m.CreatedAt.UTC().Format(time.RFC3339),
		},
	})
	return err == nil, err
}
