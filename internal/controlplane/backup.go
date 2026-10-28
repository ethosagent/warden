package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

// The backup runner (W-P1-OPS1-06) writes consistent, atomic, pruned backup
// sets of the CP's SQLite state and served config under --backup-dir. Each
// database is copied by its owning store's BackupTo (VACUUM INTO), so every
// copy is internally consistent; the set is not one snapshot across databases
// (they share no foreign keys). The sha256 values in manifest.json check
// integrity, not authenticity: anyone who can write the set can rewrite both.

const (
	// BackupFormat is the manifest's format value; a restore refuses others.
	BackupFormat = "warden.cp.backup.v1"
	// BackupManifestName is the file whose presence makes a set complete.
	BackupManifestName = "manifest.json"
	// BackupSetLayout is the Go time layout of a set directory name (UTC).
	BackupSetLayout = "20060102T150405Z"

	// Backup source keys, as accepted by --backup-include.
	BackupCP        = "cp"
	BackupAlerts    = "alerts"
	BackupConfigKey = "config"
	BackupFleet     = "fleet"

	backupTmpPrefix  = ".tmp-"
	backupTmpMaxAge  = 24 * time.Hour
	backupMinSpace   = 1.2 // free space must be at least this multiple of the sources
	backupMaxErrLen  = 200
	backupRetryDelay = time.Hour

	// Defaults and minimums for the --backup-* flags.
	DefaultBackupInterval = 24 * time.Hour
	MinBackupInterval     = time.Hour
	DefaultBackupKeep     = 7
)

// DefaultBackupInclude is the --backup-include default; fleet is opt-in.
var DefaultBackupInclude = []string{BackupCP, BackupAlerts, BackupConfigKey}

// ErrBackupInProgress is returned by RunOnce while another run is active.
var ErrBackupInProgress = errors.New("backup already in progress")

// errBackupSpace is the free-space refusal; its text is part of the contract.
var errBackupSpace = errors.New("insufficient free space")

// backupNotIncluded is what a set never contains, recorded in every manifest.
var backupNotIncluded = []string{"cp-audit.key", "IdP storage", "secret backend"}

var (
	backupSetRe = regexp.MustCompile(`^\d{8}T\d{6}Z$`)
	backupDBs   = []struct{ key, file string }{
		{BackupCP, "warden-cp.db"},
		{BackupAlerts, "warden-alerts.db"},
		{BackupFleet, "warden-fleet.db"},
	}
)

// backupSource is what the runner needs of a store: a consistent copy to dst.
// Implemented by *cpstate.DB, *integration.Store and *analytics.FleetSQLiteStore.
type backupSource interface {
	BackupTo(ctx context.Context, dst string) error
}

// BackupReporter receives the outcome of each run. Both methods are optional
// in effect: a nil reporter is allowed.
type BackupReporter interface {
	// BackupFailed is called once per failed run; db names the source that
	// failed ("cp", "alerts", "fleet", "config") or "run" for a failure before
	// or after any single source (free space, directory, manifest, rename).
	BackupFailed(db string, err error)
	// BackupSucceeded is called once per successful run with the set name.
	BackupSucceeded(set string)
}

// BackupConfig is the operator's --backup-* settings. Dir == "" means backups
// are off.
type BackupConfig struct {
	Dir      string
	Interval time.Duration
	Keep     int
	Include  []string
}

// Enabled reports whether a backup directory is configured.
func (c BackupConfig) Enabled() bool { return c.Dir != "" }

// Has reports whether key is in the include list.
func (c BackupConfig) Has(key string) bool { return slices.Contains(c.Include, key) }

// Validate checks the --backup-* values against each other and stateDir. Every
// error names the offending flag. The interval, keep and include values are
// checked whether or not a directory is set; the directory rules apply only
// when it is.
func (c BackupConfig) Validate(stateDir string) error {
	if c.Interval < MinBackupInterval {
		return fmt.Errorf("--backup-interval %s is too short: the minimum is %s", c.Interval, MinBackupInterval)
	}
	if c.Keep < 1 {
		return fmt.Errorf("--backup-keep %d is invalid: the minimum is 1", c.Keep)
	}
	if len(c.Include) == 0 {
		return errors.New("--backup-include is empty: list at least one of cp, alerts, config, fleet")
	}
	for _, k := range c.Include {
		if !slices.Contains([]string{BackupCP, BackupAlerts, BackupConfigKey, BackupFleet}, k) {
			return fmt.Errorf("--backup-include: unknown source %q (valid: cp, alerts, config, fleet)", k)
		}
	}
	if c.Dir == "" {
		return nil
	}
	if stateDir == "" {
		return errors.New("--backup-dir requires --state-dir")
	}
	bd, err := resolveExistingPrefix(c.Dir)
	if err != nil {
		return fmt.Errorf("--backup-dir %s: %w", c.Dir, err)
	}
	sd, err := resolveExistingPrefix(stateDir)
	if err != nil {
		return fmt.Errorf("--state-dir %s: %w", stateDir, err)
	}
	if rel, err := filepath.Rel(sd, bd); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("--backup-dir %s must not equal or sit inside --state-dir %s", c.Dir, stateDir)
	}
	return nil
}

// withDefaults fills unset (zero) fields; Validate is the strict check.
func (c BackupConfig) withDefaults() BackupConfig {
	if c.Interval <= 0 {
		c.Interval = DefaultBackupInterval
	}
	if c.Keep < 1 {
		c.Keep = DefaultBackupKeep
	}
	if len(c.Include) == 0 {
		c.Include = DefaultBackupInclude
	}
	return c
}

// resolveExistingPrefix returns p as an absolute, cleaned path with symlinks
// resolved in the longest prefix that exists; the missing tail is appended
// unchanged.
func resolveExistingPrefix(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	var tail []string
	cur := abs
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				r = filepath.Join(r, tail[i])
			}
			return r, nil
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// BackupStore is one database the runner can copy. A nil Source means the
// store is absent: it is not copied and is listed in the manifest's skipped
// with Reason.
type BackupStore struct {
	Source backupSource
	// Path is the live database file, used only to size the free-space check.
	Path   string
	Reason string
}

// BackupDeps are the runner's collaborators.
type BackupDeps struct {
	CP, Alerts, Fleet BackupStore
	// ConfigPath is the served config.yaml, read once per run.
	ConfigPath string
	// Version is the warden version recorded in the manifest.
	Version string
	// AuditKeyID is the admin audit key id; empty omits the manifest field
	// (console.adminAudit.enabled is false).
	AuditKeyID string
	// SchemaVersion reads the cpstate schema version (nil omits the field).
	SchemaVersion func(ctx context.Context) (int, error)
	// Clock is the schedule's time port (nil = clock.Real()).
	Clock clock.Clock
	// FreeBytes reports the bytes available to this process on the filesystem
	// holding dir (nil = the OS's, see diskFree).
	FreeBytes func(dir string) (uint64, error)
	// Reporter is optional.
	Reporter BackupReporter
	Logger   *slog.Logger
}

// BackupFile is one file of a set, as recorded in the manifest.
type BackupFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// BackupSkip is a source the set does not contain, with why.
type BackupSkip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// BackupManifest is manifest.json. It is written last; a set directory with
// no manifest is not complete.
type BackupManifest struct {
	Format              string       `json:"format"`
	WardenVersion       string       `json:"warden_version"`
	SchemaVersion       int          `json:"schema_version,omitempty"`
	AuditKeyFingerprint string       `json:"audit_key_fingerprint,omitempty"`
	CreatedAt           time.Time    `json:"created_at"`
	FinishedAt          time.Time    `json:"finished_at"`
	Files               []BackupFile `json:"files"`
	Skipped             []BackupSkip `json:"skipped"`
	NotIncluded         []string     `json:"not_included"`
}

// BackupResult is what one successful run produced.
type BackupResult struct {
	Set       string // directory name, e.g. 20260102T150405Z
	Path      string // absolute path of the set directory
	SizeBytes int64  // sum of the file sizes
	Manifest  BackupManifest
}

// BackupStatus is the runner's last known state, for health and /setup.
type BackupStatus struct {
	LastSuccessAt time.Time
	LastError     string
	LastSet       string
	SizeBytes     int64
}

// BackupRunner writes and prunes backup sets and schedules itself.
type BackupRunner struct {
	cfg  BackupConfig
	deps BackupDeps
	clk  clock.Clock
	log  *slog.Logger

	run  sync.Mutex     // held for the length of a RunOnce
	od   sync.WaitGroup // on-demand runs started by StartOnDemand
	mu   sync.Mutex     // guards status
	stat BackupStatus
	done chan struct{}

	// beforeRename, when set (tests), runs after the manifest is written and
	// before the set is renamed into place; an error aborts the run.
	beforeRename func() error
}

// NewBackupRunner builds a runner for cfg (zero fields take their defaults).
func NewBackupRunner(cfg BackupConfig, deps BackupDeps) *BackupRunner {
	r := &BackupRunner{cfg: cfg.withDefaults(), deps: deps, clk: deps.Clock, log: deps.Logger}
	if r.clk == nil {
		r.clk = clock.Real()
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	if r.deps.FreeBytes == nil {
		r.deps.FreeBytes = diskFree
	}
	return r
}

// Status returns the last known state.
func (r *BackupRunner) Status() BackupStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stat
}

// Start launches the schedule goroutine, bound to ctx. It returns at once: an
// overdue backup runs inside the goroutine, never delaying the caller. Wait
// blocks until the goroutine has stopped.
func (r *BackupRunner) Start(ctx context.Context) {
	r.done = make(chan struct{})
	r.loadStatus()
	go func() {
		defer close(r.done)
		r.loop(ctx)
	}()
}

// Wait blocks until the goroutine Start launched and any run StartOnDemand
// started have returned (after their ctx is cancelled). It is a no-op if
// neither was started.
func (r *BackupRunner) Wait() {
	if r.done != nil {
		<-r.done
	}
	r.od.Wait()
}

func (r *BackupRunner) loop(ctx context.Context) {
	for {
		wait := r.untilNext()
		if wait > 0 {
			t := r.clk.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C():
			}
		}
		if ctx.Err() != nil {
			return
		}
		if _, err := r.RunOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			// Retry sooner than the interval, but not in a tight loop.
			t := r.clk.NewTimer(min(r.cfg.Interval, backupRetryDelay))
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C():
			}
		}
	}
}

// untilNext is how long until the next run: the newest complete set's
// timestamp plus the interval, so a CP that restarts nightly still backs up;
// zero when that is due or there is no set.
func (r *BackupRunner) untilNext() time.Duration {
	sets, err := listBackupSets(r.cfg.Dir)
	if err != nil || len(sets) == 0 {
		return 0
	}
	next := sets[0].at.Add(r.cfg.Interval)
	return max(next.Sub(r.clk.Now()), 0)
}

// loadStatus seeds Status from the newest complete set on disk so a restart
// does not report "never backed up" while a fresh set exists.
func (r *BackupRunner) loadStatus() {
	sets, err := listBackupSets(r.cfg.Dir)
	if err != nil || len(sets) == 0 {
		return
	}
	newest := sets[0]
	var size int64
	if b, err := os.ReadFile(filepath.Join(r.cfg.Dir, newest.name, BackupManifestName)); err == nil {
		var m BackupManifest
		if json.Unmarshal(b, &m) == nil {
			for _, f := range m.Files {
				size += f.Size
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stat.LastSet == "" {
		r.stat.LastSet, r.stat.LastSuccessAt, r.stat.SizeBytes = newest.name, newest.at, size
	}
}

// RunOnce writes one complete set and prunes. A second call while one is
// running returns ErrBackupInProgress. A failure is logged, recorded in
// Status().LastError and reported once through the reporter.
func (r *BackupRunner) RunOnce(ctx context.Context) (BackupResult, error) {
	if !r.run.TryLock() {
		return BackupResult{}, ErrBackupInProgress
	}
	defer r.run.Unlock()
	return r.runLocked(ctx)
}

// StartOnDemand starts one run in a goroutine bound to ctx and returns at once:
// ErrBackupInProgress when a run is already active, nil when this one has
// started. The run's outcome reaches Status and the reporter, as for RunOnce.
// The admin trigger (POST /dashboard/api/backup) uses it so a busy runner
// answers synchronously.
func (r *BackupRunner) StartOnDemand(ctx context.Context) error {
	if !r.run.TryLock() {
		return ErrBackupInProgress
	}
	r.od.Add(1)
	go func() {
		defer r.od.Done()
		defer r.run.Unlock()
		_, _ = r.runLocked(ctx)
	}()
	return nil
}

// runLocked is RunOnce's body; the caller holds r.run.
func (r *BackupRunner) runLocked(ctx context.Context) (BackupResult, error) {
	res, db, err := r.write(ctx)
	if err != nil {
		r.fail(ctx, db, err)
		return BackupResult{}, err
	}
	r.mu.Lock()
	r.stat.LastSuccessAt = res.Manifest.FinishedAt
	r.stat.LastError, r.stat.LastSet, r.stat.SizeBytes = "", res.Set, res.SizeBytes
	r.mu.Unlock()
	if r.deps.Reporter != nil {
		r.deps.Reporter.BackupSucceeded(res.Set)
	}
	r.prune(res.Set)
	return res, nil
}

func (r *BackupRunner) fail(ctx context.Context, db string, err error) {
	msg := err.Error()
	if len(msg) > backupMaxErrLen {
		msg = strings.ToValidUTF8(msg[:backupMaxErrLen], "")
	}
	r.mu.Lock()
	r.stat.LastError = msg
	r.mu.Unlock()
	if ctx.Err() != nil {
		return // shutdown, not a backup problem
	}
	r.log.Error("cp_backup", "db", db, "outcome", "error", "error", msg)
	if r.deps.Reporter != nil {
		r.deps.Reporter.BackupFailed(db, err)
	}
}

// write builds one set under .tmp-<ts>, then renames it into place. On any
// failure it removes the partial directory and names the failing source.
func (r *BackupRunner) write(ctx context.Context) (res BackupResult, db string, err error) {
	db = "run"
	start := r.clk.Now().UTC()
	if err := os.MkdirAll(r.cfg.Dir, 0o700); err != nil {
		return res, db, fmt.Errorf("backup: create backup dir: %w", err)
	}

	// The served config is read once: hashed and written from the same bytes.
	var cfgBytes []byte
	if r.cfg.Has(BackupConfigKey) {
		cfgBytes, err = os.ReadFile(r.deps.ConfigPath)
		if err != nil {
			return res, BackupConfigKey, fmt.Errorf("backup: read served config: %w", err)
		}
	}

	type job struct {
		key, file string
		st        BackupStore
	}
	var jobs []job
	var skipped []BackupSkip
	var need int64
	for _, d := range backupDBs {
		if !r.cfg.Has(d.key) {
			continue
		}
		st := map[string]BackupStore{BackupCP: r.deps.CP, BackupAlerts: r.deps.Alerts, BackupFleet: r.deps.Fleet}[d.key]
		if st.Source == nil {
			reason := st.Reason
			if reason == "" {
				reason = "store not available"
			}
			skipped = append(skipped, BackupSkip{Name: d.file, Reason: reason})
			continue
		}
		jobs = append(jobs, job{d.key, d.file, st})
		need += dbFootprint(st.Path)
	}
	need += int64(len(cfgBytes))

	free, ferr := r.deps.FreeBytes(r.cfg.Dir)
	if ferr != nil {
		return res, db, fmt.Errorf("backup: free space check: %w", ferr)
	}
	if float64(free) < float64(need)*backupMinSpace {
		return res, db, fmt.Errorf("backup: %w: %d bytes free, need %.0f (1.2x the %d bytes of sources)",
			errBackupSpace, free, float64(need)*backupMinSpace, need)
	}

	// A set name is one second wide: when a set (or a stale .tmp-) already
	// holds this second, as with an on-demand run beside the schedule, take the
	// next free one rather than fail after copying everything.
	stamp := start
	for taken(r.cfg.Dir, stamp) {
		stamp = stamp.Add(time.Second)
	}
	tmp := filepath.Join(r.cfg.Dir, backupTmpPrefix+stamp.Format(BackupSetLayout))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return res, db, fmt.Errorf("backup: create set dir: %w", err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.RemoveAll(tmp)
		}
	}()

	var files []BackupFile
	var total int64
	for _, j := range jobs {
		t0 := r.clk.Now()
		bf, cerr := r.copyDB(ctx, j.st.Source, tmp, j.file)
		r.logCopy(j.key, bf.Size, r.clk.Now().Sub(t0), cerr)
		if cerr != nil {
			return res, j.key, cerr
		}
		files = append(files, bf)
		total += bf.Size
	}
	if r.cfg.Has(BackupConfigKey) {
		t0 := r.clk.Now()
		bf, cerr := writeBackupFile(filepath.Join(tmp, "config.yaml"), cfgBytes)
		r.logCopy(BackupConfigKey, bf.Size, r.clk.Now().Sub(t0), cerr)
		if cerr != nil {
			return res, BackupConfigKey, cerr
		}
		files = append(files, bf)
		total += bf.Size
	}

	m := BackupManifest{
		Format: BackupFormat, WardenVersion: r.deps.Version,
		AuditKeyFingerprint: r.deps.AuditKeyID,
		CreatedAt:           start, FinishedAt: r.clk.Now().UTC(),
		Files: files, Skipped: skipped, NotIncluded: backupNotIncluded,
	}
	if m.Files == nil {
		m.Files = []BackupFile{}
	}
	if m.Skipped == nil {
		m.Skipped = []BackupSkip{}
	}
	if r.cfg.Has(BackupCP) && r.deps.SchemaVersion != nil && r.deps.CP.Source != nil {
		if m.SchemaVersion, err = r.deps.SchemaVersion(ctx); err != nil {
			return res, db, fmt.Errorf("backup: read schema version: %w", err)
		}
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return res, db, fmt.Errorf("backup: encode manifest: %w", err)
	}
	if _, err := writeBackupFile(filepath.Join(tmp, BackupManifestName), append(mb, '\n')); err != nil {
		return res, db, err
	}
	if err := syncDir(tmp); err != nil {
		return res, db, fmt.Errorf("backup: sync set dir: %w", err)
	}
	if r.beforeRename != nil {
		if err := r.beforeRename(); err != nil {
			return res, db, err
		}
	}
	name := stamp.Format(BackupSetLayout)
	final := filepath.Join(r.cfg.Dir, name)
	if err := os.Rename(tmp, final); err != nil {
		return res, db, fmt.Errorf("backup: publish set: %w", err)
	}
	renamed = true
	if err := syncDir(r.cfg.Dir); err != nil {
		r.log.Warn("cp_backup", "db", "run", "outcome", "dir_sync_failed", "error", err.Error())
	}
	return BackupResult{Set: name, Path: final, SizeBytes: total, Manifest: m}, "", nil
}

// copyDB has src write a consistent copy at <dir>/<file>, then fsyncs and
// hashes it.
func (r *BackupRunner) copyDB(ctx context.Context, src backupSource, dir, file string) (BackupFile, error) {
	dst := filepath.Join(dir, file)
	if err := src.BackupTo(ctx, dst); err != nil {
		return BackupFile{Name: file}, fmt.Errorf("backup %s: %w", file, err)
	}
	f, err := os.Open(dst)
	if err != nil {
		return BackupFile{Name: file}, fmt.Errorf("backup %s: %w", file, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return BackupFile{Name: file}, fmt.Errorf("backup %s: hash: %w", file, err)
	}
	if err := f.Sync(); err != nil {
		return BackupFile{Name: file}, fmt.Errorf("backup %s: sync: %w", file, err)
	}
	return BackupFile{Name: file, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

// writeBackupFile creates path exclusively with mode 0600, writes b, fsyncs
// and returns its manifest entry.
func writeBackupFile(path string, b []byte) (BackupFile, error) {
	name := filepath.Base(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return BackupFile{Name: name}, fmt.Errorf("backup %s: %w", name, err)
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return BackupFile{Name: name}, fmt.Errorf("backup %s: %w", name, err)
	}
	sum := sha256.Sum256(b)
	return BackupFile{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))}, nil
}

// taken reports whether dir already holds the set or .tmp- name for at.
func taken(dir string, at time.Time) bool {
	n := at.Format(BackupSetLayout)
	for _, p := range []string{n, backupTmpPrefix + n} {
		if _, err := os.Lstat(filepath.Join(dir, p)); err == nil {
			return true
		}
	}
	return false
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// dbFootprint is the live size of a database: the file plus its WAL.
func dbFootprint(path string) int64 {
	if path == "" {
		return 0
	}
	var n int64
	for _, p := range []string{path, path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// logCopy logs one source copy. It never carries row contents.
func (r *BackupRunner) logCopy(db string, bytes int64, d time.Duration, err error) {
	if err != nil {
		r.log.Error("cp_backup", "db", db, "bytes", bytes, "duration_ms", d.Milliseconds(), "outcome", "error", "error", err.Error())
		return
	}
	r.log.Info("cp_backup", "db", db, "bytes", bytes, "duration_ms", d.Milliseconds(), "outcome", "ok")
}

type backupSet struct {
	name string
	at   time.Time
}

// listBackupSets returns the complete sets in dir (a set-named directory that
// holds manifest.json), newest first. A missing dir has none.
func listBackupSets(dir string) ([]backupSet, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []backupSet
	for _, e := range ents {
		if !e.IsDir() || !backupSetRe.MatchString(e.Name()) { // IsDir is false for a symlink
			continue
		}
		at, err := time.Parse(BackupSetLayout, e.Name())
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), BackupManifestName)); err != nil {
			continue
		}
		out = append(out, backupSet{e.Name(), at})
	}
	slices.SortFunc(out, func(a, b backupSet) int { return b.at.Compare(a.at) })
	return out, nil
}

// prune keeps the newest cfg.Keep complete sets (never deleting the newest,
// nor justWritten) and removes .tmp- directories older than 24h. Entries that
// are neither a set nor a .tmp- directory are never touched. A failure only
// logs: the backup itself succeeded.
func (r *BackupRunner) prune(justWritten string) {
	dir := r.cfg.Dir
	sets, err := listBackupSets(dir)
	if err != nil {
		r.log.Warn("cp_backup", "db", "run", "outcome", "prune_failed", "error", err.Error())
		return
	}
	for i, s := range sets {
		if i < r.cfg.Keep || i == 0 || s.name == justWritten {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, s.name)); err != nil {
			r.log.Warn("cp_backup", "db", "run", "outcome", "prune_failed", "set", s.name, "error", err.Error())
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := r.clk.Now()
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), backupTmpPrefix) {
			continue
		}
		born := tmpAge(e, strings.TrimPrefix(e.Name(), backupTmpPrefix))
		if born.IsZero() || now.Sub(born) <= backupTmpMaxAge {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			r.log.Warn("cp_backup", "db", "run", "outcome", "prune_failed", "tmp", e.Name(), "error", err.Error())
		}
	}
}

// tmpAge is when a .tmp- directory was started: the timestamp in its name,
// else its mtime.
func tmpAge(e os.DirEntry, stamp string) time.Time {
	if t, err := time.Parse(BackupSetLayout, stamp); err == nil {
		return t
	}
	if fi, err := e.Info(); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// newRunBackupRunner wires the runner Run starts: the stores it opened, the
// resolved database paths and the served config. A store that is absent (no
// alert store, a memory analytics provider) is passed as skipped with a reason.
func newRunBackupRunner(p Params, clk clock.Clock, logger *slog.Logger, state *cpstate.DB, alerts *integration.Store,
	fleet analytics.FleetStore, servedPath, fleetPath, alertsPath string, audit *adminaudit.Store) *BackupRunner {
	deps := BackupDeps{
		ConfigPath: servedPath, Version: p.Version, Clock: clk, Reporter: p.BackupReporter, Logger: logger,
		CP:     BackupStore{Source: state, Path: state.Path()},
		Alerts: BackupStore{Reason: "no alert store is running"},
		Fleet:  BackupStore{Reason: "analytics provider is memory: no fleet database"},

		SchemaVersion: state.SchemaVersion,
	}
	if alerts != nil {
		deps.Alerts = BackupStore{Source: alerts, Path: alertsPath}
	}
	if src, ok := fleet.(backupSource); ok && p.AnalyticsProvider != "memory" {
		deps.Fleet = BackupStore{Source: src, Path: fleetPath}
	}
	if audit != nil {
		deps.AuditKeyID = audit.KeyID()
	}
	return NewBackupRunner(p.Backup, deps)
}
