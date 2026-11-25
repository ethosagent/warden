package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
)

// The last-known-good bundle cache (W-P2-SBND-06). A pinned worker with
// controlPlane.stateDir set persists each verified bundle, so a restart while
// the control plane is down can enforce it instead of staying fail-closed.
//
// What is on disk is the signed envelope as the control plane sent it, minus
// the credentials sidecar: the file holds policy and signatures, never a
// secret. Nothing is trusted because it is on disk. LoadCache runs the same
// bundle.Verify as a live pull (pins, issuer, expiry) and additionally refuses a
// bundle older than the configured max age, so a restart cannot bring back a
// very old block list. The cached bundle's seq becomes the applied State, so a
// control plane that later serves an older seq is rejected as a rollback.

// BundleCacheDirName is the subdirectory of controlPlane.stateDir holding the
// cache; BundleCacheFileName is the cache file in it.
const (
	BundleCacheDirName  = "bundle"
	BundleCacheFileName = "bundle.json"
)

// ErrNoBundleCache is returned by LoadCache when no cache file exists (a first
// boot, or a cache that was never written). It is not a failure of the cache.
var ErrNoBundleCache = errors.New("config: remote: no bundle cache")

// ErrBundleCacheTooOld is returned by LoadCache for a cached bundle issued
// longer ago than the max age.
var ErrBundleCacheTooOld = errors.New("config: remote: cached bundle is older than bundleCacheMaxAge")

// BundleCachePath returns <stateDir>/bundle/bundle.json.
func BundleCachePath(stateDir string) string {
	return filepath.Join(stateDir, BundleCacheDirName, BundleCacheFileName)
}

// bundleCache is the provider's cache settings.
type bundleCache struct {
	path   string
	maxAge time.Duration
	// failed is true after a write failure was logged, so a broken disk logs
	// one ERROR until a write succeeds again.
	failed bool
	// floor is the applied State the boot pull verifies against: the cached
	// bundle's seq, content and issuedAt (SeedCacheFloor). Zero without one.
	floor *bundle.State
	// floorExpiresAt is the cached bundle's expiresAt: past it plus the skew
	// the floor is ignored.
	floorExpiresAt time.Time
	// started is set when the long-poll begins; LoadCache is refused after.
	started bool
}

// SetBundleCache turns the cache on: verified bundles are written under
// <stateDir>/bundle/ (created 0700) and LoadCache may read them. Call it after
// SetBundleTrust and before the first Pull. It fails without trust, with an
// empty stateDir or non-positive maxAge, or when the directory cannot be made.
func (r *RemoteProvider) SetBundleCache(stateDir string, maxAge time.Duration) error {
	if stateDir == "" || maxAge <= 0 {
		return errors.New("config: remote: bundle cache needs a state directory and a positive max age")
	}
	dir := filepath.Join(stateDir, BundleCacheDirName)
	// stateDir and bundle/ must be real directories (never symlinks) owned by
	// this user and not writable by group or others, or another local user
	// could swap the cache for an older valid bundle. Ones that are missing
	// are created 0700.
	if err := ensureOwnDir(stateDir); err != nil {
		return err
	}
	if err := ensureOwnDir(dir); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trust == nil {
		return errors.New("config: remote: bundle cache needs bundle trust (SetBundleTrust first)")
	}
	r.cache = &bundleCache{path: filepath.Join(dir, BundleCacheFileName), maxAge: maxAge}
	return nil
}

// ensureOwnDir creates dir 0700 when it is missing, and requires an existing
// one to be a real directory (Lstat: a symlink is refused) owned by the current
// user and not writable by group or others.
func ensureOwnDir(dir string) error {
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("config: remote: create bundle cache dir: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("config: remote: secure bundle cache dir: %w", err)
		}
		st, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("config: remote: check bundle cache dir: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("config: remote: bundle cache path %s is not a real directory (a symlink or file is refused)", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("config: remote: bundle cache directory %s is not owned by the worker user", dir)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config: remote: bundle cache directory %s is writable by group or others (mode %04o); chmod 700 it", dir, st.Mode().Perm())
	}
	return nil
}

// writeCache persists the verified envelope body without its credentials. The
// caller holds applyMu and has already swapped the snapshot, so a failure here
// is logged once and changes nothing that is enforced. It runs for a Refresh
// too: the cached issuedAt moves with each re-signed bundle, or the max age
// would be measured from a stale time.
func (r *RemoteProvider) writeCache(t *BundleTrust, body []byte) {
	r.mu.RLock()
	c := r.cache
	r.mu.RUnlock()
	if c == nil {
		return
	}
	err := writeCacheFile(c.path, body)
	r.mu.Lock()
	logFail := err != nil && !c.failed
	c.failed = err != nil
	r.mu.Unlock()
	if logFail && t.Logger != nil {
		// The error names the path and the OS cause, never bundle content.
		t.Logger.Error("bundle cache write failed; the applied policy is unaffected", "error", err)
	}
}

// writeCacheFile writes the envelope minus "credentials" to path atomically:
// temp file in the same directory (0600), fsync, rename, fsync the directory.
func writeCacheFile(path string, body []byte) error {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return errors.New("envelope is not a JSON object")
	}
	delete(env, "credentials")
	out, err := json.Marshal(env)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bundle-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true // the rename happened: the file is in place whatever the fsync says
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// LoadCache installs the cached bundle as the provider's snapshot, as if it had
// just been pulled: it reads the file, verifies it against the current pins at
// the worker's clock (bundle.Options.AllowMissingCredentials, because the
// sidecar is never cached), requires issuedAt within the max age, and
// installs the policy, settings and verified facts. The credential is absent,
// so the secret backend must use the worker's own env or IAM credentials.
//
// It is for boot only: it fails when a bundle is already applied, and the
// worker calls it before any loop that could change the snapshot starts. A
// runtime reload would have to go through the worker's serialized evaluator.
//
// A missing file returns ErrNoBundleCache. Every other error means the cache
// was present and refused (corrupt, tampered, signed by an unpinned key,
// expired, too old); nothing is installed and the worker stays fail-closed.
// Errors carry only a reason, never file content.
func (r *RemoteProvider) LoadCache() (VerifiedBundle, error) {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.RLock()
	t, c, applied := r.trust, r.cache, r.bundle != nil
	started := c != nil && c.started
	r.mu.RUnlock()
	if t == nil || c == nil {
		return VerifiedBundle{}, errors.New("config: remote: bundle cache is not enabled")
	}
	if applied || started {
		return VerifiedBundle{}, errors.New("config: remote: bundle cache can only be loaded at boot, before a bundle is applied or the long-poll has started")
	}

	now := t.Now()
	v, err := readCachedBundle(c.path, t, now)
	if err != nil {
		return VerifiedBundle{}, err
	}
	if now.Sub(v.Bundle.IssuedAt) > c.maxAge {
		return VerifiedBundle{}, ErrBundleCacheTooOld
	}
	p, settings, vb, err := bundleSnapshot(v)
	if err != nil {
		return VerifiedBundle{}, errors.New("config: remote: cached bundle policy is not enforceable by this worker")
	}

	r.mu.Lock()
	r.policy, r.settings, r.bundle = p, settings, vb
	// No ETag: the first poll asks for the full bundle, and a same-seq,
	// same-content answer is "unchanged" against the seeded State.
	r.etag, r.pollETag = "", ""
	r.mu.Unlock()
	if t.Logger != nil {
		t.Logger.Info("bundle loaded from cache", "seq", v.Seq, "kid", v.KID)
	}
	return vb.clone(), nil
}

// readCachedBundle reads the cache file safely and verifies it against the
// pins at now (credentials sidecar allowed to be absent). The open refuses
// symlinks and never blocks on a FIFO; the handle must be a regular file that
// group and others cannot access. A missing file is ErrNoBundleCache. Errors
// carry a reason only, never content.
func readCachedBundle(path string, t *BundleTrust, now time.Time) (bundle.Verified, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return bundle.Verified{}, ErrNoBundleCache
	}
	if err != nil {
		return bundle.Verified{}, errors.New("config: remote: bundle cache cannot be opened (a symlink is refused)")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return bundle.Verified{}, fmt.Errorf("config: remote: stat bundle cache: %w", err)
	}
	if !st.Mode().IsRegular() {
		return bundle.Verified{}, errors.New("config: remote: bundle cache is not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return bundle.Verified{}, fmt.Errorf("config: remote: bundle cache is accessible by group or others (mode %04o)", st.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, bundle.MaxEnvelopeBytes+1))
	if err != nil {
		return bundle.Verified{}, fmt.Errorf("config: remote: read bundle cache: %w", err)
	}
	opt := bundle.Options{Now: now, Skew: t.Skew, Issuer: t.Issuer, AllowMissingCredentials: true}
	v, err := bundle.Verify(raw, t.Pins, bundle.State{}, opt)
	if err != nil {
		return bundle.Verified{}, fmt.Errorf("config: remote: cached bundle rejected (%s)", bundle.Reason(err))
	}
	return v, nil
}

// SeedCacheFloor makes a verifiable cached bundle the rollback floor of the
// boot pull: with it, a control plane that is up at boot but serves a lower
// seq is rejected as a rollback (and an equal seq with different content as
// equivocation) instead of being applied on an empty state, and the worker then
// falls back to LoadCache. Call it after SetBundleCache and before Pull. Only a
// cache that passes bundle.Verify (pins, issuer, not expired) is used; any
// failure means no floor, and the max age is not applied (an old but valid
// bundle is still proof of a seq the control plane once served). The floor
// applies only until the first bundle is applied.
func (r *RemoteProvider) SeedCacheFloor() {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.RLock()
	t, c := r.trust, r.cache
	r.mu.RUnlock()
	if t == nil || c == nil {
		return
	}
	v, err := readCachedBundle(c.path, t, t.Now())
	if err != nil {
		return
	}
	r.mu.Lock()
	c.floor = &bundle.State{Seq: v.Seq, ContentSHA256: v.ContentSHA256, IssuedAt: v.Bundle.IssuedAt}
	c.floorExpiresAt = v.Bundle.ExpiresAt
	r.mu.Unlock()
}
