package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: remote: create bundle cache dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("config: remote: secure bundle cache dir: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trust == nil {
		return errors.New("config: remote: bundle cache needs bundle trust (SetBundleTrust first)")
	}
	r.cache = &bundleCache{path: filepath.Join(dir, BundleCacheFileName), maxAge: maxAge}
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
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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
	r.mu.RUnlock()
	if t == nil || c == nil {
		return VerifiedBundle{}, errors.New("config: remote: bundle cache is not enabled")
	}
	if applied {
		return VerifiedBundle{}, errors.New("config: remote: bundle cache can only be loaded before a bundle is applied")
	}

	f, err := os.Open(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return VerifiedBundle{}, ErrNoBundleCache
	}
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("config: remote: open bundle cache: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, bundle.MaxEnvelopeBytes+1))
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("config: remote: read bundle cache: %w", err)
	}

	now := t.Now()
	opt := bundle.Options{Now: now, Skew: t.Skew, Issuer: t.Issuer, AllowMissingCredentials: true}
	v, err := bundle.Verify(raw, t.Pins, bundle.State{}, opt)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("config: remote: cached bundle rejected (%s)", bundle.Reason(err))
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
