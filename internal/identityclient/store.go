package identityclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Entry is the JSON shape of a cache file. It is exported so tests can seed a
// cache. ReceivedAt is the LOCAL time the ID token was received; the 2/3 refresh
// rule is measured from it, so a skewed IdP clock does not matter.
type Entry struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ReceivedAt   time.Time `json:"received_at"`
}

// FileStore is the cache of one (issuer, client id) pair: a 0600 file in a 0700
// directory, and an exclusive flock on "<file>.lock" for writers.
type FileStore struct {
	Dir  string
	Name string // file name inside Dir, see CacheFileName
}

// CacheFileName is "<sha256(issuer|client_id)[:16]>.json".
func CacheFileName(issuer, clientID string) string {
	sum := sha256.Sum256([]byte(issuer + "|" + clientID))
	return hex.EncodeToString(sum[:])[:16] + ".json"
}

// NewFileStore returns the store for cfg.
func NewFileStore(cfg Config) *FileStore {
	return &FileStore{Dir: cfg.CacheDir, Name: CacheFileName(cfg.Issuer, cfg.ClientID)}
}

// Path is the cache file path.
func (s *FileStore) Path() string { return filepath.Join(s.Dir, s.Name) }

func (s *FileStore) lockPath() string { return s.Path() + ".lock" }

// Load reads the entry. A missing file returns an error matching
// fs.ErrNotExist. A file readable by group or others is refused with an error
// naming the path.
func (s *FileStore) Load() (Entry, error) {
	p := s.Path()
	st, err := os.Stat(p)
	if err != nil {
		return Entry{}, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return Entry{}, fmt.Errorf("identityclient: cache file %s is accessible by group or others (mode %04o); chmod 600 it or run `warden identity logout`", p, st.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return Entry{}, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return Entry{}, fmt.Errorf("identityclient: cache file %s is not valid; run `warden identity login` again", p)
	}
	return e, nil
}

// Save writes the entry atomically: a temp file in the same directory (0600),
// fsync, rename. The directory is created 0700.
func (s *FileStore) Save(e Entry) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("identityclient: create cache dir %s: %w", s.Dir, err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("identityclient: write cache in %s: %w", s.Dir, err)
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, s.Path()); err != nil {
		cleanup()
		return fmt.Errorf("identityclient: write cache %s: %w", s.Path(), err)
	}
	if d, err := os.Open(s.Dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Remove deletes the cache file and its lock file; absent files are fine.
func (s *FileStore) Remove() error {
	var errs []error
	for _, p := range []string{s.Path(), s.lockPath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithLock runs fn holding an exclusive lock on the cache's lock file, so two
// processes (or goroutines) never refresh at once.
func (s *FileStore) WithLock(fn func() error) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("identityclient: create cache dir %s: %w", s.Dir, err)
	}
	unlock, err := lockFile(s.lockPath())
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func osGetenv(k string) string { return os.Getenv(k) }
