// Package filestore is the default keys.PrivateKeyStore: one file per key at
// <dir>/<purpose>/<kid>.pem, the encoded private key the manager hands it.
// Directories are 0700 and files 0600, a file is created with O_CREATE|O_EXCL
// so a Put never overwrites, and it is fsynced (with its directory) before Put
// returns. The directory can be the default <state-dir>/keys or a separate
// secret mount. Key bytes are never logged or put in an error.
package filestore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/keys"
)

const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
	ext                  = ".pem"
)

// Store implements keys.PrivateKeyStore over a directory.
type Store struct {
	dir string
}

var _ keys.PrivateKeyStore = (*Store)(nil)

// New returns a Store rooted at dir. Nothing is created until the first Put.
func New(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("filestore: empty key directory")
	}
	return &Store{dir: filepath.Clean(dir)}, nil
}

// Dir returns the root directory.
func (s *Store) Dir() string { return s.dir }

// path validates purpose and kid and returns the key file path.
func (s *Store) path(purpose, kid string) (string, error) {
	if !keys.ValidPurpose(purpose) {
		return "", fmt.Errorf("%w: %q", keys.ErrInvalidPurpose, purpose)
	}
	if !keys.ValidKID(kid) {
		return "", fmt.Errorf("%w: kid is not a thumbprint", keys.ErrInvalidKey)
	}
	return filepath.Join(s.dir, purpose, kid+ext), nil
}

// Put writes pem to <dir>/<purpose>/<kid>.pem. The directories are created 0700
// and the file 0600 with O_EXCL: an existing file is keys.ErrKeyExists and is
// left untouched. A failed write removes the partial file.
func (s *Store) Put(ctx context.Context, purpose, kid string, pem []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.path(purpose, kid)
	if err != nil {
		return err
	}
	if err := ensureDir(s.dir); err != nil {
		return err
	}
	pdir := filepath.Dir(path)
	if err := ensureDir(pdir); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return keys.ErrKeyExists
		}
		return fmt.Errorf("filestore: create key file: %w", pathless(err))
	}
	fail := func(op string, err error) error {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("filestore: %s key file: %w", op, pathless(err))
	}
	// The umask can only remove bits from the requested mode; make it exact.
	if err := f.Chmod(fileMode); err != nil {
		return fail("chmod", err)
	}
	if _, err := f.Write(pem); err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("filestore: close key file: %w", pathless(err))
	}
	return syncDir(pdir)
}

// Get returns the file's bytes, or keys.ErrKeyNotFound.
func (s *Store) Get(ctx context.Context, purpose, kid string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.path(purpose, kid)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, keys.ErrKeyNotFound
		}
		return nil, fmt.Errorf("filestore: read key file: %w", pathless(err))
	}
	return b, nil
}

// Delete removes the file; a missing file is not an error.
func (s *Store) Delete(ctx context.Context, purpose, kid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.path(purpose, kid)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("filestore: delete key file: %w", pathless(err))
	}
	return syncDir(filepath.Dir(path))
}

// List returns the kids that have a file under purpose. A missing directory is
// an empty list. Files that are not <valid kid>.pem are ignored.
func (s *Store) List(ctx context.Context, purpose string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !keys.ValidPurpose(purpose) {
		return nil, fmt.Errorf("%w: %q", keys.ErrInvalidPurpose, purpose)
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, purpose))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("filestore: list key files: %w", pathless(err))
	}
	var kids []string
	for _, e := range entries {
		name := e.Name()
		kid, ok := strings.CutSuffix(name, ext)
		if !ok || e.IsDir() || !keys.ValidKID(kid) {
			continue
		}
		kids = append(kids, kid)
	}
	return kids, nil
}

// ensureDir creates dir (and parents) and makes sure it is private. A directory
// that already has no group or other access (0700, or a read-only secret mount
// at 0500) is accepted as is, never loosened; anything more open is tightened
// to 0700, and an error there is returned.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("filestore: create key directory: %w", pathless(err))
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("filestore: stat key directory: %w", pathless(err))
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("filestore: key directory %s is mode %04o and cannot be tightened to %04o: %w",
			dir, info.Mode().Perm(), dirMode, pathless(err))
	}
	return nil
}

// syncDir fsyncs dir so a new or removed entry survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("filestore: open key directory for sync: %w", pathless(err))
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("filestore: sync key directory: %w", pathless(err))
	}
	return nil
}

// pathless drops the path from an *fs.PathError so a key file's name (its kid)
// is not repeated in every wrapped error; the operation and cause remain.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Op, pe.Err)
	}
	return err
}
