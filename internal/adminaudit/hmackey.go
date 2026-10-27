package adminaudit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// HMACKeyFileName is the default name of the actor/state HMAC key file; it
// sits in the same directory as the audit signing key.
const HMACKeyFileName = "cp-audit-hmac.key"

const (
	hmacKeyLen      = 32
	hmacKeyFileMode = 0o600
	raceWait        = 2 * time.Second
	raceInterval    = 10 * time.Millisecond
)

// DefaultHMACKeyPath returns the HMAC key path beside the audit key file.
func DefaultHMACKeyPath(auditKeyPath string) string {
	return filepath.Join(filepath.Dir(auditKeyPath), HMACKeyFileName)
}

// LoadOrCreateHMACKey returns the 32-byte key that keys actor_id (and the
// state-hash HMACs). An existing file must hold exactly 32 bytes; a missing
// one is created with 32 crypto/rand bytes, O_CREATE|O_EXCL at mode 0600, and
// a process that loses the create race re-reads the winner's key. Errors name
// the path, never the key.
func LoadOrCreateHMACKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("adminaudit: empty HMAC key file path")
	}
	_, err := os.Stat(path)
	switch {
	case err == nil:
		// The file may be one a concurrent creator is still writing.
		return waitForHMACKey(path)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("adminaudit: read HMAC key file %q: %w", path, err)
	}
	key := make([]byte, hmacKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("adminaudit: generate HMAC key: %w", err)
	}
	created, err := createKeyFile(path, key)
	if err != nil {
		return nil, err
	}
	if created {
		return key, nil
	}
	return waitForHMACKey(path)
}

// createKeyFile writes data to a new 0600 file, reporting false when the file
// already exists. A failed write removes the partial file.
func createKeyFile(path string, data []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, hmacKeyFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("adminaudit: create HMAC key file %q: %w", path, err)
	}
	werr := f.Chmod(hmacKeyFileMode) // the umask can only drop bits; make it exact
	if werr == nil {
		_, werr = f.Write(data)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return false, fmt.Errorf("adminaudit: persist HMAC key file %q: %w", path, werr)
	}
	return true, nil
}

// waitForHMACKey reads a key a concurrent creator may still be writing: a
// short file is retried for up to raceWait.
func waitForHMACKey(path string) ([]byte, error) {
	deadline := time.Now().Add(raceWait)
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("adminaudit: read HMAC key file %q: %w", path, err)
		}
		if len(data) >= hmacKeyLen || time.Now().After(deadline) {
			return checkHMACKey(path, data)
		}
		time.Sleep(raceInterval)
	}
}

func checkHMACKey(path string, data []byte) ([]byte, error) {
	if len(data) != hmacKeyLen {
		return nil, fmt.Errorf("adminaudit: HMAC key file %q must hold exactly %d bytes", path, hmacKeyLen)
	}
	return data, nil
}
