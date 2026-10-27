package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// keyFileMode is the mode of a key file LoadOrCreateSigner creates.
const keyFileMode os.FileMode = 0o600

// raceWait bounds how long a caller that lost the create race waits for the
// winner to finish writing the key before giving up.
const (
	raceWait     = 2 * time.Second
	raceInterval = 10 * time.Millisecond
)

// KeyID returns the short identifier of an Ed25519 public key: the hex of the
// first 8 bytes of sha256(pub). It is safe to log and to store next to data
// the key signs.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// LoadOrCreateSigner returns a signer whose key is persisted at path as a
// PKCS#8 PEM file. An existing file is loaded; a missing one is created with
// O_CREATE|O_EXCL at mode 0600, so two processes starting at once never
// overwrite each other: the loser re-reads the winner's key. A file holding a
// key that is not Ed25519 is rejected. Errors name the path, never the key.
func LoadOrCreateSigner(path string) (*Signer, error) {
	if path == "" {
		return nil, errors.New("audit: empty key file path")
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseSignerPEM(path, data)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("audit: read key file %q: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("audit: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	created, err := createExclusive(path, pemBytes)
	if err != nil {
		return nil, err
	}
	if created {
		return NewSignerFromKey(priv), nil
	}
	// Another process created the file first: use its key.
	return waitForKey(path)
}

// createExclusive writes data to a new file at path. It reports false (and no
// error) when the file already exists. A failed write removes the partial
// file so no truncated key is left behind.
func createExclusive(path string, data []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, keyFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("audit: create key file %q: %w", path, err)
	}
	werr := f.Chmod(keyFileMode) // the umask can only drop bits; make it exact
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
		return false, fmt.Errorf("audit: persist key file %q: %w", path, werr)
	}
	return true, nil
}

// waitForKey reads the key a concurrent creator is writing. The file exists
// but may still be empty or partly written, so an incomplete PEM is retried
// for up to raceWait; any other problem is returned at once.
func waitForKey(path string) (*Signer, error) {
	deadline := time.Now().Add(raceWait)
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("audit: read key file %q: %w", path, err)
		}
		if block, _ := pem.Decode(data); block != nil || time.Now().After(deadline) {
			return parseSignerPEM(path, data)
		}
		time.Sleep(raceInterval)
	}
}

func parseSignerPEM(path string, data []byte) (*Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("audit: no PEM block in key file %q", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: parse key file %q: %w", path, err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit: key file %q is not an Ed25519 key", path)
	}
	return NewSignerFromKey(ed), nil
}
