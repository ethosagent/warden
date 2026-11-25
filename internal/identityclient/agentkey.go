package identityclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/keys"
)

// ErrKeyExists is returned by SaveAgentKey when the file exists and force is
// not set.
var ErrKeyExists = errors.New("identityclient: the agent key file already exists; use --force to replace it")

// maxKeyFileBytes caps a key file read; a PKCS#8 Ed25519 PEM is about 120 bytes.
const maxKeyFileBytes = 16 << 10

// AgentKey is an agent's Ed25519 key pair. It implements keys.Signer, so the
// internal/keys JWS helpers sign with it. The private half never leaves the
// value: the string, Go-syntax and slog forms carry only the kid.
type AgentKey struct {
	priv ed25519.PrivateKey
	jwk  keys.JWK
	kid  string
}

var _ keys.Signer = AgentKey{}

// GenerateAgentKey creates a fresh Ed25519 agent key from crypto/rand.
func GenerateAgentKey() (AgentKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return AgentKey{}, fmt.Errorf("identityclient: generate the agent key: %w", err)
	}
	return newAgentKey(priv)
}

func newAgentKey(priv ed25519.PrivateKey) (AgentKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return AgentKey{}, errors.New("identityclient: the agent key is not an Ed25519 private key")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return AgentKey{}, errors.New("identityclient: the agent key is not an Ed25519 private key")
	}
	jwk, err := keys.PublicJWK(pub, keys.AlgEdDSA)
	if err != nil {
		return AgentKey{}, fmt.Errorf("identityclient: build the public JWK: %w", err)
	}
	return AgentKey{priv: priv, jwk: jwk, kid: jwk.Kid}, nil
}

// WithKID returns a copy that names kid in assertion headers, for an agent
// registered under a key id other than the RFC 7638 thumbprint. The public JWK
// is unchanged.
func (k AgentKey) WithKID(kid string) AgentKey {
	if kid != "" {
		k.kid = kid
	}
	return k
}

// KID is the key id assertions name: the RFC 7638 thumbprint unless WithKID
// replaced it.
func (k AgentKey) KID() string { return k.kid }

// Alg is always EdDSA.
func (k AgentKey) Alg() string { return keys.AlgEdDSA }

// Public is the public half.
func (k AgentKey) Public() crypto.PublicKey { return k.priv.Public() }

// PublicJWK is the public JWK (kty OKP, crv Ed25519, alg EdDSA, kid the RFC
// 7638 thumbprint, no private member) an operator registers for the agent.
func (k AgentKey) PublicJWK() keys.JWK { return k.jwk }

// Sign signs a JWS signing input. It is crypto.Signer's Sign for Ed25519, which
// signs the message itself.
func (k AgentKey) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(k.priv) == 0 {
		return nil, keys.ErrNoActiveKey
	}
	// This is the agent's own client-side credential on the user's host, not a
	// Warden service key: it is the same operation as ed25519.Sign on a key the
	// agent owns, which is why it sits outside the internal/keys signer paths
	// that architecture rule X1 guards.
	return k.priv.Sign(nil, signingInput, crypto.Hash(0))
}

// String, GoString and LogValue never show key material.
func (k AgentKey) String() string   { return "identityclient.AgentKey(kid=" + k.kid + ")" }
func (k AgentKey) GoString() string { return k.String() }
func (k AgentKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kid", k.kid), slog.String("alg", keys.AlgEdDSA))
}

// DefaultAgentKeyPath is <os.UserConfigDir()>/warden/agents/<id>.key. The id
// must pass agentid.ValidID, so it can never contain a path separator.
func DefaultAgentKeyPath(agentID string) (string, error) {
	if err := agentid.ValidID(agentID); err != nil {
		return "", err
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("identityclient: no user config directory: set --key-file")
	}
	return filepath.Join(dir, configSubdir, "agents", agentID+".key"), nil
}

// SaveAgentKey writes k as a PKCS#8 PEM to path (see writePrivateFile). It
// refuses an existing file with ErrKeyExists, atomically, unless force is set.
func SaveAgentKey(path string, k AgentKey, force bool) error {
	if path == "" {
		return errors.New("identityclient: no agent key file path")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return errors.New("identityclient: encode the agent key")
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return writePrivateFile(path, data, force)
}

// LoadAgentKey reads a key written by SaveAgentKey. A file readable by group or
// others is refused with an error naming the path. Errors never carry file
// content.
func LoadAgentKey(path string) (AgentKey, error) {
	raw, err := readPrivateFile(path, "agent key file")
	if err != nil {
		return AgentKey{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return AgentKey{}, fmt.Errorf("identityclient: %s is not a PKCS#8 PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return AgentKey{}, fmt.Errorf("identityclient: %s is not a PKCS#8 PEM private key", path)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return AgentKey{}, fmt.Errorf("identityclient: %s is not an Ed25519 key", path)
	}
	return newAgentKey(priv)
}

// readPrivateFile reads an agent key file: 0600 or tighter and small.
func readPrivateFile(path, what string) ([]byte, error) {
	return readCappedFile(path, what, maxKeyFileBytes)
}

// readCappedFile reads a secret file: regular, 0600 or tighter, at most limit
// bytes.
func readCappedFile(path, what string, limit int64) ([]byte, error) {
	return readRegularFile(path, what, limit, true)
}

// readRegularFile reads a regular file of at most limit bytes. A FIFO, device
// or directory is refused before any read, and the open is non-blocking, so a
// FIFO swapped in after the check cannot hang the caller. When private is set a
// file accessible by group or others is refused, naming the path.
func readRegularFile(path, what string, limit int64, private bool) ([]byte, error) {
	// Stat follows symlinks (a mounted secret is often one) and never blocks.
	if st, err := os.Stat(path); err == nil && !st.Mode().IsRegular() {
		return nil, fmt.Errorf("identityclient: the %s %s is not a regular file", what, path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("identityclient: open the %s %s: %w", what, path, unwrapPathErr(err))
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("identityclient: stat the %s %s: %w", what, path, unwrapPathErr(err))
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("identityclient: the %s %s is not a regular file", what, path)
	}
	if private && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identityclient: the %s %s is accessible by group or others (mode %04o); chmod 600 it", what, path, st.Mode().Perm())
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("identityclient: the %s %s is larger than %d bytes", what, path, limit)
	}
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("identityclient: read the %s %s: %w", what, path, unwrapPathErr(err))
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("identityclient: the %s %s is larger than %d bytes", what, path, limit)
	}
	return buf, nil
}

func unwrapPathErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// writePrivateFile writes data to path atomically: a temp file (0600) in the
// same directory, fsync, then publish. The directory is created 0700 and a
// directory that group or others can write to is refused. With force the temp
// file is renamed over path; without it the temp file is hard-linked to path,
// which fails with ErrKeyExists if anything is there, so refusing an existing
// file is atomic. FileStore.Save uses it too.
func writePrivateFile(path string, data []byte, force bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identityclient: create %s: %w", dir, unwrapPathErr(err))
	}
	if st, err := os.Stat(dir); err != nil {
		return fmt.Errorf("identityclient: check %s: %w", dir, unwrapPathErr(err))
	} else if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("identityclient: the directory %s is writable by group or others (mode %04o); chmod 700 it", dir, st.Mode().Perm())
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("identityclient: write in %s: %w", dir, unwrapPathErr(err))
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("identityclient: write %s: %w", path, unwrapPathErr(err))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("identityclient: write %s: %w", path, unwrapPathErr(err))
	}
	if force {
		err = os.Rename(name, path)
	} else {
		err = os.Link(name, path)
		_ = os.Remove(name)
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w (%s)", ErrKeyExists, path)
		}
	}
	if err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("identityclient: write %s: %w", path, unwrapPathErr(err))
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
