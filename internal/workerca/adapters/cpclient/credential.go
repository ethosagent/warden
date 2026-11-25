// Package cpclient is the worker side of worker certificates (W-P2-WCA-03): it
// enrolls with a wet_ token, keeps the key and certificate in the worker's state
// directory, and renews the certificate ahead of its expiry. It does HTTP and
// file I/O, so it is a data-plane adapter beside the pure internal/workerca
// domain, which the control plane shares.
//
// The package never touches crypto/tls: the worker's one shared control-plane
// client turns a Credential into the certificate its TLS handshake presents
// (internal/worker), so there is a single source of the current certificate
// for the policy client, the heartbeat and the ingest forwarder.
//
// A private key lives only in a Credential and in a 0600 file. Neither the key,
// its PEM nor the enrollment token is ever logged or put in an error.
package cpclient

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/workerca"
)

// File names under <stateDir>/cert.
const (
	certDirName  = "cert"
	keyFileName  = "worker-key.pem"
	certFileName = "worker-cert.pem"
	// nextSuffix marks a replacement key written before its certificate lands.
	nextSuffix = ".next"
)

// Credential is a worker client certificate with its private key.
type Credential struct {
	// Leaf is the worker certificate; Chain is what the control plane sent
	// above it (the signing intermediate first).
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	// Key is the private key of Leaf.
	Key crypto.Signer
	// ReceivedAt is the clock reading when the certificate arrived (or was
	// loaded). Renewal is scheduled from it, so with a real clock the interval
	// is measured on the monotonic clock.
	ReceivedAt time.Time
}

// WorkerID is the worker id the certificate carries.
func (c *Credential) WorkerID() string {
	id, _ := workerca.WorkerIDFromCert(c.Leaf, c.trustDomain())
	return id
}

func (c *Credential) trustDomain() string {
	if c == nil || c.Leaf == nil || len(c.Leaf.URIs) != 1 {
		return ""
	}
	return c.Leaf.URIs[0].Host
}

// Serial is the certificate serial as the control plane prints it.
func (c *Credential) Serial() string { return c.Leaf.SerialNumber.Text(16) }

// NotAfter is the certificate expiry.
func (c *Credential) NotAfter() time.Time { return c.Leaf.NotAfter }

// Expired reports whether the certificate is past NotAfter at now.
func (c *Credential) Expired(now time.Time) bool { return !now.Before(c.Leaf.NotAfter) }

// DER is the certificate chain a TLS handshake presents: the leaf, then the
// chain the control plane sent.
func (c *Credential) DER() [][]byte {
	out := [][]byte{c.Leaf.Raw}
	for _, x := range c.Chain {
		out = append(out, x.Raw)
	}
	return out
}

// String, GoString and LogValue keep every printable form of a Credential to
// the worker id, serial and expiry: the key must never reach a log line or a
// %v of a struct that embeds one.
func (c *Credential) String() string   { return "cpclient.Credential{" + c.describe() + "}" }
func (c *Credential) GoString() string { return c.String() }
func (c *Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("worker_id", c.WorkerID()), slog.String("serial", c.Serial()),
		slog.String("not_after", c.NotAfter().UTC().Format(time.RFC3339)))
}

func (c *Credential) describe() string {
	return "worker=" + c.WorkerID() + " serial=" + c.Serial() + " not_after=" + c.NotAfter().UTC().Format(time.RFC3339)
}

// Source is the worker's single source of its current client certificate. The
// renewer swaps the pointer after each renewal; every reader sees the new
// certificate on its next handshake.
type Source struct{ p atomic.Pointer[Credential] }

// NewSource returns a Source holding c (nil: none yet, e.g. a worker that has
// not enrolled).
func NewSource(c *Credential) *Source {
	s := &Source{}
	s.p.Store(c)
	return s
}

// Current returns the certificate in use, or nil before the first enrollment.
func (s *Source) Current() *Credential { return s.p.Load() }

// Set replaces the certificate in use.
func (s *Source) Set(c *Credential) { s.p.Store(c) }

// certDir is <stateDir>/cert.
func certDir(stateDir string) string { return filepath.Join(stateDir, certDirName) }

// ensureDirs creates the state directory and its cert/ subdirectory with mode
// 0700 (a directory this call creates is chmod-ed, so the umask cannot widen it).
func ensureDirs(stateDir string) error {
	for _, d := range []string{stateDir, certDir(stateDir)} {
		if _, err := os.Stat(d); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cpclient: stat %s: %w", d, err)
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("cpclient: create %s: %w", d, err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return fmt.Errorf("cpclient: chmod %s: %w", d, err)
		}
	}
	return nil
}

// loadPersisted reads the persisted key and certificate. It returns (nil, nil)
// when there is no certificate file. A certificate whose key file does not match
// is recovered from a pending key (an interrupted renewal) or reported as an
// error. The caller decides whether an expired one is reusable.
func loadPersisted(stateDir string, now time.Time) (*Credential, error) {
	dir := certDir(stateDir)
	certPEM, err := os.ReadFile(filepath.Join(dir, certFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cpclient: read worker certificate: %w", err)
	}
	certs, err := workerca.ParseCertsPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cpclient: persisted worker certificate: %w", err)
	}
	keyPath := filepath.Join(dir, keyFileName)
	key, kerr := readKey(keyPath)
	if kerr != nil || !keyMatches(key, certs[0]) {
		// An interrupted renewal leaves the new certificate with the new key still
		// under the pending name: finish the swap.
		next, nerr := readKey(keyPath + nextSuffix)
		if nerr != nil || !keyMatches(next, certs[0]) {
			if kerr != nil {
				return nil, kerr
			}
			return nil, errors.New("cpclient: the persisted worker key does not match the persisted certificate")
		}
		if err := os.Rename(keyPath+nextSuffix, keyPath); err != nil {
			return nil, fmt.Errorf("cpclient: promote the renewed worker key: %w", err)
		}
		key = next
	}
	cred := &Credential{Leaf: certs[0], Chain: certs[1:], Key: key, ReceivedAt: now}
	if _, err := workerca.WorkerIDFromCert(cred.Leaf, cred.trustDomain()); err != nil {
		return nil, errors.New("cpclient: the persisted certificate is not a worker certificate")
	}
	return cred, nil
}

// LoadStatic reads a client certificate and key issued outside Warden. The
// certificate must carry a worker SPIFFE id. It is never renewed.
func LoadStatic(certPath, keyPath string, now time.Time) (*Credential, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cpclient: read controlPlane.clientCert: %w", err)
	}
	certs, err := workerca.ParseCertsPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cpclient: controlPlane.clientCert: %w", err)
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	if !keyMatches(key, certs[0]) {
		return nil, errors.New("cpclient: controlPlane.clientKey does not match controlPlane.clientCert")
	}
	cred := &Credential{Leaf: certs[0], Chain: certs[1:], Key: key, ReceivedAt: now}
	if _, err := workerca.WorkerIDFromCert(cred.Leaf, cred.trustDomain()); err != nil {
		return nil, errors.New("cpclient: controlPlane.clientCert carries no spiffe://<trust domain>/warden/worker/<id> identity")
	}
	return cred, nil
}

// readKey parses a PKCS#8 (or SEC1 EC) PEM private key. Errors never echo bytes.
func readKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cpclient: read worker key %s: %w", filepath.Base(path), err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("cpclient: worker key %s has no PEM block", filepath.Base(path))
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("cpclient: worker key %s is not a PKCS#8 or EC private key", filepath.Base(path))
}

// keyMatches reports whether key is the private half of cert's public key.
func keyMatches(key crypto.Signer, cert *x509.Certificate) bool {
	if key == nil || cert == nil {
		return false
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	return err == nil && bytes.Equal(der, cert.RawSubjectPublicKeyInfo)
}

// persist writes the credential: the key under its pending name first, then the
// certificate (atomically), then the key into place. A crash after the second
// step is repaired by loadPersisted.
func persist(stateDir string, c *Credential) error {
	if err := ensureDirs(stateDir); err != nil {
		return err
	}
	dir := certDir(stateDir)
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return errors.New("cpclient: encode the worker key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	keyPath := filepath.Join(dir, keyFileName)
	if err := writeFileAtomic(keyPath+nextSuffix, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, certFileName), workerca.EncodeCertsPEM(append([]*x509.Certificate{c.Leaf}, c.Chain...)...), 0o600); err != nil {
		return err
	}
	if err := os.Rename(keyPath+nextSuffix, keyPath); err != nil {
		return fmt.Errorf("cpclient: install the worker key: %w", err)
	}
	return syncDir(dir)
}

// writeFileAtomic writes data to path through a temp file (created O_EXCL, so a
// pre-planted file or link is never followed), fsyncs it and renames it over path.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("cpclient: create %s: %w", filepath.Base(tmp), err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("cpclient: write %s: %w", filepath.Base(tmp), err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("cpclient: sync %s: %w", filepath.Base(tmp), err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cpclient: close %s: %w", filepath.Base(tmp), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cpclient: install %s: %w", filepath.Base(path), err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("cpclient: open %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync() // best effort: not every filesystem supports it
	return nil
}
