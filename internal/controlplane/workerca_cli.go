package controlplane

import (
	"context"
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

// File names `ca init` writes under --out-dir.
const (
	caRootKeyFile      = "root.key"
	caRootCertFile     = "root.crt"
	caChainFile        = "intermediate-chain.pem"
	caIntermediateKey  = "intermediate.key"
	caKeyFileMode      = 0o600
	caCertFileMode     = 0o644
	caOutDirMode       = 0o700
	caRootKeyWarning   = "WARNING: %s is the worker CA root key. Move it to offline storage now and delete it from this host; the control plane never needs it.\n"
	caCSRKeyFileNotice = "intermediate key written to %s (mode 0600); point workerCA.keyFile at it and keep it outside --state-dir\n"
)

// CAOptions are the inputs `warden control-plane ca init|csr` share.
type CAOptions struct {
	// KeySource is config.WorkerCAKeySourceKeys or WorkerCAKeySourceFile.
	KeySource string
	// Force allows replacing existing files, and an existing ca key.
	Force bool
	// StateDir and ConfigPath locate the key manager for keySource=keys (the
	// state dir must already hold signing_keys; ConfigPath carries the keys:
	// block).
	StateDir, ConfigPath string
	// KeysAWSClient replaces the Secrets Manager client (tests).
	KeysAWSClient secrets.AWSSecretsClient
	// Clock is the time source (nil = real).
	Clock clock.Clock
	// Out receives results (paths, the CSR); ErrOut receives warnings.
	Out, ErrOut io.Writer
}

// CAInitOptions is `ca init`.
type CAInitOptions struct {
	CAOptions
	// OutDir receives root.key, root.crt, intermediate-chain.pem and, for
	// keySource=file, intermediate.key.
	OutDir      string
	TrustDomain string
}

// CACSROptions is `ca csr`.
type CACSROptions struct {
	CAOptions
	// KeyFile is where keySource=file writes the new intermediate key.
	KeyFile string
}

func (o CAOptions) clk() clock.Clock {
	if o.Clock == nil {
		return clock.Real()
	}
	return o.Clock
}

func (o CAOptions) validateSource() error {
	switch o.KeySource {
	case config.WorkerCAKeySourceKeys:
		if o.StateDir == "" {
			return errors.New("ca: --key-source keys needs --state-dir (the key manager's signing_keys table lives there)")
		}
	case config.WorkerCAKeySourceFile:
	default:
		return fmt.Errorf("ca: --key-source %q is not supported; use %q or %q", o.KeySource, config.WorkerCAKeySourceKeys, config.WorkerCAKeySourceFile)
	}
	return nil
}

// CAInit creates a P-256 root (10 years) and an intermediate (1 year, pathLen
// 0, name-constrained to the trust domain), writes the root key and
// certificates to OutDir and stores the intermediate key in the key source. It
// never reads the proxy CA and refuses to overwrite anything without Force.
func CAInit(ctx context.Context, o CAInitOptions) error {
	if err := o.validateSource(); err != nil {
		return err
	}
	if !workerca.ValidTrustDomain(o.TrustDomain) {
		return fmt.Errorf("ca: --trust-domain %q must be a lowercase DNS name (no scheme, port, path or wildcard)", o.TrustDomain)
	}
	if o.OutDir == "" {
		return errors.New("ca: --out-dir is required")
	}
	targets := []string{caRootKeyFile, caRootCertFile, caChainFile}
	if o.KeySource == config.WorkerCAKeySourceFile {
		targets = append(targets, caIntermediateKey)
		if inside, err := pathInside(o.OutDir, o.StateDir); err != nil {
			return fmt.Errorf("ca: --out-dir: %w", err)
		} else if inside {
			return errors.New("ca: --out-dir is inside --state-dir; the intermediate key must stay outside it")
		}
	}
	if !o.Force {
		for _, t := range targets {
			if _, err := os.Lstat(filepath.Join(o.OutDir, t)); err == nil {
				return fmt.Errorf("ca: %s already exists; pass --force to replace it", filepath.Join(o.OutDir, t))
			}
		}
	}
	ok, release, err := o.prepareKeys(ctx)
	if err != nil {
		return err
	}
	if ok != nil {
		defer func() { _ = ok.Close() }()
		defer release()
	}

	now := o.clk().Now()
	root, rootKey, err := wcasigner.NewRoot(now)
	if err != nil {
		return err
	}
	interKey, err := wcasigner.GenerateKey()
	if err != nil {
		return err
	}
	inter, err := wcasigner.NewIntermediate(root, rootKey, &interKey.PublicKey, o.TrustDomain, now)
	if err != nil {
		return err
	}
	rootPEM, err := keysigner.MarshalPKCS8PEM(rootKey)
	if err != nil {
		return err
	}
	defer clear(rootPEM)

	if err := os.MkdirAll(o.OutDir, caOutDirMode); err != nil {
		return fmt.Errorf("ca: create --out-dir: %w", err)
	}
	// Nothing is destructive until the key is stored: every file is staged at
	// 0600 beside its target and renamed into place only afterwards.
	st := &staged{}
	defer st.abort()
	if err := st.add(filepath.Join(o.OutDir, caRootKeyFile), rootPEM, caKeyFileMode); err != nil {
		return err
	}
	if err := st.add(filepath.Join(o.OutDir, caRootCertFile), workerca.EncodeCertsPEM(root), caCertFileMode); err != nil {
		return err
	}
	if err := st.add(filepath.Join(o.OutDir, caChainFile), workerca.EncodeCertsPEM(inter, root), caCertFileMode); err != nil {
		return err
	}
	if o.KeySource == config.WorkerCAKeySourceFile {
		interPEM, err := keysigner.MarshalPKCS8PEM(interKey)
		if err != nil {
			return err
		}
		defer clear(interPEM)
		if err := st.add(filepath.Join(o.OutDir, caIntermediateKey), interPEM, caKeyFileMode); err != nil {
			return err
		}
	} else {
		kid, err := ok.importCA(ctx, interKey, o.Force)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(o.Out, "intermediate key stored in the key manager (purpose ca, kid %s)\n", kid)
	}
	if err := st.commit(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(o.ErrOut, caRootKeyWarning, filepath.Join(o.OutDir, caRootKeyFile))
	_, _ = fmt.Fprintf(o.Out, "wrote %s (intermediate first, then root), %s\n", filepath.Join(o.OutDir, caChainFile), filepath.Join(o.OutDir, caRootCertFile))
	_, _ = fmt.Fprintf(o.Out, "intermediate not_after %s; set workerCA.certFile to the chain file and workerCA.trustDomain to %s\n",
		inter.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), o.TrustDomain)
	if o.KeySource == config.WorkerCAKeySourceFile {
		_, _ = fmt.Fprintf(o.ErrOut, caCSRKeyFileNotice, filepath.Join(o.OutDir, caIntermediateKey))
	}
	return nil
}

// CACSR generates the intermediate key in the key source and prints a PEM CSR
// for an offline root to sign. The CSR is public; the key never leaves the
// key source. With keySource=keys the order is: stop the control plane, run
// csr, have the root sign the CSR, install the chain at workerCA.certFile,
// start the control plane (a running one only imports a missing key; --force
// needs it stopped).
func CACSR(ctx context.Context, o CACSROptions) error {
	if err := o.validateSource(); err != nil {
		return err
	}
	if o.KeySource == config.WorkerCAKeySourceFile {
		if o.KeyFile == "" {
			return errors.New("ca: --key-file is required with --key-source file")
		}
		if inside, err := pathInside(o.KeyFile, o.StateDir); err != nil {
			return fmt.Errorf("ca: --key-file: %w", err)
		} else if inside {
			return errors.New("ca: --key-file is inside --state-dir; the intermediate key must stay outside it")
		}
		if _, err := os.Lstat(o.KeyFile); err == nil && !o.Force {
			return fmt.Errorf("ca: %s already exists; pass --force to replace it", o.KeyFile)
		}
	}
	ok, release, err := o.prepareKeys(ctx)
	if err != nil {
		return err
	}
	if ok != nil {
		defer func() { _ = ok.Close() }()
		defer release()
	}
	key, err := wcasigner.GenerateKey()
	if err != nil {
		return err
	}
	der, err := wcasigner.NewCSR(key)
	if err != nil {
		return err
	}
	if o.KeySource == config.WorkerCAKeySourceFile {
		keyPEM, err := keysigner.MarshalPKCS8PEM(key)
		if err != nil {
			return err
		}
		defer clear(keyPEM)
		st := &staged{}
		defer st.abort()
		if err := st.add(o.KeyFile, keyPEM, caKeyFileMode); err != nil {
			return err
		}
		if err := st.commit(); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(o.ErrOut, caCSRKeyFileNotice, o.KeyFile)
	} else {
		kid, err := ok.importCA(ctx, key, o.Force)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(o.ErrOut, "intermediate key stored in the key manager (purpose ca, kid %s)\n", kid)
	}
	return pem.Encode(o.Out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// prepareKeys makes every refusal of the keys source before anything is
// written: it opens the key manager, takes the state dir's instance lock when
// --force will replace a key (a running control plane refuses here, not after
// files changed), and fails on an existing ca key without --force. For the
// file source it returns nils.
func (o CAOptions) prepareKeys(ctx context.Context) (*OfflineKeys, func(), error) {
	if o.KeySource != config.WorkerCAKeySourceKeys {
		return nil, func() {}, nil
	}
	ok, err := o.openKeys(ctx)
	if err != nil {
		return nil, nil, err
	}
	release := func() {}
	if o.Force {
		rel, lerr := cpstate.AcquireDirLock(o.StateDir)
		if errors.Is(lerr, cpstate.ErrLocked) {
			_ = ok.Close()
			return nil, nil, errors.New("ca: the control plane is running; stop it before --force replaces the ca key")
		}
		if lerr != nil {
			_ = ok.Close()
			return nil, nil, fmt.Errorf("ca: %w", lerr)
		}
		release = func() { _ = rel() }
	}
	if err := ok.requireNoCAKey(ctx, o.Force); err != nil {
		release()
		_ = ok.Close()
		return nil, nil, err
	}
	return ok, release, nil
}

func (o CAOptions) openKeys(ctx context.Context) (*OfflineKeys, error) {
	ok, err := OpenKeysOffline(ctx, o.StateDir, KeysCLIOptions{ConfigPath: o.ConfigPath, Clock: o.Clock, KeysAWSClient: o.KeysAWSClient})
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	return ok, nil
}

// requireNoCAKey fails when a ca key already exists and force is not set.
func (o *OfflineKeys) requireNoCAKey(ctx context.Context, force bool) error {
	rows, err := o.Rows(ctx, keys.PurposeCA)
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	for _, r := range rows {
		if r.State == keys.StateActive && !force {
			return fmt.Errorf("ca: the key manager already holds an active ca key (kid %s); pass --force to replace it", r.KID)
		}
	}
	return nil
}

// importCA stores priv as the active ca key, replacing an existing one only
// with force; the caller holds the state dir lock then (prepareKeys).
func (o *OfflineKeys) importCA(ctx context.Context, priv crypto.Signer, force bool) (string, error) {
	if force {
		rows, err := o.Rows(ctx, keys.PurposeCA)
		if err != nil {
			return "", fmt.Errorf("ca: %w", err)
		}
		if len(rows) > 0 {
			if _, err := o.resetLocked(ctx, keys.PurposeCA); err != nil {
				return "", fmt.Errorf("ca: replace the existing ca key: %w", err)
			}
		}
	}
	kid, err := o.mgr.ImportKey(ctx, keys.PurposeCA, priv, keys.Actor{Subject: adminaudit.CLIActor(), AuthMethod: adminaudit.AuthMethodCLI})
	if err != nil {
		return "", fmt.Errorf("ca: store the intermediate key: %w", err)
	}
	return kid, nil
}

// staged collects files written at 0600 beside their targets; commit renames
// them into place (after fsync), abort removes what is left. A target is never
// truncated in place, so a refusal or crash leaves the old file byte-identical
// and no key byte ever sits in a wider-mode file.
type staged struct {
	tmps, targets []string
	modes         []os.FileMode
}

func (s *staged) add(target string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(target), ".ca-*.tmp")
	if err != nil {
		return fmt.Errorf("ca: stage %s: %w", target, err)
	}
	s.tmps, s.targets, s.modes = append(s.tmps, f.Name()), append(s.targets, target), append(s.modes, mode)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("ca: stage %s: %w", target, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("ca: stage %s: %w", target, err)
	}
	return f.Close()
}

func (s *staged) commit() error {
	for i, tmp := range s.tmps {
		if err := os.Chmod(tmp, s.modes[i]); err != nil {
			return fmt.Errorf("ca: write %s: %w", s.targets[i], err)
		}
	}
	for i, tmp := range s.tmps {
		if err := os.Rename(tmp, s.targets[i]); err != nil {
			return fmt.Errorf("ca: write %s: %w", s.targets[i], err)
		}
		s.tmps[i] = ""
	}
	return nil
}

func (s *staged) abort() {
	for _, tmp := range s.tmps {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}
}
