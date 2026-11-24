package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

const (
	// workerCARetryInterval is how often a degraded worker CA retries loading
	// its key.
	workerCARetryInterval = 30 * time.Second
	// workerCAExpiryWarn is how close to NotAfter the intermediate logs a WARN.
	workerCAExpiryWarn = 30 * 24 * time.Hour
	// workerCALoadTimeout bounds the startup key load.
	workerCALoadTimeout = 10 * time.Second
)

// WorkerCAVerifier returns the verifier of the pinned worker intermediates, or
// nil when workerCA is disabled. Unlike WorkerCA it is available while the key
// backend is down, so certificate authentication keeps working in an outage.
func (s *Server) WorkerCAVerifier() *workerca.Verifier { return s.cfg.WorkerCAVerifier }

// SetWorkerCA installs the worker CA once the retry loop has loaded it.
func (s *Server) SetWorkerCA(ca *workerca.CA) { s.workerCA.Store(ca) }

// WorkerCA returns the live worker CA, or nil while workerCA is disabled or
// degraded. Enrollment and renewal answer 503 on nil when WorkerCADegraded.
func (s *Server) WorkerCA() *workerca.CA { return s.workerCA.Load() }

// WorkerCADegraded reports workerCA.enabled with no CA loaded yet: the key
// backend was unreachable at start and the retry loop has not succeeded.
func (s *Server) WorkerCADegraded() bool {
	return s.cfg.WorkerCAEnabled && s.workerCA.Load() == nil
}

// workerCAPlan is a validated worker CA configuration waiting for its key.
type workerCAPlan struct {
	cfg      config.WorkerCAConfig
	chain    []*x509.Certificate
	previous []*x509.Certificate
	// fileSigner is the key of keySource=file, loaded eagerly.
	fileSigner crypto.Signer
	// verifier pins the intermediates; it needs no key, so it is live from
	// startup even while the issuing CA is degraded.
	verifier *workerca.Verifier
	clk      clock.Clock
	logger   *slog.Logger
}

// String, GoString and LogValue keep the plan's printable forms free of the
// file signer's key bytes.
func (p *workerCAPlan) String() string {
	return "controlplane.workerCAPlan{trust_domain=" + p.cfg.TrustDomain + "}"
}
func (p *workerCAPlan) GoString() string { return p.String() }
func (p *workerCAPlan) LogValue() slog.Value {
	return slog.GroupValue(slog.String("trust_domain", p.cfg.TrustDomain), slog.String("key_source", p.cfg.KeySource))
}

// resolveWorkerCA reads the workerCA block from the operator-owned --config
// file and, when enabled, checks everything that can be checked without the key
// backend: key source against keys.enabled, the key file, the intermediate
// chain against the --ca-cert used for the control plane's server TLS, and its
// validity. Any failure is a startup error naming the key or flag; nothing has
// been bound yet. A nil plan with a nil error is the disabled default.
func resolveWorkerCA(configPath, stateDir, caCertPath string, keysCfg config.KeysConfig, clk clock.Clock, logger *slog.Logger) (*workerCAPlan, error) {
	wc := config.DefaultWorkerCA()
	if configPath != "" {
		var err error
		if wc, err = config.LoadWorkerCA(configPath); err != nil {
			return nil, fmt.Errorf("control-plane: %w", err)
		}
	}
	if !wc.Enabled {
		return nil, nil
	}
	if wc.KeySource == config.WorkerCAKeySourceKeys && !keysCfg.Enabled {
		return nil, errors.New("control-plane: workerCA.keySource is \"keys\" but keys.enabled is false; enable the keys block or use workerCA.keySource: file for development")
	}
	p := &workerCAPlan{cfg: wc, clk: clk, logger: logger}
	var err error
	if p.chain, err = readCertChain("workerCA.certFile", wc.CertFile); err != nil {
		return nil, err
	}
	if wc.PreviousCertFile != "" {
		if p.previous, err = readCertChain("workerCA.previousCertFile", wc.PreviousCertFile); err != nil {
			return nil, err
		}
	}
	now := clk.Now()
	if err := workerca.CheckIntermediate(p.chain[0], now); err != nil {
		return nil, fmt.Errorf("control-plane: workerCA.certFile: %w", err)
	}
	// A previous intermediate that is no longer valid is dropped with a WARN, so
	// the rotation runbook (leave previousCertFile set until the next rotation)
	// cannot brick startup; a structurally wrong one is still a startup error.
	if len(p.previous) > 0 {
		if err := workerca.CheckIntermediate(p.previous[0], now); errors.Is(err, workerca.ErrIntermediateExpired) {
			logger.Warn("workerCA.previousCertFile is outside its validity window and is ignored: remove it from the config",
				"not_after", p.previous[0].NotAfter.UTC().Format(time.RFC3339))
			p.previous = nil
		} else if err != nil {
			return nil, fmt.Errorf("control-plane: workerCA.previousCertFile: %w", err)
		}
	}
	if caCertPath != "" {
		proxyCAs, err := readCertChain("--ca-cert", caCertPath)
		if err != nil {
			return nil, err
		}
		if err := workerca.CheckSeparateRoot(p.chain, proxyCAs); err != nil {
			return nil, fmt.Errorf("control-plane: workerCA.certFile vs --ca-cert: %w", err)
		}
		if err := workerca.CheckSeparateRoot(p.previous, proxyCAs); err != nil {
			return nil, fmt.Errorf("control-plane: workerCA.previousCertFile vs --ca-cert: %w", err)
		}
	}
	if p.verifier, err = workerca.NewVerifier(p.options(nil)); err != nil {
		return nil, fmt.Errorf("control-plane: workerCA.certFile: %w", err)
	}
	if wc.KeySource == config.WorkerCAKeySourceFile {
		if p.fileSigner, err = loadWorkerCAKeyFile(wc.KeyFile, stateDir); err != nil {
			return nil, err
		}
		logger.Warn("workerCA.keySource=file is for development only: the intermediate key sits in a plain file; use keySource keys in production",
			"key_source", wc.KeySource)
	}
	return p, nil
}

// readCertChain reads a PEM certificate file. field names the flag or key in
// errors; the content is never echoed.
func readCertChain(field, path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("control-plane: %s: read %q: %w", field, path, err)
	}
	chain, err := workerca.ParseCertsPEM(data)
	if err != nil {
		return nil, fmt.Errorf("control-plane: %s %q: %w", field, path, err)
	}
	return chain, nil
}

// loadWorkerCAKeyFile reads the dev-only key file: a regular file of mode 0600
// that sits outside --state-dir (so a state-dir backup never carries it).
func loadWorkerCAKeyFile(path, stateDir string) (crypto.Signer, error) {
	if inside, err := pathInside(path, stateDir); err != nil {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile: %w", err)
	} else if inside {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile %q is inside --state-dir; keep the key outside it", path)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile %q must be a regular file", path)
	}
	if fi.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile %q has mode %04o; it must be 0600", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile: %w", err)
	}
	defer clear(data)
	key, err := keysigner.ParsePKCS8PEM(data)
	if err != nil {
		return nil, fmt.Errorf("control-plane: workerCA.keyFile %q: %w", path, err)
	}
	return key, nil
}

// pathInside reports whether path is dir or below it. An empty dir contains
// nothing. Symlinks in the existing part of path are resolved.
func pathInside(path, dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	a, err := resolveAbs(path)
	if err != nil {
		return false, err
	}
	b, err := resolveAbs(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(b, a)
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

func resolveAbs(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// Resolve the deepest existing ancestor so a symlinked state dir compares
	// equal to its target.
	rest := ""
	for cur := abs; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(real, rest), nil
		}
		if filepath.Dir(cur) == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// build constructs the CA from the plan and a signer.
func (p *workerCAPlan) build(sg crypto.Signer) (*workerca.CA, error) {
	return workerca.New(p.options(sg))
}

func (p *workerCAPlan) options(sg crypto.Signer) workerca.Options {
	return workerca.Options{
		Chain: p.chain, Previous: p.previous, Signer: sg, Create: wcasigner.CreateCertificate,
		TrustDomain: p.cfg.TrustDomain, Clock: p.clk.Now,
	}
}

// loadSigner returns the CA key: the eagerly loaded file key, or the key
// manager's active ca key. An error from the manager means the key backend is
// unavailable or holds no ca key yet (degraded, retry); a key the manager
// cannot hand out as a crypto.Signer is permanent.
func (p *workerCAPlan) loadSigner(ctx context.Context, mgr *keys.Manager) (crypto.Signer, error) {
	if p.fileSigner != nil {
		return p.fileSigner, nil
	}
	return mgr.CertSigner(ctx)
}

// errWorkerCADegraded is Load's answer when the key backend could not supply
// the ca key yet.
var errWorkerCADegraded = errors.New("worker CA degraded")

// Load makes the first attempt to build the CA. A key backend that is
// unreachable, or a ca key not yet imported, returns errWorkerCADegraded: the control
// plane starts degraded and Retry keeps trying. A key that does not match the
// intermediate, or cannot sign certificates, is a startup error.
func (p *workerCAPlan) Load(ctx context.Context, mgr *keys.Manager) (*workerca.CA, error) {
	p.logStart()
	sg, err := p.loadSigner(ctx, mgr)
	if errors.Is(err, keys.ErrNoCertSigner) {
		return nil, fmt.Errorf("control-plane: workerCA: %w", err)
	}
	if err != nil {
		p.logger.Warn("worker CA degraded: the ca key could not be loaded; enroll and renew answer 503 and loading is retried every 30s",
			"key_source", p.cfg.KeySource, "error", err.Error())
		return nil, errWorkerCADegraded
	}
	ca, err := p.build(sg)
	if err != nil {
		return nil, fmt.Errorf("control-plane: workerCA: %w", err)
	}
	p.logReady(ca)
	return ca, nil
}

// Retry loads the key every 30 seconds until it succeeds or ctx ends, then
// hands the CA to install. It runs only for a degraded start.
func (p *workerCAPlan) Retry(ctx context.Context, mgr *keys.Manager, install func(*workerca.CA)) {
	for waitOn(ctx, p.clk, workerCARetryInterval) {
		lctx, cancel := context.WithTimeout(ctx, workerCALoadTimeout)
		sg, err := p.loadSigner(lctx, mgr)
		cancel()
		if err != nil {
			p.logger.Warn("worker CA still degraded", "error", err.Error())
			continue
		}
		ca, err := p.build(sg)
		if err != nil {
			p.logger.Error("worker CA key does not match the intermediate; still degraded", "error", err.Error())
			continue
		}
		install(ca)
		p.logReady(ca)
		return
	}
}

// logStart is the one startup line: no key, PEM or CSR bytes.
func (p *workerCAPlan) logStart() {
	inter := p.chain[0]
	p.logger.Info("worker CA configured",
		"worker_ca", "enabled", "trust_domain", p.cfg.TrustDomain,
		"intermediate_subject", inter.Subject.String(),
		"not_after", inter.NotAfter.UTC().Format(time.RFC3339),
		"key_source", p.cfg.KeySource)
	if left := inter.NotAfter.Sub(p.clk.Now()); left < workerCAExpiryWarn {
		p.logger.Warn("worker intermediate expires soon: issue a new one with `warden control-plane ca init` or `ca csr` and rotate",
			"not_after", inter.NotAfter.UTC().Format(time.RFC3339), "remaining", left.Round(time.Hour).String())
	}
}

func (p *workerCAPlan) logReady(ca *workerca.CA) {
	p.logger.Info("worker CA ready", "worker_ca", "ready", "trust_domain", ca.TrustDomain(),
		"not_after", ca.NotAfter().UTC().Format(time.RFC3339))
}

// verifierOrNil is the plan's verifier, nil for a disabled worker CA (a nil
// plan).
func (p *workerCAPlan) verifierOrNil() *workerca.Verifier {
	if p == nil {
		return nil
	}
	return p.verifier
}
