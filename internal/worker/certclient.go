package worker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/workerca/adapters/cpclient"
)

// The worker's mTLS identity (W-P2-WCA-03). One workerCert per worker holds the
// single source of the current client certificate and the one control-plane
// transport whose TLS handshake presents it. The policy client, the heartbeat
// and the ingest forwarder all send through clients that share that transport,
// so a renewal reaches every one of them at once.

const (
	// cpClientTimeout is the timeout of the clients derived from the shared transport.
	cpClientTimeout = 10 * time.Second
	// certExpiryCheck is how often the expiry watcher looks at the certificate.
	certExpiryCheck = time.Minute
	// certExpiredLogEvery is the quiet period of the `worker cert expired` ERROR.
	certExpiredLogEvery = time.Hour
	// enrollTimeout bounds one enrollment request.
	enrollTimeout = 30 * time.Second
)

// cpTransport is the one control-plane transport. A renewed certificate takes
// effect through Rotate: TLS presents the certificate once per connection, and a
// held long-poll (or an HTTP/2 connection that never goes idle) would keep the
// old one for as long as it lives. Rotate sends every later request over a fresh
// transport, so its handshake presents the current certificate, and lets the
// requests in flight finish on the old one, which idles out by itself.
type cpTransport struct {
	base *http.Transport // template only: never used for a request
	cur  atomic.Pointer[http.Transport]
}

func newCPTransport(base *http.Transport) *cpTransport {
	base.IdleConnTimeout = 90 * time.Second
	t := &cpTransport{base: base}
	t.cur.Store(base.Clone())
	return t
}

// RoundTrip implements http.RoundTripper.
func (t *cpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.cur.Load().RoundTrip(req)
}

// CloseIdleConnections drops the pooled idle connections (http.Client uses it).
func (t *cpTransport) CloseIdleConnections() { t.cur.Load().CloseIdleConnections() }

// Rotate starts a new connection pool and closes the idle connections of the old one.
func (t *cpTransport) Rotate() {
	t.cur.Swap(t.base.Clone()).CloseIdleConnections()
}

// workerCert is a worker's certificate machinery. nil when the worker
// authenticates with the bearer token.
type workerCert struct {
	source    *cpclient.Source
	transport *cpTransport
	// enroller is nil for a certificate issued outside Warden.
	enroller *cpclient.Enroller
	renewURL string
	clk      clock.Clock
	logger   *slog.Logger
	// proxyID is central.proxyID after env expansion ("" when unset).
	proxyID string
	// centralShared is true when central.endpoint is on the control plane's
	// origin, so the ingest forwarder presents the certificate too. A separate
	// aggregator keeps its bearer client (and its own trust).
	centralShared bool
	// jitter feeds the renewer (nil: crypto/rand); a test sets it to 0.
	jitter func() float64
}

// newWorkerCert loads or enrolls the worker certificate. It returns nil when
// the config asks for neither enrollment nor clientCert. A control plane that is
// merely unreachable leaves the worker without a certificate (it stays
// fail-closed and start retries in the background); a rejected token, an
// unreadable certificate or a worker id that contradicts central.proxyID is an
// error that stops startup.
func newWorkerCert(ctx context.Context, cfg config.ControlPlaneConfig, central config.CentralConfig, clk clock.Clock, logger *slog.Logger) (*workerCert, error) {
	if !cfg.CertAuth() {
		return nil, nil
	}
	wc := &workerCert{clk: clk, logger: logger, proxyID: expandEnv(central.ProxyID),
		centralShared: central.Mode == "worker" && sameOrigin(cfg.Endpoint, central.Endpoint)}
	// The shared pool trusts central.caCert only when the aggregator is the
	// control plane's own origin: it must not widen trust for a separate one.
	caPaths := []string{cfg.CACert}
	if wc.centralShared {
		caPaths = append(caPaths, central.CACert)
	}
	base, err := newControlPlaneTransport(wc.getClientCertificate, caPaths...)
	if err != nil {
		return nil, err
	}
	wc.transport = newCPTransport(base)
	if cfg.ClientCert != "" {
		cred, err := cpclient.LoadStatic(cfg.ClientCert, cfg.ClientKey, clk.Now())
		if err != nil {
			return nil, err
		}
		if err := wc.checkProxyID(cred, "controlPlane.clientCert"); err != nil {
			return nil, err
		}
		wc.source = cpclient.NewSource(cred)
		return wc, nil
	}

	enrollURL, err := controlURL(cfg.Endpoint, "/control/enroll")
	if err != nil {
		return nil, err
	}
	if wc.renewURL, err = controlURL(cfg.Endpoint, "/control/renew"); err != nil {
		return nil, err
	}
	// Enrollment presents no certificate: the token is the credential.
	plain, err := newControlPlaneHTTPClient(enrollTimeout, cfg.CACert)
	if err != nil {
		return nil, err
	}
	wc.enroller = &cpclient.Enroller{
		Endpoint: enrollURL, HTTP: plain, StateDir: cfg.StateDir,
		Token:  os.Getenv(cfg.Enrollment.TokenEnv),
		Suffix: workerIDSuffix(cfg.Enrollment.WorkerIDSuffixEnv),
		Now:    clk.Now, Logger: logger,
	}
	wc.source = cpclient.NewSource(nil)
	cred, err := wc.enroller.LoadOrEnroll(ctx)
	switch {
	case err == nil:
		if err := wc.checkProxyID(cred, "controlPlane.enrollment"); err != nil {
			return nil, err
		}
		wc.source.Set(cred)
	case errors.Is(err, cpclient.ErrNoToken):
		return nil, fmt.Errorf("worker has no usable certificate in %s and $%s is empty: set the enrollment token", cfg.StateDir, cfg.Enrollment.TokenEnv)
	case !errors.Is(err, cpclient.ErrUnreachable):
		// A refusal, a response that failed verification or a local file error:
		// waiting will not fix it.
		return nil, err
	default:
		logger.Warn("worker not enrolled yet: the control plane is unreachable; staying FAIL-CLOSED (deny all) and retrying", "error", err.Error())
	}
	return wc, nil
}

// checkProxyID fails when central.proxyID is set and differs from the id the
// certificate carries: the certificate is the worker's identity.
func (wc *workerCert) checkProxyID(c *cpclient.Credential, source string) error {
	if wc.proxyID != "" && wc.proxyID != c.WorkerID() {
		return fmt.Errorf("central.proxyID %q differs from the worker id %q in the certificate (%s): remove central.proxyID or issue the certificate for that id", wc.proxyID, c.WorkerID(), source)
	}
	return nil
}

// getClientCertificate is the tls.Config hook: the certificate in the source, or
// an empty certificate (no client certificate sent) when there is none or it has
// expired, so an expired credential is never offered.
func (wc *workerCert) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := wc.source.Current()
	if c == nil || c.Expired(wc.clk.Now()) {
		return &tls.Certificate{}, nil
	}
	return &tls.Certificate{Certificate: c.DER(), PrivateKey: c.Key, Leaf: c.Leaf}, nil
}

// Client returns a client with the given timeout over the shared transport.
func (wc *workerCert) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: wc.transport}
}

// WorkerID is the id in the certificate in use, or the configured
// central.proxyID while the worker holds none yet.
func (wc *workerCert) WorkerID() string {
	if c := wc.source.Current(); c != nil {
		return c.WorkerID()
	}
	return wc.proxyID
}

// certInfo is the heartbeat's view of the certificate in use.
func (wc *workerCert) certInfo() (string, time.Time, bool) {
	c := wc.source.Current()
	if c == nil {
		return "", time.Time{}, false
	}
	return c.Serial(), c.NotAfter(), true
}

// secondsToExpiry feeds warden_worker_cert_expiry_seconds.
func (wc *workerCert) secondsToExpiry() (float64, bool) {
	c := wc.source.Current()
	if c == nil {
		return 0, false
	}
	return c.NotAfter().Sub(wc.clk.Now()).Seconds(), true
}

// start runs the background work until ctx ends: enrolling when boot could not
// reach the control plane, renewing, and watching the expiry. m may be nil.
func (wc *workerCert) start(ctx context.Context, m *observability.Metrics) {
	if err := m.RegisterWorkerCertExpiry(wc.secondsToExpiry); err != nil {
		wc.logger.Warn("worker cert expiry metric not registered", "error", err.Error())
	}
	go wc.watchExpiry(ctx)
	if wc.enroller == nil {
		return // a certificate issued outside Warden is never renewed
	}
	go func() {
		if wc.source.Current() == nil && !wc.enrollUntilDone(ctx) {
			return
		}
		(&cpclient.Renewer{
			Endpoint: wc.renewURL, HTTP: wc.Client(enrollTimeout), Source: wc.source, StateDir: wc.enroller.StateDir,
			Clock: wc.clk, Jitter: wc.jitter, CloseIdle: wc.transport.Rotate, Logger: wc.logger,
			OnRenew: m.RecordWorkerCertRenewal,
		}).Run(ctx)
	}()
}

// enrollUntilDone retries the enrollment of a worker that booted without a
// certificate, with the renewer's backoff (5s doubling to 5m). It reports false
// when ctx ended or the enrollment can never succeed.
func (wc *workerCert) enrollUntilDone(ctx context.Context) bool {
	backoff := cpclient.BackoffMin
	for {
		select {
		case <-ctx.Done():
			return false
		case <-wc.clk.After(backoff):
		}
		cred, err := wc.enroller.LoadOrEnroll(ctx)
		switch {
		case err == nil:
			if perr := wc.checkProxyID(cred, "controlPlane.enrollment"); perr != nil {
				wc.logger.Error("worker certificate refused; staying FAIL-CLOSED", "error", perr.Error())
				return false
			}
			wc.source.Set(cred)
			wc.transport.Rotate()
			wc.logger.Info("worker enrolled", "worker_id", cred.WorkerID(), "serial", cred.Serial())
			return true
		case !errors.Is(err, cpclient.ErrUnreachable):
			wc.logger.Error("worker enrollment failed for good; staying FAIL-CLOSED", "error", err.Error())
			return false
		}
		wc.logger.Warn("worker enrollment failed; retrying", "retry_in", backoff.String(), "error", err.Error())
		if backoff *= 2; backoff > cpclient.BackoffMax {
			backoff = cpclient.BackoffMax
		}
	}
}

// watchExpiry logs `worker cert expired` at ERROR, at most once an hour, while
// the certificate in use is past its expiry. The worker keeps enforcing its
// last-known-good policy meanwhile (the policy engine does not depend on the
// certificate); only its control-plane calls fail.
func (wc *workerCert) watchExpiry(ctx context.Context) {
	var logged time.Time
	t := wc.clk.NewTimer(certExpiryCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			t.Reset(certExpiryCheck)
		}
		c := wc.source.Current()
		now := wc.clk.Now()
		if c == nil || !c.Expired(now) {
			continue
		}
		if due := logged.IsZero() || now.Sub(logged) >= certExpiredLogEvery; due {
			logged = now
			wc.logger.Error("worker cert expired", "worker_id", c.WorkerID(), "serial", c.Serial(),
				"not_after", c.NotAfter().UTC().Format(time.RFC3339))
		}
	}
}

// sameOrigin reports whether two URLs share scheme and host (with port).
func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Host != "" && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// controlURL is the control plane's path on the host of the policy endpoint.
func controlURL(policyEndpoint, path string) (string, error) {
	u, err := url.Parse(policyEndpoint)
	if err != nil {
		return "", fmt.Errorf("controlPlane.endpoint: %w", err)
	}
	u.Path, u.RawQuery = path, ""
	return u.String(), nil
}

// workerIDSuffix is the suffix a prefix-bound enrollment token appends: the
// value of env, else the hostname, restricted to the characters of a worker id.
func workerIDSuffix(env string) string {
	v := ""
	if env != "" {
		v = strings.TrimSpace(os.Getenv(env))
	}
	if v == "" {
		v, _ = os.Hostname()
	}
	b := []byte(v)
	for i, c := range b {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			b[i] = '-'
		}
	}
	if len(b) > 100 {
		b = b[:100]
	}
	return string(b)
}
