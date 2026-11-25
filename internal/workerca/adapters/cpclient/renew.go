package cpclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// Renewal outcomes, the label of warden_worker_cert_renewals_total.
const (
	OutcomeOK           = "ok"
	OutcomeUnauthorized = "unauthorized"
	OutcomeRateLimited  = "rate_limited"
	OutcomeRejected     = "rejected"
	OutcomeError        = "error"
)

// Renewal timing.
const (
	// renewFraction of the remaining lifetime passes before a renewal fires.
	renewFraction = 0.5
	// renewJitter is the share of that interval the jitter moves it by.
	renewJitter = 0.1
	// BackoffMin and BackoffMax bound the retry delay after a failed renewal.
	BackoffMin = 5 * time.Second
	BackoffMax = 5 * time.Minute
)

// Renewer keeps the worker's certificate fresh: at about half of its lifetime
// it posts a fresh-key CSR to /control/renew over the shared client (which
// presents the current certificate), persists the answer, swaps it into the
// Source and drops idle connections so the next handshake presents it. A failed
// renewal retries with exponential backoff and the current certificate stays
// in use until it expires.
type Renewer struct {
	// Endpoint is the full URL of /control/renew.
	Endpoint string
	// HTTP is the shared control-plane client: its TLS handshake presents
	// Source's certificate.
	HTTP *http.Client
	// Source holds the certificate in use; it must hold one.
	Source *Source
	// StateDir is where the renewed key and certificate are persisted.
	StateDir string
	// Clock drives the schedule; nil means the real clock.
	Clock clock.Clock
	// Jitter returns a value in [-1, 1] that moves each wait by up to 10%; nil
	// draws from crypto/rand, a test passes func() float64 { return 0 }.
	Jitter func() float64
	// CloseIdle drops pooled connections after a swap (the shared transport's
	// CloseIdleConnections).
	CloseIdle func()
	// OnRenew receives each attempt's outcome (the Outcome* constants).
	OnRenew func(outcome string)
	// Logger may be nil.
	Logger *slog.Logger

	// unpersisted is a renewed certificate that is installed but not yet on
	// disk. Only the Run goroutine touches it.
	unpersisted *Credential
}

// flushPersist retries writing a renewed certificate that could not be written,
// with the renewal backoff, until it lands or the next renewal is due (which
// writes a newer one). It reports false when ctx ended.
func (r *Renewer) flushPersist(ctx context.Context) bool {
	pending := r.unpersisted
	if pending == nil {
		return true
	}
	next := pending.ReceivedAt.Add(pending.NotAfter().Sub(pending.ReceivedAt) / 2)
	backoff := BackoffMin
	for r.clk().Now().Before(next) {
		if !r.sleep(ctx, backoff) {
			return false
		}
		if err := persist(r.StateDir, pending); err == nil {
			r.unpersisted = nil
			if r.Logger != nil {
				r.Logger.Info("worker certificate persisted", "serial", pending.Serial())
			}
			return true
		}
		if backoff *= 2; backoff > BackoffMax {
			backoff = BackoffMax
		}
	}
	r.unpersisted = nil
	return true
}

func (r *Renewer) clk() clock.Clock {
	if r.Clock != nil {
		return r.Clock
	}
	return clock.Real()
}

func (r *Renewer) jitter() float64 {
	if r.Jitter != nil {
		return r.Jitter()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11)/float64(1<<52) - 1 // [-1, 1)
}

// renewAfter is how long after the certificate was received its renewal fires:
// half of its remaining lifetime, moved by the jitter share. It is never negative.
func (r *Renewer) renewAfter(c *Credential) time.Duration {
	life := c.NotAfter().Sub(c.ReceivedAt)
	d := time.Duration(float64(life) * renewFraction * (1 + renewJitter*r.jitter()))
	return max(d, 0)
}

// Run renews until ctx ends. It returns immediately when Source holds no
// certificate.
func (r *Renewer) Run(ctx context.Context) {
	for ctx.Err() == nil {
		cur := r.Source.Current()
		if cur == nil {
			return
		}
		// Never sooner than BackoffMin: a certificate issued with a lifetime of
		// seconds must not turn the renewer into a tight loop against the CP.
		due := cur.ReceivedAt.Add(r.renewAfter(cur))
		if !r.sleep(ctx, max(due.Sub(r.clk().Now()), BackoffMin)) {
			return
		}
		backoff := BackoffMin
		for ctx.Err() == nil {
			outcome, err := r.renewOnce(ctx, cur)
			if r.OnRenew != nil {
				r.OnRenew(outcome)
			}
			if err == nil {
				if !r.flushPersist(ctx) {
					return
				}
				break
			}
			if r.Logger != nil && ctx.Err() == nil {
				r.Logger.Warn("worker cert renewal failed; keeping the current certificate", "outcome", outcome,
					"serial", cur.Serial(), "not_after", cur.NotAfter().UTC().Format(time.RFC3339),
					"retry_in", backoff.String(), "error", err.Error())
			}
			if !r.sleep(ctx, time.Duration(float64(backoff)*(1+renewJitter*r.jitter()))) {
				return
			}
			if backoff *= 2; backoff > BackoffMax {
				backoff = BackoffMax
			}
		}
	}
}

// sleep waits d on the clock; it reports false when ctx ended first.
func (r *Renewer) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-r.clk().After(d):
		return true
	}
}

// renewOnce makes one renewal attempt from cur and, on success, persists and
// installs the new certificate.
func (r *Renewer) renewOnce(ctx context.Context, cur *Credential) (string, error) {
	key, csr, err := newKeyCSR()
	if err != nil {
		return OutcomeError, err
	}
	resp, err := post(ctx, r.HTTP, r.Endpoint, map[string]string{"csr": csr})
	if err != nil {
		return outcomeOf(err), fmt.Errorf("cpclient: renew: %w", err)
	}
	got, err := verifyIssued(resp, key, r.clk().Now(), cur.WorkerID(), cur.trustDomain())
	if err != nil {
		return OutcomeRejected, fmt.Errorf("cpclient: renew: %w", err)
	}
	// The control plane already counts the new certificate as the worker's
	// lineage head, so it is installed even when it cannot be written: a retry
	// from the superseded serial would look like a copied key.
	if perr := persist(r.StateDir, got); perr != nil {
		r.unpersisted = got
		if r.Logger != nil {
			r.Logger.Error("worker cert renewed but could not be persisted; retrying. A restart before it is written reloads the superseded certificate, whose renewal the control plane treats as a copied key (lineage conflict) and revokes the worker",
				"serial", got.Serial(), "error", perr.Error())
		}
	}
	r.Source.Set(got)
	if r.CloseIdle != nil {
		r.CloseIdle()
	}
	if r.Logger != nil {
		r.Logger.Info("worker certificate renewed", "serial", got.Serial(), "prev_serial", cur.Serial(),
			"not_after", got.NotAfter().UTC().Format(time.RFC3339))
	}
	return OutcomeOK, nil
}

func outcomeOf(err error) string {
	var cpe *ControlPlaneError
	switch {
	case !errors.As(err, &cpe):
		return OutcomeError
	case cpe.Status == http.StatusUnauthorized:
		return OutcomeUnauthorized
	case cpe.Status == http.StatusTooManyRequests:
		return OutcomeRateLimited
	}
	return OutcomeError
}
