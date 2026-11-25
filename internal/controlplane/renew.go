package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/workerca"
)

// POST /control/renew (W-P2-WCA-04): a worker trades a CSR for a fresh
// certificate, authenticating with the certificate it holds (mutual TLS, no
// bearer). The new certificate keeps the worker id and lengthens the lineage
// one link (prev_serial); the rule that keeps a copied key from renewing
// quietly in parallel is RenewCert's.
const (
	renewPath = "/control/renew"
	// renewMinInterval is the least time between two renewals of one worker.
	renewMinInterval = 10 * time.Minute
	// renewGraceMax bounds the renewals one worker may retry from a predecessor
	// (a lost response) inside renewMinInterval.
	renewGraceMax = 3
	// renewPerMinute is the request budget per remote address.
	renewPerMinute = 30

	actionLineageConflict = "worker.cert_lineage_conflict"
	// lineageActor is the actor of the revocation a lineage conflict triggers.
	lineageActor = "system:cert_lineage"
)

// Renewal outcomes, the label of warden_cp_worker_renew_total.
const (
	RenewOutcomeOK              = "ok"
	RenewOutcomeUnauthorized    = "unauthorized"
	RenewOutcomeBadCSR          = "bad_csr"
	RenewOutcomeRateLimited     = "rate_limited"
	RenewOutcomeLineageConflict = "lineage_conflict"
	RenewOutcomeCAUnavailable   = "ca_unavailable"
	RenewOutcomeError           = "error"
)

var renewOutcomes = []string{RenewOutcomeOK, RenewOutcomeUnauthorized, RenewOutcomeBadCSR, RenewOutcomeRateLimited,
	RenewOutcomeLineageConflict, RenewOutcomeCAUnavailable, RenewOutcomeError}

// renewState is what handleRenew keeps next to the enrollment state.
type renewState struct {
	byAddr *sessionLimiter
	lim    *renewLimiter
	counts map[string]*atomic.Int64
}

func newRenewState(e *enrollState) *renewState {
	rs := &renewState{
		byAddr: newSessionLimiter(e.clk, renewPerMinute, time.Minute),
		lim:    &renewLimiter{clk: e.clk, last: map[string]time.Time{}, grace: map[string][]time.Time{}},
		counts: map[string]*atomic.Int64{},
	}
	for _, o := range renewOutcomes {
		rs.counts[o] = new(atomic.Int64)
	}
	return rs
}

// RenewCount is the in-memory warden_cp_worker_renew_total{outcome} counter (0
// when renewal is not mounted). The labels are the RenewOutcome* constants.
func (s *Server) RenewCount(outcome string) int64 {
	if s.enroll == nil || s.enroll.renew.counts[outcome] == nil {
		return 0
	}
	return s.enroll.renew.counts[outcome].Load()
}

// renewLimiter allows one renewal per worker per renewMinInterval, plus up to
// renewGraceMax retries from a predecessor (a response lost on the way) in the
// same window. It is in memory: a restart forgets it, and RenewCert's lineage
// rule, not this, is what stops a forked chain.
type renewLimiter struct {
	clk clock.Clock
	mu  sync.Mutex
	// last is the time of the worker's latest admitted renewal.
	last  map[string]time.Time
	grace map[string][]time.Time
}

// check reports whether a renewal of worker is within budget without spending
// it; when it is not, wait is how long until it would be.
func (l *renewLimiter) check(worker string, grace bool) (ok bool, wait time.Duration) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if grace {
		recent := 0
		var oldest time.Time
		for _, t := range l.grace[worker] {
			if now.Sub(t) < renewMinInterval {
				if recent == 0 {
					oldest = t
				}
				recent++
			}
		}
		if recent >= renewGraceMax {
			return false, renewMinInterval - now.Sub(oldest)
		}
		return true, 0
	}
	if t, seen := l.last[worker]; seen && now.Sub(t) < renewMinInterval {
		return false, renewMinInterval - now.Sub(t)
	}
	return true, 0
}

// record spends one renewal of worker. It is called only after the renewal
// committed, so a CA or database error never leaves the worker rate limited.
func (l *renewLimiter) record(worker string, grace bool) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.last) >= maxLimiterKeys {
		for k, t := range l.last {
			if now.Sub(t) >= renewMinInterval {
				delete(l.last, k)
				delete(l.grace, k)
			}
		}
	}
	if grace {
		recent := l.grace[worker][:0]
		for _, t := range l.grace[worker] {
			if now.Sub(t) < renewMinInterval {
				recent = append(recent, t)
			}
		}
		l.grace[worker] = append(recent, now)
	}
	l.last[worker] = now
}

type renewRequest struct {
	CSR string `json:"csr"`
}

type renewResponse struct {
	enrollResponse
	PrevSerial string `json:"prevSerial"`
}

// renewReject counts the outcome and logs `worker renew rejected` at most once
// a minute per reason and remote address. It never logs the CSR.
func (s *Server) renewReject(outcome, reason, workerID, serial, addr string) {
	e := s.enroll
	e.renew.counts[outcome].Add(1)
	if !e.shouldLog(reason + "\x00" + addr) {
		return
	}
	attrs := []any{"reason", reason, "remote_addr", addr}
	if workerID != "" {
		attrs = append(attrs, "worker_id", workerID)
	}
	if serial != "" {
		attrs = append(attrs, "serial", serial)
	}
	s.cfg.Logger.Warn("worker renew rejected", attrs...)
}

// handleRenew is POST /control/renew. Checks run in this order: remote address
// budget, certificate authentication, CA availability, body and CSR, new key,
// then the lineage rule and the per-worker limit inside RenewCert's
// transaction; nothing is issued before all of them pass.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	e := s.enroll
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addr := remoteHost(r)
	if ok, wait := e.renew.byAddr.allow(addr); !ok {
		s.renewReject(RenewOutcomeRateLimited, "rate_limited_addr", "", "", addr)
		tooMany(w, wait)
		return
	}
	// Renewal needs a certificate principal: no bearer, shared token or
	// anonymous caller is ever accepted here, whatever the auth mode.
	p, err := s.workerAuth.AuthenticateCert(r)
	if err != nil {
		s.enroll.renew.counts[RenewOutcomeUnauthorized].Add(1)
		WriteWorkerAuthError(w, err)
		return
	}
	ca := s.WorkerCA()
	if ca == nil {
		s.renewReject(RenewOutcomeCAUnavailable, "ca_unavailable", p.ProxyID, p.CertSerial, addr)
		writeEnrollError(w, http.StatusServiceUnavailable, "ca_unavailable")
		return
	}
	var req renewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, enrollBodyMax)).Decode(&req); err != nil {
		s.renewReject(RenewOutcomeBadCSR, "bad_request", p.ProxyID, p.CertSerial, addr)
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		writeEnrollError(w, status, "bad_request")
		return
	}
	csr, err := workerca.ParseCSRPEM([]byte(req.CSR))
	if err == nil {
		err = workerca.CheckCSR(csr)
	}
	if err != nil {
		s.renewReject(RenewOutcomeBadCSR, "bad_csr", p.ProxyID, p.CertSerial, addr)
		writeEnrollError(w, http.StatusBadRequest, "bad_csr")
		return
	}
	// A renewal must rotate the key: the same public key would make a stolen
	// certificate's key outlive every renewal.
	if leaf := presentedCert(r); leaf == nil || bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		s.renewReject(RenewOutcomeBadCSR, "same_key", p.ProxyID, p.CertSerial, addr)
		writeEnrollError(w, http.StatusBadRequest, "same_key")
		return
	}

	var (
		wait  time.Duration
		grace bool
	)
	spki := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	rec, cert, err := e.certs.RenewCert(r.Context(), p.ProxyID, p.CertSerial, hex.EncodeToString(spki[:]),
		func(serial string) bool { return s.workerAuth.SeenCertSerial(p.ProxyID, serial) },
		func(g bool) bool {
			// Checked before issuing; spent only once the renewal committed.
			var ok bool
			ok, wait = e.renew.lim.check(p.ProxyID, g)
			grace = g
			return ok
		},
		func(workerID string) (*x509.Certificate, *x509.Certificate, error) {
			c, err := ca.Issue(csr, workerID, e.ttl)
			return c, ca.Intermediate(), err
		})
	switch {
	case errors.Is(err, ErrRenewRateLimited):
		s.renewReject(RenewOutcomeRateLimited, "rate_limited_worker", p.ProxyID, p.CertSerial, addr)
		tooMany(w, wait)
		return
	case errors.Is(err, ErrSameKey):
		s.renewReject(RenewOutcomeBadCSR, "same_key", p.ProxyID, p.CertSerial, addr)
		writeEnrollError(w, http.StatusBadRequest, "same_key")
		return
	case errors.Is(err, ErrLineageConflict):
		s.lineageConflict(r.Context(), p, addr)
		unauthorizedRenew(w)
		return
	case errors.Is(err, ErrCertRevoked), errors.Is(err, ErrCertNotFound):
		// Revoked since the index last loaded, or a serial this database never
		// issued (a restored older backup): either way not a current certificate.
		reason := "revoked"
		if errors.Is(err, ErrCertNotFound) {
			reason = "unknown_serial"
		}
		s.renewReject(RenewOutcomeUnauthorized, reason, p.ProxyID, p.CertSerial, addr)
		unauthorizedRenew(w)
		return
	case errors.Is(err, workerca.ErrBadCSR), errors.Is(err, workerca.ErrUnsupportedKey):
		s.renewReject(RenewOutcomeBadCSR, "bad_csr", p.ProxyID, p.CertSerial, addr)
		writeEnrollError(w, http.StatusBadRequest, "bad_csr")
		return
	case err != nil:
		e.renew.counts[RenewOutcomeError].Add(1)
		s.cfg.Logger.Error("worker renew failed", "worker_id", p.ProxyID, "serial", p.CertSerial, "remote_addr", addr, "error", err.Error())
		writeEnrollError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	e.renew.lim.record(p.ProxyID, grace)
	if grace {
		// The unused successor was revoked as superseded: cut off its long-polls now.
		s.syncCertIndex(r.Context())
	}
	if err := s.finishRenew(r.Context(), ca, cert, p); err != nil {
		e.renew.counts[RenewOutcomeError].Add(1)
		s.cfg.Logger.Error("worker renew failed", "worker_id", p.ProxyID, "serial", rec.Serial, "remote_addr", addr, "error", err.Error())
		writeEnrollError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	e.renew.counts[RenewOutcomeOK].Add(1)
	s.cfg.Logger.Info("worker certificate renewed", "worker_id", p.ProxyID, "serial", rec.Serial, "prev_serial", p.CertSerial)

	out := renewResponse{PrevSerial: p.CertSerial, enrollResponse: enrollResponse{
		WorkerID: p.ProxyID, SpiffeID: cert.URIs[0].String(), Certificate: string(workerca.EncodeCertsPEM(cert)),
		Serial: rec.Serial, NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
	}}
	for _, c := range ca.Chain() {
		out.Chain = append(out.Chain, string(workerca.EncodeCertsPEM(c)))
	}
	writeEnrollJSON(w, http.StatusCreated, out)
}

func unauthorizedRenew(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// finishRenew checks what the control plane is about to hand out: the
// certificate must verify for the worker it was issued to, signed by the
// intermediate. When it does not, the certificate is revoked again. Renewals
// are logged and counted, not admin-audited (the worker presented a live
// certificate; only a lineage conflict is a security event).
func (s *Server) finishRenew(ctx context.Context, ca *workerca.CA, cert *x509.Certificate, p WorkerPrincipal) error {
	serial := cert.SerialNumber.Text(16)
	id, err := ca.Verify(cert)
	if err == nil && id != p.ProxyID {
		err = workerca.ErrNotWorkerCert
	}
	if err == nil {
		err = cert.CheckSignatureFrom(ca.Intermediate())
	}
	if err == nil {
		return nil
	}
	if rerr := s.enroll.certs.RevokeCert(context.WithoutCancel(ctx), serial, "worker:"+p.ProxyID, RevokeReasonRenewFailed); rerr != nil {
		s.cfg.Logger.Error("worker renew: revoking the unverified certificate failed", "serial", serial, "error", rerr.Error())
	}
	s.syncCertIndex(ctx)
	return err
}

// lineageConflict handles a renewal from a serial that is not the worker's
// lineage head: two holders of one key exist, so the worker is revoked (every
// certificate, its unused enrollment tokens), the held long-polls are cut off,
// and worker.cert_lineage_conflict is recorded. The worker re-enrolls with a new
// admin-issued token.
func (s *Server) lineageConflict(ctx context.Context, p WorkerPrincipal, addr string) {
	e := s.enroll
	ctx = context.WithoutCancel(ctx)
	serials, err := e.certs.RevokeWorker(ctx, p.ProxyID, lineageActor, RevokeReasonLineage)
	if err != nil {
		s.cfg.Logger.Error("worker cert lineage conflict: revoking the worker failed", "worker_id", p.ProxyID, "serial", p.CertSerial, "error", err.Error())
	}
	s.syncCertIndex(ctx)
	s.certsRevoked.Add(int64(len(serials)))
	if err == nil && len(serials) == 0 {
		// Already revoked by an earlier conflict: count, but do not repeat the
		// ERROR line and audit row for every further use of a dead key.
		s.enroll.renew.counts[RenewOutcomeLineageConflict].Add(1)
		return
	}
	s.renewReject(RenewOutcomeLineageConflict, "lineage_conflict", p.ProxyID, p.CertSerial, addr)
	s.cfg.Logger.Error("worker cert lineage conflict: the worker was revoked", "worker_id", p.ProxyID, "serial", p.CertSerial, "revoked", len(serials))
	if s.auditRec == nil {
		return
	}
	if _, aerr := s.auditRec.Record(ctx, adminaudit.Input{
		Actor:      adminaudit.Actor{Sub: "worker:" + p.ProxyID},
		AuthMethod: adminaudit.AuthMethodSystem,
		Action:     actionLineageConflict,
		Target:     auditTargetWorkerCerts,
		TargetRef:  "worker:" + p.ProxyID,
		Details:    map[string]string{"serial": p.CertSerial, "revoked": strconv.Itoa(len(serials))},
		Outcome:    adminaudit.OutcomeDenied,
		HTTPStatus: http.StatusUnauthorized,
		ClientIP:   addr,
	}); aerr != nil {
		s.cfg.Logger.Error("worker cert lineage conflict: audit append failed", "worker_id", p.ProxyID, "error", aerr.Error())
	}
}

// syncCertIndex reloads the revoked index now, after a local revocation, so the
// worker's next request is refused without waiting for the poll (and its held
// long-polls are cancelled). A failure keeps the last index; the poll retries.
func (s *Server) syncCertIndex(ctx context.Context) {
	if s.certIdx == nil {
		return
	}
	if err := s.certIdx.Rebuild(ctx); err != nil {
		s.cfg.Logger.Warn("worker certs: revoked index reload failed after a revocation", "error", err.Error())
	}
}
