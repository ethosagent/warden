package controlplane

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/workerca"
)

// The enrollment endpoint (W-P2-WCA-02): a worker trades a wet_ token and a CSR
// for a worker certificate. It is outside the session, CSRF and admin-audit
// middleware; the token is the credential, and the handler appends its own
// worker.enrolled row.
const (
	enrollPath = "/control/enroll"
	// enrollBodyMax caps the request body.
	enrollBodyMax = 16 << 10
	// enrollPerMinute is the request budget per remote address and per token id.
	enrollPerMinute = 10
	// enrollLogEvery is the quiet period of one rejection log line per reason
	// and remote address.
	enrollLogEvery = time.Minute
	maxEnrollLogs  = 4096

	defaultWorkerCertTTL = 24 * time.Hour

	// auditTargetWorkerCerts is the admin audit target of enrollment rows.
	auditTargetWorkerCerts = "worker_certs"
	actionWorkerEnrolled   = "worker.enrolled"
)

// Enrollment outcomes, the label of warden_cp_worker_enroll_total.
const (
	EnrollOutcomeOK            = "ok"
	EnrollOutcomeBadToken      = "bad_token"
	EnrollOutcomeBadCSR        = "bad_csr"
	EnrollOutcomeRateLimited   = "rate_limited"
	EnrollOutcomeCAUnavailable = "ca_unavailable"
)

var enrollOutcomes = []string{EnrollOutcomeOK, EnrollOutcomeBadToken, EnrollOutcomeBadCSR, EnrollOutcomeRateLimited, EnrollOutcomeCAUnavailable}

// enrollState is what handleEnroll needs; nil when the route is not mounted.
type enrollState struct {
	tokens EnrollmentTokenStore
	certs  WorkerCertStore
	ttl    time.Duration
	clk    clock.Clock
	log    *slog.Logger

	byAddr, byToken *sessionLimiter
	counts          map[string]*atomic.Int64

	logMu  sync.Mutex
	logged map[string]time.Time
}

// newEnrollState returns nil unless workerCA is enabled and both stores exist.
func newEnrollState(cfg Config) *enrollState {
	if !cfg.WorkerCAEnabled || cfg.Enrollment == nil || cfg.WorkerCerts == nil {
		return nil
	}
	ttl := cfg.WorkerCertTTL
	if ttl <= 0 {
		ttl = defaultWorkerCertTTL
	}
	e := &enrollState{
		tokens: cfg.Enrollment, certs: cfg.WorkerCerts, ttl: ttl, clk: cfg.Clock, log: cfg.Logger,
		byAddr:  newSessionLimiter(cfg.Clock, enrollPerMinute, time.Minute),
		byToken: newSessionLimiter(cfg.Clock, enrollPerMinute, time.Minute),
		counts:  map[string]*atomic.Int64{}, logged: map[string]time.Time{},
	}
	for _, o := range enrollOutcomes {
		e.counts[o] = new(atomic.Int64)
	}
	return e
}

// EnrollCount is the in-memory warden_cp_worker_enroll_total{outcome} counter
// (0 when enrollment is not mounted). The labels are the EnrollOutcome*
// constants; it holds no token, address or worker id.
func (s *Server) EnrollCount(outcome string) int64 {
	if s.enroll == nil || s.enroll.counts[outcome] == nil {
		return 0
	}
	return s.enroll.counts[outcome].Load()
}

// reject counts the outcome and, at most once per reason and remote address a
// minute, logs `worker enroll rejected`. It never logs the token, its hash or
// the CSR.
func (e *enrollState) reject(outcome, reason, tokenID, addr string) {
	e.counts[outcome].Add(1)
	now := e.clk.Now()
	key := reason + "\x00" + addr
	e.logMu.Lock()
	if last, ok := e.logged[key]; ok && now.Sub(last) < enrollLogEvery {
		e.logMu.Unlock()
		return
	}
	if len(e.logged) >= maxEnrollLogs {
		for k, t := range e.logged {
			if now.Sub(t) >= enrollLogEvery {
				delete(e.logged, k)
			}
		}
	}
	e.logged[key] = now
	e.logMu.Unlock()
	attrs := []any{"reason", reason, "remote_addr", addr}
	if tokenID != "" {
		attrs = append(attrs, "token_id", tokenID)
	}
	e.log.Warn("worker enroll rejected", attrs...)
}

type enrollRequest struct {
	Token          string `json:"token"`
	CSR            string `json:"csr"`
	WorkerIDSuffix string `json:"workerIdSuffix"`
}

type enrollResponse struct {
	WorkerID    string   `json:"workerId"`
	SpiffeID    string   `json:"spiffeId"`
	Certificate string   `json:"certificate"`
	Chain       []string `json:"chain"`
	Serial      string   `json:"serial"`
	NotAfter    string   `json:"notAfter"`
}

func writeEnrollJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeEnrollError(w http.ResponseWriter, status int, code string) {
	writeEnrollJSON(w, status, map[string]string{"error": code})
}

// unauthorizedEnroll is the one 401 body for an unknown, used-up, expired or
// revoked token, so the status never says which.
func unauthorizedEnroll(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	retryAfter(w, wait)
	writeEnrollError(w, http.StatusTooManyRequests, "rate_limited")
}

// handleEnroll is POST /control/enroll.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	e := s.enroll
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addr := remoteHost(r)
	if ok, wait := e.byAddr.allow(addr); !ok {
		e.reject(EnrollOutcomeRateLimited, "rate_limited_addr", "", addr)
		tooMany(w, wait)
		return
	}
	// A degraded CA is checked before anything is consumed: the worker retries
	// with the same token once the key loads.
	ca := s.WorkerCA()
	if ca == nil {
		e.reject(EnrollOutcomeCAUnavailable, "ca_unavailable", "", addr)
		writeEnrollError(w, http.StatusServiceUnavailable, "ca_unavailable")
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, enrollBodyMax)).Decode(&req); err != nil {
		e.reject(EnrollOutcomeBadCSR, "bad_request", "", addr)
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		writeEnrollError(w, status, "bad_request")
		return
	}
	// The CSR and the worker id are checked before the token is consumed, so a
	// malformed request leaves a single-use token usable.
	csr, err := workerca.ParseCSRPEM([]byte(req.CSR))
	if err == nil {
		err = workerca.CheckCSR(csr)
	}
	if err != nil {
		e.reject(EnrollOutcomeBadCSR, "bad_csr", "", addr)
		writeEnrollError(w, http.StatusBadRequest, "bad_csr")
		return
	}
	tok, err := e.tokens.Peek(req.Token)
	if tok.ID != "" {
		if ok, wait := e.byToken.allow(tok.ID); !ok {
			e.reject(EnrollOutcomeRateLimited, "rate_limited_token", tok.ID, addr)
			tooMany(w, wait)
			return
		}
	}
	if err != nil {
		e.reject(EnrollOutcomeBadToken, enrollReason(err), tok.ID, addr)
		unauthorizedEnroll(w)
		return
	}
	if _, err := tok.ResolveWorkerID(req.WorkerIDSuffix); err != nil {
		e.reject(EnrollOutcomeBadCSR, "bad_worker_id", tok.ID, addr)
		writeEnrollError(w, http.StatusBadRequest, "bad_worker_id")
		return
	}

	res, err := e.tokens.Redeem(r.Context(), req.Token, req.WorkerIDSuffix, func(workerID string) (*x509.Certificate, error) {
		return ca.Issue(csr, workerID, e.ttl)
	})
	switch {
	case errors.Is(err, ErrEnrollUnknown), errors.Is(err, ErrEnrollRevoked), errors.Is(err, ErrEnrollExpired), errors.Is(err, ErrEnrollExhausted):
		// Lost a race with another redemption or a revoke after Peek.
		e.reject(EnrollOutcomeBadToken, enrollReason(err), tok.ID, addr)
		unauthorizedEnroll(w)
		return
	case errors.Is(err, ErrEnrollBadWorkerID):
		e.reject(EnrollOutcomeBadCSR, "bad_worker_id", tok.ID, addr)
		writeEnrollError(w, http.StatusBadRequest, "bad_worker_id")
		return
	case errors.Is(err, workerca.ErrBadCSR), errors.Is(err, workerca.ErrUnsupportedKey):
		e.reject(EnrollOutcomeBadCSR, "bad_csr", tok.ID, addr)
		writeEnrollError(w, http.StatusBadRequest, "bad_csr")
		return
	case err != nil:
		s.cfg.Logger.Error("worker enroll failed", "token_id", tok.ID, "remote_addr", addr, "error", err.Error())
		writeEnrollError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	serial := res.Cert.SerialNumber.Text(16)
	if err := s.finishEnroll(r.Context(), ca, res, serial, addr); err != nil {
		s.cfg.Logger.Error("worker enroll failed", "token_id", tok.ID, "worker_id", res.WorkerID, "remote_addr", addr, "error", err.Error())
		writeEnrollError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	e.counts[EnrollOutcomeOK].Add(1)
	s.cfg.Logger.Info("worker enrolled", "worker_id", res.WorkerID, "serial", serial, "token_id", res.Token.ID)

	chain := ca.Chain()
	out := enrollResponse{
		WorkerID: res.WorkerID, SpiffeID: res.Cert.URIs[0].String(), Certificate: string(workerca.EncodeCertsPEM(res.Cert)),
		Serial: serial, NotAfter: res.Cert.NotAfter.UTC().Format(time.RFC3339),
	}
	for _, c := range chain {
		out.Chain = append(out.Chain, string(workerca.EncodeCertsPEM(c)))
	}
	writeEnrollJSON(w, http.StatusCreated, out)
}

// finishEnroll checks what the control plane is about to hand out and records
// the worker.enrolled audit row. The issued certificate must verify against the
// pinned intermediates for the id it was issued for, and the chain returned to
// the worker must be a real one (each certificate signed by the next); when a
// check or the audit append fails the certificate is revoked again, so no
// credential leaves without its audit entry.
func (s *Server) finishEnroll(ctx context.Context, ca *workerca.CA, res Redeemed, serial, addr string) error {
	err := verifyEnrollChain(ca, res)
	if err == nil && s.auditRec != nil {
		_, err = s.auditRec.Record(ctx, adminaudit.Input{
			Actor:      adminaudit.Actor{Sub: "enroll:" + res.Token.ID},
			AuthMethod: adminaudit.AuthMethodSystem,
			Action:     actionWorkerEnrolled,
			Target:     auditTargetWorkerCerts,
			TargetRef:  "worker:" + res.WorkerID,
			Details:    map[string]string{"token_id": res.Token.ID, "serial": serial},
			Outcome:    adminaudit.OutcomeOK,
			HTTPStatus: http.StatusCreated,
			ClientIP:   addr,
		})
	}
	if err == nil {
		return nil
	}
	if rerr := s.enroll.certs.RevokeCert(context.WithoutCancel(ctx), serial, "enroll:"+res.Token.ID, "enroll_failed"); rerr != nil {
		s.cfg.Logger.Error("worker enroll: revoking the unrecorded certificate failed", "serial", serial, "error", rerr.Error())
	}
	return err
}

// verifyEnrollChain proves the issued certificate chains to the pinned
// intermediate for the right worker, and that every certificate of the chain
// the response carries was signed by the next one.
func verifyEnrollChain(ca *workerca.CA, res Redeemed) error {
	id, err := ca.Verify(res.Cert)
	if err != nil {
		return err
	}
	if id != res.WorkerID {
		return workerca.ErrNotWorkerCert
	}
	chain := ca.Chain()
	if err := res.Cert.CheckSignatureFrom(chain[0]); err != nil {
		return err
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func enrollReason(err error) string {
	switch {
	case errors.Is(err, ErrEnrollRevoked):
		return "revoked"
	case errors.Is(err, ErrEnrollExpired):
		return "expired"
	case errors.Is(err, ErrEnrollExhausted):
		return "exhausted"
	}
	return "unknown_token"
}
