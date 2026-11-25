package controlplane

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
)

// actionWorkerRevoked is the admin audit action of a worker certificate
// revocation, from the console (this file) and the offline CLI.
const actionWorkerRevoked = "worker.revoked"

// workerRef is the admin audit target_ref of a worker.
func workerRef(id string) string { return "worker:" + id }

var serialRe = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// workerCertAdmin adapts the WorkerCertStore to dashboard.WorkerCertAdmin. It
// takes the actor from the console Principal, revokes through the store,
// refreshes the revoked index at once (an in-process write does not move
// data_version, so the poll would never see it) and so cancels the worker's
// held long-polls, and annotates the admin audit row.
type workerCertAdmin struct{ s *Server }

// Revoke implements dashboard.WorkerCertAdmin.
func (a workerCertAdmin) Revoke(ctx context.Context, workerID, serial string) (int, int, error) {
	p, ok := PrincipalFrom(ctx)
	// ActorSub: a revoke made with an API key (workers:admin) is the owner's.
	actor := p.ActorSub()
	if !ok || actor == "" {
		return 0, 0, dashboard.ErrWorkerCertNoActor
	}
	serial = strings.ToLower(serial)
	if serial != "" && !serialRe.MatchString(serial) {
		return 0, 0, fmt.Errorf("%w: serial must be lowercase hex", dashboard.ErrWorkerCertInvalid)
	}
	adminaudit.Annotate(ctx, workerRef(workerID), map[string]string{adminaudit.DetailWorkerID: workerID, adminaudit.DetailCount: "0", adminaudit.DetailEnrollTokens: "0"})
	n, tokens, err := a.s.revokeWorkerCerts(ctx, workerID, serial, actor)
	switch {
	case errors.Is(err, ErrCertNotFound):
		return 0, 0, dashboard.ErrWorkerCertNotFound
	case err != nil:
		a.s.cfg.Logger.Error("worker certs: revoke failed", "worker_id", workerID, "error", err.Error())
		return 0, 0, err
	}
	adminaudit.Annotate(ctx, "", map[string]string{adminaudit.DetailCount: strconv.Itoa(n), adminaudit.DetailEnrollTokens: strconv.Itoa(tokens)})
	return n, tokens, nil
}

// revokeWorkerCerts revokes the unexpired certificates of workerID (only
// serial when it is not empty) and syncs the revoked index after the write. It
// returns the certificates revoked and the unused id-bound enrollment tokens
// revoked with them (only a whole-worker revoke touches tokens).
func (s *Server) revokeWorkerCerts(ctx context.Context, workerID, serial, actor string) (int, int, error) {
	var (
		serials []string
		tokens  int
		err     error
	)
	if serial == "" {
		serials, tokens, err = s.cfg.WorkerCerts.RevokeWorkerAll(ctx, workerID, actor, RevokeReasonAdmin)
	} else {
		serials, err = s.cfg.WorkerCerts.RevokeWorkerSerial(ctx, workerID, serial, actor, RevokeReasonAdmin)
	}
	// The row may be committed even when the call reports an error after it.
	s.syncCertIndex(context.WithoutCancel(ctx))
	if err != nil {
		return 0, 0, err
	}
	if n := len(serials); n > 0 || tokens > 0 {
		s.certsRevoked.Add(int64(n))
		s.cfg.Logger.Info("worker certs revoked", "worker_id", workerID, "count", n, "enroll_tokens", tokens)
	}
	return len(serials), tokens, nil
}

// CertRevokedCount is the in-memory warden_cp_worker_cert_revoked_total
// counter: certificates revoked by the console or a lineage conflict since the
// process started (a CLI revoke is another process).
func (s *Server) CertRevokedCount() int64 { return s.certsRevoked.Load() }

// workerCertsStateHash is the keyed hash of the revoked certificates' ids and
// reasons (never a key or a cert body), so a revoke changes the audit hash.
func (s *Server) workerCertsStateHash(ctx context.Context) (string, error) {
	rows, err := s.cfg.WorkerCerts.RevokedCerts(ctx, time.Time{})
	if err != nil {
		return "", err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Serial < rows[j].Serial })
	type meta struct {
		Serial string `json:"serial"`
		Worker string `json:"worker_id"`
		Reason string `json:"reason"`
	}
	out := make([]meta, 0, len(rows))
	for _, r := range rows {
		out = append(out, meta{r.Serial, r.WorkerID, r.Reason})
	}
	// The id-bound enrollment tokens a worker revoke also revokes: without them
	// a revoke that only revoked a token would hash as no change.
	type tokMeta struct {
		ID      string `json:"id"`
		Worker  string `json:"worker_id"`
		Revoked bool   `json:"revoked"`
	}
	var toks []tokMeta
	if s.cfg.Enrollment != nil {
		all, err := s.cfg.Enrollment.List(ctx)
		if err != nil {
			return "", err
		}
		for _, t := range all {
			if t.WorkerID != "" {
				toks = append(toks, tokMeta{t.ID, t.WorkerID, !t.RevokedAt.IsZero()})
			}
		}
	}
	return s.stateHashJSON(auditTargetWorkerCerts, struct {
		Certs  []meta    `json:"certs"`
		Tokens []tokMeta `json:"enroll_tokens"`
	}{out, toks})
}

// wireWorkerCerts mounts the revoke route and its audit hasher when the control
// plane has a certificate store (workerCA enabled with a state dir).
func (s *Server) wireWorkerCerts(dash *dashboard.Server) {
	if s.cfg.WorkerCerts == nil {
		return
	}
	dash.SetWorkerCertAdmin(workerCertAdmin{s: s})
	s.RegisterStateHasher(auditTargetWorkerCerts, s.workerCertsStateHash)
}

// ParkedWorkerPolls is how many held /policy long-polls are parked for the
// certificate serial (a test seam: a scenario waits on it before revoking).
func (s *Server) ParkedWorkerPolls(serial string) int {
	a := s.workerAuth
	a.cancelMu.Lock()
	defer a.cancelMu.Unlock()
	if e := a.cancels[certCancelKey(serial)]; e != nil {
		return e.waiters
	}
	return 0
}

// CertPruneRuns is how many times the expired-row pruner has run (a test seam).
func (s *Server) CertPruneRuns() int64 {
	if s.certIdx == nil {
		return 0
	}
	return s.certIdx.pruneRuns.Load()
}
