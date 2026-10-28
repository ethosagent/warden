package controlplane

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
)

// Login and logout events (W-P1-AAUD-07). The admin audit middleware never
// wraps /auth/callback or /auth/logout (they are handler-recorded in the
// authz table); the handlers record their own rows through the Recorder:
//
//	auth.login         a successful callback: the verified sub, email and role
//	auth.login_failed  a failed callback after the state was consumed, with a
//	                   closed details.reason
//	auth.logout        a logout that ended a live session, for that session's actor
//
// No code, state, verifier, nonce, token or cookie value is ever recorded or
// logged. With admin audit disabled none of this runs.

const (
	actionLogin       = "auth.login"
	actionLoginFailed = "auth.login_failed"
	actionLogout      = "auth.logout"
	targetSession     = "session"

	// loginFailedPerMinute caps auth.login_failed rows per client address per
	// minute, so an unauthenticated client cannot flood the chain.
	loginFailedPerMinute = 20
	loginFailedWindow    = time.Minute
	// loginFailedMaxAddrs caps the limiter's memory. With every slot held by a
	// live window, a new address writes no row (it is counted and logged).
	loginFailedMaxAddrs = 4096

	detailRole = "role"
)

// The closed details.reason enum of auth.login_failed.
const (
	failNoRole         = "no_role"
	failBadToken       = "bad_token"
	failIDPError       = "idp_error"
	failStateInvalid   = "state_invalid"
	failExchangeFailed = "exchange_failed"
)

// loginFailure maps a console login error code onto the recorded reason and
// outcome: a refusal of the user or the token is denied, an IdP or exchange
// failure is error.
func loginFailure(code string) (reason, outcome string) {
	switch code {
	case loginNoRole:
		return failNoRole, adminaudit.OutcomeDenied
	case loginTokenInvalid, loginNonceMismatch:
		return failBadToken, adminaudit.OutcomeDenied
	case loginStateInvalid:
		return failStateInvalid, adminaudit.OutcomeDenied
	case loginUserBlocked:
		return failUserBlocked, adminaudit.OutcomeDenied
	case loginBlockUnavailable:
		return failBlockUnavailable, adminaudit.OutcomeError
	case loginIDPError, loginIDPUnavailable:
		return failIDPError, adminaudit.OutcomeError
	}
	return failExchangeFailed, adminaudit.OutcomeError
}

// recordLogin records the outcome of one callback. The authService calls it
// only for a success or a failure that consumed a pending state.
func (s *Server) recordLogin(r *http.Request, res loginResult) {
	a := s.audit
	in := adminaudit.Input{
		Actor: res.actor, ActorRole: res.role, AuthMethod: adminaudit.AuthMethodOIDC,
		Target: targetSession, HTTPStatus: http.StatusFound,
		ClientIP: clientIP(r, a.trusted), RequestID: RequestIDFrom(r.Context()),
	}
	if res.reason == "" {
		in.Action, in.Outcome = actionLogin, adminaudit.OutcomeOK
		in.TargetRef = shortHash(res.sessionHash)
		in.Details = map[string]string{detailRole: res.role}
	} else {
		if !a.loginFailed.allow(in.ClientIP) {
			a.noteLoginFailedDropped(in.ClientIP)
			return
		}
		reason, outcome := loginFailure(res.reason)
		in.Action, in.Outcome = actionLoginFailed, outcome
		if res.reason == loginUserBlocked {
			in.Action, in.HTTPStatus = actionBlockedLogin, http.StatusForbidden
		}
		if res.reason == loginBlockUnavailable {
			in.HTTPStatus = http.StatusServiceUnavailable
		}
		in.Details = map[string]string{detailReason: reason}
	}
	s.recordAuth(r.Context(), in)
}

// recordLogout records a logout that ended a live session. who was resolved
// from the session's Principal before the row was deleted.
func (s *Server) recordLogout(r *http.Request, who auditActor, sessionHash string) {
	a := s.audit
	s.recordAuth(r.Context(), adminaudit.Input{
		Actor: who.actor, ActorRole: who.role, AuthMethod: who.authMethod,
		Action: actionLogout, Target: targetSession, TargetRef: shortHash(sessionHash),
		Outcome: adminaudit.OutcomeOK, HTTPStatus: http.StatusNoContent,
		ClientIP: clientIP(r, a.trusted), RequestID: RequestIDFrom(r.Context()),
	})
}

// recordAuth appends one auth entry. A failure is logged at ERROR and raises
// the degraded flag and Finding, but never fails the login or logout: signing
// in changes no admin state.
func (s *Server) recordAuth(ctx context.Context, in adminaudit.Input) {
	a := s.audit
	if _, err := a.rec.Record(context.WithoutCancel(ctx), in); err != nil {
		a.degraded.Store(true)
		s.logPersistFailed(in, err)
		s.publishAuditDegraded("append_failed")
		return
	}
	a.degraded.Store(false)
}

// noteLoginFailedDropped counts a failed login that was over the per-address
// limit and logs it, at most once a minute per address.
func (a *adminAuditor) noteLoginFailedDropped(ip string) {
	n := a.loginFailedDropped.Add(1)
	if !a.loginFailedLog.allow(ip) {
		return
	}
	a.logger.Warn("admin_audit_login_failed_rate_limited", "client_ip", ip, "limit_per_minute", loginFailedPerMinute, "dropped", n)
}

// requestIDWrap gives an auth handler a request id when admin audit is on;
// off, the handler is returned unchanged.
func (s *Server) requestIDWrap(h http.Handler) http.Handler {
	if s.audit == nil {
		return h
	}
	return withRequestID(h)
}

// windowLimiter allows limit events per key in each fixed window, keeping at
// most maxKeys keys.
type windowLimiter struct {
	mu      sync.Mutex
	clock   clock.Clock
	limit   int
	window  time.Duration
	maxKeys int
	counts  map[string]windowCount
}

type windowCount struct {
	start time.Time
	n     int
}

func newWindowLimiter(clk clock.Clock, limit int, window time.Duration, maxKeys int) *windowLimiter {
	return &windowLimiter{clock: clk, limit: limit, window: window, maxKeys: maxKeys, counts: map[string]windowCount{}}
}

func (l *windowLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	c, ok := l.counts[key]
	if ok && now.Sub(c.start) < l.window {
		if c.n >= l.limit {
			return false
		}
		c.n++
		l.counts[key] = c
		return true
	}
	if !ok && len(l.counts) >= l.maxKeys {
		for k, v := range l.counts {
			if now.Sub(v.start) >= l.window {
				delete(l.counts, k)
			}
		}
		if len(l.counts) >= l.maxKeys {
			return false
		}
	}
	l.counts[key] = windowCount{start: now, n: 1}
	return true
}
