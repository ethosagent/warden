package controlplane

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
)

// POST /auth/breakglass (W-P1-OPS1-08): the emergency local admin login for
// when the IdP is down. Every attempt is loud on purpose: one signed
// admin_audit row (when admin audit is on), one ERROR log line and one
// Finding, so use is never silent. The submitted username and password are
// never stored or logged, and nothing in the response, the logs, the rows or
// the Findings tells an unknown username from a wrong password.

const (
	breakGlassPath = "/auth/breakglass"
	// breakGlassMaxBody bounds the request body.
	breakGlassMaxBody = 4 << 10
	// breakGlassVerifySlots is how many argon2 verifications may run at once.
	breakGlassVerifySlots = 2

	actionBreakGlass   = "auth.breakglass"
	actorBreakGlassFmt = "breakglass:"
	actorUnknown       = "breakglass:unknown"

	findingBreakGlass = "breakglass_login"

	// Attempt outcomes as logged and put in Finding evidence.
	bgOK          = "ok"
	bgDenied      = "denied"
	bgRateLimited = "rate_limited"
	bgBusy        = "busy"
	bgNoHash      = "breakglass_unavailable"
	bgNoAudit     = "audit_unavailable"
	bgNoSession   = "session_unavailable"
)

// breakGlass is the break-glass login's state. It exists only when
// console.breakGlass.enabled and sessions are on.
type breakGlass struct {
	limiter *failureLimiter
	sem     chan struct{}
	// verify checks a password against a hash; tests count its calls.
	verify func(PHC, string) bool
}

// initBreakGlass builds the break-glass state when it is enabled.
func (s *Server) initBreakGlass() {
	cc := s.cfg.Console
	if !cc.BreakGlass.Enabled || cc.Auth != config.ConsoleAuthOIDC {
		return
	}
	if s.sessions == nil {
		s.cfg.Logger.Error("control plane: break-glass login disabled (console sessions are unavailable)")
		return
	}
	s.breakGlass = &breakGlass{
		limiter: newFailureLimiter(s.cfg.Clock, breakGlassWindow, breakGlassPerAddr, breakGlassGlobal, breakGlassLimiterAddrs),
		sem:     make(chan struct{}, breakGlassVerifySlots),
		verify:  func(p PHC, pw string) bool { return p.Verify(pw) },
	}
}

type breakGlassRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// remoteHost is the host of r.RemoteAddr. Break-glass never trusts
// X-Forwarded-For: the limiter keys on the TCP peer.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// retryAfter sets Retry-After in whole seconds, at least one.
func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(d.Seconds())))))
}

// handleBreakGlass serves POST /auth/breakglass. Checks run in this order:
// method, content type, Origin, body size, strict JSON, the failure limiter,
// the verify semaphore, then argon2id.
func (s *Server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	bg := s.breakGlass
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		authError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		authError(w, http.StatusUnsupportedMediaType, "content_type")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.sessionCookie.origin {
		authError(w, http.StatusForbidden, "origin")
		return
	}
	req, status, code := decodeBreakGlass(w, r)
	if status != 0 {
		authError(w, status, code)
		return
	}

	ip := remoteHost(r)
	if limited, wait := bg.limiter.limited(ip); limited {
		retryAfter(w, wait)
		authError(w, http.StatusTooManyRequests, "rate_limited")
		if bg.limiter.firstLimited(ip) {
			// The row is best effort: the request is refused either way.
			_ = s.recordBreakGlass(r, adminaudit.OutcomeDenied, http.StatusTooManyRequests, actorUnknown, "", map[string]string{detailReason: bgRateLimited})
		}
		s.breakGlassOutcome(bgRateLimited, ip, "")
		return
	}
	select {
	case bg.sem <- struct{}{}:
		defer func() { <-bg.sem }()
	default:
		retryAfter(w, time.Second)
		authError(w, http.StatusTooManyRequests, "busy")
		s.breakGlassOutcome(bgBusy, ip, "")
		return
	}

	cfg := s.cfg.Console.BreakGlass
	match := subtle.ConstantTimeCompare([]byte(req.Username), []byte(cfg.Username)) == 1
	actor := actorUnknown
	if match {
		actor = actorBreakGlassFmt + cfg.Username
	}
	phc, err := LoadBreakGlassHash(cfg)
	if err != nil {
		// The error names the config key, never the hash.
		s.cfg.Logger.Error("breakglass_hash_unavailable", "error", err)
		_ = s.recordBreakGlass(r, adminaudit.OutcomeError, http.StatusServiceUnavailable, actor, "", map[string]string{detailReason: bgNoHash})
		authError(w, http.StatusServiceUnavailable, bgNoHash)
		s.breakGlassOutcome(bgNoHash, ip, "")
		return
	}
	// Exactly one verification per attempt: against the configured hash when the
	// username matches, against the dummy hash when it does not, so a wrong
	// username and a wrong password take the same time.
	if !match {
		phc = DummyPHC()
	}
	passOK := bg.verify(phc, req.Password)
	if !match || !passOK {
		bg.limiter.fail(ip)
		_ = s.recordBreakGlass(r, adminaudit.OutcomeDenied, http.StatusUnauthorized, actor, "", nil)
		authError(w, http.StatusUnauthorized, "invalid_credentials")
		s.breakGlassOutcome(bgDenied, ip, "")
		return
	}
	s.finishBreakGlass(w, r, ip, actor)
}

// decodeBreakGlass reads the strict JSON body. A non-zero status is the
// refusal to send.
func decodeBreakGlass(w http.ResponseWriter, r *http.Request) (breakGlassRequest, int, string) {
	var req breakGlassRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, breakGlassMaxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	if err == nil {
		// Exactly one JSON value: trailing data is a malformed request.
		if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
			err = terr
			if err == nil {
				err = errors.New("trailing data")
			}
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return req, http.StatusRequestEntityTooLarge, "body_too_large"
		}
		return req, http.StatusBadRequest, "bad_request"
	}
	return req, 0, ""
}

// finishBreakGlass runs after the credentials verified: it mints the session,
// writes the audit row (failing closed), then answers. The cookie is sent only
// after the row is committed.
func (s *Server) finishBreakGlass(w http.ResponseWriter, r *http.Request, ip, actor string) {
	ctx := r.Context()
	cfg := s.cfg.Console.BreakGlass
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = config.DefaultBreakGlassSessionTTL
	}
	raw, sess, err := s.sessions.Create(ctx, SessionInput{
		Iss: "warden-breakglass", Sub: actor, AuthMethod: AuthMethodBreakglass,
	}, CreateOptions{AbsoluteTTL: ttl})
	if err != nil {
		s.cfg.Logger.Error("breakglass_session_failed", "error", err)
		_ = s.recordBreakGlass(r, adminaudit.OutcomeError, http.StatusServiceUnavailable, actor, "", map[string]string{detailReason: bgNoSession})
		authError(w, http.StatusServiceUnavailable, bgNoSession)
		s.breakGlassOutcome(bgNoSession, ip, "")
		return
	}
	short := shortHash(sess.IDHash)
	if err := s.recordBreakGlass(r, adminaudit.OutcomeOK, http.StatusOK, actor, short, nil); err != nil {
		if derr := s.sessions.Delete(context.WithoutCancel(ctx), raw); derr != nil {
			s.cfg.Logger.Error("breakglass_session_cleanup_failed", "session", short, "error", derr)
		}
		authError(w, http.StatusServiceUnavailable, bgNoAudit)
		s.breakGlassOutcome(bgNoAudit, ip, "")
		return
	}
	// A new login revokes the earlier break-glass sessions.
	if _, err := s.sessions.DeleteBySubExcept(ctx, actor, sess.IDHash); err != nil {
		s.cfg.Logger.Error("breakglass_revoke_failed", "error", err)
	}
	ck := s.sessionCookie.New(raw, ttl)
	ck.Secure = true // always, even behind a TLS terminator
	http.SetCookie(w, ck)
	writeAuthJSON(w, http.StatusOK, map[string]any{"ok": true, "expiresAt": sess.ExpiresAt.UTC().Format(time.RFC3339)})
	s.breakGlassOutcome(bgOK, ip, short)
}

// recordBreakGlass writes the attempt's audit row. With admin audit off it
// writes nothing and succeeds. A failed write is logged and raises the
// admin_audit_degraded Finding; the caller decides whether it denies the login.
func (s *Server) recordBreakGlass(r *http.Request, outcome string, status int, actor, targetRef string, details map[string]string) error {
	a := s.audit
	if a == nil {
		return nil
	}
	in := adminaudit.Input{
		Actor: adminaudit.Actor{Sub: actor}, AuthMethod: adminaudit.AuthMethodBreakglass,
		Action: actionBreakGlass, Target: targetSession, TargetRef: targetRef, Details: details,
		Outcome: outcome, HTTPStatus: status, ClientIP: remoteHost(r), RequestID: RequestIDFrom(r.Context()),
	}
	if outcome == adminaudit.OutcomeOK {
		in.ActorRole = config.RoleAdmin.String()
	}
	if _, err := a.rec.Record(context.WithoutCancel(r.Context()), in); err != nil {
		a.degraded.Store(true)
		s.logPersistFailed(in, err)
		s.publishAuditDegraded("append_failed")
		return err
	}
	a.degraded.Store(false)
	return nil
}

// breakGlassOutcome logs the attempt at ERROR and publishes its Finding: a
// success is critical with a key of its own (one alert per login); everything
// else is high and aggregated by the alert's count. The fields are the outcome
// and the client address, never a credential.
func (s *Server) breakGlassOutcome(outcome, ip, session string) {
	attrs := []any{"outcome", outcome, "client_ip", ip}
	if session != "" {
		attrs = append(attrs, "session", session)
	}
	s.cfg.Logger.Error("breakglass_login", attrs...)
	f := integration.Finding{
		RuleID:   findingBreakGlass,
		Category: "security",
		Severity: integration.SevHigh,
		Subject:  integration.Subject{Tool: "breakglass"},
		Summary:  "break-glass login attempt failed",
		Evidence: integration.Evidence("outcome=" + outcome + " client_ip=" + ip),
		DedupKey: findingBreakGlass + ":failure",
		Ts:       s.cfg.Clock.Now(),
	}
	if outcome == bgOK {
		f.Severity = integration.SevCritical
		f.Summary = "break-glass admin login succeeded"
		f.DedupKey = findingBreakGlass + ":success:" + session
	}
	s.publishFinding(f)
}
