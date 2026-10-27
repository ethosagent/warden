package controlplane

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
)

// The admin audit middleware (W-P1-AAUD-02). With console.adminAudit enabled,
// Server.Handler wraps /dashboard/ and /central/secrets* as
//
//	session (Principal) -> request id -> admin audit -> authz -> handler
//
// and the middleware records one row per audited request (authzRow.Audited)
// by an authenticated actor: who, what, the outcome and HMAC state hashes
// before and after. It never reads the request body. Disabled, none of this is
// mounted and the handler tree is unchanged.

const (
	// RequestIDHeader carries the request id in and out.
	RequestIDHeader = "X-Request-Id"

	// actorCPAdminToken is the actor sub of a write authorized by the CP admin
	// bearer in console.auth none.
	actorCPAdminToken = "cp-admin-token"

	// adminMutationTimeout bounds the wait for the admin-mutation lock.
	adminMutationTimeout = 30 * time.Second

	// unauthLogEvery is the per-address interval of the unauthenticated log line.
	unauthLogEvery = time.Minute
	// unauthLogMaxAddrs caps the per-address log limiter's memory.
	unauthLogMaxAddrs = 4096

	// findingAdminAuditDegraded is the rule id of the Finding published when
	// audited changes cannot be recorded.
	findingAdminAuditDegraded = "admin_audit_degraded"

	// Details the middleware itself sets (never a value from the request).
	detailHashError = "hash_error"
	detailReason    = "reason"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// adminAuditor holds the admin audit middleware's state. One per Server.
type adminAuditor struct {
	rec adminaudit.Recorder
	// probe reports whether an append could run now; it clears the degraded
	// flag. Nil means the recorder cannot be probed (always assumed healthy
	// until an append fails, then refused until one succeeds).
	probe func(context.Context) error
	// mac is the keyed state hash (adminaudit.Store.StateHash).
	mac func(target string, data []byte) (string, error)

	// sem is the CP-wide admin-mutation lock (capacity 1), taken with a
	// timeout so a stuck change cannot wedge the console forever.
	sem         chan struct{}
	lockTimeout time.Duration

	degraded        atomic.Bool
	unauthenticated atomic.Int64
	unauthLog       *addrLimiter

	hashersMu sync.RWMutex
	hashers   map[string]func(context.Context) (string, error)

	trusted []netip.Prefix
	clock   clock.Clock
	logger  *slog.Logger
}

func newAdminAuditor(rec adminaudit.Recorder, probe func(context.Context) error,
	mac func(string, []byte) (string, error), cc config.ConsoleConfig, clk clock.Clock, logger *slog.Logger) *adminAuditor {
	a := &adminAuditor{
		rec: rec, probe: probe, mac: mac,
		sem:         make(chan struct{}, 1),
		lockTimeout: adminMutationTimeout,
		unauthLog:   newAddrLimiter(clk, unauthLogEvery, unauthLogMaxAddrs),
		hashers:     map[string]func(context.Context) (string, error){},
		clock:       clk,
		logger:      logger,
	}
	for _, c := range cc.TrustedProxies {
		// Validated at config load; a bad entry here is skipped, never trusted.
		if p, err := netip.ParsePrefix(c); err == nil {
			a.trusted = append(a.trusted, p.Masked())
		}
	}
	return a
}

// enableAdminAudit turns the middleware on with rec and registers the
// built-in state hashers. New calls it when cfg.AdminAudit is set; tests call
// it with a fake recorder.
func (s *Server) enableAdminAudit(rec adminaudit.Recorder, probe func(context.Context) error, mac func(string, []byte) (string, error)) {
	s.audit = newAdminAuditor(rec, probe, mac, s.cfg.Console, s.cfg.Clock, s.cfg.Logger)
	s.registerBuiltinStateHashers()
}

// auditWrap puts next behind the request-id and admin audit middleware,
// classifying each request with classify. It is the identity when admin audit
// is disabled, so the handler tree stays exactly as it was.
func (s *Server) auditWrap(classify func(*http.Request) (authzRow, bool), next http.Handler) http.Handler {
	if s.audit == nil {
		return next
	}
	return withRequestID(s.adminAuditMiddleware(classify, next))
}

// dashboardRoute classifies a /dashboard/ request by the authz table, in every
// console.auth mode.
func dashboardRoute(table map[routeKey]authzRow) func(*http.Request) (authzRow, bool) {
	return func(r *http.Request) (authzRow, bool) {
		row, ok := table[routeKey{r.Method, r.URL.Path}]
		return row, ok
	}
}

// patternRoute classifies a request on a ServeMux pattern by cpRouteTable.
func patternRoute(table map[routeKey]authzRow, pattern string) func(*http.Request) (authzRow, bool) {
	return func(r *http.Request) (authzRow, bool) {
		row, ok := table[routeKey{r.Method, pattern}]
		return row, ok
	}
}

// auditActor is who made a request, as the audit row records it.
type auditActor struct {
	actor      adminaudit.Actor
	role       string
	authMethod string
}

// resolveActor finds the authenticated actor: a session or break-glass
// Principal (any console mode that set one), else, in console.auth none, the
// CP admin bearer compared in constant time. ok is false for an
// unauthenticated request. The bearer is never recorded.
func (s *Server) resolveActor(r *http.Request) (auditActor, bool) {
	if p, ok := PrincipalFrom(r.Context()); ok {
		role, _ := s.cfg.Console.RoleFor(p.Groups)
		method := adminaudit.AuthMethodOIDC
		if p.Kind == PrincipalBreakglass {
			method = adminaudit.AuthMethodBreakglass
		}
		return auditActor{actor: adminaudit.Actor{Sub: p.Sub, Email: p.Email}, role: role.String(), authMethod: method}, true
	}
	if s.cfg.Console.Auth == config.ConsoleAuthOIDC {
		return auditActor{}, false
	}
	if tok := s.dashboardWriteToken(); tok != "" &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+tok)) == 1 {
		return auditActor{actor: adminaudit.Actor{Sub: actorCPAdminToken}, role: config.RoleAdmin.String(), authMethod: adminaudit.AuthMethodBearer}, true
	}
	return auditActor{}, false
}

// openWrites reports whether a request with no credential at all can change
// admin state: console.auth none with no admin token and no shared token
// (development only; /central/secrets then passes, see adminBearerOK). A
// successful anonymous change is recorded with auth_method none rather than
// going unrecorded; a failed or refused one writes no row.
func (s *Server) openWrites() bool {
	return s.cfg.Console.Auth != config.ConsoleAuthOIDC && s.dashboardWriteToken() == "" && !s.cfg.RequireAdminToken
}

// adminAuditMiddleware records audited requests. Order of work for one
// audited request by an authenticated actor: refuse with 503 when the store is
// degraded and still failing its probe; take the admin-mutation lock (503
// admin_audit_busy after the timeout); hash the target; run the handler;
// hash again unless the request was denied; append; release. An
// unauthenticated request never takes the lock and never writes a row.
func (s *Server) adminAuditMiddleware(classify func(*http.Request) (authzRow, bool), next http.Handler) http.Handler {
	a := s.audit
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		row, ok := classify(r)
		if !ok || !row.Audited {
			next.ServeHTTP(w, r)
			return
		}
		who, authed := s.resolveActor(r)
		if !authed && !s.openWrites() {
			// Unauthenticated: the guard or authz answers 401; nothing is chained,
			// so nobody can flood the table.
			next.ServeHTTP(w, r)
			a.noteUnauthenticated(r, row)
			return
		}
		if !authed {
			who = auditActor{authMethod: adminaudit.AuthMethodNone}
		}
		ctx := r.Context()
		if !a.healthy(ctx) {
			s.publishAuditDegraded("unavailable")
			writeAuthzJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "admin_audit_unavailable"})
			return
		}
		release, ok := a.lock(ctx)
		if !ok {
			writeAuthzJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "admin_audit_busy"})
			return
		}
		defer release()

		before, beforeErr := a.stateHash(ctx, row.Target)
		actx, ann := adminaudit.WithAnnotation(ctx)
		sw := wrapStatus(w)
		next.ServeHTTP(sw.writer(), r.WithContext(actx))
		status := sw.code()
		outcome := outcomeFor(status)
		if !authed && outcome != adminaudit.OutcomeOK {
			// Only an anonymous request that changed state needs a row; anything
			// else is counted like other unauthenticated traffic, so open mode
			// cannot be used to flood the table either.
			a.noteUnauthenticated(r, row)
			return
		}
		// A denied write changed nothing; every other outcome may have (even an
		// error may have partly applied), so the state is hashed again.
		after, afterErr := before, beforeErr
		if outcome != adminaudit.OutcomeDenied {
			after, afterErr = a.stateHash(ctx, row.Target)
		}
		ref, details := ann.Snapshot()
		if details == nil {
			details = map[string]string{}
		}
		if beforeErr != nil || afterErr != nil {
			before, after = "", ""
			details[detailHashError] = "true"
		}
		if csrfRefused(ctx) {
			details[detailReason] = "csrf"
		}
		in := adminaudit.Input{
			Actor: who.actor, ActorRole: who.role, AuthMethod: who.authMethod,
			Action: row.Action, Target: row.Target, TargetRef: ref, Details: details,
			Outcome: outcome, HTTPStatus: status, BeforeHash: before, AfterHash: after,
			ClientIP: clientIP(r, a.trusted), RequestID: RequestIDFrom(ctx),
		}
		// The append must not be cancelled by a client that hangs up after the
		// change was made.
		if _, err := a.rec.Record(context.WithoutCancel(ctx), in); err != nil {
			a.degraded.Store(true)
			s.logPersistFailed(in, err)
			s.publishAuditDegraded("append_failed")
			return
		}
		a.degraded.Store(false)
	})
}

// healthy reports whether audited changes may run. A degraded store gets one
// probe per request; a passing probe clears the flag.
func (a *adminAuditor) healthy(ctx context.Context) bool {
	if !a.degraded.Load() {
		return true
	}
	if a.probe == nil || a.probe(ctx) != nil {
		return false
	}
	a.degraded.Store(false)
	return true
}

// lock takes the admin-mutation lock, waiting at most lockTimeout.
func (a *adminAuditor) lock(ctx context.Context) (func(), bool) {
	ctx, cancel := context.WithTimeout(ctx, a.lockTimeout)
	defer cancel()
	select {
	case a.sem <- struct{}{}:
		return func() { <-a.sem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// noteUnauthenticated counts an unauthenticated audited request and logs it,
// at most once a minute per client address. It logs the route only: never a
// header, cookie, token or body.
func (a *adminAuditor) noteUnauthenticated(r *http.Request, row authzRow) {
	n := a.unauthenticated.Add(1)
	ip := clientIP(r, a.trusted)
	if !a.unauthLog.allow(ip) {
		return
	}
	a.logger.Warn("admin_audit_unauthenticated", "action", row.Action, "method", r.Method,
		"path", r.URL.Path, "client_ip", ip, "count", n)
}

// logPersistFailed logs an entry that could not be appended. The fields are
// the entry's own (no request body, header or secret value is in it).
func (s *Server) logPersistFailed(in adminaudit.Input, err error) {
	s.cfg.Logger.Error("admin_audit_persist_failed", "persist_failed", true,
		"action", in.Action, "target", in.Target, "target_ref", in.TargetRef,
		"outcome", in.Outcome, "http_status", in.HTTPStatus,
		"actor_sub", in.Actor.Sub, "actor_role", in.ActorRole, "auth_method", in.AuthMethod,
		"before_hash", in.BeforeHash, "after_hash", in.AfterHash,
		"client_ip", in.ClientIP, "request_id", in.RequestID, "error", err)
}

// publishAuditDegraded raises the admin_audit_degraded Finding on the alert
// bus. Without a pipeline the ERROR log line is the only signal.
func (s *Server) publishAuditDegraded(reason string) {
	m := s.currentManager()
	if m == nil {
		return
	}
	bus := m.Bus()
	if bus == nil {
		return
	}
	bus.PublishFinding(integration.Finding{
		RuleID:   findingAdminAuditDegraded,
		Category: "security",
		Severity: integration.SevHigh,
		Summary:  "admin audit log cannot record changes; audited admin changes are refused",
		Evidence: integration.Evidence("reason=" + reason),
		DedupKey: findingAdminAuditDegraded + ":control-plane",
		Ts:       s.cfg.Clock.Now(),
	})
}

// outcomeFor maps an HTTP status to an audit outcome.
func outcomeFor(status int) string {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return adminaudit.OutcomeDenied
	case status >= 500:
		return adminaudit.OutcomeError
	case status >= 400:
		return adminaudit.OutcomeRejected
	}
	return adminaudit.OutcomeOK
}

// --- request id ---

type requestIDKey struct{}

// withRequestID sets the request id: a valid incoming X-Request-Id (1 to 64
// characters of [A-Za-z0-9-]) or a fresh random one. It is echoed in the
// response and carried in the context.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !requestIDPattern.MatchString(id) {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFrom returns the request id withRequestID assigned, or "".
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("control plane: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// --- client ip ---

// clientIP is the request's peer address, unless the peer is inside a
// trusted proxy CIDR: then it is the left-most valid X-Forwarded-For address
// (the peer when there is none). An untrusted peer's X-Forwarded-For is
// ignored. It returns "" when RemoteAddr is not an IP.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	peer = peer.Unmap()
	if !inPrefixes(trusted, peer) {
		return peer.String()
	}
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(v, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
				return a.Unmap().String()
			}
		}
	}
	return peer.String()
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- csrf refusal ---

type csrfRefusedKey struct{}

// csrfRefused reports whether withSession refused this request for CSRF.
func csrfRefused(ctx context.Context) bool {
	v, _ := ctx.Value(csrfRefusedKey{}).(bool)
	return v
}

// csrfRefusal answers a session write that failed the CSRF checks. withSession
// calls it with the session's Principal in the context, so when admin audit
// wraps it the refusal is recorded as denied.
var csrfRefusal = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"csrf"}` + "\n"))
})

// --- per-address log limiter ---

// addrLimiter allows one event per key per interval, keeping at most max keys.
type addrLimiter struct {
	mu    sync.Mutex
	clock clock.Clock
	every time.Duration
	max   int
	last  map[string]time.Time
}

func newAddrLimiter(clk clock.Clock, every time.Duration, maxKeys int) *addrLimiter {
	return &addrLimiter{clock: clk, every: every, max: maxKeys, last: map[string]time.Time{}}
}

func (l *addrLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.every {
		return false
	}
	if len(l.last) >= l.max {
		for k, t := range l.last {
			if now.Sub(t) >= l.every {
				delete(l.last, k)
			}
		}
		if len(l.last) >= l.max {
			return false
		}
	}
	l.last[key] = now
	return true
}

// --- status-capturing writer ---

// statusWriter records the status a handler writes. writer() returns it
// wrapped so the result implements http.Flusher and http.Hijacker exactly
// when the underlying writer does.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func wrapStatus(w http.ResponseWriter) *statusWriter { return &statusWriter{ResponseWriter: w} }

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// code is the status written, 200 when the handler wrote nothing.
func (s *statusWriter) code() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

type flushStatusWriter struct{ *statusWriter }

func (f flushStatusWriter) Flush() {
	if f.status == 0 {
		f.status = http.StatusOK
	}
	f.ResponseWriter.(http.Flusher).Flush()
}

type hijackStatusWriter struct{ *statusWriter }

func (h hijackStatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.status == 0 {
		h.status = http.StatusSwitchingProtocols
	}
	return h.ResponseWriter.(http.Hijacker).Hijack()
}

type flushHijackStatusWriter struct{ *statusWriter }

func (f flushHijackStatusWriter) Flush() { flushStatusWriter(f).Flush() }

func (f flushHijackStatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return hijackStatusWriter(f).Hijack()
}

func (s *statusWriter) writer() http.ResponseWriter {
	_, fl := s.ResponseWriter.(http.Flusher)
	_, hj := s.ResponseWriter.(http.Hijacker)
	switch {
	case fl && hj:
		return flushHijackStatusWriter{s}
	case fl:
		return flushStatusWriter{s}
	case hj:
		return hijackStatusWriter{s}
	}
	return s
}
