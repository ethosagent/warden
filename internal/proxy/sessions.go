package proxy

import (
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// The session registry makes the block list a kill switch for connections that
// never pass a per-request check again: raw tunnels, idle HTTP/1 keep-alive
// connections, HTTP/2 connections and WebSocket frame pumps. A session registers
// under its user's normalized sub and lowercase email when an identity resolves
// (CONNECT, or a request carrying a header identity) and deregisters when it
// ends. Anonymous sessions never register, so anonymous traffic pays one nil
// check. After each applied policy change CloseBlockedSessions closes the
// sessions the new list matches. A session that registers after that scan (its
// admission check ran under the old list, the block landed before it
// registered) is checked against the live list by its own bind, under the same
// lock, so no session escapes the cut by registering late.
//
// Semantics: a request that ARRIVED under the old policy completes under it. An
// HTTP/1 session that is mid-request is cut as soon as that request completes;
// a tunnel, h2 connection or WebSocket is cut at once, active streams included.

// sessionRegistry maps a sub and a lowercase email to the sessions of that user.
// One mutex guards the maps and every session's fields, so register, bind and
// close cannot interleave.
type sessionRegistry struct {
	mu      sync.Mutex
	bySub   map[string]map[*session]struct{}
	byEmail map[string]map[*session]struct{}
	// all holds every open session, identified or not, so a disabled agent can
	// close the anonymous ones too (W-P2-AREG-05). refuse, set while the bound
	// agent is disabled, closes a session the moment it is created, so one that
	// passed the per-connection check just before the flag flipped cannot
	// outlive the cut.
	all    map[*session]struct{}
	refuse bool

	// blocked reports whether claims name a user on the live block list, and
	// onCut writes the deny events and runs the closers of sessions it marked.
	// bind checks a newly registered identity against blocked under mu, the
	// lock takeBlocked holds while it scans, so a session that registers just
	// after a block's CloseBlockedSessions is cut by its own bind: every
	// admission check (CONNECT, blockStage) runs before registration, and a
	// block applied in between would otherwise never reach the session. Nil in
	// registry-only tests.
	blocked func(identity.Claims) bool
	onCut   func([]closedSession)

	// expiry is the min-heap of require-mode sessions by next due time and wake
	// tells the expiry loop it changed (expiry.go).
	expiry expiryHeap
	wake   chan struct{}
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		bySub:   make(map[string]map[*session]struct{}),
		byEmail: make(map[string]map[*session]struct{}),
		all:     make(map[*session]struct{}),
		wake:    make(chan struct{}, 1),
	}
}

// session is one open client connection. All fields are guarded by reg.mu.
type session struct {
	reg    *sessionRegistry
	proto  string // protocol of the closing deny event: tcp, https/http, http2, websocket
	domain string
	port   int

	closers []io.Closer
	ids     []connIdentity // every identity bound, for the deny event
	subs    []string
	emails  []string

	// interruptible sessions are cut at once; an HTTP/1 session that is busy
	// (mid-request) is cut when the request ends instead.
	interruptible bool
	busy          bool
	closing       bool // a block matched: the deny event is written, the cut is done or pending
	closed        bool // the closers have run
	released      bool
	refused       bool // created while the registry refused sessions: already closed

	// Require-mode expiry (expiry.go). heapIdx is -1 while the session is not in
	// the registry's expiry heap. tracked is the CONNECT identity it was armed
	// with (its exp and kid), re-checked after each bundle apply. graceful sends
	// GOAWAY on an h2 connection; goaway records that it did.
	exp      time.Time
	skew     time.Duration
	due      time.Time
	heapIdx  int
	tracked  connIdentity
	graceful func()
	goaway   bool
	late     bool
}

// newSession builds an unregistered session; it joins the registry when bind
// sees the first identity.
func (r *sessionRegistry) newSession(proto, domain string, port int, interruptible bool, c io.Closer) *session {
	s := &session{reg: r, proto: proto, domain: domain, port: port, interruptible: interruptible, closers: []io.Closer{c}, heapIdx: -1}
	r.mu.Lock()
	r.all[s] = struct{}{}
	refused := r.refuse
	if refused {
		s.closing, s.closed, s.refused = true, true, true
	}
	r.mu.Unlock()
	if refused {
		_ = c.Close()
	}
	return s
}

// bind registers the session under the identity's sub and email. It is a no-op
// for an identity with neither, and for keys already registered, so calling it
// on every request costs one short critical section. When it registers a new
// key it checks the identity against the live block list under the registry
// lock: a block that landed after the caller's admission check, and whose
// CloseBlockedSessions ran before this registration, cuts the session here
// (deny event and closers, as CloseBlockedSessions would). It reports whether
// the session is now cut; the caller must not dial or forward for it.
//
// Every caller whose admission check ran before the registration uses bind:
// the tunnels (checked once at CONNECT, never again) and blockStage (checked
// just before it binds).
func (s *session) bind(ci connIdentity) (cut bool) { return s.register(ci, true) }

// bindForRequests registers the session like bind but never cuts it. It is for
// an HTTP/1 or HTTP/2 session at creation: nothing is forwarded on it before a
// request passes blockStage, which reads the live list after this registration,
// so a block that landed earlier is answered with a user_blocked 403 on the
// first request rather than a bare close.
func (s *session) bindForRequests(ci connIdentity) { s.register(ci, false) }

func (s *session) register(ci connIdentity, enforce bool) (cut bool) {
	if s == nil || (ci.Claims.Sub == "" && ci.Claims.Email == "") {
		return false
	}
	email := strings.ToLower(ci.Claims.Email)
	r := s.reg
	r.mu.Lock()
	if s.released {
		r.mu.Unlock()
		return false
	}
	added := false
	if sub := ci.Claims.Sub; sub != "" && !contains(s.subs, sub) {
		s.subs = append(s.subs, sub)
		add(r.bySub, sub, s)
		added = true
	}
	if email != "" && !contains(s.emails, email) {
		s.emails = append(s.emails, email)
		add(r.byEmail, email, s)
		added = true
	}
	var hit []closedSession
	if added {
		s.ids = append(s.ids, ci)
		if enforce && !s.closing && r.blocked != nil && r.blocked(ci.Claims) {
			hit = r.markLocked(map[*session]struct{}{s: {}}, false, func(id connIdentity) bool { return r.blocked(id.Claims) })
		}
	}
	cut = s.closing
	r.mu.Unlock()
	if len(hit) > 0 && r.onCut != nil {
		r.onCut(hit)
	}
	return cut
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func add(m map[string]map[*session]struct{}, key string, s *session) {
	set := m[key]
	if set == nil {
		set = make(map[*session]struct{})
		m[key] = set
	}
	set[s] = struct{}{}
}

func remove(m map[string]map[*session]struct{}, key string, s *session) {
	if set := m[key]; set != nil {
		delete(set, s)
		if len(set) == 0 {
			delete(m, key)
		}
	}
}

// release deregisters the session; every session kind defers it.
func (s *session) release() {
	if s == nil {
		return
	}
	r := s.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	s.released = true
	r.untrackLocked(s)
	delete(r.all, s)
	for _, k := range s.subs {
		remove(r.bySub, k, s)
	}
	for _, k := range s.emails {
		remove(r.byEmail, k, s)
	}
}

// addCloser adds a closer (the tunnel's upstream leg, a WebSocket's upstream).
// When the session was already cut the closer runs at once.
func (s *session) addCloser(c io.Closer) {
	if s == nil {
		return
	}
	s.reg.mu.Lock()
	if s.closed {
		s.reg.mu.Unlock()
		_ = c.Close()
		return
	}
	s.closers = append(s.closers, c)
	s.reg.mu.Unlock()
}

// upgrade turns an HTTP/1 session into a WebSocket one: from the handoff the
// pump owns the connection and a cut must interrupt it, not wait for the
// request to end. It returns false when a block already matched the session
// (the caller abandons the upgrade; its deny event is written).
func (s *session) upgrade(proto string, c io.Closer) bool {
	if s == nil {
		return true
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	if s.closing {
		return false
	}
	s.proto, s.interruptible = proto, true
	s.closers = append(s.closers, c)
	s.reg.refreshDueLocked(s) // a WebSocket is cut at exp+skew, not at exp
	return true
}

// beginRequest marks an HTTP/1 request as arrived: a cut now waits for it.
func (s *session) beginRequest() {
	if s == nil {
		return
	}
	s.reg.mu.Lock()
	s.busy = true
	s.reg.mu.Unlock()
}

// endRequest marks the request complete and reports whether a block matched
// meanwhile: the response is out, so the session ends here.
func (s *session) endRequest() (cut bool) {
	if s == nil {
		return false
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	s.busy = false
	return s.closing
}

// closedSession is what CloseBlockedSessions needs to write the deny event
// after the registry lock is released.
type closedSession struct {
	ci      connIdentity
	proto   string
	domain  string
	port    int
	closers []io.Closer
	// silent marks a step whose deny event was already written (the hard close
	// after an h2 GOAWAY).
	silent bool
}

// takeBlocked marks and returns the sessions whose registered sub or email the
// callbacks report blocked, once each. claimsBlocked picks, among a session's
// bound identities, the one the deny event names. Sessions that may be cut now
// carry their closers; a busy HTTP/1 session carries none and is cut by its
// endRequest.
func (r *sessionRegistry) takeBlocked(subBlocked, emailBlocked func(string) bool, claimsBlocked func(identity.Claims) bool) []closedSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	hit := make(map[*session]struct{})
	for sub, set := range r.bySub {
		if subBlocked(sub) {
			for s := range set {
				hit[s] = struct{}{}
			}
		}
	}
	for email, set := range r.byEmail {
		if emailBlocked(email) {
			for s := range set {
				hit[s] = struct{}{}
			}
		}
	}
	return r.markLocked(hit, false, func(id connIdentity) bool { return claimsBlocked(id.Claims) })
}

// markLocked marks every not-yet-closing session in hit as closing and returns
// what the caller needs to write its deny event and close it. pick chooses,
// among a session's bound identities, the one the event names (the first when
// none matches). With force a busy HTTP/1 session is cut at once too, so a
// streaming upload or download stops with it. r.mu must be held.
func (r *sessionRegistry) markLocked(hit map[*session]struct{}, force bool, pick func(connIdentity) bool) []closedSession {
	var out []closedSession
	for s := range hit {
		if s.closing {
			continue
		}
		s.closing = true
		cs := closedSession{proto: s.proto, domain: s.domain, port: s.port}
		for i, id := range s.ids {
			if i == 0 {
				cs.ci = id
			}
			if pick != nil && pick(id) {
				cs.ci = id
				break
			}
		}
		if force || s.interruptible || !s.busy {
			s.closed = true
			cs.closers = append(cs.closers, s.closers...)
		}
		out = append(out, cs)
	}
	return out
}

// takeAll marks and returns every open session, once each, and makes the
// registry close any session created from now on until allow is called. It
// serves the agent kill switch, which cuts anonymous sessions too.
func (r *sessionRegistry) takeAll() []closedSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refuse = true
	return r.markLocked(r.all, true, func(connIdentity) bool { return false })
}

// refuseNew makes the registry close every session created from now on, until
// allow. takeAll sets it too; this is for a caller that sets the flag first.
func (r *sessionRegistry) refuseNew() {
	r.mu.Lock()
	r.refuse = true
	r.mu.Unlock()
}

// allow lets new sessions open again (the bound agent was re-enabled).
func (r *sessionRegistry) allow() {
	r.mu.Lock()
	r.refuse = false
	r.mu.Unlock()
}

// CloseBlockedSessions closes every registered session whose user the live block
// list now names, writes one user_blocked deny event for each and counts them. A
// worker calls it after each applied policy change. It also refreshes the
// block-list size gauge.
func (p *Proxy) CloseBlockedSessions() {
	if bc, ok := p.cfg.Policy.(interface{ BlockedCount() int }); ok {
		p.cfg.Metrics.RecordBlocklistEntries(bc.BlockedCount())
	}
	p.finishBlockedCut(p.sessions.takeBlocked(
		func(sub string) bool { return p.cfg.Policy.IsBlocked(sub, "") },
		func(email string) bool { return p.cfg.Policy.IsBlocked("", email) },
		p.claimsBlocked,
	))
}

// finishBlockedCut writes one user_blocked deny event for each session a block
// marked, counts the sessions and then runs the closers it may run now, so a
// client that sees its connection cut also sees the event and the count. It
// runs without the registry lock, for CloseBlockedSessions and for a bind that
// found its user already blocked.
func (p *Proxy) finishBlockedCut(cut []closedSession) {
	if len(cut) == 0 {
		return
	}
	for _, cs := range cut {
		p.emitDenyEvent(cs.ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    cs.domain,
			Port:      cs.port,
			Protocol:  cs.proto,
			Reason:    string(denyreason.UserBlocked),
		})
	}
	p.cfg.Metrics.RecordBlocklistSessionsClosed(len(cut))
	for _, cs := range cut {
		for _, c := range cs.closers {
			_ = c.Close()
		}
	}
}

// wasRefused reports whether the registry closed this session at creation
// (the bound agent is disabled). The caller must not dial or forward.
func (s *session) wasRefused() bool { return s != nil && s.refused }

// isClosing reports whether a cut already matched this session.
func (s *session) isClosing() bool {
	if s == nil {
		return false
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	return s.closing
}
