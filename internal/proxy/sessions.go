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
// sessions the new list matches.
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
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		bySub:   make(map[string]map[*session]struct{}),
		byEmail: make(map[string]map[*session]struct{}),
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
}

// newSession builds an unregistered session; it joins the registry when bind
// sees the first identity.
func (r *sessionRegistry) newSession(proto, domain string, port int, interruptible bool, c io.Closer) *session {
	return &session{reg: r, proto: proto, domain: domain, port: port, interruptible: interruptible, closers: []io.Closer{c}}
}

// bind registers the session under the identity's sub and email. It is a no-op
// for an identity with neither, and for keys already registered, so calling it
// on every request costs one short critical section.
func (s *session) bind(ci connIdentity) {
	if s == nil || (ci.Claims.Sub == "" && ci.Claims.Email == "") {
		return
	}
	email := strings.ToLower(ci.Claims.Email)
	r := s.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.released {
		return
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
	if added {
		s.ids = append(s.ids, ci)
	}
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
	var out []closedSession
	for s := range hit {
		if s.closing {
			continue
		}
		s.closing = true
		cs := closedSession{proto: s.proto, domain: s.domain, port: s.port}
		for _, id := range s.ids {
			if claimsBlocked(id.Claims) {
				cs.ci = id
				break
			}
		}
		if s.interruptible || !s.busy {
			s.closed = true
			cs.closers = append(cs.closers, s.closers...)
		}
		out = append(out, cs)
	}
	return out
}

// CloseBlockedSessions closes every registered session whose user the live block
// list now names, writes one user_blocked deny event for each and counts them. A
// worker calls it after each applied policy change. It also refreshes the
// block-list size gauge.
func (p *Proxy) CloseBlockedSessions() {
	if bc, ok := p.cfg.Policy.(interface{ BlockedCount() int }); ok {
		p.cfg.Metrics.RecordBlocklistEntries(bc.BlockedCount())
	}
	cut := p.sessions.takeBlocked(
		func(sub string) bool { return p.cfg.Policy.IsBlocked(sub, "") },
		func(email string) bool { return p.cfg.Policy.IsBlocked("", email) },
		p.claimsBlocked,
	)
	for _, cs := range cut {
		p.emitDenyEvent(cs.ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    cs.domain,
			Port:      cs.port,
			Protocol:  cs.proto,
			Reason:    string(denyreason.UserBlocked),
		})
		for _, c := range cs.closers {
			_ = c.Close()
		}
	}
	if len(cut) > 0 {
		p.cfg.Metrics.RecordBlocklistSessionsClosed(len(cut))
	}
}
