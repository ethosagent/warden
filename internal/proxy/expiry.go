package proxy

import (
	"container/heap"
	"context"
	"io"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// Require-mode session closing (W-P2-WBND-09). A raw tunnel, an upgraded
// WebSocket, an h2 connection or an idle HTTP/1 keep-alive is admitted once, at
// CONNECT, and no per-request check ever sees it again, so a 15 minute Warden
// token could be outlived indefinitely. In require mode every such session that
// carries a verified Warden token registers its exp and key id in the block
// list's session registry (sessions.go) and is cut:
//
//   - at exp for an idle HTTP/1 keep-alive (a busy one when its request ends);
//   - at exp for an h2 connection, which first gets GOAWAY so in-flight streams
//     finish, and is closed at exp+skew at the latest;
//   - at exp+skew for a raw tunnel or a WebSocket, which no per-request check
//     covers (skew is the verifier's own exp tolerance).
//
// One loop goroutine per Proxy owns a min-heap of due times; no connection has
// a goroutine or a timer of its own. The loop decides what is due from
// validityClock and sleeps on Config.IdentityTimer, so both follow
// Config.IdentityClock: wall time in production, the fake clock in tests.
//
// RecheckIdentitySessions runs after each applied bundle and closes sessions
// whose binding no longer holds (key left the JWKS, agent disabled or key
// removed). Attribute-mode and anonymous sessions never register here.

// expiryHeap orders armed sessions by due time. Indexes live on the session so a
// release or a re-arm is O(log n). All access is under sessionRegistry.mu.
type expiryHeap []*session

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h expiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx, h[j].heapIdx = i, j
}
func (h *expiryHeap) Push(x any) {
	s := x.(*session)
	s.heapIdx = len(*h)
	*h = append(*h, s)
}
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	s := old[n-1]
	old[n-1] = nil
	s.heapIdx = -1
	*h = old[:n-1]
	return s
}

// h2LateGrace bounds how long a session armed after exp (inside the skew window)
// may outlive its GOAWAY or busy request: it is cut at exp+skew plus this.
const h2LateGrace = 5 * time.Second

// dueLocked is when the session's next expiry step runs. r.mu must be held.
// late marks an h1/h2 session armed after exp but inside the verifier's skew (the
// CONNECT verified, so it must be served): its first step moves out to exp+skew
// and its hard stop is that plus a short grace, not another skew.
func (s *session) dueLocked() time.Time {
	base, hardAfter := s.exp, s.skew
	if s.late {
		base, hardAfter = base.Add(s.skew), h2LateGrace
	}
	switch {
	case s.hard:
		return base.Add(hardAfter) // busy HTTP/1: forced close
	case s.graceful != nil && !s.goaway:
		return base // GOAWAY at exp
	case s.graceful != nil:
		return base.Add(hardAfter) // h2 hard stop
	case s.interruptible:
		return s.exp.Add(s.skew) // tunnel, WebSocket
	default:
		return base // idle HTTP/1 keep-alive
	}
}

// refreshDueLocked re-keys an armed session after its kind changed (a WebSocket
// upgrade, GOAWAY sent). r.mu must be held.
func (r *sessionRegistry) refreshDueLocked(s *session) {
	if s.heapIdx < 0 {
		return
	}
	s.due = s.dueLocked()
	heap.Fix(&r.expiry, s.heapIdx)
	r.wakeLoop()
}

// wakeLoop nudges the expiry loop to re-read the earliest due time.
func (r *sessionRegistry) wakeLoop() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// track arms the session's expiry from its CONNECT identity. It is a no-op for
// a session already released or cut.
func (r *sessionRegistry) track(s *session, ci connIdentity, skew time.Duration, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.released || s.closing || s.heapIdx >= 0 || ci.Expiry.IsZero() {
		return
	}
	s.exp, s.skew, s.tracked = ci.Expiry, skew, ci
	s.armed.Store(true)
	s.late = !now.Before(ci.Expiry) && (s.graceful != nil || !s.interruptible)
	s.due = s.dueLocked()
	heap.Push(&r.expiry, s)
	r.wakeLoop()
}

// untrackLocked removes a session from the heap. r.mu must be held.
func (r *sessionRegistry) untrackLocked(s *session) {
	if s.heapIdx >= 0 {
		heap.Remove(&r.expiry, s.heapIdx)
	}
}

// setGraceful installs the h2 connection's GOAWAY trigger. Call it before track.
func (s *session) setGraceful(f func()) {
	if s == nil {
		return
	}
	s.reg.mu.Lock()
	s.graceful = f
	s.reg.mu.Unlock()
}

// armExpiry registers a require-mode session for expiry: only a verified Warden
// token with an exp, in require mode, is armed. enforce re-checks the binding
// against the snapshot now and cuts the session when it already fails (a bundle
// applied between CONNECT verification and registration); it reports whether
// the session was cut, and the caller must not dial for it. Callers that cannot
// act on a cut (h1/h2 sessions, whose first request re-checks anyway) pass false.
func (p *Proxy) armExpiry(s *session, ci connIdentity, enforce bool) (cut bool) {
	if s == nil {
		return false
	}
	s.reg.mu.Lock()
	s.pending = false // the creator has bound the identity: the sweep may judge it
	s.reg.mu.Unlock()
	if ci.status() != identity.StatusValid || ci.Claims.TokenType != identity.TokenWarden || ci.Expiry.IsZero() {
		return false
	}
	h := p.identity()
	if h == nil || h.mode != IdentityModeRequire {
		return false
	}
	s.reg.track(s, ci, h.skew, p.validityClock())
	if !enforce {
		return false
	}
	if br := p.rebind(h, idResult{claims: ci.Claims, status: identity.StatusValid}); br.status != identity.StatusValid {
		p.cutItems([]cutItem{{s: s, ci: connIdentity{Claims: ci.Claims, Status: br.status, Reason: br.reason}}}, true)
		return true
	}
	return false
}

// runSessionExpiry is the Proxy's one expiry goroutine, started by Serve.
func (p *Proxy) runSessionExpiry(ctx context.Context) {
	r := p.sessions
	for {
		var t IdentityTimer
		var c <-chan time.Time
		if due, ok := r.nextDue(); ok {
			d := due.Sub(p.validityClock())
			if d <= 0 {
				p.expireDue()
				continue
			}
			t = p.newIdentityTimer(d)
			c = t.C()
		}
		select {
		case <-ctx.Done():
			if t != nil {
				t.Stop()
			}
			return
		case <-r.wake:
		case <-c:
		}
		if t != nil {
			t.Stop()
		}
	}
}

// IdentityTimer is the one-shot timer the expiry loop sleeps on; clock.Timer
// satisfies it, so the worker passes Overrides.Clock.NewTimer through a one-line
// adapter (the proxy does not import the clock port).
type IdentityTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type wallTimer struct{ t *time.Timer }

func (w wallTimer) C() <-chan time.Time { return w.t.C }
func (w wallTimer) Stop() bool          { return w.t.Stop() }

func (p *Proxy) newIdentityTimer(d time.Duration) IdentityTimer {
	if p.idTimer != nil {
		return p.idTimer(d)
	}
	return wallTimer{time.NewTimer(d)}
}

func (r *sessionRegistry) nextDue() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.expiry) == 0 {
		return time.Time{}, false
	}
	return r.expiry[0].due, true
}

// expireDue runs every expiry step whose due time has passed.
func (p *Proxy) expireDue() {
	now := p.validityClock()
	var goaway []func()
	var cut []closedSession
	r := p.sessions
	r.mu.Lock()
	for len(r.expiry) > 0 && !r.expiry[0].due.After(now) {
		s := r.expiry[0]
		if s.released || (s.closing && !s.hard) {
			heap.Pop(&r.expiry)
			continue
		}
		switch {
		case s.hard:
			// A busy HTTP/1 request outlived exp by the skew (an SSE relay, a long
			// download or upload): stop it now. The event was written at exp.
			heap.Pop(&r.expiry)
			if !s.closed {
				s.closed = true
				cut = append(cut, closedSession{ci: firstID(s), proto: s.proto, domain: s.domain, port: s.port,
					closers: append([]io.Closer(nil), s.closers...), silent: true})
			}
		case s.graceful != nil && !s.goaway:
			// GOAWAY first: the client finishes its in-flight streams and the
			// connection ends when they do; the hard stop follows.
			s.goaway, s.reported = true, true
			s.due = s.dueLocked()
			heap.Fix(&r.expiry, 0)
			cut = append(cut, closedSession{ci: firstID(s), proto: s.proto, domain: s.domain, port: s.port,
				reason: denyreason.IdentityExpired})
			goaway = append(goaway, s.graceful)
		case s.graceful != nil:
			heap.Pop(&r.expiry)
			for _, cs := range r.markLocked(map[*session]struct{}{s: {}}, true, nil) {
				cs.silent = true // the GOAWAY step already wrote the event
				cut = append(cut, cs)
			}
		case !s.interruptible && s.busy:
			// Mid-request: the request may finish, then the session ends
			// (endRequest); a stream that outlives the skew is force-closed.
			for _, cs := range r.markLocked(map[*session]struct{}{s: {}}, false, nil) {
				cs.reason = denyreason.IdentityExpired
				cut = append(cut, cs)
			}
			s.reported, s.hard = true, true
			s.due = s.dueLocked()
			heap.Fix(&r.expiry, 0)
		default:
			heap.Pop(&r.expiry)
			for _, cs := range r.markLocked(map[*session]struct{}{s: {}}, false, nil) {
				cs.reason = denyreason.IdentityExpired
				cut = append(cut, cs)
			}
			s.reported = true
		}
	}
	r.mu.Unlock()
	for i := range cut {
		if cut[i].reason == denyreason.IdentityExpired {
			cut[i].ci.Status, cut[i].ci.Reason = identity.StatusExpired, ""
		}
	}
	p.finishIdentityCut(cut)
	for _, f := range goaway {
		f()
	}
}

func firstID(s *session) connIdentity {
	if len(s.ids) > 0 {
		return s.ids[0]
	}
	return s.tracked
}

// cutItem is one session an identity check found no longer valid, with the
// identity (status and reason included) its deny event carries.
type cutItem struct {
	s  *session
	ci connIdentity
}

// RecheckIdentitySessions re-runs the binding check of every require-mode
// session against the snapshot current now and closes those that fail: the
// signing key left the bundle's JWKS (unknown_kid), or the agent was disabled or
// its key removed (agent_disabled, cnf_mismatch, ...). Each cut is one
// identity_required deny event whose stored identity_status and identity_reason
// are the failed check's, and it is counted as an identity verification. Open
// sessions that were never armed (opened under attribute or challenge mode
// before the agent moved to require) are swept too: one holding a Warden token
// that still binds is armed now, one holding any other identity is cut, and an
// interruptible one (tunnel, raw TLS, WebSocket, h2) with no identity is cut as
// identity_required. A worker calls it after every applied bundle, right after
// CloseBlockedSessions. With identity off or not in require mode it does
// nothing.
func (p *Proxy) RecheckIdentitySessions() {
	h := p.identity()
	if h == nil || h.mode != IdentityModeRequire {
		return
	}
	r := p.sessions
	type seen struct {
		s             *session
		ci            connIdentity
		interruptible bool
	}
	var armed, loose []seen
	r.mu.Lock()
	for s := range r.all {
		if s.closing || s.released {
			continue
		}
		if s.pending {
			continue
		}
		if s.heapIdx >= 0 {
			armed = append(armed, seen{s: s, ci: s.tracked})
			continue
		}
		var ci connIdentity
		for _, id := range s.ids {
			if id.status() == identity.StatusValid {
				ci = id
				break
			}
		}
		loose = append(loose, seen{s: s, ci: ci, interruptible: s.interruptible})
	}
	r.mu.Unlock()

	var items []cutItem
	now := p.validityClock()
	check := func(a seen) (ok bool) {
		br := p.rebind(h, idResult{claims: a.ci.Claims, status: identity.StatusValid})
		if br.status == identity.StatusValid {
			return true
		}
		items = append(items, cutItem{s: a.s, ci: connIdentity{Claims: a.ci.Claims, Status: br.status, Reason: br.reason}})
		return false
	}
	for _, a := range armed {
		check(a)
	}
	for _, a := range loose {
		switch {
		case a.ci.status() != identity.StatusValid:
			if a.interruptible {
				items = append(items, cutItem{s: a.s, ci: connIdentity{Status: identity.StatusNone}})
			}
		case check(a):
			if a.ci.Claims.TokenType == identity.TokenWarden {
				if a.ci.Expiry.IsZero() {
					a.ci.Expiry = a.ci.Claims.Expiry
				}
				r.track(a.s, a.ci, h.skew, now)
			}
		}
	}
	p.cutItems(items, true)
}

// cutItems closes the sessions of items with an identity_required deny event
// each (none for a session whose event was already written), and counts the
// failed verification.
func (p *Proxy) cutItems(items []cutItem, force bool) {
	r := p.sessions
	var cut []closedSession
	r.mu.Lock()
	for _, it := range items {
		r.untrackLocked(it.s)
		reported := it.s.reported
		for _, cs := range r.markLocked(map[*session]struct{}{it.s: {}}, force, nil) {
			cs.ci, cs.reason, cs.silent = it.ci, denyreason.IdentityRequired, reported
			cs.detail = string(it.ci.Reason)
			it.s.reported = true
			cut = append(cut, cs)
		}
	}
	r.mu.Unlock()
	p.finishIdentityCut(cut)
}

// finishIdentityCut writes one deny event per cut session (counted through
// RecordBlocked by the shared deny chokepoint) and records the identity result
// it carries, then runs the closers it may run now, like finishBlockedCut.
func (p *Proxy) finishIdentityCut(cut []closedSession) {
	for _, cs := range cut {
		if cs.silent {
			continue
		}
		p.recordIdentity(cs.ci.status(), cs.ci.Reason, tokenTypeOf(cs.ci.Claims))
		p.emitDenyEventDetail(cs.ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    cs.domain,
			Port:      cs.port,
			Protocol:  cs.proto,
			Reason:    string(cs.reason),
		}, cs.detail)
	}
	for _, cs := range cut {
		for _, c := range cs.closers {
			closeQuiet(c)
		}
	}
}

func closeQuiet(c io.Closer) { _ = c.Close() }
