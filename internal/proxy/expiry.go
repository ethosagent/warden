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

// dueLocked is when the session's next expiry step runs. r.mu must be held.
// late marks an h1/h2 session armed after exp but inside the verifier's skew (the
// CONNECT verified, so it must be served): its steps move out by one skew rather
// than cutting a connection the verifier just admitted.
func (s *session) dueLocked() time.Time {
	base := s.exp
	if s.late {
		base = base.Add(s.skew)
	}
	switch {
	case s.graceful != nil && !s.goaway:
		return base // GOAWAY at exp
	case s.graceful != nil:
		return base.Add(s.skew) // h2 hard stop
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
	if s.released || s.closing || s.heapIdx >= 0 {
		return
	}
	s.exp, s.skew, s.tracked = ci.Expiry, skew, ci
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

// expiryReason says why a session was cut by the identity checks: the deny
// reason of its event and a bounded detail (the verifier's reason).
type expiryReason struct {
	reason denyreason.Reason
	detail string
}

// armExpiry registers a require-mode session for expiry: only a verified Warden
// token with an exp, in require mode, is armed. enforce re-checks the binding
// against the snapshot now and cuts the session when it already fails (a bundle
// applied between CONNECT verification and registration); it reports whether
// the session was cut, and the caller must not dial for it. Callers that cannot
// act on a cut (h1/h2 sessions, whose first request re-checks anyway) pass false.
func (p *Proxy) armExpiry(s *session, ci connIdentity, enforce bool) (cut bool) {
	if s == nil || ci.status() != identity.StatusValid || ci.Claims.TokenType != identity.TokenWarden || ci.Expiry.IsZero() {
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
		p.cutSessions([]*session{s}, expiryReason{denyreason.IdentityRequired, string(br.reason)})
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

// expireDue cuts every session whose due time has passed.
func (p *Proxy) expireDue() {
	now := p.validityClock()
	var goaway []func()
	var cut []closedSession
	r := p.sessions
	r.mu.Lock()
	for len(r.expiry) > 0 && !r.expiry[0].due.After(now) {
		s := r.expiry[0]
		if s.closing || s.released {
			heap.Pop(&r.expiry)
			continue
		}
		if s.graceful != nil && !s.goaway {
			// GOAWAY first: the client finishes its in-flight streams and the
			// connection ends when they do; the hard stop is exp+skew.
			s.goaway = true
			s.due = s.dueLocked()
			heap.Fix(&r.expiry, 0)
			cut = append(cut, closedSession{ci: firstID(s), proto: s.proto, domain: s.domain, port: s.port})
			goaway = append(goaway, s.graceful)
			continue
		}
		heap.Pop(&r.expiry)
		silent := s.goaway // the GOAWAY step already wrote the deny event
		for _, cs := range r.markLocked(map[*session]struct{}{s: {}}, false, nil) {
			cs.silent = silent
			cut = append(cut, cs)
		}
	}
	r.mu.Unlock()
	p.finishIdentityCut(cut, expiryReason{denyreason.IdentityExpired, ""})
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

// RecheckIdentitySessions re-runs the binding check of every armed require-mode
// session against the snapshot current now and closes those that fail: the
// signing key left the bundle's JWKS (unknown_kid), or the agent was disabled or
// the key removed (agent_mismatch, key_revoked ...). Each cut writes one
// identity_required deny event whose detail is the verifier reason. A worker
// calls it after every applied bundle, right after CloseBlockedSessions. With
// identity off or not in require mode it does nothing.
func (p *Proxy) RecheckIdentitySessions() {
	h := p.identity()
	if h == nil || h.mode != IdentityModeRequire {
		return
	}
	r := p.sessions
	r.mu.Lock()
	type armed struct {
		s  *session
		ci connIdentity
	}
	list := make([]armed, 0, len(r.expiry))
	for _, s := range r.expiry {
		if !s.closing {
			list = append(list, armed{s, s.tracked})
		}
	}
	r.mu.Unlock()
	byReason := make(map[identity.Reason][]*session)
	for _, a := range list {
		if br := p.rebind(h, idResult{claims: a.ci.Claims, status: identity.StatusValid}); br.status != identity.StatusValid {
			byReason[br.reason] = append(byReason[br.reason], a.s)
		}
	}
	for reason, ss := range byReason {
		p.cutSessions(ss, expiryReason{denyreason.IdentityRequired, string(reason)})
	}
}

// cutSessions closes the given sessions for the identity reason, once each.
func (p *Proxy) cutSessions(ss []*session, why expiryReason) {
	r := p.sessions
	hit := make(map[*session]struct{}, len(ss))
	for _, s := range ss {
		hit[s] = struct{}{}
	}
	r.mu.Lock()
	for _, s := range ss {
		r.untrackLocked(s)
	}
	cut := r.markLocked(hit, false, nil)
	r.mu.Unlock()
	p.finishIdentityCut(cut, why)
}

// finishIdentityCut writes one deny event per cut session (counted through
// RecordBlocked by the shared deny chokepoint), then runs the closers it may
// run now, like finishBlockedCut.
func (p *Proxy) finishIdentityCut(cut []closedSession, why expiryReason) {
	for _, cs := range cut {
		if cs.silent {
			continue
		}
		p.emitDenyEventDetail(cs.ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    cs.domain,
			Port:      cs.port,
			Protocol:  cs.proto,
			Reason:    string(why.reason),
		}, why.detail)
	}
	for _, cs := range cut {
		for _, c := range cs.closers {
			closeQuiet(c)
		}
	}
}

func closeQuiet(c io.Closer) { _ = c.Close() }
