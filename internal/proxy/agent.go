package proxy

import (
	"io"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
)

// The agent kill switch (W-P2-AREG-05). A worker bound to a registered agent
// learns, on every applied policy change, whether that agent is disabled. While
// it is, every CONNECT, request and h2 stream is refused with 403 agent_disabled
// in every identity mode, and CloseAgentSessions cuts what is already open. The
// switch is deny-only: nothing here can allow a request, and the worker never
// clears it on its own (the worker package sets it from the applied policy).

// agentDisabledBody is the JSON body of every agent_disabled 403, built from the
// declared reason, never a second literal of it.
var agentDisabledBody = `{"error":"` + string(denyreason.AgentDisabled) + `"}`

// SetAgentDisabled sets whether the bound agent is disabled. It is one atomic
// store, safe against the hot path. Disabling also makes the session registry
// refuse sessions that open from now on, so a connection that passed the
// per-connection check just before the flip is still cut; the caller then runs
// CloseAgentSessions for the sessions already open. Enabling lifts both.
func (p *Proxy) SetAgentDisabled(disabled bool) {
	if disabled {
		p.agentDisabled.Store(true)
		p.sessions.refuseNew()
		return
	}
	p.agentDisabled.Store(false)
	p.sessions.allow()
}

// AgentDisabled reports whether the bound agent is currently disabled.
func (p *Proxy) AgentDisabled() bool { return p.agentDisabled.Load() }

// SetSessionTracking makes every session register, anonymous tunnels included,
// so CloseAgentSessions can cut them. A worker managed by a control plane turns
// it on; a standalone worker never has a registry and does not register
// anonymous tunnels. (Every h1/h2 session already costs one map insert and
// delete on the registry.) Call it before Serve.
func (p *Proxy) SetSessionTracking(on bool) { p.trackAll.Store(on) }

// trackSession reports whether a session for a connection with this identity
// must register: an attributed one always does (block-list cuts), an anonymous
// one only while every session is tracked.
func (p *Proxy) trackSession(ci connIdentity) bool {
	return ci.Claims.Sub != "" || ci.Claims.Email != "" || p.trackAll.Load()
}

// connectAgentDisabled is the CONNECT-time check: before identity resolution,
// the policy check, any dial and the 200. One atomic load when the agent is
// enabled. It records the deny through the shared chokepoint and answers a JSON
// 403.
func (p *Proxy) connectAgentDisabled(w io.Writer, domain string, port int) bool {
	if !p.agentDisabled.Load() {
		return false
	}
	p.emitDenyEvent(connIdentity{}, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Reason:    string(denyreason.AgentDisabled),
	})
	writeJSONResponse(w, http.StatusForbidden, agentDisabledBody)
	return true
}

// agentStage denies every request while the bound agent is disabled. It runs
// first in the request chain, ahead of identity and every policy gate, so a
// disabled agent's request reaches no judge, no secret swap and no upstream; h1
// requests, h2 streams and WebSocket upgrades all pass through it. The flag is
// read live, so an open keep-alive or h2 connection is refused on its next
// request.
func (p *Proxy) agentStage(s *requestScope) (endSession bool) {
	if !p.agentDisabled.Load() {
		return false
	}
	p.emitDeny(s, denyreason.AgentDisabled, denyExtra{LatencyMs: s.latencyMs()})
	s.out.errorJSON(http.StatusForbidden, agentDisabledBody)
	return true
}

// CloseAgentSessions closes every open session (tunnels, keep-alive and h2
// connections, WebSockets), identified or not, and writes one agent_disabled
// deny event for each. A worker calls it after an applied policy change that
// disabled the bound agent. A request already in flight completes; an HTTP/1
// session is cut as soon as it does.
func (p *Proxy) CloseAgentSessions() {
	for _, cs := range p.sessions.takeAll() {
		p.emitDenyEvent(cs.ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    cs.domain,
			Port:      cs.port,
			Protocol:  cs.proto,
			Reason:    string(denyreason.AgentDisabled),
		})
		for _, c := range cs.closers {
			_ = c.Close()
		}
	}
}

// refusedAtCreate writes the agent_disabled deny event for a session the
// registry closed at creation and reports true: the caller returns without
// dialing or forwarding a byte.
func (p *Proxy) refusedAtCreate(sess *session, ci connIdentity, domain string, port int, proto string) bool {
	if !sess.wasRefused() {
		return false
	}
	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  proto,
		Reason:    string(denyreason.AgentDisabled),
	})
	return true
}
