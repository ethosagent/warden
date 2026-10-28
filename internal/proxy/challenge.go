package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// Identity challenge mode (#558, docs/identity-contract.md). A CONNECT without a
// valid identity is refused with a 407 that carries a sign-in URL; the client
// signs in with its own provider and retries with the token. The worker starts
// the device authorization but never polls for it and never holds a user token
// or refresh token (ADR 0002).

// The in-tunnel challenge (#621, docs/identity-contract.md "In-tunnel
// challenge"). A client that can hide the offer from its agent asks for it with
// ChallengeHeader on the CONNECT; the worker then accepts the tunnel, puts the
// offer in SignInHeader on the 200 and answers every request inside with a 403
// that names the link (challenge_tunnel.go).
const (
	// ChallengeHeader is the CONNECT request header that asks for the challenge
	// inside the tunnel.
	ChallengeHeader = "X-Warden-Challenge"
	// ChallengeInTunnel is its only value.
	ChallengeInTunnel = "in-tunnel"
	// SignInHeader carries the offer (base64url JSON of the SignInOffer, no
	// padding) on the 200 of an in-tunnel challenge. The client strips it.
	SignInHeader = "X-Warden-Sign-In"
)

// The JSON bodies of a 403 on a request of a terminated tunnel whose connection
// identity has expired, or that names a second subject, in challenge mode.
var (
	identityExpiredBody  = `{"error":"` + string(denyreason.IdentityExpired) + `"}`
	identityConflictBody = `{"error":"` + string(denyreason.IdentityConflict) + `"}`
)

// challengeBody is the 407 body. Reason is the bounded identity status (never
// token text or a library error); SignInError is set instead of SignIn when the
// worker could not start a device authorization.
type challengeBody struct {
	Error       string        `json:"error"`
	Reason      string        `json:"reason"`
	SignIn      *SignInOffer  `json:"sign_in,omitempty"`
	SignInError SignInOutcome `json:"sign_in_error,omitempty"`
}

// challengeReason maps a CONNECT identity status to the 407 `reason`. Every
// status that can reach the challenge is one of the four bounded values; a
// status this build does not know is reported as invalid, never echoed.
func challengeReason(st identity.Status) string {
	switch st {
	case identity.StatusNone, identity.StatusExpired, identity.StatusInvalid, identity.StatusUnverified:
		return string(st)
	default:
		return string(identity.StatusInvalid)
	}
}

// challengeConnect is the challenge gate on a CONNECT. It runs right after the
// connection identity is resolved and BEFORE the block-list check, policy
// evaluation and any dial. In challenge mode a connection whose identity is not
// valid gets a 407 with a sign-in offer and one deny event (identity_required);
// it returns true and the caller returns. unverified (the verifier could not
// fetch keys within its bound) fails closed here. A valid identity ends the
// agent's pending sign-in and returns false. In every other mode it does
// nothing.
//
// When the client asked for the in-tunnel challenge (ask) and the worker
// terminates TLS, the CONNECT is accepted instead and served by the
// challenge-only handler; otherwise, and always on a raw tunnel, it is the 407.
func (p *Proxy) challengeConnect(conn net.Conn, br *bufio.Reader, ci connIdentity, domain string, port int, ask string) bool {
	h := p.identity()
	if h == nil || h.mode != IdentityModeChallenge {
		return false
	}
	if ci.status() == identity.StatusValid {
		if h.signin != nil {
			h.signin.Forget(p.cfg.AgentID)
		}
		return false
	}
	body := challengeBody{Error: string(denyreason.IdentityRequired), Reason: challengeReason(ci.status())}
	outcome := SignInIssuerUnreachable
	if h.signin != nil {
		var offer SignInOffer
		offer, outcome = h.signin.Start(context.Background(), p.cfg.AgentID)
		if outcome == SignInStarted || outcome == SignInReused {
			body.SignIn = &offer
		}
	}
	if body.SignIn == nil {
		body.SignInError = outcome
	}
	inTunnel := ask == ChallengeInTunnel && p.caCert != nil
	p.cfg.Metrics.RecordSignInStarted(string(outcome))
	// The agent id and the outcome only: never the offer, its codes or a token.
	p.logSignIn(outcome)

	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Reason:    string(denyreason.IdentityRequired),
	})
	if inTunnel {
		p.serveChallengeTunnel(conn, br, domain, body)
		return true
	}
	writeChallenge(conn, body)
	return true
}

// offerHeader is the X-Warden-Sign-In value: base64url (no padding) of the
// offer as JSON.
func offerHeader(o SignInOffer) string {
	b, err := json.Marshal(o)
	if err != nil { // strings and ints: cannot fail
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (p *Proxy) logSignIn(outcome SignInOutcome) {
	switch outcome {
	case SignInStarted:
		p.cfg.Logger.Info("identity challenge: sign-in started", "agent", p.cfg.AgentID, "outcome", string(outcome))
	case SignInReused:
		p.cfg.Logger.Debug("identity challenge: sign-in reused", "agent", p.cfg.AgentID, "outcome", string(outcome))
	default:
		p.cfg.Logger.Warn("identity challenge: no sign-in offered", "agent", p.cfg.AgentID, "outcome", string(outcome))
	}
}

// writeChallenge writes the 407. It never carries WWW-Authenticate or a 401
// (the same rule as require mode), and it closes the connection.
func writeChallenge(w io.Writer, body challengeBody) {
	b, err := json.Marshal(body)
	if err != nil { // a struct of strings and ints cannot fail; fail closed anyway
		b = []byte(`{"error":"` + string(denyreason.IdentityRequired) + `"}`)
	}
	resp := &http.Response{
		StatusCode: http.StatusProxyAuthRequired,
		Status:     fmt.Sprintf("%d %s", http.StatusProxyAuthRequired, http.StatusText(http.StatusProxyAuthRequired)),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{
			"Proxy-Authenticate": {`Basic realm="warden"`},
			"Content-Type":       {"application/json"},
			"Cache-Control":      {"no-store"},
		},
		Body:          io.NopCloser(strings.NewReader(string(b))),
		ContentLength: int64(len(b)),
		Close:         true,
	}
	_ = resp.Write(w)
}

// challengeTerminated enforces challenge mode on a request of a terminated
// tunnel: a connection identity past exp plus skew (expired) or a second
// subject in X-Warden-Identity (conflict) is refused with a JSON 403 and
// Connection: close, so the client reconnects and is challenged again. Other
// statuses are only recorded: the CONNECT gate already required a valid
// identity. It reports whether the request ended.
func (p *Proxy) challengeTerminated(s *requestScope, h *identityHolder) bool {
	if h.mode != IdentityModeChallenge {
		return false
	}
	var reason denyreason.Reason
	var body string
	switch s.idStatus {
	case identity.StatusExpired:
		reason, body = denyreason.IdentityExpired, identityExpiredBody
	case identity.StatusConflict:
		reason, body = denyreason.IdentityConflict, identityConflictBody
	default:
		return false
	}
	p.emitDeny(s, reason, denyExtra{LatencyMs: s.latencyMs()})
	s.out.errorJSON(http.StatusForbidden, body)
	return true
}
