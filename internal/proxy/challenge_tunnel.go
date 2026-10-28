package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

const (
	// challengeTunnelTimeout bounds a whole challenge tunnel (handshake, the one
	// request, the answer). The handler holds nothing upstream, so a short bound
	// is the slowloris floor for a client that stalls after the 200.
	challengeTunnelTimeout = 30 * time.Second
	// challengeMaxHeaderBytes caps the request head read inside the tunnel.
	challengeMaxHeaderBytes = 64 << 10
)

// tunnelSignIn is the machine-readable part of the in-tunnel 403: what a UI
// needs to show a button. Never the device code, the token endpoint or the
// client id.
type tunnelSignIn struct {
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	UserCode                string `json:"user_code"`
	ExpiresIn               int    `json:"expires_in"`
}

type tunnelError struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// tunnelBody is the JSON of the in-tunnel 403, in the OpenAI / Anthropic error
// shape so an SDK puts error.message in front of the user.
type tunnelBody struct {
	Type        string        `json:"type"`
	Error       tunnelError   `json:"error"`
	SignIn      *tunnelSignIn `json:"sign_in,omitempty"`
	SignInError SignInOutcome `json:"sign_in_error,omitempty"`
}

// challengeTunnelJSON renders the 403 body for a challenge. The user code is in
// the message on purpose (the user types it); it is not a credential.
func challengeTunnelJSON(c challengeBody) []byte {
	tb := tunnelBody{
		Type:  "error",
		Error: tunnelError{Type: string(denyreason.IdentityRequired), Code: string(denyreason.IdentityRequired)},
	}
	if o := c.SignIn; o != nil {
		url := o.VerificationURIComplete
		if url == "" {
			url = o.VerificationURI
		}
		tb.Error.Message = fmt.Sprintf("Sign in to continue: %s (code %s). Then send your message again.", url, o.UserCode)
		tb.SignIn = &tunnelSignIn{
			VerificationURI:         o.VerificationURI,
			VerificationURIComplete: o.VerificationURIComplete,
			UserCode:                o.UserCode,
			ExpiresIn:               o.ExpiresIn,
		}
	} else {
		tb.Error.Message = fmt.Sprintf("Sign-in is not available right now (%s). Try again in a moment.", c.SignInError)
		tb.SignInError = c.SignInError
	}
	b, err := json.Marshal(tb)
	if err != nil { // strings and ints: cannot fail; fail closed anyway
		return []byte(`{"type":"error","error":{"type":"identity_required","code":"identity_required","message":"Sign in required."}}`)
	}
	return b
}

// serveChallengeTunnel accepts the CONNECT and answers it inside the tunnel: a
// 200 with the offer in X-Warden-Sign-In (when there is one), the TLS handshake
// with the minted leaf, then a 403 naming the sign-in link to every request,
// and a close. It never dials upstream, never evaluates the policy and never
// swaps a secret: the connection has no identity, so nothing is reachable.
func (p *Proxy) serveChallengeTunnel(conn net.Conn, br *bufio.Reader, domain string, c challengeBody) {
	p.reach(PathChallenge)
	leaf, err := p.getOrCreateCert(domain)
	if err != nil {
		// Same as before this feature: the client sees the tunnel close. Say so
		// with the 407 rather than a 200 that leads nowhere.
		writeChallenge(conn, c)
		return
	}
	head := "HTTP/1.1 200 Connection Established\r\n"
	if c.SignIn != nil {
		if v := offerHeader(*c.SignIn); v != "" {
			head += SignInHeader + ": " + v + "\r\n"
		}
	}
	if _, err := io.WriteString(conn, head+"\r\n"); err != nil {
		return
	}

	limit := challengeTunnelTimeout
	if p.challengeTimeout > 0 {
		limit = p.challengeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(limit))
	tlsConn := tls.Server(bufferedConn{Reader: br, Conn: conn}, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer func() { _ = tlsConn.Close() }()

	serveChallengeConn(tlsConn, challengeTunnelJSON(c), limit)
}

// serveChallengeConn answers every request on the one already-handshaken
// connection with the 403 and Connection: close, over HTTP/1.1 or HTTP/2 as
// negotiated: net/http closes an h1 connection after the answer and sends GOAWAY
// on h2. It returns once the connection has ended.
func serveChallengeConn(tc *tls.Conn, body []byte, limit time.Duration) {
	ln := &oneConnListener{conn: tc, done: make(chan struct{})}
	// net/http clears the connection deadline before it reads a request head, so
	// the bound must be set here too: a client that handshakes and then stalls
	// (h1: no request; h2: no frames) is cut at limit, not held open.
	srv := &http.Server{
		MaxHeaderBytes:    challengeMaxHeaderBytes,
		ReadHeaderTimeout: limit,
		ReadTimeout:       limit,
		WriteTimeout:      limit,
		IdleTimeout:       limit,
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				ln.finish()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			h.Set("Content-Type", "application/json")
			h.Set("Cache-Control", "no-store")
			h.Set("Connection", "close")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(body)
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	_ = srv.Serve(ln)
}

// oneConnListener yields one connection, then blocks until that connection has
// ended and reports the listener closed, so http.Server.Serve returns exactly
// when the connection is done.
type oneConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) finish()      { l.once.Do(func() { close(l.done) }) }
func (l *oneConnListener) Close() error { l.finish(); return nil }
func (l *oneConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
