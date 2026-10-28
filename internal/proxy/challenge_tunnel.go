package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/ethosagent/warden/internal/denyreason"
)

const (
	// challengeTunnelTimeout bounds a whole challenge tunnel (handshake, the one
	// request, the answer). The handler holds nothing upstream, so a short bound
	// is the slowloris floor for a client that stalls after the 200.
	challengeTunnelTimeout = 30 * time.Second
	// challengeDrainBytes and challengeDrainTime bound how much of an unread
	// request body is discarded after the 403, so the close does not reset the
	// connection before the client has read the answer.
	challengeDrainBytes = 4 << 20
	challengeDrainTime  = 2 * time.Second
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

	_ = conn.SetDeadline(time.Now().Add(challengeTunnelTimeout))
	tlsConn := tls.Server(bufferedConn{Reader: br, Conn: conn}, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer func() { _ = tlsConn.Close() }()

	body := challengeTunnelJSON(c)
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		serveChallengeH2(tlsConn, body)
		return
	}
	serveChallengeH1(tlsConn, body)
}

// serveChallengeH1 reads one request head and answers it with the 403 and
// Connection: close. A body the client is still sending is drained (bounded)
// after the answer so the close is not a reset.
func serveChallengeH1(tc *tls.Conn, body []byte) {
	hbr := bufio.NewReaderSize(io.LimitReader(tc, challengeMaxHeaderBytes), 4096)
	req, err := http.ReadRequest(hbr)
	if err != nil {
		return
	}
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":  {"application/json"},
			"Cache-Control": {"no-store"},
		},
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	if err := resp.Write(tc); err != nil {
		return
	}
	_ = tc.CloseWrite()
	_ = tc.SetReadDeadline(time.Now().Add(challengeDrainTime))
	_, _ = io.Copy(io.Discard, io.LimitReader(tc, challengeDrainBytes))
}

// serveChallengeH2 answers every stream with the 403 and asks for a GOAWAY
// (Connection: close in the handler makes the h2 server send it after the
// first answer).
func serveChallengeH2(tc *tls.Conn, body []byte) {
	(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			h.Set("Content-Type", "application/json")
			h.Set("Cache-Control", "no-store")
			h.Set("Connection", "close")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(body)
		}),
	})
}
