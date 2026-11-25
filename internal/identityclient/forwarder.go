package identityclient

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// Forwarder limits. They equal the worker's own CONNECT preamble limits in
// internal/proxy/serve.go (maxConnectLineBytes, maxConnectHeaderBytes,
// connectPreambleTimeout); TestForwarderLimitsMatchWorker compares them to the
// worker's source, so a change on one side fails the other's test. They are
// constants on purpose: a knob could only weaken the floor.
const (
	// maxConnectLineBytes caps the CONNECT request line, CRLF included (414).
	maxConnectLineBytes = 8 << 10 // 8 KiB
	// maxConnectHeaderBytes caps the whole preamble: request line, every header
	// line and the blank line (431).
	maxConnectHeaderBytes = 64 << 10 // 64 KiB
	// maxConnectHeaderLines caps the header lines after the request line (431).
	maxConnectHeaderLines = 100
	// connectPreambleTimeout is how long a client may take to deliver the
	// whole preamble.
	connectPreambleTimeout = 10 * time.Second
	// workerDialTimeout bounds the one dial to the worker.
	workerDialTimeout = 10 * time.Second

	// maxWorkerReplyBody caps a non-200 worker reply body that is relayed.
	maxWorkerReplyBody = 64 << 10
	// drainLimit and drainTimeout bound how much of a rejected request is read
	// and discarded, so the close does not reset the connection before the
	// client has read the rejection.
	drainLimit   = 1 << 20
	drainTimeout = 2 * time.Second

	// clientUser and workerUser are the Basic user names. The client proves it
	// is the supervised child with "wx:<ClientCredential>"; the worker reads
	// the token from "session:<token>" (identity contract v1).
	clientUser = "wx"
	workerUser = "session"
)

// Fixed 503 bodies: they name the failure class, never the error text.
const (
	reasonLoginRequired     = "login_required"
	reasonIssuerUnreachable = "issuer_unreachable"
	reasonTokenUnavailable  = "token_unavailable"
	// The reasons of the Warden-token path (also State reasons) and the tunnel cap.
	reasonCPUnreachable  = "cp_unreachable"
	reasonExchangeDenied = "exchange_denied"
	reasonTunnelLimit    = "tunnel_limit"

	// reasonHeader names the failure class of a 503 for programs.
	reasonHeader = "X-Warden-Forwarder-Reason"
)

// Forwarder is a CONNECT-only HTTP proxy for loopback. A child process points
// HTTPS_PROXY at it; for every CONNECT it asks Token for the current user ID
// token and opens a fresh CONNECT to the single worker at WorkerAddr carrying
// that token as Proxy-Authorization: Basic base64("session:"+token). The token
// lives only in memory: it is never written to an environment, argv, file or
// log (logs carry Fingerprint(token), 8 hex characters).
//
// What the forwarder does and does not do:
//
//   - It serves CONNECT only; any other method gets 405.
//   - The client must present Proxy-Authorization: Basic base64("wx:"+
//     ClientCredential), checked in constant time and never sent on. A
//     missing or wrong credential gets 407 and no dial. Every other client
//     header is dropped: the CONNECT to the worker is built fresh from the
//     request target, Host and the injected Proxy-Authorization.
//   - It dials only WorkerAddr and never the CONNECT target, so it adds no
//     egress route of its own. The worker's status line is relayed verbatim
//     (a 403 stays a 403). On a 200 the two sides are spliced.
//   - With no valid token (Token returns an error) the client gets 503 and the
//     worker is not dialled. One failure does not poison the next CONNECT.
//
// The preamble is bounded exactly like the worker's: a request line over
// 8 KiB gets 414, a header block over 64 KiB gets 431, and the whole preamble
// must arrive within 10 s.
//
// Limitation: attribution is bound per tunnel at CONNECT time. A tunnel opened
// before a token refresh keeps the token it was opened with, so clients are
// expected to recycle connections. No refresh timer is needed: Token (for the
// Client, Client.Token) refreshes on demand when 2/3 of the token lifetime has
// passed, which gives every new tunnel a fresh token without a goroutine.
//
// A Forwarder is safe for concurrent use; fields must not change after Serve.
type Forwarder struct {
	// WorkerAddr is the worker proxy's host:port, the only address dialled.
	WorkerAddr string
	// Token returns the current ID token; IDC-06 passes Client.Token's IDToken.
	// Ignored when Source is set.
	Token func(ctx context.Context) (string, error)
	// Source, when set, supplies the Warden token of an agent (RCP-01) instead
	// of Token: a worker 407 forces one Refresh and a retry, a rotation drains
	// the tunnels opened with the old token, and a 503 carries the failure
	// class in X-Warden-Forwarder-Reason.
	Source TokenSource
	// ClientCredential is the per-run secret the child must present. It may be
	// empty only with AllowAnonymousClients.
	ClientCredential string
	// AllowAnonymousClients lets clients connect without a credential
	// (`identity forward` when --client-credential-env is not given): the
	// forwarder is then reachable by anything that can reach its listener. Any
	// Proxy-Authorization a client sends is still dropped.
	AllowAnonymousClients bool
	// MaxTunnels caps the CONNECTs being served at once; above it a CONNECT gets
	// 503. Zero selects 512.
	MaxTunnels int
	// DialContext opens the one connection to WorkerAddr; nil uses a net.Dialer
	// with the 10s dial timeout. Tests pass a recording dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Clock times the tunnel drain (idle for 2s, token exp); nil is the real
	// clock. The preamble and dial deadlines use Now and real time.
	Clock clock.Clock
	// Now is the clock for the preamble deadline; nil selects time.Now.
	Now func() time.Time
	// Log receives one line per tunnel; nil discards.
	Log *slog.Logger

	// Challenge, when set, turns on sign-in challenge handling (#558): with no
	// usable login (Token returns ErrLoginRequired) the forwarder still dials
	// the worker, WITHOUT Proxy-Authorization, and a 407 identity_required from
	// it is answered by the Challenger and relayed to the agent without the
	// device code. When nil, no login means 503 login_required and nothing is
	// dialled, as before.
	Challenge *Challenger
	// InTunnel, with Challenge set, asks the worker to put the sign-in challenge
	// inside the tunnel (#621) instead of refusing the CONNECT with a 407: the
	// anonymous CONNECT carries X-Warden-Challenge: in-tunnel, and a worker that
	// terminates TLS answers 200 with the offer in X-Warden-Sign-In (removed here
	// before the agent sees the head); the agent's first request then gets a 403
	// that names the link. A worker that cannot (no CA, an older build) still
	// sends the 407, which is handled as before. Without InTunnel the CONNECT is
	// byte for byte what it was.
	InTunnel bool

	// preambleTimeout overrides connectPreambleTimeout in tests.
	preambleTimeout time.Duration

	// tunnels is set by Serve.
	tunnels *tunnelRegistry
}

func (f *Forwarder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (f *Forwarder) preamble() time.Duration {
	if f.preambleTimeout > 0 {
		return f.preambleTimeout
	}
	return connectPreambleTimeout
}

// Serve accepts connections on ln until ctx is cancelled or ln is closed, then
// closes ln, closes every open tunnel and returns once all handlers are done.
// It returns nil for those two causes and the accept error otherwise.
func (f *Forwarder) Serve(ctx context.Context, ln net.Listener) error {
	switch {
	case f.WorkerAddr == "":
		return errors.New("identityclient: forwarder needs a worker address")
	case f.Token == nil && f.Source == nil:
		return errors.New("identityclient: forwarder needs a token source")
	case f.ClientCredential == "" && !f.AllowAnonymousClients:
		return errors.New("identityclient: forwarder needs a client credential")
	}
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	f.tunnels = newTunnelRegistry(f.Clock, f.MaxTunnels, f.currentFingerprint)
	var loops sync.WaitGroup
	loopCtx, stopLoops := context.WithCancel(ctx)
	// The drain loop outlives the handlers (they are waited for first), so a
	// token's exp is enforced while the tunnels wind down.
	defer loops.Wait()
	defer stopLoops()
	loops.Add(1)
	go func() { defer loops.Done(); f.tunnels.run(loopCtx) }()
	var wg sync.WaitGroup
	defer wg.Wait()
	if f.Source != nil {
		f.Source.OnRotate(f.onRotate)
	}
	if f.Challenge != nil {
		// On return: cancel the context the poll is bound to, wait for the poll,
		// then for the handlers (defers run in reverse).
		defer f.Challenge.Wait()
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
	}
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Transient (for example out of descriptors): back off.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(delay):
					continue
				case <-ctx.Done():
					return nil
				}
			}
			return fmt.Errorf("identityclient: forwarder accept: %w", err)
		}
		delay = 0
		wg.Add(1)
		go func() {
			defer wg.Done()
			closeConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer closeConn()
			f.handle(ctx, conn)
		}()
	}
}

// errLineTooLong reports a line that crossed its cap before its newline.
var errLineTooLong = errors.New("identityclient: forwarder line too long")

// readBoundedLine reads one '\n'-terminated line, newline included, and
// refuses any line longer than limit without buffering past it.
func readBoundedLine(br *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return "", errLineTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return string(line), nil
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
}

// reply writes a complete bodyless-or-fixed-body response and announces close.
func reply(w io.Writer, status, extraHeaders, body string) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %s\r\n%sConnection: close\r\nContent-Length: %d\r\n\r\n%s",
		status, extraHeaders, len(body), body)
}

// rejectAndClose answers a request the forwarder will not serve, then discards
// a bounded amount of what the client is still sending so closing does not
// reset the connection ahead of the response.
func rejectAndClose(conn net.Conn, br *bufio.Reader, status, extra, body string) {
	reply(conn, status, extra, body)
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(drainTimeout))
	_, _ = io.Copy(io.Discard, io.LimitReader(br, drainLimit))
}

// handle serves one client connection.
func (f *Forwarder) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)

	if err := conn.SetReadDeadline(f.now().Add(f.preamble())); err != nil {
		return
	}
	line, err := readBoundedLine(br, maxConnectLineBytes)
	if err != nil {
		if errors.Is(err, errLineTooLong) {
			rejectAndClose(conn, br, "414 URI Too Long", "", "")
		}
		return
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "HTTP/1.") {
		rejectAndClose(conn, br, "400 Bad Request", "", "")
		return
	}
	if fields[0] != "CONNECT" {
		rejectAndClose(conn, br, "405 Method Not Allowed", "Allow: CONNECT\r\n", "")
		return
	}
	target := fields[1]
	if !validTarget(target) {
		rejectAndClose(conn, br, "400 Bad Request", "", "")
		return
	}

	// Header block: only Proxy-Authorization is looked at; everything else is
	// read (to bound it and find the end) and dropped.
	total := len(line)
	var auth string
	authLines, lines := 0, 0
	for {
		hdr, err := readBoundedLine(br, maxConnectHeaderBytes-total)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				rejectAndClose(conn, br, "431 Request Header Fields Too Large", "", "")
			}
			return
		}
		total += len(hdr)
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
		if lines++; lines > maxConnectHeaderLines {
			rejectAndClose(conn, br, "431 Request Header Fields Too Large", "", "")
			return
		}
		if name, value, ok := strings.Cut(hdr, ":"); ok && strings.EqualFold(name, "Proxy-Authorization") {
			if authLines == 0 {
				auth = strings.TrimSpace(value)
			}
			authLines++
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	if f.ClientCredential != "" && (authLines != 1 || !f.credentialOK(auth)) {
		rejectAndClose(conn, br, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"warden-forwarder\"\r\n", "")
		return
	}

	if !f.tunnels.reserve() {
		f.log().Warn("identity forwarder: tunnel limit reached", "max_tunnels", f.tunnels.max)
		rejectAndClose(conn, br, "503 Service Unavailable", "Content-Type: text/plain\r\n"+reasonHeader+": "+reasonTunnelLimit+"\r\n", "warden forwarder: "+reasonTunnelLimit+"\n")
		return
	}
	defer f.tunnels.release()

	token, exp, err := f.acquire(ctx)
	anonymous := false
	if (err != nil || token == "") && f.Challenge != nil && errors.Is(err, ErrLoginRequired) {
		// No usable login and the sign-in challenge is on: ask the worker. It
		// either challenges (407) or, when it does not enforce identity, lets
		// the request through unattributed, which is what that mode means.
		anonymous, token, err = true, "", nil
	}
	if !anonymous && (err != nil || token == "") {
		reason := f.failureReason(err)
		f.log().Warn("identity forwarder: no token for CONNECT", "reason", reason)
		rejectAndClose(conn, br, "503 Service Unavailable", "Content-Type: text/plain\r\n"+reasonHeader+": "+reason+"\r\n", "warden forwarder: "+reason+"\n")
		return
	}
	fp := "none"
	if !anonymous {
		fp = Fingerprint(token)
	}

	// A fresh CONNECT: the request target, Host and the injected identity (none
	// when the sign-in challenge is being asked for). An anonymous CONNECT asks
	// the worker to put the challenge inside the tunnel (#621): the worker's 200
	// then carries the offer, which is removed below.
	authLine := ""
	switch {
	case !anonymous:
		authLine = workerAuthLine(token)
	case f.InTunnel:
		authLine = challengeAskHeader + ": " + challengeAskValue + "\r\n"
	}
	rep, kind := f.connectWorker(ctx, target, authLine)
	if kind != "" {
		f.log().Warn("identity forwarder: "+kind, "token_fp", fp)
		rejectAndClose(conn, br, "502 Bad Gateway", "Content-Type: text/plain\r\n", "warden forwarder: "+kind+"\n")
		return
	}
	if rep.status == 407 && !anonymous && f.Source != nil {
		// The worker did not accept the token (revoked, or rotated at the CP):
		// force one exchange and try once more. The refreshed token is used even
		// when the exchange was held back by a cooldown and failed, as long as a
		// valid one is held.
		fresh, rerr := f.Source.Refresh(ctx)
		if fresh.AccessToken != "" {
			f.log().Info("identity forwarder: worker answered 407, retrying once", "token_fp", fp,
				"refreshed_fp", Fingerprint(fresh.AccessToken), "refresh_error", rerr != nil)
			if rep2, kind2 := f.connectWorker(ctx, target, workerAuthLine(fresh.AccessToken)); kind2 == "" {
				_ = rep.wc.Close()
				rep, exp, fp = rep2, fresh.Expiry, Fingerprint(fresh.AccessToken)
			}
		}
	}
	wc, wbr, status, head := rep.wc, rep.br, rep.status, rep.head
	defer func() { _ = wc.Close() }()

	if status == 407 && f.Challenge != nil {
		f.relayChallenge(ctx, conn, br, wc, wbr, head, fp)
		return
	}
	// The offer header never reaches the agent, whoever sent it and on whatever
	// status; it is only acted on for the 200 of an in-tunnel challenge.
	var offer string
	offer, head = stripHeader(head, signInHeader)
	if status == 200 && anonymous && f.InTunnel && f.Challenge != nil && offer != "" {
		f.Challenge.HandleOffer(ctx, offer)
		f.log().Info("identity forwarder: in-tunnel sign-in challenge", "token_fp", fp)
	}
	if _, err := io.WriteString(conn, head); err != nil {
		return
	}
	if status != 200 {
		f.log().Info("identity forwarder: CONNECT relayed", "token_fp", fp, "status", status)
		_ = wc.SetReadDeadline(f.now().Add(f.preamble()))
		relayErrorBody(conn, wbr, head)
		return
	}
	f.tunnels.serve(f.log(), target, status, fp, exp, conn, br, wc, wbr)
}

// workerReply is the worker's answer to one CONNECT.
type workerReply struct {
	wc     net.Conn
	br     *bufio.Reader
	status int
	head   string
}

// connectWorker dials the worker, sends a fresh CONNECT to target carrying
// authLine (empty, or one complete header line) and reads its status line and
// headers. A non-empty kind names the failure; wc is then closed.
func (f *Forwarder) connectWorker(ctx context.Context, target, authLine string) (workerReply, string) {
	dial := f.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: workerDialTimeout}).DialContext
	}
	wc, err := dial(ctx, "tcp", f.WorkerAddr)
	if err != nil {
		return workerReply{}, "worker_unreachable"
	}
	if _, err := fmt.Fprintf(wc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, authLine); err != nil {
		_ = wc.Close()
		return workerReply{}, "worker_unreachable"
	}
	status, head, wbr, err := readWorkerHead(wc, f.now, f.preamble())
	if err != nil {
		_ = wc.Close()
		return workerReply{}, "worker_bad_reply"
	}
	return workerReply{wc: wc, br: wbr, status: status, head: head}, ""
}

// workerAuthLine is the Proxy-Authorization header line that carries token.
func workerAuthLine(token string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(workerUser+":"+token)) + "\r\n"
}

// acquire returns the token to inject and its expiry (zero for the P1 ID token,
// whose tunnels are not drained).
func (f *Forwarder) acquire(ctx context.Context) (string, time.Time, error) {
	if f.Source != nil {
		tok, err := f.Source.Token(ctx)
		return tok.AccessToken, tok.Expiry, err
	}
	tok, err := f.Token(ctx)
	return tok, time.Time{}, err
}

// failureReason names why no token is available. The P1 path keeps its two
// reasons; the Warden-token path reports the State reasons.
func (f *Forwarder) failureReason(err error) string {
	var de ErrExchangeDenied
	switch {
	case errors.Is(err, ErrLoginRequired):
		return reasonLoginRequired
	case errors.As(err, &de):
		return reasonExchangeDenied
	case errors.Is(err, ErrIssuerUnreachable):
		if f.Source != nil {
			return reasonLoginRequired
		}
		return reasonIssuerUnreachable
	case f.Source != nil:
		return reasonCPUnreachable
	}
	return reasonTokenUnavailable
}

// currentFingerprint is the fingerprint of the newest valid Warden token.
func (f *Forwarder) currentFingerprint() (string, bool) {
	if f.Source == nil {
		return "", false
	}
	tok, ok := f.Source.Current()
	if !ok {
		return "", false
	}
	return Fingerprint(tok.AccessToken), true
}

// onRotate runs after every successful exchange: it logs the rotation and has
// the drain loop look at the tunnels opened with an older token.
func (f *Forwarder) onRotate() {
	if tok, ok := f.Source.Current(); ok {
		f.log().Info("token_rotated", "token_fp", Fingerprint(tok.AccessToken), "exp", tok.Expiry)
	}
	f.tunnels.wake()
}

// relayChallenge answers the agent for a worker 407. The worker's body is read
// (capped), handed to the Challenger, which shows the user where to sign in and
// starts the poll, and what it returns, without the device code, is relayed in a
// fresh 407. The worker's Content-Length and any other framing are not reused.
func (f *Forwarder) relayChallenge(ctx context.Context, conn net.Conn, br *bufio.Reader, wc net.Conn, wbr *bufio.Reader, head, fp string) {
	var raw []byte
	if n, err := strconv.Atoi(headerValue(head, "Content-Length")); err == nil && n > 0 {
		_ = wc.SetReadDeadline(f.now().Add(f.preamble()))
		raw = readLimited(wbr, min(n, maxWorkerReplyBody))
	}
	body := f.Challenge.Handle(ctx, raw)
	f.log().Info("identity forwarder: sign-in challenge relayed", "token_fp", fp, "status", 407)
	extra := "Content-Type: application/json\r\nCache-Control: no-store\r\n"
	if pa := headerValue(head, "Proxy-Authenticate"); pa != "" && !strings.ContainsAny(pa, "\r\n") {
		extra = "Proxy-Authenticate: " + pa + "\r\n" + extra
	}
	rejectAndClose(conn, br, "407 Proxy Authentication Required", extra, string(body))
}

// validTarget accepts host:port with a non-empty host, a numeric port and no
// whitespace or control characters. The forwarder never dials it; the worker
// parses it again.
func validTarget(t string) bool {
	host, port, err := net.SplitHostPort(t)
	if err != nil || host == "" {
		return false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	for _, r := range t {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// credentialOK checks a Proxy-Authorization value against
// "Basic base64(wx:ClientCredential)" in constant time.
func (f *Forwarder) credentialOK(value string) bool {
	scheme, payload, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return false
	}
	// Hash both sides so the compare takes the same time for any length.
	got := sha256.Sum256(raw)
	want := sha256.Sum256([]byte(clientUser + ":" + f.ClientCredential))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// readWorkerHead reads the worker's status line and header block (bounded like
// the client's) and returns the status code, the exact bytes read and the
// reader holding anything the worker sent after them.
func readWorkerHead(wc net.Conn, now func() time.Time, timeout time.Duration) (int, string, *bufio.Reader, error) {
	if err := wc.SetReadDeadline(now().Add(timeout)); err != nil {
		return 0, "", nil, err
	}
	wbr := bufio.NewReader(wc)
	line, err := readBoundedLine(wbr, maxConnectLineBytes)
	if err != nil {
		return 0, "", nil, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") {
		return 0, "", nil, errors.New("malformed status line")
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 999 {
		return 0, "", nil, errors.New("malformed status code")
	}
	var sb strings.Builder
	sb.WriteString(line)
	for {
		hdr, err := readBoundedLine(wbr, maxConnectHeaderBytes-sb.Len())
		if err != nil {
			return 0, "", nil, err
		}
		sb.WriteString(hdr)
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}
	if err := wc.SetReadDeadline(time.Time{}); err != nil {
		return 0, "", nil, err
	}
	return status, sb.String(), wbr, nil
}

// relayErrorBody relays the body of a non-200 worker reply when it declares a
// Content-Length (capped); the worker's 403 has none.
func relayErrorBody(client net.Conn, wbr *bufio.Reader, head string) {
	for _, l := range strings.Split(head, "\n") {
		name, value, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(name, "Content-Length") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n <= 0 {
			return
		}
		_, _ = io.Copy(client, io.LimitReader(wbr, int64(min(n, maxWorkerReplyBody))))
		return
	}
}
