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
	Token func(ctx context.Context) (string, error)
	// ClientCredential is the per-run secret the child must present.
	ClientCredential string
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

	// preambleTimeout overrides connectPreambleTimeout in tests.
	preambleTimeout time.Duration
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
	case f.Token == nil:
		return errors.New("identityclient: forwarder needs a token source")
	case f.ClientCredential == "":
		return errors.New("identityclient: forwarder needs a client credential")
	}
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()
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
	authLines := 0
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

	if authLines != 1 || !f.credentialOK(auth) {
		rejectAndClose(conn, br, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"warden-forwarder\"\r\n", "")
		return
	}

	token, err := f.Token(ctx)
	anonymous := false
	if (err != nil || token == "") && f.Challenge != nil && errors.Is(err, ErrLoginRequired) {
		// No usable login and the sign-in challenge is on: ask the worker. It
		// either challenges (407) or, when it does not enforce identity, lets
		// the request through unattributed, which is what that mode means.
		anonymous, token, err = true, "", nil
	}
	if !anonymous && (err != nil || token == "") {
		reason := reasonTokenUnavailable
		switch {
		case errors.Is(err, ErrLoginRequired):
			reason = reasonLoginRequired
		case errors.Is(err, ErrIssuerUnreachable):
			reason = reasonIssuerUnreachable
		}
		f.log().Warn("identity forwarder: no token for CONNECT", "reason", reason)
		rejectAndClose(conn, br, "503 Service Unavailable", "Content-Type: text/plain\r\n", "warden forwarder: "+reason+"\n")
		return
	}
	fp := "none"
	if !anonymous {
		fp = Fingerprint(token)
	}

	dialer := net.Dialer{Timeout: workerDialTimeout}
	wc, err := dialer.DialContext(ctx, "tcp", f.WorkerAddr)
	if err != nil {
		f.log().Warn("identity forwarder: worker unreachable", "token_fp", fp)
		rejectAndClose(conn, br, "502 Bad Gateway", "Content-Type: text/plain\r\n", "warden forwarder: worker_unreachable\n")
		return
	}
	defer func() { _ = wc.Close() }()

	// A fresh CONNECT: the request target, Host and the injected identity (none
	// when the sign-in challenge is being asked for).
	authLine := ""
	if !anonymous {
		authLine = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(workerUser+":"+token)) + "\r\n"
	}
	if _, err := fmt.Fprintf(wc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, authLine); err != nil {
		rejectAndClose(conn, br, "502 Bad Gateway", "Content-Type: text/plain\r\n", "warden forwarder: worker_unreachable\n")
		return
	}

	status, head, wbr, err := readWorkerHead(wc, f.now, f.preamble())
	if err != nil {
		f.log().Warn("identity forwarder: bad worker reply", "token_fp", fp)
		rejectAndClose(conn, br, "502 Bad Gateway", "Content-Type: text/plain\r\n", "warden forwarder: worker_bad_reply\n")
		return
	}
	if status == 407 && f.Challenge != nil {
		f.relayChallenge(ctx, conn, br, wc, wbr, head, fp)
		return
	}
	if _, err := io.WriteString(conn, head); err != nil {
		return
	}
	f.log().Info("identity forwarder: CONNECT relayed", "token_fp", fp, "status", status)
	if status != 200 {
		_ = wc.SetReadDeadline(f.now().Add(f.preamble()))
		relayErrorBody(conn, wbr, head)
		return
	}
	splice(conn, br, wc, wbr)
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

// splice copies both ways. EOF on one side half-closes the other's write side
// so a response can still finish; an error on either side, or both sides
// ending, closes both connections. Bytes the readers had already buffered are
// forwarded first.
func splice(client net.Conn, cbr *bufio.Reader, worker net.Conn, wbr *bufio.Reader) {
	var wg sync.WaitGroup
	pipe := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			_ = client.Close()
			_ = worker.Close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		_ = client.Close()
		_ = worker.Close()
	}
	wg.Add(2)
	go pipe(worker, cbr)
	go pipe(client, wbr)
	wg.Wait()
}
