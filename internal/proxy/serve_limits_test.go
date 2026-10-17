package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// This file pins the CONNECT preamble limits (#390): the request line and the
// whole header block are bounded before they are parsed, an over-limit preamble
// is answered with 414/431, exactly one deny decision is recorded, normal
// CONNECTs are unaffected, and a slow sender cannot hold a goroutine forever.

// capturingHandler records slog records so tests can assert the bounded fields
// on a deny decision record (reason/detail) without parsing stderr.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// denyRecords flattens every captured deny decision record into key=value maps.
func (h *capturingHandler) denyRecords() []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]string
	for _, r := range h.records {
		if r.Message != "egress decision" {
			continue
		}
		m := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			m[a.Key] = a.Value.String()
			return true
		})
		if m["decision"] == "deny" {
			out = append(out, m)
		}
	}
	return out
}

// newLimitsProxy builds a no-TLS proxy (raw-tunnel mode) without starting it.
func newLimitsProxy(t *testing.T, domains []string, logger *slog.Logger) (*Proxy, *syncStore) {
	t.Helper()
	var entries []config.AllowlistEntry
	for _, d := range domains {
		entries = append(entries, config.AllowlistEntry{Domain: d, Port: 443})
	}
	store := &syncStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
	}
	if logger != nil {
		cfg.Logger = logger
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, store
}

// startLimitsProxy starts a limits-test proxy on 127.0.0.1:0. dial overrides
// the upstream dialer and preambleTimeout the CONNECT preamble read deadline
// (0 = package default); both are white-box test seams (like now/leafTTL) and
// are set BEFORE Serve starts, so no other goroutine reads them concurrently.
func startLimitsProxy(t *testing.T, domains []string, dial func(network, addr string) (net.Conn, error), preambleTimeout time.Duration, logger *slog.Logger) (*Proxy, *syncStore) {
	t.Helper()
	p, store := newLimitsProxy(t, domains, logger)
	if dial != nil {
		p.dialFunc = dial
	}
	if preambleTimeout != 0 {
		p.preambleTimeout = preambleTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if p.Addr() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	return p, store
}

// dialRefused stands in for an upstream that never answers; the CONNECT 200 is
// written before the dial, so teardown afterwards cannot affect an assertion.
func dialRefused(network, addr string) (net.Conn, error) {
	return nil, errors.New("limits test: no upstream")
}

// sendPreamble dials the proxy and writes a raw preamble from a goroutine (an
// over-limit preamble is only partially consumed until the proxy's pre-close
// drain, so the write may block or error). The write side is half-closed so the
// drain sees EOF immediately and the exchange is deterministic. The conn has a
// read deadline so a regression fails instead of hanging.
func sendPreamble(t *testing.T, addr, preamble string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		_, _ = io.WriteString(conn, preamble)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn, bufio.NewReader(conn)
}

func readStatusLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line: %v", err)
	}
	return line
}

// assertOneDeny pins the "ONE deny decision event" rule: an over-limit preamble
// yields exactly one deny event, recorded before the response is written.
func assertOneDeny(t *testing.T, store *syncStore) {
	t.Helper()
	events := store.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected exactly ONE deny event, got %d (%+v)", len(events), events)
	}
	if events[0].Decision != "deny" {
		t.Fatalf("expected deny event, got %q", events[0].Decision)
	}
	if events[0].Protocol != "tcp" {
		t.Fatalf("expected protocol tcp, got %q", events[0].Protocol)
	}
}

// exactLimitLine builds a CONNECT request line of exactly n bytes (terminating
// CRLF included) targeting host :443.
func exactLimitLine(n int) (line, host string) {
	const prefix, suffix = "CONNECT ", ":443 HTTP/1.1\r\n"
	if n < len(prefix)+len(suffix)+1 {
		panic(fmt.Sprintf("exactLimitLine: n=%d too small", n))
	}
	host = strings.Repeat("a", n-len(prefix)-len(suffix))
	return prefix + host + suffix, host
}

// headerBlock appends filler headers plus the terminating blank line to line so
// the whole preamble is exactly n bytes. Filler headers are 62 bytes
// ("X-Pad: " + 53 a's + CRLF); a final longer one absorbs the remainder.
func headerBlock(line string, n int) string {
	if n < len(line)+2 {
		panic(fmt.Sprintf("headerBlock: n=%d smaller than the line", n))
	}
	var b strings.Builder
	b.WriteString(line)
	rem := n - len(line) - 2 // header-line bytes; 2 reserved for the blank line
	const unit = 62          // "X-Pad: "(7) + 53 a's + CRLF(2)
	for rem >= unit+10 {     // keep the final remainder >= one short header
		b.WriteString("X-Pad: ")
		b.WriteString(strings.Repeat("a", unit-9))
		b.WriteString("\r\n")
		rem -= unit
	}
	if rem > 0 { // final header absorbs the remainder, CRLF included
		if rem < 10 {
			panic(fmt.Sprintf("headerBlock: remainder %d too small for one header", rem))
		}
		b.WriteString("X-Pad: ")
		b.WriteString(strings.Repeat("a", rem-9))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	if b.Len() != n {
		panic(fmt.Sprintf("headerBlock: built %d bytes, want %d", b.Len(), n))
	}
	return b.String()
}

// TestConnectPreamble_LineAtLimitAccepted proves an exact-limit request line is
// normal traffic: an 8 KiB line (CRLF included) parses, gates, and CONNECTs.
func TestConnectPreamble_LineAtLimitAccepted(t *testing.T) {
	line, host := exactLimitLine(maxConnectLineBytes)
	if len(line) != maxConnectLineBytes {
		t.Fatalf("test bug: line is %d bytes, want %d", len(line), maxConnectLineBytes)
	}
	p, _ := startLimitsProxy(t, []string{host}, dialRefused, 0, nil)

	_, br := sendPreamble(t, p.Addr().String(), line+"\r\n")
	if resp := readStatusLine(t, br); !strings.Contains(resp, "200") {
		t.Fatalf("exact-limit CONNECT line: expected 200, got %q", resp)
	}
}

// TestConnectPreamble_LineOverLimitRejected proves limit+1 is rejected with 414
// before the line is fully read, and that exactly one deny decision is recorded
// with the malformed_connect reason and a bounded detail — never the content.
func TestConnectPreamble_LineOverLimitRejected(t *testing.T) {
	logs := &capturingHandler{}
	line, host := exactLimitLine(maxConnectLineBytes + 1)
	p, store := startLimitsProxy(t, []string{host}, dialRefused, 0, slog.New(logs))

	_, br := sendPreamble(t, p.Addr().String(), line+"\r\n")
	if resp := readStatusLine(t, br); !strings.Contains(resp, "414") {
		t.Fatalf("over-limit CONNECT line: expected 414, got %q", resp)
	}
	// The rest of the response is byte-exact: the client must never have to
	// guess at a body of unknown length, and the close is announced.
	if rest, err := io.ReadAll(br); err != nil {
		t.Fatalf("expected clean close after 414, got %v", err)
	} else if want := "Connection: close\r\nContent-Length: 0\r\n\r\n"; string(rest) != want {
		t.Fatalf("414 after the status line = %q, want %q", rest, want)
	}
	assertOneDeny(t, store)

	recs := logs.denyRecords()
	if len(recs) != 1 {
		t.Fatalf("expected exactly ONE deny decision record, got %d (%+v)", len(recs), recs)
	}
	if recs[0]["reason"] != "malformed_connect" {
		t.Fatalf("expected reason malformed_connect, got %q", recs[0]["reason"])
	}
	if recs[0]["detail"] != "request_line_too_long" {
		t.Fatalf("expected detail request_line_too_long, got %q", recs[0]["detail"])
	}
}

// countingConn counts the bytes the proxy consumed from the client BEFORE its
// first write — i.e. everything read while reaching its decision. The first
// Write freezes the count so the pre-close drain of an over-limit request
// (discarded through a fixed buffer) does not obscure the number that matters:
// how much of an oversized line was consumed before the rejection.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	read   int
	frozen bool
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if !c.frozen {
		c.read += n
	}
	c.mu.Unlock()
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.frozen = true
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *countingConn) counted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read
}

// TestConnectPreamble_HugeLineNotBuffered is the ticket reproduction: a 10 MB
// request line must be rejected after reading roughly the limit — not after
// buffering the whole thing. net.Pipe makes "bytes the proxy has consumed"
// exact: the writer can only deliver what the proxy reads, and the counting
// conn freezes that count at the first write (the 414).
func TestConnectPreamble_HugeLineNotBuffered(t *testing.T) {
	p, store := newLimitsProxy(t, []string{"a"}, nil)

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	cc := &countingConn{Conn: server}
	go p.handleConn(cc)

	const total = 10 << 20 // 10 MB, as reproduced on the ticket
	const chunk = 32 << 10
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = client.Close() }()
		payload := strings.Repeat("a", chunk)
		for i := 0; i < total/chunk; i++ {
			if _, err := io.WriteString(client, payload); err != nil {
				return
			}
		}
	}()

	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading response to a 10 MB request line: %v", err)
	}
	if !strings.Contains(resp, "414") {
		t.Fatalf("expected 414 for a 10 MB request line, got %q", resp)
	}
	<-done // writer finished (or was cut off by the close): no goroutine leak

	if got := cc.counted(); got > maxConnectLineBytes+4096 {
		t.Fatalf("proxy consumed %d bytes of the 10 MB line before answering (limit %d + one bufio fill)", got, maxConnectLineBytes)
	}
	assertOneDeny(t, store)
}

// TestConnectPreamble_HeaderBlockAtLimitAccepted proves an exact 64 KiB
// preamble (line + headers + terminating blank line) is accepted.
func TestConnectPreamble_HeaderBlockAtLimitAccepted(t *testing.T) {
	const line = "CONNECT exact.test:443 HTTP/1.1\r\n"
	preamble := headerBlock(line, maxConnectHeaderBytes)
	p, _ := startLimitsProxy(t, []string{"exact.test"}, dialRefused, 0, nil)

	_, br := sendPreamble(t, p.Addr().String(), preamble)
	if resp := readStatusLine(t, br); !strings.Contains(resp, "200") {
		t.Fatalf("exact-limit header block: expected 200, got %q", resp)
	}
}

// TestConnectPreamble_HeaderBlockOverLimitRejected proves one byte over the
// header-block budget is rejected with 431 and the bounded detail.
func TestConnectPreamble_HeaderBlockOverLimitRejected(t *testing.T) {
	logs := &capturingHandler{}
	const line = "CONNECT exact.test:443 HTTP/1.1\r\n"
	preamble := headerBlock(line, maxConnectHeaderBytes+1)
	p, store := startLimitsProxy(t, []string{"exact.test"}, dialRefused, 0, slog.New(logs))

	_, br := sendPreamble(t, p.Addr().String(), preamble)
	if resp := readStatusLine(t, br); !strings.Contains(resp, "431") {
		t.Fatalf("over-limit header block: expected 431, got %q", resp)
	}
	if rest, err := io.ReadAll(br); err != nil {
		t.Fatalf("expected clean close after 431, got %v", err)
	} else if want := "Connection: close\r\nContent-Length: 0\r\n\r\n"; string(rest) != want {
		t.Fatalf("431 after the status line = %q, want %q", rest, want)
	}
	assertOneDeny(t, store)

	recs := logs.denyRecords()
	if len(recs) != 1 {
		t.Fatalf("expected exactly ONE deny decision record, got %d (%+v)", len(recs), recs)
	}
	if recs[0]["reason"] != "malformed_connect" {
		t.Fatalf("expected reason malformed_connect, got %q", recs[0]["reason"])
	}
	if recs[0]["detail"] != "headers_too_large" {
		t.Fatalf("expected detail headers_too_large, got %q", recs[0]["detail"])
	}
}

// TestConnectPreamble_ManyHeadersAccepted proves the ticket's many-headers
// scenario stays normal traffic when it fits the block: 2000 headers connect
// exactly as before.
func TestConnectPreamble_ManyHeadersAccepted(t *testing.T) {
	var b strings.Builder
	b.WriteString("CONNECT many.test:443 HTTP/1.1\r\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "X-Pad-%04d: %s\r\n", i, strings.Repeat("a", 14))
	}
	b.WriteString("\r\n")
	if b.Len() >= maxConnectHeaderBytes {
		t.Fatalf("test bug: preamble is %d bytes, want < %d", b.Len(), maxConnectHeaderBytes)
	}
	p, _ := startLimitsProxy(t, []string{"many.test"}, dialRefused, 0, nil)

	_, br := sendPreamble(t, p.Addr().String(), b.String())
	if resp := readStatusLine(t, br); !strings.Contains(resp, "200") {
		t.Fatalf("2000 in-budget headers: expected 200, got %q", resp)
	}
}

// TestConnectPreamble_HeaderFloodRejected is the ticket's second reproduction:
// 2000 x 512-byte headers (~1 MB) is rejected with 431 instead of being read.
func TestConnectPreamble_HeaderFloodRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString("CONNECT flood.test:443 HTTP/1.1\r\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "X-Pad-%04d: %s\r\n", i, strings.Repeat("a", 512-16))
	}
	p, store := startLimitsProxy(t, []string{"flood.test"}, dialRefused, 0, nil)

	_, br := sendPreamble(t, p.Addr().String(), b.String())
	if resp := readStatusLine(t, br); !strings.Contains(resp, "431") {
		t.Fatalf("1 MB header flood: expected 431, got %q", resp)
	}
	assertOneDeny(t, store)
}

// TestConnectPreamble_SlowSenderDeadline proves the preamble deadline releases
// the goroutine: one partial write, then silence — the deadline (overridden to
// 200 ms, never the real 10 s) must close the connection quickly and silently,
// with nothing audited (no egress was ever attempted).
func TestConnectPreamble_SlowSenderDeadline(t *testing.T) {
	p, store := startLimitsProxy(t, []string{"slow.test"}, dialRefused, 200*time.Millisecond, nil)

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := io.WriteString(conn, "CONNECT slow.test:443 HT"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	if n != 0 {
		t.Fatalf("timed-out preamble must be dropped silently, got %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected the connection to be closed after the preamble deadline")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("slow sender held the connection %v; the preamble deadline did not fire", elapsed)
	}
	if events := store.snapshot(); len(events) != 0 {
		t.Fatalf("timed-out preamble attempted no egress; unexpected events %+v", events)
	}
}

// TestConnectPreamble_DeadlineReleasedAfterPreamble proves the preamble
// deadline is lifted once the header block completes: with a 250 ms budget, a
// tunnel that idles LONGER than that still relays — a leaked deadline would cut
// it off (and this asserts it with no real 10 s sleep).
func TestConnectPreamble_DeadlineReleasedAfterPreamble(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	p, _ := startLimitsProxy(t, []string{"echo.test"}, func(network, addr string) (net.Conn, error) {
		return net.Dial("tcp", echoLn.Addr().String())
	}, 250*time.Millisecond, nil)

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "CONNECT echo.test:443 HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	if resp := readStatusLine(t, br); !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}
	for { // consume the rest of the 200 response headers
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" || l == "\n" {
			break
		}
	}

	// Idle past the whole preamble budget, THEN use the tunnel.
	time.Sleep(500 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := "ping\n"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("tunnel died after idling past the preamble budget: %v", err)
	}
	if got != payload {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}
}

// keepSendingBytes is how much filler the client keeps writing AFTER the limit
// has already tripped: the rejection must come back while the client is still
// mid-send — exactly the case the pre-close drain in rejectPreamble exists for.
const keepSendingBytes = 2 << 20

// assertRejectionWhileStillSending pins the pre-close drain in rejectPreamble:
// it dials the proxy, writes preamble, and keeps writing filler bytes well past
// the trip point before half-closing, so the proxy must answer a client that is
// still mid-send. It then asserts the client reads exactly want followed by a
// clean close — no write error and no connection reset, which is what closing
// on a client with unread bytes in flight produces (the reset destroys the
// queued response along with the unread request bytes).
func assertRejectionWhileStillSending(t *testing.T, addr, preamble, want string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	writeErr := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(conn, preamble); err != nil {
			writeErr <- err
			return
		}
		chunk := strings.Repeat("a", 32<<10)
		for written := 0; written < keepSendingBytes; written += len(chunk) {
			if _, err := io.WriteString(conn, chunk); err != nil {
				writeErr <- err
				return
			}
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		writeErr <- nil
	}()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading the rejection while still sending (connection reset?): %v", err)
	}
	if string(got) != want {
		t.Fatalf("rejection read while still sending = %q, want %q", got, want)
	}
	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("writing past the tripped limit failed (connection reset?): %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client writer never finished")
	}
}

// TestConnectPreamble_ResponseWhileStillSending pins the drain the review
// required: the limit trips while the client is still writing, and the client
// must still receive the COMPLETE rejection — status line, Connection: close,
// Content-Length: 0 and the blank line — followed by a clean close. Without the
// drain the proxy closes on unread bytes, the kernel resets the connection, and
// the client sees the reset instead of the response. The expected bytes are
// spelled out literally so a change to the wire format cannot slip through.
func TestConnectPreamble_ResponseWhileStillSending(t *testing.T) {
	t.Run("414 request_line_too_long", func(t *testing.T) {
		p, store := startLimitsProxy(t, []string{"flood.test"}, dialRefused, 0, nil)
		line, _ := exactLimitLine(maxConnectLineBytes + 1)
		assertRejectionWhileStillSending(t, p.Addr().String(), line,
			"HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		assertOneDeny(t, store)
	})

	t.Run("431 headers_too_large", func(t *testing.T) {
		p, store := startLimitsProxy(t, []string{"exact.test"}, dialRefused, 0, nil)
		preamble := headerBlock("CONNECT exact.test:443 HTTP/1.1\r\n", maxConnectHeaderBytes+1)
		assertRejectionWhileStillSending(t, p.Addr().String(), preamble,
			"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		assertOneDeny(t, store)
	})
}
