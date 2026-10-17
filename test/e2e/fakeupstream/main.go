// Command fakeupstream is the hermetic stand-in for the entire outside world
// in the L2 e2e harness (issue #366). One container serves every upstream the
// scenarios need, all on one TLS listener with one cert:
//
//   - api.example.test/  (and /echo, /ws) — generic HTTPS app
//   - llm.example.test/v1/chat/completions — OpenAI-shaped LLM stub
//   - mcp.example.test/   — the poisoned MCP server (internal/mcp/poisoned, the
//     same handler the standalone mcp-wedge demo serves)
//   - evil.example.test/  — plain 200; the exfiltration attempt itself must be
//     refused by Warden, so the upstream never needs to misbehave
//
// Two control surfaces make the harness deterministic and testable:
//
//   - A REQUEST RECORDER: every app request is stored in memory (a bounded
//     ring — once the cap is hit the OLDEST record is dropped and the count of
//     dropped records is reported in /_recorded's "dropped" field); the
//     scenario runner reads them via GET /_recorded on the control port and
//     asserts (among other things) that the Authorization header carries the
//     placeholder, never the real canary secret.
//
//     /echo deserves a warning: it REFLECTS the request headers back, so a
//     canary-swapped request comes back to the AGENT carrying the real secret.
//     That is BY DESIGN — it is the endpoint the echo-leak scenarios need — so
//     never use /echo for a "the agent never sees the secret" check. That
//     assertion belongs to the RECORDER (/_recorded), which sees the traffic
//     on the wire while the agent only sees its own response.
//
//   - DNS CONTROL: the container also answers DNS on the egress network. The
//     known scenario names resolve to this container's IP, unknown names get
//     NXDOMAIN — so a hijacked agent cannot silently reach the real internet.
//     POST /_rebind?host=api.example.test re-arms a name to answer 127.0.0.1
//     (the SSRF red-team case; Warden must refuse the redirected dial);
//     POST /_reset clears records and rebinding.
//
// Docker-only binaries live under test/e2e (tagged by path); the behavior is
// still tested in main_test.go, which runs in the plain `go test ./...` gate
// against in-process loopback servers.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/mcp/poisoned"
	"golang.org/x/net/dns/dnsmessage"
)

// record is one observed request, as the scenario runner sees it.
type record struct {
	ID     int         `json:"id"`
	Time   time.Time   `json:"time"`
	Method string      `json:"method"`
	Host   string      `json:"host"`
	Path   string      `json:"path"`
	Query  string      `json:"query,omitempty"`
	Proto  string      `json:"proto"`
	Header http.Header `json:"header"`
	Body   string      `json:"body,omitempty"`
}

// maxRecordedBody caps how much of a request body is stored — big enough for
// every scenario payload, small enough that a runaway agent cannot balloon
// the container's memory.
const maxRecordedBody = 64 << 10

// maxRecordedRecords caps HOW MANY requests are kept. Once full, each new
// record evicts the oldest, and /_recorded reports how many were evicted in
// its "dropped" field — a long scenario run cannot balloon the container, and
// the runner can tell when it lost the head of its recording.
const maxRecordedRecords = 1024

// recorder stores requests in call order, bounded at maxRecordedRecords
// (oldest dropped, counted). The control API reads it; the app mux appends to
// it. A single mutex is plenty at scenario traffic levels.
type recorder struct {
	mu      sync.Mutex
	recs    []record
	next    int
	dropped int // records evicted by the cap, reported by /_recorded
	cap     int
}

func newRecorder() *recorder { return newRecorderWithCap(maxRecordedRecords) }

// newRecorderWithCap builds a recorder capped at n kept records; tests use a
// small n so the eviction behavior needs no thousand-request run.
func newRecorderWithCap(n int) *recorder { return &recorder{cap: n} }

// middleware captures r into the recorder, then serves next with a
// re-readable body (handlers like the MCP mux read it themselves). The
// ResponseWriter is passed through untouched so /ws can still Hijack.
func (r *recorder) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body bytes.Buffer
		_, _ = io.Copy(&body, io.LimitReader(req.Body, maxRecordedBody))
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))

		r.mu.Lock()
		rec := record{
			ID:     r.next,
			Time:   time.Now().UTC(),
			Method: req.Method,
			Host:   req.Host,
			Path:   req.URL.Path,
			Query:  req.URL.RawQuery,
			Proto:  req.Proto,
			Header: req.Header.Clone(),
			Body:   body.String(),
		}
		r.next++
		r.recs = append(r.recs, rec)
		if len(r.recs) > r.cap {
			r.recs = r.recs[len(r.recs)-r.cap:]
			r.dropped++
		}
		r.mu.Unlock()

		next.ServeHTTP(w, req)
	})
}

// snapshot returns a copy of the kept records in call order.
func (r *recorder) snapshot() []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]record, len(r.recs))
	copy(out, r.recs)
	return out
}

// droppedCount reports how many records the cap has evicted so far.
func (r *recorder) droppedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// reset empties the recorder (and the dropped counter).
func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = nil
	r.next = 0
	r.dropped = 0
}

// rebinds is the DNS red-team state: armed names answer 127.0.0.1 instead of
// the fake upstream's own IP. Armed state is persistent until /_reset or an
// explicit disarm — a scenario arms it deliberately and knows it did.
type rebinds struct {
	mu    sync.Mutex
	armed map[string]bool
}

func newRebinds() *rebinds { return &rebinds{armed: map[string]bool{}} }

func (b *rebinds) arm(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.armed[name] = true
}

func (b *rebinds) disarm(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.armed, name)
}

func (b *rebinds) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.armed = map[string]bool{}
}

func (b *rebinds) armedNames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.armed))
	for name := range b.armed {
		out = append(out, name)
	}
	return out
}

// armedFor reports whether name should answer 127.0.0.1.
func (b *rebinds) armedFor(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.armed[name]
}

// writeJSON is the shared JSON responder for both muxes.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// hostRoot strips any :port from the Host header — through Warden the host
// arrives bare, but direct callers may include one.
func hostRoot(host string) string {
	if h, _, found := strings.Cut(host, ":"); found && !strings.Contains(h, "]") {
		return h
	}
	return host
}

// handleGRPCEcho is a minimal unary gRPC echo service (e2e.Echo/Echo) for the
// harness's gRPC scenarios: decode the single length-prefixed protobuf frame,
// take message field 1, answer "echo: " + it with grpc-status 0. Hand rolled
// (no protobuf/grpc-go dependency) — deliberately shallow, it exists so gRPC
// traffic can be proven to transit Warden's tunnel, not to serve real RPCs.
func handleGRPCEcho(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Announce trailers up front; values set after WriteHeader go out as
	// HTTP/2 trailers, which is where gRPC clients read the status from.
	h.Set("Trailer", "Grpc-Status, Grpc-Message")
	h.Set("Content-Type", "application/grpc+proto")

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRecordedBody))
	if err != nil {
		grpcFail(w, "read frame")
		return
	}
	payload, ok := grpcField1(body)
	if !ok {
		grpcFail(w, "malformed frame")
		return
	}
	out := append([]byte("echo: "), payload...)
	msg := append([]byte{0x0A, byte(len(out))}, out...)
	frame := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(frame)
	h.Set("Grpc-Status", "0")
	h.Set("Grpc-Message", "")
}

// grpcFail ends a call with gRPC status 13 (INTERNAL) and no message.
func grpcFail(w http.ResponseWriter, why string) {
	log.Printf("fakeupstream: grpc echo rejected: %s", why)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Grpc-Status", "13")
	w.Header().Set("Grpc-Message", why)
}

// grpcField1 decodes one gRPC data frame (1-byte compressed flag + 4-byte
// big-endian length + message) and returns the message's field-1 string
// (wire type 2). ok=false on any malformed shape.
func grpcField1(frame []byte) (payload []byte, ok bool) {
	if len(frame) < 5 || frame[0] != 0 {
		return nil, false
	}
	n := int(frame[1])<<24 | int(frame[2])<<16 | int(frame[3])<<8 | int(frame[4])
	if n != len(frame)-5 {
		return nil, false
	}
	msg := frame[5:]
	// field 1, wire type 2 (length-delimited): tag 0x0A, then a varint length.
	if len(msg) < 2 || msg[0] != 0x0A {
		return nil, false
	}
	length, used := binary.Uvarint(msg[1:])
	if used <= 0 || len(msg) < 1+used+int(length) {
		return nil, false
	}
	return msg[1+used : 1+used+int(length)], true
}

// hostAwareDefault routes by Host header: mcp.example.test serves the poisoned
// MCP handler, everything else (api/llm/evil/…, unknown) a plain 200.
func hostAwareDefault() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostRoot(r.Host) == "mcp.example.test" {
			poisoned.Handler().ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "fakeupstream")
	})
}

// handleEcho reflects the request back as JSON. It reflects HEADERS, so the
// swapped canary goes back to the AGENT by design — this is the endpoint the
// echo-leak scenarios need. Never use /echo to check "the agent never sees the
// secret": that oracle is the recorder (/_recorded), which watches the wire.
func handleEcho(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"method": r.Method,
		"host":   hostRoot(r.Host),
		"path":   r.URL.Path,
		"proto":  r.Proto,
		"header": r.Header,
	})
}

// chatRequest is the slice of the OpenAI chat format the stub reads.
type chatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// handleChat answers an OpenAI-shaped chat completion echoing the last user
// message — enough structure for an agent under test to parse, nothing more.
func handleChat(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, maxRecordedBody)).Decode(&req)
	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			prompt = req.Messages[i].Content
			break
		}
	}
	if len(prompt) > 512 {
		prompt = prompt[:512]
	}
	model := req.Model
	if model == "" {
		model = "e2e-model"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-e2e-1",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": "fake-llm reply: " + prompt,
			},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     len(prompt) / 4,
			"completion_tokens": 12,
			"total_tokens":      len(prompt)/4 + 12,
		},
	})
}

// handleWS is the WebSocket echo endpoint: RFC 6455 server handshake, then
// frames are echoed back one-for-one (text/binary as-is, ping→pong). Hand
// rolled to keep the container stdlib-only apart from x/net.
func handleWS(w http.ResponseWriter, r *http.Request) {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	// Sec-WebSocket-Accept = base64(SHA1(key + magic)).
	h := sha1.New()
	h.Write([]byte(key + magic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = conn.Close() }()

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := buf.WriteString(resp); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}

	echoFrames(conn, buf.Reader)
}

// opcodes for the frame types the echo loop cares about.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// echoFrames reads one frame at a time and answers: text/binary echoed with
// the same opcode (unmasked — server frames are never masked), ping→pong,
// close→close. Malformed frames end the loop; this is a lab stub, not a
// general-purpose WS server.
func echoFrames(conn net.Conn, br *bufio.Reader) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		fin := hdr[0]&0x80 != 0
		op := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		n := int64(hdr[1] & 0x7F)
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				return
			}
			n = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				return
			}
			n = int64(binary.BigEndian.Uint64(ext[:]))
		}
		if n > maxRecordedBody {
			return
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(br, mask[:]); err != nil {
				return
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}

		switch op {
		case opClose:
			writeFrame(conn, opClose, payload)
			return
		case opPing:
			writeFrame(conn, opPong, payload)
		case opPong:
			// ignore
		case opText, opBinary, opContinuation:
			// Echo what we got; frames from the scenario clients are single
			// and unfragmented, so pass the opcode through.
			_ = fin
			writeFrame(conn, op, payload)
		default:
			return
		}
	}
}

// writeFrame writes one unmasked frame.
func writeFrame(w io.Writer, op byte, payload []byte) {
	hdr := []byte{0x80 | op}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 1<<16:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		hdr = append(hdr, 127)
		hdr = append(hdr, ext...)
	}
	_, _ = w.Write(hdr)
	_, _ = w.Write(payload)
}

// dnsServer answers UDP (and TCP via serveDNSConn) on the egress network.
// Known names → this container's IP; armed names → 127.0.0.1; unknown names →
// NXDOMAIN. That default-deny DNS is what makes the egress network hermetic.
type dnsServer struct {
	ip      string
	names   []string
	rebinds *rebinds
	conn    *net.UDPConn
}

// known reports whether name (no trailing dot) is one of the scenario names.
func (s *dnsServer) known(name string) bool {
	for _, n := range s.names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// answerFor returns the IPv4 a name should resolve to: 127.0.0.1 when the
// rebind is armed, otherwise the container's own IP for known names. Unknown
// names report ok=false (NXDOMAIN).
func (s *dnsServer) answerFor(name string) (ip [4]byte, ok bool) {
	if s.rebinds.armedFor(name) {
		return [4]byte{127, 0, 0, 1}, true
	}
	if s.known(name) {
		var a [4]byte
		for i, p := range strings.Split(s.ip, ".") {
			var v int
			_, _ = fmt.Sscanf(p, "%d", &v)
			a[i] = byte(v)
		}
		return a, true
	}
	return [4]byte{}, false
}

// respond builds the wire response for one DNS query packet (same shape as
// internal/dnstest, plus the rebind switch).
func (s *dnsServer) respond(query []byte) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil {
		return nil
	}
	name := m.Questions[0].Name.String()
	name = strings.TrimSuffix(name, ".")

	var answers []dnsmessage.Resource
	rcode := dnsmessage.RCodeSuccess
	if ip, ok := s.answerFor(name); ok {
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:   dnsmessage.MustNewName(name + "."),
				Type:   dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				TTL:    1,
				Length: 4,
			},
			Body: &dnsmessage.AResource{A: ip},
		})
	} else {
		rcode = dnsmessage.RCodeNameError
	}

	out := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 m.ID,
			Response:           true,
			OpCode:             m.OpCode,
			RecursionDesired:   m.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Questions: m.Questions,
		Answers:   answers,
	}
	// Keep AAAA queries cheap-but-valid: NOERROR with no answer (the worker
	// then uses the A record). Everything non-A is answered the same way when
	// the name is known.
	if m.Questions[0].Type != dnsmessage.TypeA {
		out.Answers = nil
		if !s.known(name) && !s.rebinds.armedFor(name) {
			out.RCode = dnsmessage.RCodeNameError
		}
	}
	buf, err := out.Pack()
	if err != nil {
		return nil
	}
	return buf
}

// serveUDP is the DNS read loop; run one goroutine, scenario traffic only.
func (s *dnsServer) serveUDP() {
	buf := make([]byte, 512)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // listener closed
		}
		if resp := s.respond(buf[:n]); resp != nil {
			_, _ = s.conn.WriteToUDP(resp, addr)
		}
	}
}

// serveDNSConn answers one TCP DNS connection (2-byte length framing). Used
// by the TCP test in main_test.go and by serveDNS below.
func serveDNSConn(s *dnsServer, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		var lenPrefix [2]byte
		if _, err := io.ReadFull(conn, lenPrefix[:]); err != nil {
			return
		}
		qlen := int(lenPrefix[0])<<8 | int(lenPrefix[1])
		query := make([]byte, qlen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := s.respond(query)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// defaultNames is the scenario DNS surface; FAKEUPSTREAM_NAMES overrides it.
func defaultNames() []string {
	if v := os.Getenv("FAKEUPSTREAM_NAMES"); v != "" {
		var names []string
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		return names
	}
	return []string{"api.example.test", "llm.example.test", "mcp.example.test", "evil.example.test"}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	certPath := os.Getenv("FAKEUPSTREAM_CERT")
	keyPath := os.Getenv("FAKEUPSTREAM_KEY")
	tlsAddr := envDefault("FAKEUPSTREAM_TLS_ADDR", ":443")
	controlAddr := envDefault("FAKEUPSTREAM_CONTROL_ADDR", ":8081")
	dnsAddr := envDefault("FAKEUPSTREAM_DNS_ADDR", ":53")
	ip := envDefault("FAKEUPSTREAM_IP", "10.200.0.10")

	if certPath == "" || keyPath == "" {
		log.Fatalf("fakeupstream: FAKEUPSTREAM_CERT and FAKEUPSTREAM_KEY are required " +
			"(test/e2e/certs/gen.sh creates them)")
	}
	names := defaultNames()

	rec := newRecorder()
	rb := newRebinds()

	appSrv := &http.Server{
		Addr:    tlsAddr,
		Handler: newApp(rec),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// h2 must negotiable: the gRPC path and HTTP/2 clients rely on it.
			NextProtos: []string{"h2", "http/1.1"},
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		log.Printf("fakeupstream: tls app on %s (api/llm/mcp/evil under %v)", tlsAddr, names)
		if err := appSrv.ListenAndServeTLS(certPath, keyPath); err != nil {
			log.Fatalf("fakeupstream: tls: %v", err)
		}
	}()

	controlSrv := &http.Server{
		Addr:         controlAddr,
		Handler:      newControl(rec, rb),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		log.Printf("fakeupstream: control on http://%s (/_health /_recorded /_reset /_rebind)", controlAddr)
		if err := controlSrv.ListenAndServe(); err != nil {
			log.Fatalf("fakeupstream: control: %v", err)
		}
	}()

	udpAddr, err := net.ResolveUDPAddr("udp", dnsAddr)
	if err != nil {
		log.Fatalf("fakeupstream: dns addr: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("fakeupstream: dns udp: %v", err)
	}
	dns := &dnsServer{ip: ip, names: names, rebinds: rb, conn: udpConn}
	go dns.serveUDP()
	tcpLn, err := net.Listen("tcp", dnsAddr)
	if err != nil {
		log.Fatalf("fakeupstream: dns tcp: %v", err)
	}
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go serveDNSConn(dns, conn)
		}
	}()
	log.Printf("fakeupstream: dns on %s (known names → %s, unknown → NXDOMAIN)", dnsAddr, ip)

	select {} // serve until the container stops
}
