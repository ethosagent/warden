package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/mcp/ws"
	"github.com/ethosagent/warden/internal/secrets"
)

// Echo guard (#389). Warden swaps a placeholder for the real secret on the way
// out; if the upstream copies the request into its response (an echo endpoint, an
// error that quotes the request, a reflected header) the agent would get the real
// value back. The guard remembers the EXACT values it put into THIS request and
// checks the response for them (and their common encodings) before the agent sees
// any of it. It is exact, so it is on by default and independent of responseScan.
// A request that swapped nothing records nothing and is never scanned.

const (
	// defaultEchoScanCap bounds the body the guard buffers when no responseScan cap
	// is configured. With responseScan on, the guard uses its MaxBytes instead, so
	// both checks share one limit.
	defaultEchoScanCap = 1 << 20
	// echoDecodedFactor caps a decompressed body at this multiple of the scan cap, so
	// a decompression bomb cannot make the guard buffer or burn unbounded memory/CPU.
	echoDecodedFactor = 8
	// minDerivedNeedle is the shortest derived (encoded) needle worth matching; a
	// shorter one would match innocent text. The raw value is always matched.
	minDerivedNeedle = 4

	reasonSecretEcho            = "secret_echo"
	reasonSecretEchoUnscannable = "secret_echo_unscannable"
)

// EchoGuardConfig switches the echo guard. The zero value is the default: on,
// action block.
type EchoGuardConfig struct {
	// Disabled turns the guard off entirely (no recording, no scan, no
	// Accept-Encoding change).
	Disabled bool
	// Monitor records a hit as an allow event with reason secret_echo but forwards
	// the response unchanged. The default (false) blocks.
	Monitor bool
}

// errEchoBlocked is returned from a guarded body Read when the stream carried a
// swapped value. The chunk that held it is never returned.
var errEchoBlocked = errors.New("proxy: upstream echoed a swapped secret")

// echoSecret is one real value put into a request. name is the placeholder NAME
// (log-safe) or "" for a value injected by an auth transformer.
type echoSecret struct {
	name  string
	value string
}

// noteSecret records a value put into the current request. It is the only
// per-request cost of the guard on a swap, and is never reached when nothing was
// swapped.
func (s *requestScope) noteSecret(name, value string) {
	if value == "" {
		return
	}
	s.echoSecrets = append(s.echoSecrets, echoSecret{name: name, value: value})
}

// echoNeedle is one byte pattern that, if present in a response, means secret
// number secret was echoed.
type echoNeedle struct {
	b      []byte
	secret int
}

// echoSet is the set of byte patterns searched for in a response.
type echoSet struct {
	needles []echoNeedle
	first   [256]bool // bytes that begin some needle
}

func newEchoSet(values []string) *echoSet {
	e := &echoSet{}
	for i, v := range values {
		if v == "" {
			continue
		}
		seen := map[string]struct{}{}
		add := func(n string, derived bool) {
			if n == "" || (derived && len(n) < minDerivedNeedle) {
				return
			}
			if _, dup := seen[n]; dup {
				return
			}
			seen[n] = struct{}{}
			e.needles = append(e.needles, echoNeedle{b: []byte(n), secret: i})
			e.first[n[0]] = true
		}
		add(v, false)
		for _, n := range echoEncodings(v) {
			add(n, true)
		}
	}
	return e
}

// echoEncodings lists the forms in which v may reappear in a response: base64
// (std and URL alphabets, padded or not, at every 6-bit alignment so a value
// embedded in a larger base64 string, such as Basic auth, is still found),
// percent-encoded (upper/lower hex, "+" or "%20" for space), hex, and JSON-escaped.
func echoEncodings(v string) []string {
	var out []string
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for k := 0; k < 3; k++ {
			e := enc.EncodeToString(append(make([]byte, k), v...))
			skip := [3]int{0, 2, 3}[k] // leading chars that mix in the unknown prior bytes
			drop := 0
			if (k+len(v))%3 != 0 {
				drop = 1 // trailing char mixes in the unknown following byte
			}
			if skip+drop < len(e) {
				out = append(out, e[skip:len(e)-drop])
			}
		}
	}
	for _, p := range []string{url.QueryEscape(v), url.PathEscape(v)} {
		out = append(out, p, lowerPercentHex(p))
	}
	h := hex.EncodeToString([]byte(v))
	out = append(out, h, strings.ToUpper(h))
	for _, escapeHTML := range []bool{true, false} {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(escapeHTML)
		if enc.Encode(v) == nil {
			j := strings.TrimSuffix(b.String(), "\n")
			j = j[1 : len(j)-1]
			out = append(out, j, strings.ReplaceAll(j, "/", `\/`))
		}
	}
	return out
}

// lowerPercentHex lower-cases the two hex digits of every %XX escape in s.
func lowerPercentHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] |= 0x20
			b[i+2] |= 0x20
		}
	}
	return string(b)
}

// find reports whether b contains any needle and which secret it belongs to.
func (e *echoSet) find(b []byte) (secret int, ok bool) {
	for _, n := range e.needles {
		if bytes.Contains(b, n.b) {
			return n.secret, true
		}
	}
	return 0, false
}

// heldSuffix is the length of the longest suffix of b that is a proper prefix of
// some needle: the only bytes that could still turn into a needle once more data
// arrives. Everything before it is clear of any needle. b must hold no whole needle.
func (e *echoSet) heldSuffix(b []byte) int {
	longest := 0
	for _, n := range e.needles {
		// Longest suffix first, so stop at the first start that already loses to best.
		for i := max(0, len(b)-(len(n.b)-1)); i < len(b)-longest; i++ {
			if e.first[b[i]] && bytes.HasPrefix(n.b, b[i:]) {
				longest = len(b) - i
				break
			}
		}
	}
	return longest
}

// endsInNeedlePrefix reports whether b ends in a proper prefix, at least
// minDerivedNeedle bytes long, of some needle. b must hold no whole needle.
func (e *echoSet) endsInNeedlePrefix(b []byte) bool {
	return e.heldSuffix(b) >= minDerivedNeedle
}

// prefixSecret names the secret whose needle b ends in a prefix of.
func (e *echoSet) prefixSecret(b []byte) int {
	for _, n := range e.needles {
		for k := min(len(n.b)-1, len(b)); k >= minDerivedNeedle; k-- {
			if bytes.HasSuffix(b, n.b[:k]) {
				return n.secret
			}
		}
	}
	return 0
}

func (e *echoSet) findString(s string) (int, bool) {
	for _, n := range e.needles {
		if strings.Contains(s, string(n.b)) {
			return n.secret, true
		}
	}
	return 0, false
}

func (e *echoSet) findHeader(h http.Header) (int, bool) {
	for k, vs := range h {
		if i, ok := e.findString(k); ok {
			return i, true
		}
		for _, v := range vs {
			if i, ok := e.findString(v); ok {
				return i, true
			}
		}
	}
	return 0, false
}

// echoReader scans a response body as it is read, chunk by chunk, and never lets
// the agent see any byte of a swapped value, not even the leading part of one
// that is still arriving. After each chunk it holds back only the longest suffix
// of what it has read that is a prefix of some needle (usually nothing: an SSE
// event ends in a blank line, a JSON chunk in "}" or a quote) and releases the
// rest at once. The held bytes go out with the next chunk, once no needle can
// start inside them, or at a clean EOF after a final check. On a hit nothing more is returned: every Read from then
// on fails with errEchoBlocked, and the held bytes are dropped.
type echoReader struct {
	rc      io.ReadCloser
	set     *echoSet
	trailer func() http.Header // consulted at EOF, when trailers have arrived
	onHit   func(secret int)
	monitor bool // report the hit but keep passing bytes
	// hit/secret record the first finding; the caller reads them once the relay ends
	// (echoStreamDone) — the reader holds no reference to the request scope.
	hit    bool
	secret int

	hold, buf []byte // withheld tail; scratch for hold+chunk
	ready     []byte // cleared bytes that did not fit the caller's buffer
	rerr      error  // read error to return once ready is drained
	err       error
	off       bool
}

func newEchoReader(rc io.ReadCloser, set *echoSet, onHit func(int)) *echoReader {
	return &echoReader{rc: rc, set: set, onHit: onHit}
}

func (r *echoReader) found(secret int) {
	r.hit, r.secret = true, secret
	if r.onHit != nil {
		r.onHit(secret)
	}
	if r.monitor {
		r.off = true
		return
	}
	r.err = errEchoBlocked
	r.hold = nil
}

// release hands the whole of r.buf (held tail included) to the caller: used at a
// clean EOF and when monitor mode stops guarding.
func (r *echoReader) release(p []byte, err error) (int, error) {
	r.hold = nil
	r.ready = append(r.ready[:0], r.buf...)
	r.rerr = err
	return r.drain(p)
}

func (r *echoReader) drain(p []byte) (int, error) {
	n := copy(p, r.ready)
	r.ready = r.ready[n:]
	if len(r.ready) > 0 {
		return n, nil
	}
	return n, r.rerr
}

func (r *echoReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil // nothing to fill; the loop below would spin on an empty read
	}
	if len(r.ready) > 0 || r.rerr != nil {
		return r.drain(p)
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.off {
		return r.rc.Read(p)
	}
	for {
		n, err := r.rc.Read(p)
		r.buf = append(append(r.buf[:0], r.hold...), p[:n]...)
		if n > 0 {
			if secret, ok := r.set.find(r.buf); ok {
				r.found(secret)
				if r.err != nil {
					return 0, r.err
				}
				return r.release(p, err)
			}
		}
		if err == io.EOF && r.trailer != nil {
			if secret, ok := r.set.findHeader(r.trailer()); ok {
				r.found(secret)
				if r.err != nil {
					return 0, r.err
				}
				return r.release(p, err)
			}
		}
		if err == io.EOF {
			// Clean end: nothing can follow, so a held tail that is only the start of a
			// needle will never complete. Releasing it would still hand the agent the
			// first bytes of the value, so it counts as a hit.
			if r.set.endsInNeedlePrefix(r.buf) {
				r.found(r.set.prefixSecret(r.buf))
				if r.err != nil {
					return 0, r.err
				}
			}
			return r.release(p, err)
		}
		if err != nil {
			r.hold = nil
			return 0, err
		}
		// Everything before the longest needle-prefix suffix is clear of any
		// needle. It can be longer than p (the old hold plus this chunk), so it
		// goes through ready.
		rel := len(r.buf) - r.set.heldSuffix(r.buf)
		r.hold = append(r.hold[:0], r.buf[rel:]...)
		if rel > 0 {
			r.ready = append(r.ready[:0], r.buf[:rel]...)
			return r.drain(p)
		}
	}
}

func (r *echoReader) Close() error { return r.rc.Close() }

// echoPeekSize bounds the first chunk read up front from a body of known length.
const echoPeekSize = 32 << 10

// readFirstChunk blocks for the first bytes of rc (at most limit) and returns them.
// io.EOF is not an error here: an empty or short body simply ends.
func readFirstChunk(rc io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	buf := make([]byte, limit)
	for {
		n, err := rc.Read(buf)
		if n > 0 || err != nil {
			if err == io.EOF {
				err = nil
			}
			return buf[:n], err
		}
	}
}

// echoScanCap is the largest body the guard will buffer (a compressed one, or one
// with trailers); one limit shared with responseScan when that is configured.
func (p *Proxy) echoScanCap() int64 {
	if p.cfg.ResponseScan != nil {
		return int64(p.cfg.ResponseScan.MaxBytes())
	}
	return defaultEchoScanCap
}

// echoDecoders returns the content codings to undo, outermost first, or ok=false
// when one is not gzip/deflate (br, zstd, unknown): the body cannot be checked.
func echoCodings(h http.Header) (codings []string, ok bool) {
	for _, v := range h.Values("Content-Encoding") {
		for _, c := range strings.Split(v, ",") {
			c = strings.ToLower(strings.TrimSpace(c))
			switch c {
			case "", "identity":
			case "gzip", "x-gzip":
				codings = append(codings, "gzip")
			case "deflate":
				codings = append(codings, "deflate")
			default:
				return nil, false
			}
		}
	}
	return codings, true
}

// echoDecode wraps r in the decoders for codings (listed in the order applied).
func echoDecode(r io.Reader, codings []string) (io.Reader, error) {
	for i := len(codings) - 1; i >= 0; i-- {
		switch codings[i] {
		case "gzip":
			zr, err := gzip.NewReader(r)
			if err != nil {
				return nil, err
			}
			r = zr
		case "deflate":
			br := bufio.NewReader(r)
			hdr, err := br.Peek(2)
			if err != nil {
				return nil, err
			}
			// HTTP "deflate" is zlib-wrapped in practice but some servers send raw.
			if hdr[0]&0x0f == 8 && (int(hdr[0])<<8|int(hdr[1]))%31 == 0 {
				zr, err := zlib.NewReader(br)
				if err != nil {
					return nil, err
				}
				r = zr
			} else {
				r = flate.NewReader(br)
			}
		}
	}
	return r, nil
}

type echoVerdict int

const (
	echoClean echoVerdict = iota
	echoFound
	echoUnscannable
)

// echoScanBody checks a fully buffered body, decompressing it first (streaming,
// bounded) when codings are present.
func echoScanBody(body []byte, codings []string, set *echoSet, decodedCap int64) (secret int, v echoVerdict) {
	if len(codings) == 0 {
		if i, ok := set.find(body); ok {
			return i, echoFound
		}
		return 0, echoClean
	}
	if len(body) == 0 {
		return 0, echoClean
	}
	dr, err := echoDecode(bytes.NewReader(body), codings)
	if err != nil {
		return 0, echoUnscannable
	}
	found := -1
	er := newEchoReader(io.NopCloser(dr), set, func(i int) { found = i })
	n, err := io.Copy(io.Discard, io.LimitReader(er, decodedCap+1))
	switch {
	case found >= 0:
		return found, echoFound
	case err != nil || n > decodedCap:
		return 0, echoUnscannable
	}
	return 0, echoClean
}

// echoGuard checks the upstream response for any secret swapped into this request
// before a single byte reaches the agent. It runs once, in the shared response path,
// so HTTP/1.1, HTTP/2, gRPC, SSE and MCP are all covered.
//
//   - Headers are always checked up front.
//   - An uncompressed response (known length of any size, or unknown: SSE, gRPC
//     streams, chunked) is never buffered whole: its body is wrapped in an
//     echoReader that scans chunk by chunk, holds back only a possible needle
//     prefix, and, on a hit, aborts the stream before any byte of the value is
//     released. A known-length body also has its first chunk (up to 32 KiB)
//     checked up front, so an echo there still earns a clean 502.
//   - A body that declares trailers is buffered (within the cap) and checked, so a
//     trailer echo is also a 502.
//   - A compressed body of known length is buffered (within the cap) and checked
//     decompressed; a compressed body of unknown length, brotli/zstd/unknown
//     codings, over-cap compressed bodies and corrupt streams cannot be checked, so
//     they are blocked (secret_echo_unscannable): fail closed.
//
// It returns true when it fully handled the response (a block).
func (p *Proxy) echoGuard(s *requestScope) (terminal bool) {
	set := s.echoSet()
	resp := s.resp

	if i, ok := set.findHeader(resp.Header); ok {
		return p.echoHit(s, i, reasonSecretEcho)
	}
	// No body to carry a value: headers were the whole response.
	if s.req.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified || resp.Body == nil || resp.Body == http.NoBody {
		return false
	}
	codings, ok := echoCodings(resp.Header)
	if !ok {
		return p.echoHit(s, -1, reasonSecretEchoUnscannable)
	}
	scanCap := p.echoScanCap()

	if len(codings) > 0 && resp.ContentLength < 0 {
		// Compressed and of unknown length: it can only be checked by buffering it
		// whole, with no bound on how long the upstream takes. Refuse instead.
		return p.echoHit(s, -1, reasonSecretEchoUnscannable)
	}
	stream := func() {
		er := newEchoReader(resp.Body, set, nil)
		er.monitor = p.cfg.EchoGuard.Monitor
		s.echoRdr = er
		er.trailer = func() http.Header { return resp.Trailer }
		resp.Body = er
	}
	if len(codings) == 0 && resp.ContentLength < 0 {
		stream()
		return false
	}
	if len(codings) == 0 && len(resp.Trailer) == 0 {
		// A body of known length is streamed too (a slow one must not be held to
		// its end), but its first chunk is checked up front: an echo is almost
		// always in it, and that still earns a clean 502 before any byte is sent. One
		// that declares trailers stays buffered, so a trailer echo is also a 502.
		first, err := readFirstChunk(resp.Body, min(resp.ContentLength, echoPeekSize))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(first), resp.Body), resp.Body}
		if err != nil {
			return p.echoHit(s, -1, reasonSecretEchoUnscannable)
		}
		if i, ok := set.find(first); ok {
			return p.echoHit(s, i, reasonSecretEcho)
		}
		// The whole body in one chunk, ending in the start of a value: it would be
		// cut at EOF, so refuse cleanly while nothing has been sent.
		if int64(len(first)) == resp.ContentLength && set.endsInNeedlePrefix(first) {
			return p.echoHit(s, set.prefixSecret(first), reasonSecretEcho)
		}
		stream()
		return false
	}

	orig := resp.Body
	body, err := io.ReadAll(io.LimitReader(orig, scanCap+1))
	// Put the bytes back (and whatever was not read) so monitor mode, or a clean
	// check, still forwards the original body.
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), orig), orig}
	if err != nil || int64(len(body)) > scanCap {
		return p.echoHit(s, -1, reasonSecretEchoUnscannable)
	}
	secret, verdict := echoScanBody(body, codings, set, scanCap*echoDecodedFactor)
	if verdict == echoClean {
		if i, ok := set.findHeader(resp.Trailer); ok {
			secret, verdict = i, echoFound
		}
	}
	switch verdict {
	case echoFound:
		return p.echoHit(s, secret, reasonSecretEcho)
	case echoUnscannable:
		return p.echoHit(s, -1, reasonSecretEchoUnscannable)
	}
	return false
}

// echoSet builds the needles for the values put into this request.
func (s *requestScope) echoSet() *echoSet {
	values := make([]string, len(s.echoSecrets))
	for i, sec := range s.echoSecrets {
		values[i] = sec.value
	}
	return newEchoSet(values)
}

// echoGuardHeaders checks only the response headers, for a response whose body is
// not relayed through the normal path (a WebSocket 101). It returns true when it
// answered the agent with a block.
func (p *Proxy) echoGuardHeaders(s *requestScope) (terminal bool) {
	if i, ok := s.echoSet().findHeader(s.resp.Header); ok {
		return p.echoHit(s, i, reasonSecretEcho)
	}
	return false
}

// wsEchoGuard carries the same guard onto a WebSocket's server->agent frame
// stream (#399). It reuses the request's echoSet — the exact swapped values and
// their encodings — and applies the same zero-bytes rule as the echoReader,
// with the hold-back state carried across frame AND message boundaries for the
// whole connection: a data frame whose payload is not yet provably clear (it
// ends where a needle may still start) is held whole until a later frame proves
// it, so a value split across two frames or two messages is still caught.
//
// The DATA stream is text/binary/continuation only — what an agent reassembles
// a message from (RFC 6455 §5.4). Control frames (a ping, a pong, a close
// reason can each carry data) are checked on their own and NEVER touch the data
// accumulator: folding a control payload in would hide a value split around it
// while the agent still reassembles the message without the control bytes. A
// control frame is forwarded as soon as its own payload is clear of any needle,
// and a held data tail stays held across it (RFC 6455 allows control frames
// between fragments).
//
// A data frame with a reserved bit set carries an extension's (permessage-deflate)
// compressed bytes, which cannot be scanned: it is a violation whatever the mode
// (fail closed). Warden strips the extension offer when it swaps a value, so
// this is only a backstop.
//
// The agent->server direction is never guarded: it carries the swapped value
// legitimately. Frames are re-emitted unchanged, so a clean stream reaches the
// agent byte-identical; a held tail the connection ends on is dropped (fail
// closed). The hold is bounded: a later frame releases every earlier frame it
// proves clear, so at most one maximum-size frame is ever held — never more
// than ReadFrame itself buffers. It satisfies ws.EchoGuard.
type wsEchoGuard struct {
	set     *echoSet
	monitor bool // #389 monitor mode: report the hit, keep passing bytes

	acc      []byte     // DATA-stream bytes no forwarded frame is proved clear of yet
	spare    []byte     // recycled acc buffer: emitted payloads stay valid until the next Guard
	pend     []ws.Frame // held data frames (headers only; their payload bytes live in acc)
	pendLen  []int      // payload length of each held frame
	pendHead int        // first held frame not yet released

	clear []ws.Frame // scratch returned to the pump, consumed before the next Guard

	hit    bool   // a violation was seen (sticky)
	secret int    // which needle hit (-1: none named)
	reason string // why the guard closed: an echo or an unscannable frame
	off    bool   // monitor mode after a hit: pass everything through
}

// newWSEchoGuard arms the frame guard for an upgraded connection whose request
// swapped values. Only called when s.echoSecrets is non-empty, so a swap-free
// upgrade builds no needle set and runs no per-frame check at all.
func (p *Proxy) newWSEchoGuard(s *requestScope) *wsEchoGuard {
	return &wsEchoGuard{set: s.echoSet(), monitor: p.cfg.EchoGuard.Monitor}
}

// Guard checks f on the server->agent stream and returns the frames that are
// fully clear, in order. Data frames fold f's unmasked payload into the
// connection's DATA stream; a control frame's payload is checked on its own and
// leaves the data stream untouched. The returned frames may alias the guard's
// buffers: the pump writes them before it calls Guard again.
func (g *wsEchoGuard) Guard(f ws.Frame) ([]ws.Frame, bool) {
	// RSV on a data frame means an extension (permessage-deflate) compressed the
	// payload: nothing about it can be vouched for, so the connection is torn
	// down in monitor mode too. A control frame's RSV bits stay untouched: only
	// data frames carry a scanned payload.
	if !f.IsControl() && (f.RSV1 || f.RSV2 || f.RSV3) {
		g.hit, g.secret, g.reason = true, -1, reasonSecretEchoUnscannable
		return nil, false
	}
	if g.off {
		g.clear = append(g.clear[:0], f)
		return g.clear, true
	}
	if f.IsControl() {
		if secret, ok := g.set.find(f.Payload); ok {
			clear, pass := g.found(secret)
			if !pass {
				return nil, false
			}
			// Monitor mode reported the control frame: it goes out after the
			// held data it found (#389 monitor semantics).
			return append(clear, f), true
		}
		g.clear = append(g.clear[:0], f)
		return g.clear, true
	}
	g.compact()
	g.acc = append(g.acc, f.Payload...)
	hdr := f
	hdr.Payload = nil
	g.pend = append(g.pend, hdr)
	g.pendLen = append(g.pendLen, len(f.Payload))
	if secret, ok := g.set.find(g.acc); ok {
		return g.found(secret)
	}
	// Everything before the longest needle-prefix suffix is clear of any value.
	return g.release(len(g.acc) - g.set.heldSuffix(g.acc)), true
}

// found records a needle in the checked bytes. In block mode nothing more is
// forwarded; in monitor mode the bytes go out anyway (#389 monitor semantics):
// everything held is released and the guard stops guarding for the rest of the
// connection.
func (g *wsEchoGuard) found(secret int) ([]ws.Frame, bool) {
	g.hit, g.secret, g.reason = true, secret, reasonSecretEcho
	if g.monitor {
		g.off = true
		return g.release(len(g.acc)), true
	}
	return nil, false
}

// hitSecret reports the recorded finding for the deny event after the pump ends.
func (g *wsEchoGuard) hitSecret() (secret int, hit bool) { return g.secret, g.hit }

// hitReason names why the guard closed: reasonSecretEcho for a value in the
// stream, reasonSecretEchoUnscannable for a compressed (RSV) data frame.
func (g *wsEchoGuard) hitReason() string {
	if g.reason == "" {
		return reasonSecretEcho
	}
	return g.reason
}

// compact drops the held frames a release already returned, so a stream whose
// every frame ends in a needle prefix cannot grow pend/pendLen by one entry per
// frame for the whole connection (#399 review): the slices stay at the frames
// actually held. Their acc bytes were dropped by the release that returned them
// (acc always starts at pend[pendHead]'s first payload byte), so only headers
// move.
func (g *wsEchoGuard) compact() {
	if g.pendHead == 0 {
		return
	}
	n := copy(g.pend, g.pend[g.pendHead:])
	g.pend = g.pend[:n]
	n = copy(g.pendLen, g.pendLen[g.pendHead:])
	g.pendLen = g.pendLen[:n]
	g.pendHead = 0
}

// release returns the leading held frames fully covered by the first n bytes of
// acc, whole and unchanged. The uncleared rest — at most a needle-prefix
// suffix, plus the frame it ends in — stays for the next frame. The released
// payloads alias the buffer that just stopped being acc: the pump writes them
// before the next Guard recycles it as spare.
func (g *wsEchoGuard) release(n int) []ws.Frame {
	g.clear = g.clear[:0]
	off := 0
	for g.pendHead < len(g.pend) {
		end := off + g.pendLen[g.pendHead]
		if end > n {
			break
		}
		f := g.pend[g.pendHead]
		f.Payload = g.acc[off:end]
		g.clear = append(g.clear, f)
		off = end
		g.pendHead++
	}
	if len(g.clear) == 0 {
		return nil
	}
	g.spare = append(g.spare[:0], g.acc[n:]...)
	g.acc, g.spare = g.spare, g.acc
	if g.pendHead == len(g.pend) {
		g.pend, g.pendLen, g.pendHead = g.pend[:0], g.pendLen[:0], 0
	}
	return g.clear
}

// echoHit handles a finding on a response that has not been written yet: block
// (502 + deny event) or, in monitor mode, remember it for the single allow event.
func (p *Proxy) echoHit(s *requestScope, secret int, reason string) (terminal bool) {
	if p.cfg.EchoGuard.Monitor {
		s.echoMonitorReason = reason
		return false
	}
	p.echoDeny(s, secret, reason)
	s.out.errorResponse(502, "Bad Gateway")
	return true
}

// echoStreamDone is called once the response relay has ended. If the streaming
// reader found a secret it records it: block mode writes the deny event and marks the
// stream aborted (the headers are already on the wire, so the caller closes the h1
// connection or resets the h2 stream); monitor mode notes it for the allow event.
// It returns true when the stream was aborted.
func (p *Proxy) echoStreamDone(s *requestScope) (aborted bool) {
	er := s.echoRdr
	if er == nil || !er.hit {
		return false
	}
	if p.cfg.EchoGuard.Monitor {
		s.echoMonitorReason = reasonSecretEcho
		return false
	}
	s.abortStream = true
	p.echoDeny(s, er.secret, reasonSecretEcho)
	return true
}

// echoDeny writes the single deny decision event for a blocked response. The
// secret is named by reference only: the placeholder name plus hash/last-4/length,
// never the value. secret < 0 (unscannable) names every swapped secret.
func (p *Proxy) echoDeny(s *requestScope, secret int, reason string) {
	var names, refs []string
	for i, sec := range s.echoSecrets {
		if secret >= 0 && i != secret {
			continue
		}
		if sec.name != "" {
			names = append(names, sec.name)
		}
		refs = append(refs, secrets.Ref(sec.value).String())
	}
	fullURL := s.eventURL()
	secretRef := strings.Join(refs, ",")
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp:      time.Now(),
		Domain:         s.domain,
		Port:           s.port,
		Protocol:       s.proto,
		Method:         s.req.Method,
		URL:            fullURL,
		Decision:       "deny",
		ResponseStatus: s.resp.StatusCode,
		Reason:         reason,
		SecretRef:      secretRef,
		LatencyMs:      s.latencyMs(),
		SwappedRefs:    names,
	})
	p.cfg.Metrics.RecordRequest("deny", s.proto)
	p.cfg.Metrics.RecordBlocked(reason)
	p.logDecision(decisionLog{
		Domain: s.domain, Port: s.port, Protocol: s.proto,
		Method: s.req.Method, URL: fullURL, Decision: "deny",
		ResponseStatus: s.resp.StatusCode, SecretRef: secretRef,
	})
}

// noteTransformerSecrets records the values a matched auth transformer injected.
func (s *requestScope) noteTransformerSecrets(t auth.SecretSource) {
	for _, v := range t.InjectedSecrets() {
		s.noteSecret("", v)
	}
}

// eventURL is the request URL for an event: the query is the agent's original one,
// never the swapped one that holds a real secret value.
func (s *requestScope) eventURL() string {
	if s.origRawQuery == "" {
		return "https://" + s.domain + s.req.URL.RequestURI()
	}
	u := *s.req.URL
	u.RawQuery = s.origRawQuery
	return "https://" + s.domain + u.RequestURI()
}

// preferEchoReason prefers the echo guard's monitor-mode reason over the MCP one.
func preferEchoReason(mcpReason, echoReason string) string {
	if echoReason != "" {
		return echoReason
	}
	return mcpReason
}
