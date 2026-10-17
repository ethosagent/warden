package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

const (
	// grpcFrameHeaderLen is the gRPC length-prefixed message header: one
	// compressed-flag byte and a big-endian uint32 payload length.
	grpcFrameHeaderLen = 5
	// maxGRPCFrameBytes bounds how much of one gRPC message is buffered for
	// inspection (4 MiB, gRPC's own default max message size). It stays well under
	// maxBodySwapSize, the request-body cap of the swap path. A larger frame fails
	// closed (grpc_frame_too_large) instead of being forwarded unchecked.
	maxGRPCFrameBytes = 4 << 20
	// grpcFirstFrameWait is how long the worker holds the upstream request back
	// for the call's first message, so a refused unary (or first-message) call
	// whose message arrives in time reaches the upstream not at all, not even its
	// headers. A client that sends its first message later (an idle bidi stream)
	// is not stalled: the request goes out and the message is still inspected
	// and refused when it arrives.
	grpcFirstFrameWait = 250 * time.Millisecond
)

// gRPC status codes the refusals answer with (the numeric wire values).
const (
	grpcCodeInvalidArgument    = 3
	grpcCodePermissionDenied   = 7
	grpcCodeResourceExhausted  = 8
	grpcCodeFailedPrecondition = 9
)

// errGRPCFrameRefused is the sticky read error of a guard that refused a frame.
var errGRPCFrameRefused = errors.New("grpc request body refused")

// grpcRefusal is why a frame was not forwarded: the declared deny reason, and
// the gRPC status the client is answered with. message is fixed text, never
// request content.
type grpcRefusal struct {
	reason  denyreason.Reason
	code    int
	message string
}

func newGRPCRefusal(reason denyreason.Reason) grpcRefusal {
	switch reason {
	case denyreason.GRPCBodyPlaceholder:
		return grpcRefusal{reason, grpcCodePermissionDenied, "secret placeholders must be sent in gRPC metadata"}
	case denyreason.GRPCFrameTooLarge:
		return grpcRefusal{reason, grpcCodeResourceExhausted, "gRPC message too large to inspect"}
	case denyreason.GRPCFrameCompressed:
		return grpcRefusal{reason, grpcCodeFailedPrecondition, "compressed gRPC messages cannot be inspected"}
	default:
		return grpcRefusal{denyreason.GRPCFrameMalformed, grpcCodeInvalidArgument, "malformed gRPC message framing"}
	}
}

// grpcFrameGuard wraps a gRPC request body and inspects each length-prefixed
// message before any of its bytes are released. A message is buffered whole (up
// to maxFrame), checked for the destination's secret placeholders, then handed
// on; the next message is not read until the previous one was consumed, so a
// streaming call flows frame by frame and nothing beyond one frame is held.
//
// Why refuse instead of swap: a protobuf string cannot be told from a nested
// message without the schema, and changing a string's length means re-encoding
// every enclosing length. Credentials belong in metadata, which is swapped.
//
// Nothing is forwarded for a refused frame. The first refusal is sticky, is
// reported once through onRefuse, and surfaces as errGRPCFrameRefused.
//
// A placeholder split across two messages is still detected: the last
// maxPlaceholderLen-1 bytes of the messages so far are kept and checked joined
// with the start of the next, which is refused. The earlier half has already
// been forwarded; it is inert, since nothing in a body is ever swapped.
// The compressed flag is refused outright: a compressed payload cannot be
// inspected, and no encoding is ever trusted to be placeholder-free.
type grpcFrameGuard struct {
	src          io.ReadCloser
	placeholders [][]byte
	maxFrame     int
	onRefuse     func(grpcRefusal)
	tail         []byte // last maxPlaceholderLen-1 payload bytes forwarded so far
	maxPH        int    // length of the longest placeholder

	rmu   sync.Mutex // serialises Read with a Prime still filling in the background
	buf   []byte     // the frame being released (header + payload)
	off   int
	err   error // sticky terminal error
	ready bool  // buf holds an inspected frame

	mu       sync.Mutex
	refusal  grpcRefusal
	refused  bool
	answered bool // the client already got the refusal status (forwardH2)
}

func newGRPCFrameGuard(src io.ReadCloser, placeholders [][]byte, maxFrame int, onRefuse func(grpcRefusal)) *grpcFrameGuard {
	g := &grpcFrameGuard{src: src, placeholders: placeholders, maxFrame: maxFrame, onRefuse: onRefuse}
	for _, ph := range placeholders {
		g.maxPH = max(g.maxPH, len(ph))
	}
	return g
}

func (g *grpcFrameGuard) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	g.rmu.Lock()
	defer g.rmu.Unlock()
	for {
		if g.ready {
			n := copy(p, g.buf[g.off:])
			g.off += n
			if g.off == len(g.buf) {
				g.buf, g.off, g.ready = g.buf[:0], 0, false
			}
			return n, nil
		}
		if g.err != nil {
			return 0, g.err
		}
		g.nextFrame()
	}
}

// nextFrame reads and inspects one whole message, leaving it ready to release,
// or sets the sticky error.
func (g *grpcFrameGuard) nextFrame() {
	var hdr [grpcFrameHeaderLen]byte
	if n, err := io.ReadFull(g.src, hdr[:]); err != nil {
		switch {
		case n == 0 && errors.Is(err, io.EOF):
			g.err = io.EOF // a clean end between messages
		case errors.Is(err, io.ErrUnexpectedEOF):
			g.refuse(denyreason.GRPCFrameMalformed)
		default:
			g.err = err // the client reset or the transport failed: not ours to judge
		}
		return
	}
	switch hdr[0] {
	case 0:
	case 1:
		g.refuse(denyreason.GRPCFrameCompressed)
		return
	default:
		g.refuse(denyreason.GRPCFrameMalformed)
		return
	}
	size := binary.BigEndian.Uint32(hdr[1:5])
	if uint64(size) > uint64(g.maxFrame) {
		g.refuse(denyreason.GRPCFrameTooLarge)
		return
	}
	// Grow with the data actually received: a header claiming maxFrame bytes
	// that never arrive must not pin maxFrame of memory.
	frame := bytes.NewBuffer(make([]byte, 0, min(int(size), 4096)+grpcFrameHeaderLen))
	frame.Write(hdr[:])
	if _, err := io.CopyN(frame, g.src, int64(size)); err != nil {
		if errors.Is(err, io.EOF) {
			g.refuse(denyreason.GRPCFrameMalformed)
		} else {
			g.err = err
		}
		return
	}
	payload := frame.Bytes()[grpcFrameHeaderLen:]
	for _, ph := range g.placeholders {
		if bytes.Contains(payload, ph) {
			g.refuse(denyreason.GRPCBodyPlaceholder)
			return
		}
	}
	if g.splitAcrossBoundary(payload) {
		g.refuse(denyreason.GRPCBodyPlaceholder)
		return
	}
	g.buf, g.off, g.ready = frame.Bytes(), 0, true
}

// splitAcrossBoundary reports whether a placeholder starts in the bytes kept from
// earlier messages and ends in payload, and otherwise rolls the kept tail
// forward over payload. Empty messages leave the tail as it was, so a split
// across several messages is caught too.
func (g *grpcFrameGuard) splitAcrossBoundary(payload []byte) bool {
	keep := g.maxPH - 1
	if keep <= 0 {
		return false
	}
	if len(g.tail) > 0 && len(payload) > 0 {
		joined := append(append(make([]byte, 0, len(g.tail)+keep), g.tail...), payload[:min(len(payload), keep)]...)
		for _, ph := range g.placeholders {
			if bytes.Contains(joined, ph) {
				return true
			}
		}
	}
	if len(payload) >= keep {
		g.tail = append(g.tail[:0], payload[len(payload)-keep:]...)
	} else if len(payload) > 0 {
		g.tail = append(g.tail, payload...)
		if len(g.tail) > keep {
			g.tail = append(g.tail[:0], g.tail[len(g.tail)-keep:]...)
		}
	}
	return false
}

// Prime reads and inspects the first message, waiting at most wait for it. It
// lets the caller learn of a refusal before it sends anything upstream. If the
// message has not fully arrived in time, Prime returns and the fill carries on in
// the background; Read waits for it. A nil guard is a no-op.
func (g *grpcFrameGuard) Prime(wait time.Duration) {
	if g == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.rmu.Lock()
		defer g.rmu.Unlock()
		if !g.ready && g.err == nil {
			g.nextFrame()
		}
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

func (g *grpcFrameGuard) refuse(reason denyreason.Reason) {
	r := newGRPCRefusal(reason)
	g.err = errGRPCFrameRefused
	g.mu.Lock()
	first := !g.refused
	if first {
		g.refused, g.refusal = true, r
	}
	g.mu.Unlock()
	if first && g.onRefuse != nil {
		g.onRefuse(r)
	}
}

func (g *grpcFrameGuard) Close() error { return g.src.Close() }

// Refusal reports the refusal, if the guard has refused a frame. Safe to call
// from any goroutine and on a nil guard.
func (g *grpcFrameGuard) Refusal() (grpcRefusal, bool) {
	if g == nil {
		return grpcRefusal{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refusal, g.refused
}

// Refused reports whether the guard has refused a frame (nil-safe).
func (g *grpcFrameGuard) Refused() bool {
	_, ok := g.Refusal()
	return ok
}

// markAnswered records that the client was answered with the refusal status and
// reports whether it already had been.
func (g *grpcFrameGuard) markAnswered() (already bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	already = g.answered
	g.answered = true
	return already
}
