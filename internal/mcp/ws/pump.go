package ws

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// maxReassembledMessage caps a reassembled (fragmented) text message. Without
// Hold, a message whose accumulated payload exceeds this is still forwarded
// verbatim, but it is not scanned (no analysis on an unbounded payload). With
// Hold (enforce) it fails closed: it is denied and never forwarded.
const maxReassembledMessage = 8 << 20 // 8 MiB

// ClosePolicyViolation is the WebSocket close status used when an enforce-mode
// gateway Deny tears down the connection (RFC 6455 §7.4.1, code 1008).
const ClosePolicyViolation uint16 = 1008

// Scanner is the narrow frame-scan capability the pump consumes. It is exactly
// the two directional scan hooks the pump calls — never a concrete type — so any
// MCPGateway implementation (including a wrapper/decorator over the concrete
// gateway) drives WS frame scanning. *gateway.Gateway satisfies it, as does the
// proxy's WSScanner capability (a structural superset of this interface).
type Scanner interface {
	OnRequest(sessionKey, method, url string, hdr http.Header, body []byte) gateway.Verdict
	OnResponse(sessionKey string, status int, hdr http.Header, body []byte) gateway.Verdict
}

// EchoGuard is the server->agent secret-echo check for an upgraded connection
// (#399): the proxy arms it when the upgrade request swapped real values in,
// and the pump consults it for every frame it is about to hand the agent. It
// is nil when nothing was swapped: frames are then forwarded with no per-frame
// guard work at all. The agent->server direction is never guarded — it carries
// the swapped value legitimately.
type EchoGuard interface {
	// Guard checks one server->agent frame (unmasked payload) and returns the
	// frames that are provably clear of any swapped value, in order, for
	// forwarding. Data frames (text, binary, continuation) are matched as one
	// ordered stream for the whole connection; control frames (ping/pong/close)
	// are checked on their own — an agent reassembles a message from data
	// fragments only, so a control payload must neither join nor complete that
	// stream. clear may be empty: the frame is held until a later frame proves
	// its bytes clear (the carry-over window that catches a value split across
	// frames or messages). ok=false means the guard refused the stream (a
	// swapped value, or a data frame with reserved bits set, whose compressed
	// bytes it cannot scan): the caller must tear the session down — neither
	// this frame nor any held byte is ever forwarded, and the guard stays
	// closed.
	Guard(f Frame) (clear []Frame, ok bool)
}

// Pump scans MCP JSON-RPC text messages flowing over a WebSocket while
// forwarding every frame transparently in both directions. A nil GW forwards
// frames verbatim without scanning (the monitor/off downgrade path).
type Pump struct {
	GW         Scanner
	SessionKey string
	Log        *slog.Logger
	// Hold (enforce mode) withholds every data message (text or binary), all
	// fragments of it, until the gateway has scanned the complete message: it is
	// forwarded only on allow. A binary message that is not valid UTF-8 JSON cannot
	// be scanned and is denied. The added latency is one message; the worst-case
	// memory is one buffered message (8 MiB) per direction. Control frames are
	// never held. Without Hold (monitor/off) frames are forwarded first and scanned after.
	Hold bool
	// Echo, when non-nil, guards the server->agent direction (#399): every
	// frame the pump is about to forward to the agent — data and control alike
	// — goes through it first, in both the hold and the forward-then-scan paths,
	// so a swapped value is checked on exactly the bytes the agent would
	// receive. On a refused frame the pump tears the session down with
	// Close(1008) to both peers, like a gateway deny.
	Echo EchoGuard
}

// Run pumps frames in both directions between client and server, forwarding
// every frame transparently. Complete text messages (opcode text + any
// continuation frames until FIN) are reassembled and run through the gateway:
// client->server via OnRequest, server->client via OnResponse. Control and
// binary frames are forwarded but not scanned. On an enforce-mode Deny a Close
// frame (1008) is sent to BOTH peers and both directions are torn down.
//
// Run returns when either side closes/errors (or ctx is cancelled). It reports
// whether a gateway Deny blocked the session via blocked, alongside the first
// non-EOF transport error (if any).
func (p *Pump) Run(ctx context.Context, client, server io.ReadWriteCloser) (blocked bool, err error) {
	if p.Log == nil {
		p.Log = slog.Default()
	}

	// Each destination writer may be written by its own pump goroutine and, on a
	// block, by the other goroutine sending a Close — so guard both writers.
	var clientMu, serverMu sync.Mutex
	writeClient := func(f Frame) error {
		clientMu.Lock()
		defer clientMu.Unlock()
		return f.Write(client)
	}
	writeServer := func(f Frame) error {
		serverMu.Lock()
		defer serverMu.Unlock()
		return f.Write(server)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu        sync.Mutex // guards blocked + firstErr
		wasBlock  bool
		firstErr  error
		closeOnce sync.Once
	)
	recordErr := func(e error) {
		if e == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		mu.Unlock()
	}
	// teardown sends a Close(1008) to both peers exactly once and cancels the
	// context so the sibling goroutine unblocks.
	teardown := func() {
		closeOnce.Do(func() {
			mu.Lock()
			wasBlock = true
			mu.Unlock()
			cf := closeFrame(ClosePolicyViolation)
			_ = writeClient(cf)
			_ = writeServer(cf)
			cancel()
		})
	}

	// When either direction ends (EOF, error, or block) it cancels ctx; this
	// watcher then closes both conns so the sibling goroutine's blocking ReadFrame
	// unblocks promptly. Without it the second direction would hang until its peer
	// independently closed, leaking a goroutine.
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = server.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// client -> server (OnRequest)
	go func() {
		defer wg.Done()
		defer cancel()
		e := p.pumpDir(ctx, client, writeServer, dirRequest, teardown)
		recordErr(e)
	}()
	// server -> client (OnResponse)
	go func() {
		defer wg.Done()
		defer cancel()
		e := p.pumpDir(ctx, server, writeClient, dirResponse, teardown)
		recordErr(e)
	}()

	wg.Wait()
	// Best-effort close of both ends so neither side leaks a half-open conn.
	_ = client.Close()
	_ = server.Close()

	mu.Lock()
	defer mu.Unlock()
	return wasBlock, firstErr
}

type direction int

const (
	dirRequest direction = iota
	dirResponse
)

// pumpDir reads frames from src, forwards each to dst transparently (text
// messages are held until scanned when Hold is set), and scans each completed
// text message through the gateway. Frames forwarded to the agent also pass
// through the echo guard when one is armed (#399). On an enforce Deny — or an
// echo refusal — it calls teardown (which Close-frames both peers) and
// returns. ctx cancellation makes the goroutine stop after the current frame.
func (p *Pump) pumpDir(
	ctx context.Context,
	src io.Reader,
	dst func(Frame) error,
	dir direction,
	teardown func(),
) error {
	br, ok := src.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(src)
	}

	// emit forwards frames to dst through the echo guard when one guards this
	// direction (server->agent only). It reports whether the guard refused the
	// stream: neither the frame nor any held byte may then be forwarded, so the
	// caller tears the session down. clear may be empty (the frame is held):
	// nothing goes out for it yet.
	var guard EchoGuard
	if dir == dirResponse {
		guard = p.Echo
	}
	emit := func(f Frame) (blocked bool, werr error) {
		if guard == nil {
			return false, dst(f)
		}
		clear, ok := guard.Guard(f)
		if !ok {
			return true, nil
		}
		for _, cf := range clear {
			if werr := dst(cf); werr != nil {
				return false, werr
			}
		}
		return false, nil
	}

	var (
		assembling bool    // inside a fragmented text message
		acc        []byte  // accumulated payload (reassembly; with Hold, the only copy)
		overCap    bool    // current message exceeded maxReassembledMessage
		held       []Frame // Hold: headers (no payload) of the open message's frames
		heldLen    []int   // Hold: payload length of each held frame (bytes live in acc)
		binary     bool    // Hold: the open message is a binary data message
	)
	hold := p.Hold && p.GW != nil

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		f, err := ReadFrame(br)
		if err != nil {
			return err
		}

		if hold && !f.IsControl() {
			// Enforce: every data message (text AND binary), all fragments, is held
			// until scanned. Only the payload bytes are kept (once, in acc); the
			// per-frame headers are retained so the frames are re-emitted unchanged.
			switch f.Opcode {
			case OpcodeText, OpcodeBinary:
				if assembling {
					// A new data message inside an open one is a protocol
					// violation; the held fragments cannot be vouched for.
					teardown()
					return nil
				}
				binary = f.Opcode == OpcodeBinary
			case OpcodeContinuation:
				if !assembling {
					// A continuation with no open message cannot be scanned.
					teardown()
					return nil
				}
			default:
				// Reserved data opcode: unscannable, fail closed.
				teardown()
				return nil
			}
			if len(acc)+len(f.Payload) > maxReassembledMessage {
				// Fail closed: never forward a message we cannot scan.
				teardown()
				return nil
			}
			acc = append(acc, f.Payload...)
			hdr := f
			hdr.Payload = nil
			held = append(held, hdr)
			heldLen = append(heldLen, len(f.Payload))
			assembling = !f.Fin
			if !f.Fin {
				continue
			}
			if p.holdDeny(dir, acc, binary) {
				teardown()
				return nil
			}
			off := 0
			for i, hf := range held {
				hf.Payload = acc[off : off+heldLen[i]]
				off += heldLen[i]
				blk, werr := emit(hf)
				if blk {
					teardown()
					return nil
				}
				if werr != nil {
					return werr
				}
			}
			held, heldLen, acc = held[:0], heldLen[:0], acc[:0]
			continue
		}

		// Forward EVERY frame transparently first so the peer sees live traffic
		// even for frames we do not scan (and, without Hold, text messages too).
		blk, werr := emit(f)
		if blk {
			teardown()
			return nil
		}
		if werr != nil {
			return werr
		}

		switch {
		case f.IsControl():
			// Control frames may interleave between fragments; forward (done
			// above) without disturbing reassembly. A Close from a peer ends the
			// pump for this direction.
			if f.Opcode == OpcodeClose {
				return nil
			}
			continue

		case f.Opcode == OpcodeText:
			// Start of a (possibly fragmented) text message.
			assembling = !f.Fin
			overCap = false
			acc = acc[:0]
			if len(acc)+len(f.Payload) > maxReassembledMessage {
				overCap = true
			} else {
				acc = append(acc, f.Payload...)
			}
			if f.Fin {
				if p.scan(dir, acc, overCap) {
					teardown()
					return nil
				}
				assembling = false
			}

		case f.Opcode == OpcodeContinuation:
			if !assembling {
				// Continuation with no open message: forwarded already; ignore.
				continue
			}
			if !overCap {
				if len(acc)+len(f.Payload) > maxReassembledMessage {
					overCap = true
				} else {
					acc = append(acc, f.Payload...)
				}
			}
			if f.Fin {
				if p.scan(dir, acc, overCap) {
					teardown()
					return nil
				}
				assembling = false
			}

		default:
			// Binary or unknown data frame: forwarded above, not scanned.
		}
	}
}

// holdDeny decides a fully held message. A binary message is scanned like text
// when it is valid UTF-8 JSON; anything else cannot be scanned and fails closed.
func (p *Pump) holdDeny(dir direction, msg []byte, binary bool) bool {
	if binary && len(msg) > 0 && (!utf8.Valid(msg) || !json.Valid(msg)) {
		return true
	}
	return p.scan(dir, msg, false)
}

// scan runs the gateway EXACTLY ONCE on a completed text message (skipped when
// over cap), logs each finding value-free, and reports whether the verdict is an
// enforce-mode Deny. The gateway is stateful (id->tool correlation, rate limits,
// chain), so it must never be evaluated twice for one message.
func (p *Pump) scan(dir direction, msg []byte, overCap bool) (deny bool) {
	if overCap || len(msg) == 0 || p.GW == nil {
		return false
	}
	var v gateway.Verdict
	if dir == dirRequest {
		// WS framing carries no HTTP headers/status; the gateway is
		// transport-agnostic on the JSON-RPC body, so neutral values are passed.
		v = p.GW.OnRequest(p.SessionKey, "", "", nil, msg)
	} else {
		v = p.GW.OnResponse(p.SessionKey, 0, nil, msg)
	}
	for _, fnd := range v.Findings {
		p.Log.Debug("mcp ws finding",
			slog.String("kind", fnd.Kind),
			slog.String("severity", fnd.Severity),
			slog.String("tool", fnd.Tool),
			slog.String("path", fnd.Path),
		)
	}
	return v.Action == gateway.Deny
}
