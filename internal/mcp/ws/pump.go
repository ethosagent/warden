package ws

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"sync"

	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// maxReassembledMessage caps a reassembled (fragmented) text message. A message
// whose accumulated payload exceeds this is still forwarded verbatim, but it is
// not scanned (no analysis on an unbounded payload).
const maxReassembledMessage = 8 << 20 // 8 MiB

// ClosePolicyViolation is the WebSocket close status used when an enforce-mode
// gateway Deny tears down the connection (RFC 6455 §7.4.1, code 1008).
const ClosePolicyViolation uint16 = 1008

// Pump scans MCP JSON-RPC text messages flowing over a WebSocket while
// forwarding every frame transparently in both directions.
type Pump struct {
	GW         *gateway.Gateway
	SessionKey string
	Log        *slog.Logger
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

// pumpDir reads frames from src, forwards each to dst transparently, and scans
// each completed text message through the gateway. On an enforce Deny it calls
// teardown (which Close-frames both peers) and returns. ctx cancellation makes
// the goroutine stop after the current frame.
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

	var (
		assembling bool   // inside a fragmented text message
		acc        []byte // accumulated text payload (reassembly)
		overCap    bool   // current message exceeded maxReassembledMessage
	)

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

		// Forward EVERY frame transparently first so the peer sees live traffic
		// even for frames we do not scan.
		if werr := dst(f); werr != nil {
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
