package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// maxLineBytes bounds a single newline-delimited JSON-RPC message. MCP messages
// are small, but a buggy or hostile peer could emit a very long line; we read up
// to this cap rather than panicking on bufio.Scanner's default 64 KiB token.
const maxLineBytes = 8 << 20 // 8 MiB

// Pump fronts a single MCP stdio session: it reads newline-delimited JSON-RPC
// from the client, runs each message through the gateway, and forwards allowed
// messages to the server subprocess (and the server's responses back to the
// client). A denied message never reaches the far end; the client gets a
// JSON-RPC error instead. A Pump value is single-session; Run owns its
// goroutines and the clientOut mutex.
type Pump struct {
	GW         *gateway.Gateway
	SessionKey string // gateway session key for this connection (e.g. "stdio")
	Log        *slog.Logger

	// outMu guards clientOut: both PumpResponses (forwarding server output) and
	// PumpRequests (injecting block errors) may write it concurrently under Run.
	outMu sync.Mutex
}

// log returns a non-nil logger.
func (p *Pump) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// PumpRequests pumps client->server. It reads JSON-RPC lines from clientIn and
// runs each through OnRequest. On Pass it writes the line verbatim to serverIn.
// On Deny it writes a JSON-RPC error (matching the request id) to clientOut and
// does NOT forward. It returns when clientIn reaches EOF (or on an unrecoverable
// write error to serverIn).
func (p *Pump) PumpRequests(clientIn io.Reader, serverIn io.Writer, clientOut io.Writer) error {
	r := bufio.NewReaderSize(clientIn, 64<<10)
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			v := p.GW.OnRequest(p.SessionKey, "", "stdio", nil, line)
			p.logFindings("request", v)
			if v.Action == gateway.Deny {
				p.writeClient(clientOut, blockError(line, v.Reason))
			} else if werr := writeLine(serverIn, line); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// PumpResponses pumps server->client. It reads JSON-RPC lines from serverOut and
// runs each through OnResponse. On Deny it replaces the message with a JSON-RPC
// error (matching the id when present) to clientOut; on Pass it forwards the
// line verbatim. It returns when serverOut reaches EOF.
func (p *Pump) PumpResponses(serverOut io.Reader, clientOut io.Writer) error {
	r := bufio.NewReaderSize(serverOut, 64<<10)
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			v := p.GW.OnResponse(p.SessionKey, 200, nil, line)
			p.logFindings("response", v)
			if v.Action == gateway.Deny {
				p.writeClient(clientOut, blockError(line, v.Reason))
			} else {
				p.writeClient(clientOut, withNewline(line))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Run wires both directions concurrently and returns when both ends have
// closed. ctx cancellation is best-effort: the loops unblock when their readers
// close (the caller closes serverIn / the server's stdout on shutdown). The
// returned error is the first non-nil direction error (EOF is not an error).
func (p *Pump) Run(ctx context.Context, clientIn io.Reader, serverIn io.WriteCloser, serverOut io.Reader, clientOut io.Writer) error {
	var wg sync.WaitGroup
	errs := make([]error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Closing serverIn signals the server that client input is done, which
		// lets the server finish and close its stdout, unblocking PumpResponses.
		defer func() { _ = serverIn.Close() }()
		errs[0] = p.PumpRequests(clientIn, serverIn, clientOut)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errs[1] = p.PumpResponses(serverOut, clientOut)
	}()

	wg.Wait()
	_ = ctx // ctx is accepted for symmetry with the command's lifecycle; readers drive shutdown.
	return errors.Join(errs...)
}

// writeClient writes b to clientOut under the clientOut mutex.
func (p *Pump) writeClient(clientOut io.Writer, b []byte) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	if _, err := clientOut.Write(b); err != nil {
		p.log().Warn("mcp client write failed", "error", err)
	}
}

// logFindings emits one bounded log line per finding. It never logs a tool
// argument or result value — only the gateway's value-free Finding fields.
func (p *Pump) logFindings(dir string, v gateway.Verdict) {
	for _, f := range v.Findings {
		p.log().Info("mcp finding",
			"dir", dir,
			"kind", f.Kind,
			"tool", f.Tool,
			"severity", f.Severity,
			"detail", f.Detail,
		)
	}
}

// readLine reads one newline-delimited message, returning the bytes WITHOUT the
// trailing '\n'. It bounds a single line at maxLineBytes. The returned error is
// io.EOF on a clean end of stream (possibly with a final unterminated line).
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxLineBytes {
			// Drop the over-long line entirely rather than acting on a truncated
			// JSON-RPC message; keep draining until the newline so framing resyncs.
			if err == nil {
				return nil, nil
			}
			return nil, err
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return trimNewline(buf), err
		}
		return trimNewline(buf), nil
	}
}

// trimNewline strips a single trailing '\n' (and an optional '\r').
func trimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

// withNewline returns line with a single trailing newline, preserving the
// original bytes exactly.
func withNewline(line []byte) []byte {
	out := make([]byte, len(line)+1)
	copy(out, line)
	out[len(line)] = '\n'
	return out
}

// writeLine writes line followed by a single newline to w.
func writeLine(w io.Writer, line []byte) error {
	_, err := w.Write(withNewline(line))
	return err
}

// blockError builds the newline-terminated JSON-RPC error sent to the client for
// a blocked message. The id is extracted from the offending message (string or
// number, preserved verbatim; null when absent). The message carries only the
// bounded verdict reason — never any tool value or content.
func blockError(line []byte, reason string) []byte {
	id := extractID(line)
	if reason == "" {
		reason = "policy"
	}
	out, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Error: struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: -32600, Message: "blocked by warden: " + reason},
	})
	if err != nil {
		// Marshalling a fixed-shape struct cannot realistically fail; fall back to
		// a hand-built error with a null id so the client always gets valid JSON.
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"blocked by warden"}}` + "\n")
	}
	return append(out, '\n')
}

// extractID pulls the raw JSON-RPC id from a message, preserving its JSON type
// (string or number) verbatim. It returns the JSON literal null when the id is
// absent or the message is unparseable.
func extractID(line []byte) json.RawMessage {
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(line, &env); err != nil || len(env.ID) == 0 {
		return json.RawMessage("null")
	}
	return env.ID
}
