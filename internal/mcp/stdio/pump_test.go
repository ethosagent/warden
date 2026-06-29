package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/scan"
)

// newGW builds a gateway in the given mode allowing only the named tools.
func newGW(t *testing.T, mode string, allow ...string) *gateway.Gateway {
	t.Helper()
	cfg := config.MCPConfig{
		Enabled: true,
		Mode:    mode,
		Tools:   config.MCPToolsConfig{Allow: allow},
		Scan:    config.MCPScanConfig{ToolArgs: true, ToolResults: true, ProfileSchema: true},
		Schema:  config.MCPSchemaConfig{Pin: true},
	}
	scanner := scan.NewScanner()
	return gateway.New(cfg, scanner, nil)
}

func callLine(t *testing.T, id any, tool string) []byte {
	t.Helper()
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": map[string]any{}},
	}
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestPumpRequestsAllowedForwardsVerbatim(t *testing.T) {
	p := &Pump{GW: newGW(t, "enforce", "safe_tool"), SessionKey: "stdio"}
	line := callLine(t, 1, "safe_tool")

	var serverIn, clientOut bytes.Buffer
	in := bytes.NewReader(append(line, '\n'))
	if err := p.PumpRequests(in, &serverIn, &clientOut); err != nil {
		t.Fatalf("PumpRequests: %v", err)
	}

	got := strings.TrimRight(serverIn.String(), "\n")
	if got != string(line) {
		t.Fatalf("server did not receive verbatim line.\n got: %s\nwant: %s", got, line)
	}
	if clientOut.Len() != 0 {
		t.Fatalf("expected no client output on pass, got: %s", clientOut.String())
	}
}

func TestPumpRequestsDeniedInjectsErrorAndDoesNotForward(t *testing.T) {
	// Allow only safe_tool, so bad_tool is denied under enforce.
	p := &Pump{GW: newGW(t, "enforce", "safe_tool"), SessionKey: "stdio"}
	line := callLine(t, 42, "bad_tool")

	var serverIn, clientOut bytes.Buffer
	in := bytes.NewReader(append(line, '\n'))
	if err := p.PumpRequests(in, &serverIn, &clientOut); err != nil {
		t.Fatalf("PumpRequests: %v", err)
	}

	if serverIn.Len() != 0 {
		t.Fatalf("denied call must NOT reach server, got: %s", serverIn.String())
	}

	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(clientOut.Bytes()), &resp); err != nil {
		t.Fatalf("client output not valid JSON-RPC: %v (%s)", err, clientOut.String())
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc = %q", resp.JSONRPC)
	}
	if string(resp.ID) != "42" {
		t.Fatalf("id = %s, want 42", resp.ID)
	}
	if resp.Error.Code != -32600 {
		t.Fatalf("error code = %d, want -32600", resp.Error.Code)
	}
	if !strings.HasPrefix(resp.Error.Message, "blocked by warden:") {
		t.Fatalf("error message = %q", resp.Error.Message)
	}
	// The bounded reason must never carry a tool value; bad_tool reason is the
	// kind, not the argument content.
	if strings.Contains(resp.Error.Message, "arguments") {
		t.Fatalf("error message leaked content: %q", resp.Error.Message)
	}
}

func TestPumpRequestsMonitorForwardsBadCall(t *testing.T) {
	// Monitor mode: even a not-allowed tool is forwarded (detect, don't block).
	p := &Pump{GW: newGW(t, "monitor", "safe_tool"), SessionKey: "stdio"}
	line := callLine(t, 7, "bad_tool")

	var serverIn, clientOut bytes.Buffer
	in := bytes.NewReader(append(line, '\n'))
	if err := p.PumpRequests(in, &serverIn, &clientOut); err != nil {
		t.Fatalf("PumpRequests: %v", err)
	}

	if strings.TrimRight(serverIn.String(), "\n") != string(line) {
		t.Fatalf("monitor must forward the call, got: %q", serverIn.String())
	}
	if clientOut.Len() != 0 {
		t.Fatalf("monitor must not inject an error, got: %s", clientOut.String())
	}
}

func TestPumpRequestsIDPreserved(t *testing.T) {
	cases := []struct {
		name string
		id   any
		want string
	}{
		{"numeric", 99, "99"},
		{"string", "abc", `"abc"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Pump{GW: newGW(t, "enforce", "safe_tool"), SessionKey: "stdio"}
			line := callLine(t, tc.id, "bad_tool")
			var serverIn, clientOut bytes.Buffer
			if err := p.PumpRequests(bytes.NewReader(append(line, '\n')), &serverIn, &clientOut); err != nil {
				t.Fatalf("PumpRequests: %v", err)
			}
			var resp struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(clientOut.Bytes()), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if string(resp.ID) != tc.want {
				t.Fatalf("id = %s, want %s", resp.ID, tc.want)
			}
		})
	}
}

func TestBlockErrorNullIDWhenAbsent(t *testing.T) {
	// A notification (no id) blocked must produce id:null.
	notif := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}`)
	out := blockError(notif, "mcp_tool_denied")
	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(resp.ID) != "null" {
		t.Fatalf("id = %s, want null", resp.ID)
	}
}

func TestPumpResponsesBenignForwards(t *testing.T) {
	p := &Pump{GW: newGW(t, "enforce", "safe_tool"), SessionKey: "stdio"}
	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`)

	var clientOut bytes.Buffer
	if err := p.PumpResponses(bytes.NewReader(append(resp, '\n')), &clientOut); err != nil {
		t.Fatalf("PumpResponses: %v", err)
	}
	if strings.TrimRight(clientOut.String(), "\n") != string(resp) {
		t.Fatalf("benign response must forward verbatim, got: %q", clientOut.String())
	}
}

func TestRunConcurrentRace(t *testing.T) {
	// Two requests (one allowed, one denied) + the server echoes responses.
	p := &Pump{GW: newGW(t, "enforce", "safe_tool"), SessionKey: "stdio"}

	allowed := callLine(t, 1, "safe_tool")
	denied := callLine(t, 2, "bad_tool")
	clientIn := bytes.NewReader(bytes.Join([][]byte{allowed, denied, nil}, []byte("\n")))

	// Simulate the server: it reads what warden forwards (serverIn) and writes a
	// benign response per line to serverOut. We use pipes wired through goroutines.
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()

	go func() {
		defer func() { _ = serverOutW.Close() }()
		buf := make([]byte, 4096)
		for {
			n, err := serverInR.Read(buf)
			if n > 0 {
				// Echo a benign JSON-RPC result for whatever we received.
				_, _ = serverOutW.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` + "\n"))
			}
			if err != nil {
				return
			}
		}
	}()

	var clientOut bytes.Buffer
	if err := p.Run(context.Background(), clientIn, serverInW, serverOutR, &lockedWriter{w: &clientOut}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// We expect at least the denied error to appear in client output.
	if !strings.Contains(clientOut.String(), "blocked by warden") {
		t.Fatalf("expected a block error in client output, got: %s", clientOut.String())
	}
}

// lockedWriter is a trivially synchronized writer used by the race test's
// assertion buffer (the Pump guards clientOut, but the test buffer is also read
// after Wait so a plain buffer suffices; this keeps -race honest if internals
// change).
type lockedWriter struct {
	w io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) { return l.w.Write(p) }

// newReader wraps b in a sized bufio.Reader matching the pump's read buffer.
func newReader(b []byte) *bufio.Reader {
	return bufio.NewReaderSize(bytes.NewReader(b), 64<<10)
}

func TestReadLineLongLineDoesNotPanic(t *testing.T) {
	// A line longer than maxLineBytes is dropped (resyncs) without panic.
	long := bytes.Repeat([]byte("a"), maxLineBytes+10)
	in := append(long, '\n')
	in = append(in, []byte("short\n")...)
	r := newReader(in)
	// First read: over-long, dropped -> empty.
	got, err := readLine(r)
	if err != nil {
		t.Fatalf("read1: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("over-long line should be dropped, got %d bytes", len(got))
	}
	// Second read: the short line resyncs.
	got, err = readLine(r)
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	if string(got) != "short" {
		t.Fatalf("resync failed, got %q", got)
	}
}
