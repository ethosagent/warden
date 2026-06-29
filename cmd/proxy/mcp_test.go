package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
)

// syncWriter serializes concurrent writes for tests that point both the slog
// logger and the server subprocess's stderr at one buffer (production uses a
// real os.Stderr fd, where concurrent writes are already serialized).
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func TestMCPMissingServerCommand(t *testing.T) {
	cmd := newMCPCmd()
	cmd.SetArgs([]string{}) // no `--` and no server command
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when server command is missing")
	}
}

func TestMCPEnforceBlocksDeniedCall(t *testing.T) {
	// Use `cat` as a trivial echo server. In enforce mode with the built-in
	// default (empty allow = deny all tools/call), the tools/call is blocked and
	// a JSON-RPC error is written to stdout without ever reaching cat. cat would
	// only echo what it receives, so any stdout JSON must be warden's block error.
	cmd := newMCPCmd()
	// Force the built-in default by pointing config at a nonexistent path, then
	// override mode to enforce.
	cmd.Flags().String("config", "/nonexistent/warden-config.yaml", "")
	cmd.SetArgs([]string{"--mode", "enforce", "--", "cat"})

	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked_tool"}}` + "\n")
	var out, errBuf bytes.Buffer
	cmd.SetIn(in)
	cmd.SetOut(&out)
	cmd.SetErr(&syncWriter{w: &errBuf})
	cmd.SetContext(context.Background())

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, errBuf.String())
	}

	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	trimmed := bytes.TrimSpace(out.Bytes())
	if len(trimmed) == 0 {
		t.Fatalf("expected a block error on stdout, got nothing.\nstderr: %s", errBuf.String())
	}
	if err := json.Unmarshal(trimmed, &resp); err != nil {
		t.Fatalf("stdout not JSON-RPC: %v (%q)", err, out.String())
	}
	if resp.Error.Code != -32600 || string(resp.ID) != "1" {
		t.Fatalf("unexpected block error: %q", out.String())
	}
}
