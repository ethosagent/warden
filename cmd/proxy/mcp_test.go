package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/scan"
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

func TestVerifyServerBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-server")
	content := []byte("#!/bin/sh\necho mcp\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sigHex := hex.EncodeToString(ed25519.Sign(priv, content))
	pubHex := hex.EncodeToString(pub)

	t.Run("matching sha256 passes", func(t *testing.T) {
		servers := []config.MCPServerConfig{{Command: path, SHA256: hexSum}}
		if err := verifyServerBinary(path, path, servers, ""); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("wrong sha256 fails", func(t *testing.T) {
		servers := []config.MCPServerConfig{{Command: path, SHA256: strings.Repeat("ab", 32)}}
		if err := verifyServerBinary(path, path, servers, ""); err == nil {
			t.Fatal("want mismatch error, got nil")
		}
	})

	t.Run("matching ed25519 signature passes", func(t *testing.T) {
		servers := []config.MCPServerConfig{{Command: path, Ed25519Sig: sigHex, Ed25519Key: pubHex}}
		if err := verifyServerBinary(path, path, servers, ""); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("tampered file fails ed25519", func(t *testing.T) {
		tampered := filepath.Join(dir, "tampered")
		if err := os.WriteFile(tampered, append(append([]byte(nil), content...), '!'), 0o600); err != nil {
			t.Fatalf("write tampered: %v", err)
		}
		servers := []config.MCPServerConfig{{Command: tampered, Ed25519Sig: sigHex, Ed25519Key: pubHex}}
		if err := verifyServerBinary(tampered, tampered, servers, ""); err == nil {
			t.Fatal("want mismatch error for tampered file, got nil")
		}
	})

	t.Run("no matching server is a no-op", func(t *testing.T) {
		servers := []config.MCPServerConfig{{Command: "/some/other/cmd", SHA256: strings.Repeat("ab", 32)}}
		if err := verifyServerBinary(path, path, servers, ""); err != nil {
			t.Fatalf("unmatched command should be a no-op, got %v", err)
		}
		if err := verifyServerBinary(path, path, nil, ""); err != nil {
			t.Fatalf("nil servers should be a no-op, got %v", err)
		}
	})

	t.Run("flag sha256 still applies without a matching server", func(t *testing.T) {
		if err := verifyServerBinary(path, path, nil, hexSum); err != nil {
			t.Fatalf("flag sha256 should pass, got %v", err)
		}
		if err := verifyServerBinary(path, path, nil, strings.Repeat("ab", 32)); err == nil {
			t.Fatal("wrong flag sha256 should fail, got nil")
		}
	})
}

// TestMCPDashboardRecordsTool verifies the dashboard-wiring path: an in-memory
// store + dashboard server with the gateway attached, an mcp event recorded the
// same way runMCP's pump.OnEvent records it, surfaces the tool (with its call
// count) at /dashboard/api/mcp.
func TestMCPDashboardRecordsTool(t *testing.T) {
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := defaultMCPConfig()
	gw := gateway.New(cfg, scan.NewScanner(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	dashSrv := dashboard.NewServer(store, config.Policy{MCP: cfg}, emptySecretProvider{})
	dashSrv.SetMCPProvider(gw)
	handler := dashSrv.Handler()

	// Record an mcp event exactly as pump.OnEvent would.
	if err := store.StoreEvent(analytics.Event{Protocol: "mcp", Tool: "list_files", Decision: "allow"}); err != nil {
		t.Fatalf("store event: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Enabled bool `json:"enabled"`
		Tools   []struct {
			Tool  string `json:"tool"`
			Calls int    `json:"calls"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if !resp.Enabled {
		t.Fatal("mcp dashboard should report enabled when a provider is attached")
	}
	var found bool
	for _, tv := range resp.Tools {
		if tv.Tool == "list_files" {
			found = true
			if tv.Calls != 1 {
				t.Fatalf("calls = %d, want 1", tv.Calls)
			}
		}
	}
	if !found {
		t.Fatalf("list_files not in mcp view: %s", rec.Body.String())
	}
}

func TestMCPDashboardFlagWired(t *testing.T) {
	cmd := newMCPCmd()
	if cmd.Flags().Lookup("dashboard") == nil {
		t.Fatal("--dashboard flag not registered")
	}
	if f := cmd.Flags().Lookup("db"); f == nil || f.DefValue != ":memory:" {
		t.Fatalf("--db flag missing or wrong default: %+v", f)
	}
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
