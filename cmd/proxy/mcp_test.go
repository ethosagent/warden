package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/config"
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

func TestMCPBadEd25519SignatureRefusesLaunch(t *testing.T) {
	// A bogus Ed25519 public key + signature must fail closed: the wedge refuses
	// to launch `cat` and returns an error. If the check were skipped, cat would
	// run and Execute would succeed. Two deterministic cases are covered: an
	// all-zero (low-order) key, which Go's ed25519.Verify would otherwise let
	// spuriously verify on some platforms, and a real key whose signature was made
	// over unrelated bytes so verification against the cat binary always fails.
	assertRefuses := func(t *testing.T, pubHex, sigHex string) {
		t.Helper()
		cmd := newMCPCmd()
		cmd.Flags().String("config", "/nonexistent/warden-config.yaml", "")
		cmd.SetArgs([]string{"--verify-ed25519-pubkey", pubHex, "--verify-ed25519-sig", sigHex, "--", "cat"})
		cmd.SetIn(strings.NewReader(""))
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&syncWriter{w: &errBuf})
		cmd.SetContext(context.Background())

		if err := cmd.Execute(); err == nil {
			t.Fatalf("expected launch refusal on invalid ed25519 signature, got nil.\nstderr: %s", errBuf.String())
		}
	}

	t.Run("all-zero key rejected", func(t *testing.T) {
		pubHex := hex.EncodeToString(make([]byte, 32)) // 32-byte zero key (valid length)
		sigHex := hex.EncodeToString(make([]byte, 64)) // 64-byte zero sig (valid length)
		assertRefuses(t, pubHex, sigHex)
	})

	t.Run("valid key wrong signature rejected", func(t *testing.T) {
		// Real keypair from a fixed seed, signing bytes that are not the server
		// binary — so verification against `cat` deterministically fails everywhere.
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x01}, ed25519.SeedSize))
		pub := priv.Public().(ed25519.PublicKey)
		wrongSig := ed25519.Sign(priv, []byte("unrelated content, not the server binary"))
		pubHex := hex.EncodeToString(pub)
		sigHex := hex.EncodeToString(wrongSig)
		assertRefuses(t, pubHex, sigHex)
	})
}

func TestMCPUnknownServerNameRefusesLaunch(t *testing.T) {
	cmd := newMCPCmd()
	cmd.Flags().String("config", "/nonexistent/warden-config.yaml", "")
	cmd.SetArgs([]string{"--server", "does-not-exist", "--", "cat"})
	cmd.SetIn(strings.NewReader(""))
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&syncWriter{w: &errBuf})
	cmd.SetContext(context.Background())

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected launch refusal for unknown --server name, got nil.\nstderr: %s", errBuf.String())
	}
}

func TestResolveServerIntegrity(t *testing.T) {
	servers := []config.MCPServerConfig{
		{Name: "a", SHA256: "aa"},
		{Name: "b", Ed25519PublicKey: "bb", Ed25519Signature: "cc"},
	}

	t.Run("empty name yields zero value", func(t *testing.T) {
		got, err := resolveServerIntegrity(servers, "")
		if err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
		if got != (config.MCPServerConfig{}) {
			t.Fatalf("want zero value, got %+v", got)
		}
	})

	t.Run("match returns entry", func(t *testing.T) {
		got, err := resolveServerIntegrity(servers, "b")
		if err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
		if got.Ed25519PublicKey != "bb" || got.Ed25519Signature != "cc" {
			t.Fatalf("wrong entry: %+v", got)
		}
	})

	t.Run("unknown name errors", func(t *testing.T) {
		if _, err := resolveServerIntegrity(servers, "nope"); err == nil {
			t.Fatal("want error for unknown server name, got nil")
		}
	})
}
