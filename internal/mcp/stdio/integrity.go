// Package stdio is the newline-delimited JSON-RPC transport for the `warden mcp`
// wedge: it pumps an MCP client's traffic through the gateway and on to a real
// MCP server subprocess (and back), blocking denied messages without ever
// letting them reach the other end. It also provides an optional server-binary
// integrity check used before launch.
package stdio

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerifyBinary checks that the file at path has the given SHA-256.
// wantSHA256Hex is case-insensitive hex. An empty want skips the check (returns
// nil) so the caller can pass it through unconditionally. It returns a clear
// error when the file cannot be read, when want is not valid hex, or when the
// computed digest does not match (constant-time comparison).
func VerifyBinary(path, wantSHA256Hex string) error {
	want := strings.TrimSpace(wantSHA256Hex)
	if want == "" {
		return nil
	}
	wantBytes, err := hex.DecodeString(strings.ToLower(want))
	if err != nil {
		return fmt.Errorf("verify %s: invalid --verify-sha256 hex: %w", path, err)
	}

	f, err := os.Open(path) //nolint:gosec // path is an operator-provided server binary
	if err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	got := h.Sum(nil)

	if subtle.ConstantTimeCompare(got, wantBytes) != 1 {
		return fmt.Errorf("verify %s: sha256 mismatch (want %s, got %s)", path, strings.ToLower(want), hex.EncodeToString(got))
	}
	return nil
}
