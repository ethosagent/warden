// Package stdio is the newline-delimited JSON-RPC transport for the `warden mcp`
// wedge: it pumps an MCP client's traffic through the gateway and on to a real
// MCP server subprocess (and back), blocking denied messages without ever
// letting them reach the other end. It also provides an optional server-binary
// integrity check used before launch.
package stdio

import (
	"crypto/ed25519"
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

// VerifyEd25519 checks that the file at path carries a valid Ed25519 signature.
// publicKeyHex is the 32-byte Ed25519 public key as case-insensitive hex, and
// signatureHex is the 64-byte detached signature over the file's raw bytes, also
// as hex. When BOTH are empty the check is skipped (returns nil) so the caller
// can pass them through unconditionally, mirroring VerifyBinary's empty-skip.
//
// This is fail-closed: a public key or signature that is present but incomplete,
// malformed, wrong-length, all-zero/low-order, or does not verify returns an
// error (which the caller must treat as a refusal to launch). It returns a clear
// error when the file cannot be read, when either value is not valid hex, when
// the key/signature length is wrong, when the public key is all-zero, or when the
// signature does not verify against the file bytes.
func VerifyEd25519(path, publicKeyHex, signatureHex string) error {
	pubHex := strings.TrimSpace(publicKeyHex)
	sigHex := strings.TrimSpace(signatureHex)
	if pubHex == "" && sigHex == "" {
		return nil
	}
	// One-sided material can never verify; refuse rather than silently skipping so
	// a half-configured signature block fails closed instead of allowing launch.
	if pubHex == "" {
		return fmt.Errorf("verify %s: ed25519 signature set without a public key", path)
	}
	if sigHex == "" {
		return fmt.Errorf("verify %s: ed25519 public key set without a signature", path)
	}

	pub, err := hex.DecodeString(strings.ToLower(pubHex))
	if err != nil {
		return fmt.Errorf("verify %s: invalid ed25519 public key hex: %w", path, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verify %s: ed25519 public key must be %d bytes, got %d", path, ed25519.PublicKeySize, len(pub))
	}
	// Reject an all-zero (low-order) public key. Go's ed25519.Verify does not
	// reject small-order public keys, and against the all-zero key a zero
	// signature spuriously verifies for some messages — a fail-open. A zero key
	// is never a legitimate signer, so refuse it explicitly to stay fail-closed.
	var zeroPub [ed25519.PublicKeySize]byte
	if subtle.ConstantTimeCompare(pub, zeroPub[:]) == 1 {
		return fmt.Errorf("verify %s: ed25519 public key is all-zero (rejected)", path)
	}
	sig, err := hex.DecodeString(strings.ToLower(sigHex))
	if err != nil {
		return fmt.Errorf("verify %s: invalid ed25519 signature hex: %w", path, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("verify %s: ed25519 signature must be %d bytes, got %d", path, ed25519.SignatureSize, len(sig))
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is an operator-provided server binary
	if err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("verify %s: ed25519 signature mismatch (key %s)", path, hex.EncodeToString(pub))
	}
	return nil
}
