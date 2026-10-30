//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// TestKeysRotationDrill is the rotation drill on the real binary: it signs
// JWS test tokens with the control plane's own token keys, rotates through
// `warden control-plane keys rotate` (scheduled-style first, then emergency)
// and checks every verification against the JWKS the control plane actually
// serves — a retired key keeps verifying through its overlap window, a
// revoked key stops verifying at once, and no JWS that should verify ever
// fails.
func TestKeysRotationDrill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the rotation drill in short mode")
	}
	bin := buildWarden(t)
	ctx := context.Background()

	// A control plane on a free port: keys enabled with the default timings,
	// admin audit enabled for the rotation rows.
	stateDir := filepath.Join(t.TempDir(), "state")
	addr := freeAddr(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := fmt.Sprintf(`policy:
  allowlist:
    - domain: api.openai.com
listen: %s
keys:
  enabled: true
console:
  adminAudit:
    enabled: true
`, addr)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := exec.Command(bin, "control-plane", "--config", cfgPath, "--state-dir", stateDir, "--listen", addr)
	var logs strings.Builder
	cp.Stdout, cp.Stderr = &logs, &logs
	if err := cp.Start(); err != nil {
		t.Fatalf("start control plane: %v", err)
	}
	defer func() {
		_ = cp.Process.Kill()
		_, _ = cp.Process.Wait()
	}()

	// Wait for readiness, then read the active and next kids: the served JWKS
	// cannot say which key is in which slot, so the drill reads the metadata
	// store.
	fetchJWKS(t, addr, nil)
	activeKID := kidByState(t, ctx, stateDir, "active")
	nextKID := kidByState(t, ctx, stateDir, "next")
	if activeKID == "" || nextKID == "" {
		t.Fatalf("no active/next token key yet: %q / %q", activeKID, nextKID)
	}
	doc := fetchJWKS(t, addr, func(doc jwksDoc) bool { return doc.has(activeKID) && doc.has(nextKID) })
	const payload = `{"sub":"drill"}`
	// checks is every verification the drill makes: (label, jws, jwks
	// snapshot, want). A check that fails when want is true, or succeeds when
	// want is false, is an unexpected failure.
	var checks []jwsCheck

	oldJWS := signJWS(t, stateDir, "token", activeKID, payload)
	checks = append(checks, jwsCheck{"active key before the rotation", oldJWS, doc, true})

	// A scheduled-style rotation: the next key was published long enough ago
	// (publish_at moved back one prepublish window), so the CLI promotes it.
	// The old key retires and stays published for its overlap, so the JWS it
	// signed keeps verifying.
	backdateNextPublishAt(t, ctx, stateDir)
	runCLI(t, bin, "control-plane", "keys", "rotate", "--purpose", "token",
		"--state-dir", stateDir, "--config", cfgPath)
	afterRotate := fetchJWKS(t, addr, func(doc jwksDoc) bool { return doc.has(nextKID) })
	if !afterRotate.has(activeKID) {
		t.Fatalf("retired kid %s left the served jwks at once:\n%s", activeKID, afterRotate.raw)
	}
	checks = append(checks, jwsCheck{"retired key through the overlap", oldJWS, afterRotate, true})
	rotatedJWS := signJWS(t, stateDir, "token", nextKID, payload)
	checks = append(checks, jwsCheck{"promoted key after the rotation", rotatedJWS, afterRotate, true})

	// An emergency rotation: the serving key is revoked and leaves the served
	// JWKS at once, so the JWS it signed stops verifying — the expected
	// failure an operator accepts when they rotate under compromise.
	runCLI(t, bin, "control-plane", "keys", "rotate", "--purpose", "token",
		"--emergency", "--yes", "--state-dir", stateDir, "--config", cfgPath)
	afterEmergency := fetchJWKS(t, addr, func(doc jwksDoc) bool { return !doc.has(nextKID) })
	checks = append(checks, jwsCheck{"revoked key after the emergency", rotatedJWS, afterEmergency, false})
	finalActive := kidByState(t, ctx, stateDir, "active")
	if finalActive == "" {
		t.Fatalf("no active key after the emergency:\n%s", afterEmergency.raw)
	}
	checks = append(checks, jwsCheck{"emergency's new key", signJWS(t, stateDir, "token", finalActive, payload), afterEmergency, true})

	// Every check must come out as wanted: zero unexpected failures across
	// the whole rotation.
	for _, c := range checks {
		if got := c.doc.verifies(c.jws); got != c.want {
			t.Errorf("%s: verified = %t, want %t (jwks %s)", c.label, got, c.want, c.doc.raw)
		}
	}
}

// jwsCheck is one verification the drill asserts.
type jwsCheck struct {
	label string
	jws   string
	doc   jwksDoc
	want  bool
}

// jwksDoc is a fetched JWKS with the raw body for error messages.
type jwksDoc struct {
	raw  string
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	} `json:"keys"`
}

func (d jwksDoc) has(kid string) bool {
	for _, k := range d.Keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// verifies checks a compact EdDSA JWS against the document's keys.
func (d jwksDoc) verifies(jws string) bool {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false
	}
	var head struct {
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &head) != nil {
		return false
	}
	for _, k := range d.Keys {
		if k.Kid != head.Kid || k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return false
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), []byte(parts[0]+"."+parts[1]), sig)
	}
	return false
}

// signJWS returns a compact EdDSA JWS of payload with the private material
// the key store holds for kid (the drill runs on the control plane's host).
func signJWS(t *testing.T, stateDir, purpose, kid, payload string) string {
	t.Helper()
	path := filepath.Join(stateDir, "keys", purpose, kid+".pem")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key material: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("%s is not an Ed25519 key", path)
	}
	body := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"EdDSA","crv":"Ed25519","typ":"JWS","kid":"`+kid+`"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	return body + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(body)))
}

// fetchJWKS fetches the served JWKS until ready holds (nil: once).
func fetchJWKS(t *testing.T, addr string, ready func(jwksDoc) bool) jwksDoc {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last jwksDoc
	for {
		resp, err := http.Get("http://" + addr + "/.well-known/jwks.json")
		if err == nil {
			raw, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if rerr == nil {
				var doc jwksDoc
				if json.Unmarshal(raw, &doc) == nil {
					last = doc
					last.raw = string(raw)
					if ready == nil || ready(doc) {
						return last
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("jwks never matched:\n%s", last.raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// kidByState reads the token purpose's kid in state from the metadata store.
func kidByState(t *testing.T, ctx context.Context, stateDir, state string) string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var kid string
	if err := db.SQL().QueryRow(
		`SELECT kid FROM signing_keys WHERE purpose = 'token' AND state = ?`, state).Scan(&kid); err != nil {
		return ""
	}
	return kid
}

// backdateNextPublishAt moves token's next key one hour into the past, so a
// real-time rotation may promote it (the config floor is 10 minutes).
func backdateNextPublishAt(t *testing.T, ctx context.Context, stateDir string) {
	t.Helper()
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.SQL().Exec(
		`UPDATE signing_keys SET publish_at = publish_at - 3600 WHERE purpose = 'token' AND state = 'next'`); err != nil {
		t.Fatal(err)
	}
}

// runCLI runs the real binary for one CLI command and fails on a non-zero exit.
func runCLI(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// buildWarden builds the real binary once per test.
func buildWarden(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "warden-drill")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/proxy")
	cmd.Dir = findProjectRoot(t)
	if outb, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, outb)
	}
	return out
}

// freeAddr returns a 127.0.0.1 address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
