package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// Helpers that build hostile signed bundles from the real one the CP served and
// probe what a worker enforces afterwards.

// EvilHost is a destination only a hostile bundle allows.
const EvilHost = "evil.example.net"

// Skew is the bundle clock skew the stack's workers use (the config default
// of the harness: controlPlane.bundleClockSkew is left at its default).
const bundleSkew = 5 * time.Minute

// readCPID reads the control plane id the bundle publisher stored, waiting for
// it to exist.
func (s *Stack) readCPID() string {
	s.tb.Helper()
	var id string
	s.Eventually("the control plane to store its bundle id", func() bool {
		db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(s.CP.StateDir, "warden-cp.db"), controlplane.StateMigrations())
		if err != nil {
			return false
		}
		defer func() { _ = db.Close() }()
		return db.SQL().QueryRow(`SELECT value FROM bundle_state WHERE name = 'cp_id'`).Scan(&id) == nil && id != ""
	})
	return id
}

// BundlePins are the CP's pinned bundle keys.
func (s *Stack) pins() []keys.JWK { return s.bundlePins() }

// DecodeBundle verifies raw (a real envelope) against the pins and returns the
// bundle it carries; it fails the test when the envelope does not verify.
func (s *Stack) DecodeBundle(tb testing.TB, raw []byte) bundle.Bundle {
	tb.Helper()
	v, err := bundle.Verify(raw, s.pins(), bundle.State{}, bundle.Options{Now: s.Clock.Now(), Skew: bundleSkew})
	if err != nil {
		tb.Fatalf("security: the real envelope does not verify: %v", err)
	}
	return v.Bundle
}

// BundleSigner is the CP's bundle signing key (purpose=bundle).
func (s *Stack) BundleSigner(tb testing.TB) keys.Signer {
	tb.Helper()
	return s.signerFor(tb, keys.PurposeBundle)
}

// UnpinnedSigner is a fresh key no worker pins.
func UnpinnedSigner(tb testing.TB) keys.Signer {
	tb.Helper()
	sg, err := keysigner.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		tb.Fatalf("security: generate a signer: %v", err)
	}
	return sg
}

// Sign signs b (with creds, nil for none) by signers.
func Sign(tb testing.TB, b bundle.Bundle, creds *bundle.Credentials, signers ...keys.Signer) []byte {
	tb.Helper()
	raw, err := bundle.Sign(context.Background(), b, creds, signers...)
	if err != nil {
		tb.Fatalf("security: sign a bundle: %v", err)
	}
	return raw
}

// PolicyAllowing returns policy with host added to its allowlist. With extra,
// the entry carries those members too (an entry with groups is one a worker
// cannot enforce, which makes the signed policy invalid).
func PolicyAllowing(tb testing.TB, policy json.RawMessage, host string, extra map[string]any) json.RawMessage {
	tb.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(policy, &m); err != nil {
		tb.Fatalf("security: decode the policy: %v", err)
	}
	var list []json.RawMessage
	if raw, ok := m["allowlist"]; ok {
		if err := json.Unmarshal(raw, &list); err != nil {
			tb.Fatalf("security: decode the allowlist: %v", err)
		}
	}
	entry := map[string]any{"domain": host}
	for k, v := range extra {
		entry[k] = v
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		tb.Fatalf("security: encode an allowlist entry: %v", err)
	}
	list = append(list, raw)
	if m["allowlist"], err = json.Marshal(list); err != nil {
		tb.Fatalf("security: encode the allowlist: %v", err)
	}
	out, err := json.Marshal(m)
	if err != nil {
		tb.Fatalf("security: encode the policy: %v", err)
	}
	return out
}

// WorkerSeq is the worker's warden_bundle_seq gauge.
func (s *Stack) WorkerSeq(tb testing.TB, w *Worker) float64 {
	tb.Helper()
	return s.Metric(tb, w, "warden_bundle_seq", nil)
}

// ConnectStatus sends a CONNECT for host with token as Proxy-Authorization and
// returns the proxy's status, without sending a request through the tunnel: a
// 200 proves the worker would let the agent through, and nothing reaches the
// upstream.
func (s *Stack) ConnectStatus(tb testing.TB, w *Worker, host, token string) int {
	tb.Helper()
	conn, err := net.DialTimeout("tcp", w.ProxyAddr, 10*time.Second)
	if err != nil {
		tb.Fatalf("security: dial %s: %v", w.Name, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	req := "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n"
	if token != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+token)) + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		tb.Fatalf("security: write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		tb.Fatalf("security: read the CONNECT reply: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Workers returns the fleet view the admin API serves.
func (s *Stack) FleetView(tb testing.TB) []dashboard.WorkerView {
	tb.Helper()
	r := s.AdminSession(tb).Do(tb, http.MethodGet, "/dashboard/api/workers", nil)
	if r.Status != http.StatusOK {
		tb.Fatalf("security: GET /dashboard/api/workers = %d", r.Status)
	}
	var out []dashboard.WorkerView
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		tb.Fatalf("security: decode the fleet view: %v", err)
	}
	return out
}

// FleetWorker is worker w's row of the fleet view.
func (s *Stack) FleetWorker(tb testing.TB, w *Worker) (dashboard.WorkerView, bool) {
	tb.Helper()
	for _, v := range s.FleetView(tb) {
		if v.ProxyID == w.Name {
			return v, true
		}
	}
	return dashboard.WorkerView{}, false
}

// SetKV and KV share a value between a test and its cases' Attack funcs.
func (s *Stack) SetKV(key string, v any) { s.kv.Store(key, v) }

// KV returns the value stored under key ("" ok false when none).
func (s *Stack) KV(key string) (any, bool) { return s.kv.Load(key) }

// decodeJSON reports whether body is JSON for out.
func decodeJSON(body string, out any) bool { return json.Unmarshal([]byte(body), out) == nil }

// FreshToken mints a Warden token for a user of the registered agent, valid at
// the shared clock now: tokens are short lived and the clock moves.
func (s *Stack) FreshToken(tb testing.TB, agentID string) string {
	tb.Helper()
	s.mu.Lock()
	a := s.agents[agentID]
	s.mu.Unlock()
	if a == nil {
		tb.Fatalf("security: agent %q is not registered through RegisterAgent", agentID)
	}
	return s.MintWardenToken(tb, a, "user-"+agentID, "eng")
}

// digestOf is the first 16 hex digits of the SHA-256 of b, for messages that
// must name an input without printing it.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
