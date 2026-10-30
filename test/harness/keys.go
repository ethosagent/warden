package harness

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/fakes"
)

// The signing-key gate (W-P2-KEYS-02): the control plane boots with
// keys.enabled and a state dir, so it creates an active and a next key per
// purpose (token, bundle) in its private-key store, records their public
// metadata in warden-cp.db, and keeps serving policy whatever state the store
// is in. The control plane runs on the harness's fake clock, so
// h.Clock().Advance drives the key reload backoff.

// keysState is what the harness records about the running key manager.
type keysState struct {
	mu       sync.Mutex
	mgr      *keys.Manager
	findings []integration.Finding
}

// PublishFinding implements controlplane.FindingPublisher: with keys enabled
// the harness captures the control plane's Findings instead of the alert
// pipeline, so a scenario can assert on them.
func (k *keysState) PublishFinding(f integration.Finding) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.findings = append(k.findings, f)
}

// WithKeys boots the control plane with keys.enabled: true, the file private
// key store under the control plane's state dir, and a state dir under the
// harness root. In-process only.
func WithKeys() Option {
	return func(h *H) { h.wantKeys = true }
}

// WithFlakyKeyStore is WithKeys with an in-memory private-key store the
// scenario can take down and bring back: h.KeyStore().SetDown(err).
func WithFlakyKeyStore() Option {
	return func(h *H) {
		h.wantKeys = true
		h.keyStore = fakes.NewFakeKeyStore()
	}
}

// keyTiming is the token purpose's rotation timing as WithKeyRotation set it.
type keyTiming struct {
	interval, prepublish, overlap time.Duration
}

// WithKeyRotation is WithKeys with the token purpose's rotation timing set in
// the keys config (keys.token.rotationInterval and friends), so a scenario
// drives rotations with the harness clock instead of the 720h default. The
// bundle purpose stays manual: its interval must be 0. The floors still apply
// (prepublish 10m, overlap 20m, interval prepublish+overlap or 0).
func WithKeyRotation(interval, prepublish, overlap time.Duration) Option {
	return func(h *H) {
		h.wantKeys = true
		h.keyTiming = keyTiming{interval: interval, prepublish: prepublish, overlap: overlap}
	}
}

func (h *H) applyKeys(p *controlplane.Params) {
	if !h.wantKeys {
		return
	}
	if p.StateDir == "" {
		p.StateDir = filepath.Join(h.root, "cp-state")
	}
	p.Clock = h.fake
	if h.keyStore != nil {
		p.KeyStore = h.keyStore
	}
	p.Findings = &h.keyState
	p.KeysReady = func(m *keys.Manager) {
		h.keyState.mu.Lock()
		defer h.keyState.mu.Unlock()
		h.keyState.mgr = m
	}
}

// keysYAML renders the keys block of the control plane's config file.
func (h *H) keysYAML() string {
	if !h.wantKeys {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nkeys:\n  enabled: true\n")
	if h.keyTiming != (keyTiming{}) {
		fmt.Fprintf(&b, "  token:\n    rotationInterval: %s\n    prepublish: %s\n    overlap: %s\n",
			h.keyTiming.interval, h.keyTiming.prepublish, h.keyTiming.overlap)
	}
	return b.String()
}

// KeyStore is the fake private-key store of WithFlakyKeyStore.
func (h *H) KeyStore() *fakes.FakeKeyStore {
	h.tb.Helper()
	if h.keyStore == nil {
		h.tb.Fatal("harness: KeyStore needs the WithFlakyKeyStore option")
	}
	return h.keyStore
}

// KeyManager is the key manager of the control plane's latest start.
func (h *H) KeyManager() *keys.Manager {
	h.tb.Helper()
	if !h.wantKeys {
		h.tb.Fatal("harness: KeyManager needs the WithKeys option")
	}
	h.keyState.mu.Lock()
	defer h.keyState.mu.Unlock()
	if h.keyState.mgr == nil {
		h.tb.Fatal("harness: the control plane has not started its key manager")
	}
	return h.keyState.mgr
}

// KeyFindings returns the Findings with the given rule id the control plane
// published since the harness booted.
func (h *H) KeyFindings(rule string) []integration.Finding {
	h.tb.Helper()
	h.keyState.mu.Lock()
	defer h.keyState.mu.Unlock()
	var out []integration.Finding
	for _, f := range h.keyState.findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// KeyRow is one signing_keys row as the control plane stored it.
type KeyRow struct {
	KID, Purpose, Alg, State, Backend string
	// PublicJWK is the row's public_jwk column (JSON).
	PublicJWK string
}

// KeyRows reads the signing_keys table of the control plane's state database,
// read-only and oldest first: what the control plane stored, independent of
// its API.
func (h *H) KeyRows() []KeyRow {
	h.tb.Helper()
	if !h.wantKeys {
		h.tb.Fatal("harness: KeyRows needs the WithKeys option")
	}
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(h.KeyStateDir(), "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT kid, purpose, alg, state, store_backend, public_jwk FROM signing_keys ORDER BY created_at, rowid`)
	if err != nil {
		h.tb.Fatalf("harness: read signing_keys: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KeyRow
	for rows.Next() {
		var r KeyRow
		if err := rows.Scan(&r.KID, &r.Purpose, &r.Alg, &r.State, &r.Backend, &r.PublicJWK); err != nil {
			h.tb.Fatalf("harness: scan a signing_keys row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read signing_keys: %v", err)
	}
	return out
}

// KeyStateDir is the control plane's state dir. The file key store sits in its
// keys/ subdirectory.
func (h *H) KeyStateDir() string {
	h.tb.Helper()
	if !h.wantKeys {
		h.tb.Fatal("harness: KeyStateDir needs the WithKeys option")
	}
	return filepath.Join(h.root, "cp-state")
}

// KeysTablePresent reports whether the control plane's state database has a
// signing_keys table. It needs a state dir (WithBackup or WithKeys).
func (h *H) KeysTablePresent() bool {
	h.tb.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(h.root, "cp-state", "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'signing_keys'`).Scan(&n); err != nil {
		h.tb.Fatalf("harness: inspect the state db: %v", err)
	}
	return n == 1
}
