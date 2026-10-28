package harness

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/integration"
)

// The break-glass login (W-P1-OPS1-08): the control plane boots with
// console.breakGlass enabled over a real argon2id hash file, so a scenario
// signs in at POST /auth/breakglass exactly as an operator would.

const (
	// BreakGlassUsername and BreakGlassPassword are the credentials the hash
	// file holds. They are test values, not secrets.
	BreakGlassUsername = "harness-operator"
	BreakGlassPassword = "harness break-glass passphrase"
)

// WithBreakGlass enables console.breakGlass (username BreakGlassUsername,
// password BreakGlassPassword, a hash file under the harness root). It needs
// WithConsoleOIDC and combines with WithAdminAudit.
func WithBreakGlass() Option {
	return func(h *H) { h.wantBreakGlass = true }
}

// WithOIDCIssuerDown stops the issuer fake before the control plane boots, the
// state break-glass exists for: the control plane starts, its discovery keeps
// failing and /auth/login answers 503 until h.Issuer().Start(). Combine with
// WithConsoleOIDC.
func WithOIDCIssuerDown() Option {
	return func(h *H) { h.wantIssuerDown = true }
}

func (h *H) writeBreakGlassHash() {
	hash, err := controlplane.HashPassword(BreakGlassPassword, rand.Reader)
	if err != nil {
		h.tb.Fatalf("harness: hash the break-glass password: %v", err)
	}
	h.breakGlassHash = filepath.Join(h.root, "breakglass.hash")
	if err := os.WriteFile(h.breakGlassHash, []byte(hash+"\n"), 0o600); err != nil {
		h.tb.Fatalf("harness: write the break-glass hash: %v", err)
	}
}

// Alerts reads the control plane's alert store (cp-alerts.db), newest first:
// what the alert pipeline persisted for the Findings the control plane
// published.
func (h *H) Alerts() []integration.Alert {
	h.tb.Helper()
	// Opening migrates, which can meet the control plane's own write lock under
	// load (SQLITE_BUSY): retry briefly before failing.
	var st *integration.Store
	var err error
	for i := 0; i < 50; i++ {
		if st, err = integration.NewStore(filepath.Join(h.root, "cp-alerts.db")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		h.tb.Fatalf("harness: open the alert store: %v", err)
	}
	defer func() { _ = st.Close() }()
	alerts, err := st.ListAlerts(100)
	if err != nil {
		h.tb.Fatalf("harness: list alerts: %v", err)
	}
	return alerts
}
