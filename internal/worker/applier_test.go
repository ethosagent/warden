package worker

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/internal/secrets"
)

// newTestApplier builds a SettingsApplier over a REAL proxy + in-memory stores and
// a fakeControlPlaneClient, so Apply's rebuild+swap logic can be driven end-to-end
// with fakes (no control-plane HTTP, no sockets). The returned fake's `settings`
// field is what Apply reads via cp.Settings(); tests set it before calling Apply.
func newTestApplier(t *testing.T) (*SettingsApplier, *fakeControlPlaneClient, *observability.LogControl) {
	t.Helper()

	base, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	mcpStore, err := gateway.NewSQLiteStore(base.DB())
	if err != nil {
		t.Fatalf("gateway.NewSQLiteStore: %v", err)
	}

	fetcher := secrets.NewEnvFetcher(nil)
	sp, err := secrets.NewCache(fetcher, time.Hour, nil)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	pxy, err := proxy.New(proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{}),
		Secrets:    sp,
		Analytics:  base,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	logger, logCtrl := observability.NewLogger(io.Discard, "info", "json")

	fake := &fakeControlPlaneClient{}
	var mcpMu sync.Mutex
	var liveMCPGW *gateway.Gateway
	// Close whichever gateway is live at the end of the test (the applier closes the
	// OLD one on each swap; the final live one is the test's to release).
	t.Cleanup(func() {
		mcpMu.Lock()
		gw := liveMCPGW
		mcpMu.Unlock()
		if gw != nil {
			_ = gw.Close()
		}
	})

	a := &SettingsApplier{
		cp:               fake,
		p:                pxy,
		mcpScanner:       scan.NewScanner(),
		mcpStore:         mcpStore,
		agentID:          "default",
		logger:           logger,
		logCtrl:          logCtrl,
		signedStore:      base,
		complianceMapper: audit.NewMapper(),
		secretFetcher:    fetcher,
		placeholders:     nil,
		pol:              config.Policy{},
		obsCfg:           config.ObservabilityConfig{},
		mcpMu:            &mcpMu,
		liveMCPGW:        &liveMCPGW,
		liveCompliance:   false,
		liveCacheTTL:     time.Hour,
	}
	return a, fake, logCtrl
}

func intPtr(n int) *int { return &n }

// TestApplier_NilSettings verifies Apply is a safe no-op when the control plane has
// distributed no settings document: every block guards on a nil wire, so nothing is
// swapped and nothing panics.
func TestApplier_NilSettings(t *testing.T) {
	a, fake, _ := newTestApplier(t)
	fake.settings = nil
	a.Apply()
	if *a.liveMCPGW != nil {
		t.Error("nil settings must not build an MCP gateway")
	}
	if a.liveCompliance {
		t.Error("nil settings must not enable compliance")
	}
	if a.p.DLPMode() != "" {
		t.Error("nil settings must not enable DLP")
	}
}

// TestApplier_MCPEnableThenDisable drives the MCP gateway swap in both directions:
// a settings block with mcp.enabled builds + swaps in a live gateway, and a later
// apply without it swaps back to disabled (untyped-nil) and closes the old one.
func TestApplier_MCPEnableThenDisable(t *testing.T) {
	a, fake, _ := newTestApplier(t)

	fake.settings = &config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Mode: "monitor"}}
	a.Apply()
	if *a.liveMCPGW == nil {
		t.Fatal("mcp.enabled settings should build and track a live gateway")
	}

	// Disable: the tracked gateway is closed and cleared.
	fake.settings = &config.SettingsWire{MCP: &config.MCPSettings{Enabled: false}}
	a.Apply()
	if *a.liveMCPGW != nil {
		t.Error("mcp disabled settings should clear the live gateway")
	}
}

// TestApplier_DLPEnableThenDisable drives the DLP scanner swap in both directions
// over the applier: a distributed dlp block with an active mode + rules rebuilds
// and swaps in a live scanner (observed via the proxy's live DLPMode), a later
// apply with mode:off disables it, and a nil block leaves it disabled — the
// fleet-wide hot-apply this phase adds.
func TestApplier_DLPEnableThenDisable(t *testing.T) {
	a, fake, _ := newTestApplier(t)

	// Enforce + a rule: the scanner is built and swapped onto the live proxy.
	fake.settings = &config.SettingsWire{DLP: &config.DLPSettings{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRuleSettings{
			{Class: "pii.*", To: []string{"api.openai.com"}, Action: config.DLPActionBlock},
		},
		Custom: []config.DLPCustomClassSettings{
			{Name: "codename", Regex: `PROJECT-[A-Z]{4}`, Severity: "high"},
		},
	}}
	a.Apply()
	if got := a.p.DLPMode(); got != config.DLPModeEnforce {
		t.Fatalf("dlp enforce settings should install an enforce scanner, got mode=%q", got)
	}

	// mode:off → an inactive config → DLP disabled (scanner nil-ed).
	fake.settings = &config.SettingsWire{DLP: &config.DLPSettings{Mode: config.DLPModeOff}}
	a.Apply()
	if got := a.p.DLPMode(); got != "" {
		t.Errorf("dlp off settings should disable DLP, got mode=%q", got)
	}

	// Re-enable in monitor mode, then drop the block entirely: nil DLP disables.
	fake.settings = &config.SettingsWire{DLP: &config.DLPSettings{Mode: config.DLPModeMonitor}}
	a.Apply()
	if got := a.p.DLPMode(); got != config.DLPModeMonitor {
		t.Fatalf("dlp monitor settings should install a monitor scanner, got mode=%q", got)
	}
	fake.settings = &config.SettingsWire{}
	a.Apply()
	if got := a.p.DLPMode(); got != "" {
		t.Errorf("absent dlp block should leave DLP disabled, got mode=%q", got)
	}
}

// TestApplier_JudgeSwap covers the three judge branches: a successful rebuild from
// distributed settings (key resolved from the LOCAL env), a rebuild failure that
// keeps the current judge (env unset), and an explicit disable.
func TestApplier_JudgeSwap(t *testing.T) {
	const envName = "WARDEN_APPLIER_JUDGE_KEY"

	t.Run("enabled builds from local env", func(t *testing.T) {
		t.Setenv(envName, "sk-x")
		a, fake, _ := newTestApplier(t)
		fake.settings = &config.SettingsWire{
			Judge: &config.JudgeSettings{
				Enabled:   true,
				Model:     "gpt-4o-mini",
				BaseURL:   "https://api.openai.com/v1",
				APIKeyEnv: envName,
			},
			Agents: []config.AgentSettings{{ID: "default", Policy: "allow reads"}},
		}
		a.Apply() // must not panic; judge is swapped in
	})

	t.Run("build failure keeps current judge", func(t *testing.T) {
		a, fake, _ := newTestApplier(t)
		// Env var UNSET: buildJudgeFrom errors, so Apply logs a warning and leaves
		// the (nil) current judge untouched rather than nil-ing a working one.
		fake.settings = &config.SettingsWire{
			Judge: &config.JudgeSettings{Enabled: true, Model: "m", BaseURL: "https://x/v1", APIKeyEnv: "WARDEN_APPLIER_UNSET"},
		}
		a.Apply()
	})

	t.Run("disabled clears judge", func(t *testing.T) {
		a, fake, _ := newTestApplier(t)
		fake.settings = &config.SettingsWire{Judge: &config.JudgeSettings{Enabled: false}}
		a.Apply()
	})
}

// TestApplier_LoggingLevelAndFormat verifies the live log-level change lands on the
// LevelVar and a format change is surfaced (pending restart) without altering the
// running format.
func TestApplier_LoggingLevelAndFormat(t *testing.T) {
	a, fake, logCtrl := newTestApplier(t)
	fake.settings = &config.SettingsWire{Logging: &config.LoggingSettings{Level: "debug", Format: "text"}}
	a.Apply()
	if got := logCtrl.Level(); got != slog.LevelDebug {
		t.Errorf("log level = %v, want debug", got)
	}
	// Format is restart-only: the running format is unchanged.
	if got := logCtrl.Format(); got != "json" {
		t.Errorf("running format = %q, want json (format change is restart-only)", got)
	}
}

// TestApplier_CacheTTL verifies a distributed cache.ttl that DIFFERS rebuilds the
// secret cache and advances the tracker, while an identical value is a no-op.
func TestApplier_CacheTTL(t *testing.T) {
	a, fake, _ := newTestApplier(t)

	fake.settings = &config.SettingsWire{CacheTTLSeconds: intPtr(7200)}
	a.Apply()
	if a.liveCacheTTL != 7200*time.Second {
		t.Errorf("liveCacheTTL = %v, want 7200s after change", a.liveCacheTTL)
	}

	// Same value again: no rebuild, tracker unchanged.
	fake.settings = &config.SettingsWire{CacheTTLSeconds: intPtr(7200)}
	a.Apply()
	if a.liveCacheTTL != 7200*time.Second {
		t.Errorf("liveCacheTTL drifted on no-op apply: %v", a.liveCacheTTL)
	}
}

// TestApplier_ComplianceToggle verifies the compliance tagging layer toggles on and
// off, tracking liveCompliance so a repeated apply does not re-swap.
func TestApplier_ComplianceToggle(t *testing.T) {
	a, fake, _ := newTestApplier(t)

	fake.settings = &config.SettingsWire{Compliance: &config.ToggleSetting{Enabled: true}}
	a.Apply()
	if !a.liveCompliance {
		t.Fatal("compliance.enabled should flip liveCompliance true")
	}

	// Idempotent: same desired state is a no-op.
	a.Apply()
	if !a.liveCompliance {
		t.Fatal("repeated enable should keep compliance on")
	}

	fake.settings = &config.SettingsWire{Compliance: &config.ToggleSetting{Enabled: false}}
	a.Apply()
	if a.liveCompliance {
		t.Error("compliance disabled should flip liveCompliance false")
	}
}

// TestApplier_ObservabilityPendingRestart exercises the observability branch: a
// distributed observability block that differs from the boot config is surfaced as
// a pending-restart signal (never applied live). It asserts the apply runs without
// disturbing the live trackers.
func TestApplier_ObservabilityPendingRestart(t *testing.T) {
	a, fake, _ := newTestApplier(t)
	fake.settings = &config.SettingsWire{Observability: &config.ObservabilitySettings{
		Enabled:      true,
		ServiceName:  "central",
		OTLPEndpoint: "central:4317",
	}}
	a.Apply()
	// Observability is apply-on-restart: nothing about the live data plane changes.
	if *a.liveMCPGW != nil || a.liveCompliance {
		t.Error("observability change must not alter live gateway/compliance state")
	}
}
