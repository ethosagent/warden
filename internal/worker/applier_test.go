package worker

import (
	"errors"
	"io"
	"log/slog"
	"runtime"
	"strings"
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

// TestApplier_NoMCPSwapAfterShutdown pins the shutdown race: an Apply that is
// still in flight after the shutdown defer took the final gateway must not
// install a new one (nothing would Close it and its flusher goroutine would
// leak), and must close the one it just built.
func TestApplier_NoMCPSwapAfterShutdown(t *testing.T) {
	a, fake, _ := newTestApplier(t)
	closed := true
	a.mcpClosed = &closed
	fake.settings = &config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Mode: "monitor"}}
	a.Apply()
	if *a.liveMCPGW != nil {
		t.Fatal("Apply installed an MCP gateway after shutdown took the live one")
	}
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	if strings.Contains(string(buf[:n]), "(*Gateway).flushLoop") {
		t.Fatal("the gateway Apply built after shutdown was not closed: flushLoop leaked")
	}
}

// TestApplier_ApplyBoot pins the boot apply: a distributed block is applied
// exactly as a changed long-poll applies it, while a block the control plane
// does not distribute keeps the local boot config (never less strict than the
// local file), where Apply would turn it off. The MCP gateway is left to Run.
func TestApplier_ApplyBoot(t *testing.T) {
	t.Run("distributed blocks applied", func(t *testing.T) {
		a, fake, _, _, _ := identityApplier(t)
		fake.settings = &config.SettingsWire{
			DLP:        &config.DLPSettings{Mode: config.DLPModeMonitor},
			Compliance: &config.ToggleSetting{Enabled: true},
			MCP:        &config.MCPSettings{Enabled: true, Mode: "monitor"},
			Identity:   &config.IdentitySettings{DefaultMode: "attribute", Issuer: "http://idp.test", Audience: "warden", InternalIssuerURL: "http://idp.test"},
		}
		a.ApplyBoot()
		if got := a.p.DLPMode(); got != config.DLPModeMonitor {
			t.Errorf("DLP mode = %q, want monitor", got)
		}
		if !a.liveCompliance {
			t.Error("compliance not enabled from the boot pull")
		}
		if a.identity.live.mode != proxy.IdentityModeAttribute {
			t.Errorf("identity mode = %q, want attribute", a.identity.live.mode)
		}
		if *a.liveMCPGW != nil {
			t.Error("ApplyBoot built an MCP gateway; Run builds the boot gateway")
		}
	})
	t.Run("absent blocks keep the local config", func(t *testing.T) {
		a, fake, _, _, _ := identityApplier(t)
		// The local boot config: DLP enforce, compliance on, identity attribute.
		fake.settings = &config.SettingsWire{
			DLP:        &config.DLPSettings{Mode: config.DLPModeEnforce},
			Compliance: &config.ToggleSetting{Enabled: true},
			Identity:   &config.IdentitySettings{DefaultMode: "attribute", Issuer: "http://idp.test", Audience: "warden", InternalIssuerURL: "http://idp.test"},
		}
		a.Apply()
		for _, s := range []*config.SettingsWire{nil, {}} {
			fake.settings = s
			a.ApplyBoot()
			if got := a.p.DLPMode(); got != config.DLPModeEnforce {
				t.Errorf("settings %+v: DLP mode = %q, want the local enforce", s, got)
			}
			if !a.liveCompliance {
				t.Errorf("settings %+v: local compliance turned off", s)
			}
			if a.identity.live.mode != proxy.IdentityModeAttribute {
				t.Errorf("settings %+v: identity mode = %q, want the local attribute", s, a.identity.live.mode)
			}
		}
	})
	t.Run("absent judge keeps the local judge", func(t *testing.T) {
		a, fake, _ := newTestApplier(t)
		a.p.SetJudge(stubJudge{}) // the judge Run built from the local file
		fake.settings = &config.SettingsWire{DLP: &config.DLPSettings{Mode: config.DLPModeMonitor}}
		a.ApplyBoot()
		if !a.p.JudgeEnabled() {
			t.Error("ApplyBoot with no distributed judge dropped the local judge")
		}
		// A changed long-poll with the same settings turns it off (Apply semantics).
		a.Apply()
		if a.p.JudgeEnabled() {
			t.Error("Apply with no distributed judge kept the judge")
		}
	})
	t.Run("cache TTL and log level", func(t *testing.T) {
		a, fake, logCtrl := newTestApplier(t)
		// Absent: the local TTL (1h) and level (info) stand.
		fake.settings = &config.SettingsWire{DLP: &config.DLPSettings{Mode: config.DLPModeMonitor}}
		a.ApplyBoot()
		if a.liveCacheTTL != time.Hour {
			t.Errorf("liveCacheTTL = %v, want the local 1h", a.liveCacheTTL)
		}
		if got := logCtrl.Level(); got != slog.LevelInfo {
			t.Errorf("log level = %v, want the local info", got)
		}
		// Present: applied at boot, as a changed long-poll would.
		fake.settings = &config.SettingsWire{
			CacheTTLSeconds: intPtr(120),
			Logging:         &config.LoggingSettings{Level: "debug"},
		}
		a.ApplyBoot()
		if a.liveCacheTTL != 120*time.Second {
			t.Errorf("liveCacheTTL = %v, want 120s from the boot pull", a.liveCacheTTL)
		}
		if got := logCtrl.Level(); got != slog.LevelDebug {
			t.Errorf("log level = %v, want debug from the boot pull", got)
		}
	})
}

// stubJudge allows everything; only its presence matters.
type stubJudge struct{}

func (stubJudge) Evaluate(string, string, string, string, string, bool) proxy.Verdict {
	return proxy.Verdict{Decision: "allow"}
}

// failingFetcher fails every fetch and counts them, like the no-credentials
// fetcher of a cache boot.
type failingFetcher struct{ calls int }

func (f *failingFetcher) Fetch(string) (string, error) {
	f.calls++
	return "", errors.New("no credentials")
}

// TestApplier_CacheTTLSecretsUnavailable: on a worker booted from the bundle
// cache with no AWS credentials, a distributed TTL change (the boot apply
// included) builds another unhealthy cache: no prefetch, nothing resolved.
func TestApplier_CacheTTLSecretsUnavailable(t *testing.T) {
	a, fake, _ := newTestApplier(t)
	f := &failingFetcher{}
	a.secretFetcher, a.placeholders, a.secretsUnavailable = f, []string{"OPENAI_KEY"}, true
	fake.settings = &config.SettingsWire{CacheTTLSeconds: intPtr(7200)}
	a.ApplyBoot()
	if a.liveCacheTTL != 7200*time.Second {
		t.Errorf("liveCacheTTL = %v, want 7200s", a.liveCacheTTL)
	}
	if f.calls != 0 {
		t.Errorf("%d fetches, want 0: the rebuilt cache must stay unhealthy, not prefetch", f.calls)
	}
}
