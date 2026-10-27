package controlplane

// llmproviders_write.go adds the LLM-provider registry editor: persist an edited
// `llmProviders:` block to the served config file (preserving every other block
// byte-for-byte) and reload the live consumers. It mirrors WriteIntegrations /
// WriteDetection. The registry rides the settings WIRE (the judge runs on workers),
// so a write refreshes the policy watch — managed workers pull the new registry and
// rebuild their judge on their next apply (M2's applier) — AND re-injects the CP
// dashboard's Explore NL→SQL generator so a selection change takes effect on the CP
// without a restart. SECRET-LOCAL: the block carries only provider names + env NAMES
// + timeouts; nothing here holds, echoes, or logs a key value.

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/worker"
)

// WriteLLMProviders validates and atomically persists an edited `llmProviders:` block
// to the served config file, then reloads the live consumers — the registry analogue
// of WriteIntegrations/WriteDetection. Like them it round-trips the file through a
// top-level YAML map so every block it does not own (policy, logging, judge, explore,
// integrations, detection, secrets, audit, …) survives byte-for-byte; it replaces
// ONLY the `llmProviders` key. An EMPTY list DELETES the key (consistent with how
// WriteDetection/WriteIntegrations remove absent blocks) rather than writing an empty
// sequence.
//
// Persistence goes through atomicWriteConfig, which validates the candidate with the
// full loader (config.NewLocalYAMLProvider → validateLLMProviders + the cross-block
// judge.llmProvider / explore.llmProvider reference checks) before it can replace the
// good file — so a duplicate name, a missing required field, OR removing a provider
// still referenced by the judge/Explore is rejected THERE, and we do not reimplement
// that validation.
//
// In versioned mode it creates a policy version instead (publishLLMProviders);
// ctx carries the author and meta the expected head and message. File mode
// ignores both.
func (s *Server) WriteLLMProviders(ctx context.Context, ps []config.LLMProvider, meta dashboard.WriteMeta) error {
	if s.versions != nil {
		return s.publishLLMProviders(ctx, ps, meta)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		// Best-effort: a malformed current file just means we rebuild the block we
		// own; the loader validation in atomicWriteConfig still guards the result.
		_ = yaml.Unmarshal(cur, &root)
	}

	if err := renderLLMProvidersBlock(root, ps); err != nil {
		return err
	}

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	// The registry rides the settings wire, so wake long-poll waiters: managed
	// workers pull the new registry and rebuild their judge on their next apply.
	s.refresh()
	// Re-inject the CP dashboard's Explore generator so a provider edit that changes
	// the resolved Explore/judge client takes effect here without a restart (mirrors
	// reloadDetection's live re-point).
	s.reinjectExploreLLM()
	s.cfg.Logger.Info("control plane llmProviders updated via dashboard", "count", len(ps))
	return nil
}

// renderLLMProvidersBlock replaces root's llmProviders block with ps; an empty
// list deletes the key. It is shared by WriteLLMProviders and renderDocToRoot.
func renderLLMProvidersBlock(root map[string]yaml.Node, ps []config.LLMProvider) error {
	if len(ps) == 0 {
		delete(root, "llmProviders")
		return nil
	}
	node, err := config.EncodeLLMProvidersNode(ps)
	if err != nil {
		return fmt.Errorf("controlplane: encode llmProviders block: %w", err)
	}
	root["llmProviders"] = node
	return nil
}

// injectExploreLLM (re)computes the Explore / NL→SQL SQLGenerator for the CP
// dashboard from the CURRENT served settings and installs it — or CLEARS it (nil)
// when nothing resolves, which routes Explore to the existing 409 llm_not_configured
// path. It is the single home for the Explore-selection wiring, called at
// dashboard-build time AND after a settings/llmProviders edit so a selection change
// takes effect live. SECRET-LOCAL: every key resolves from the CP's OWN env; a
// provider whose key env is empty here yields no client (logged, metadata only).
// Fail-soft: it never returns an error and never blocks.
func (s *Server) injectExploreLLM(dash *dashboard.Server) {
	if dash == nil {
		return
	}
	wire, _, _, _ := s.policy.snapshot()
	if wire.Settings == nil {
		dash.SetSQLGenerator(nil)
		return
	}
	jc := config.JudgeConfigFromSettings(wire.Settings.Judge)
	judgeClient, _ := worker.BuildLLMClient(jc) // may be nil (judge off / key env empty here)
	clients, errs := worker.BuildLLMClients(config.LLMProvidersFromSettings(wire.Settings.LLMProviders))
	for name, e := range errs {
		s.cfg.Logger.Warn("llm provider unavailable on control plane", "provider", name, "error", e.Error())
	}
	exploreName := ""
	if wire.Settings.Explore != nil {
		exploreName = wire.Settings.Explore.LLMProvider
	}
	// Guard the typed-nil interface trap: only box a NON-nil concrete client; an
	// unresolved pick explicitly clears the generator (untyped nil) → the 409 path.
	if gen := worker.PickExploreLLM(exploreName, clients, judgeClient); gen != nil {
		dash.SetSQLGenerator(gen)
	} else {
		dash.SetSQLGenerator(nil)
	}
}

// reinjectExploreLLM re-runs injectExploreLLM against the dashboard captured at build
// time. A nil dash (Handler not yet called) is a no-op — writes are only reachable
// through the dashboard writer, which is wired in Handler, so dash is always set by
// the time a write occurs.
func (s *Server) reinjectExploreLLM() { s.injectExploreLLM(s.dash) }

// llmProvidersView builds the dashboard's LLM-providers status view from the CURRENTLY
// served settings, resolving each provider against the CP's OWN env. It is the CP's
// SetLLMProvidersSource closure body, factored out for readability.
func (s *Server) llmProvidersView() dashboard.LLMProvidersView {
	wire, _, _, _ := s.policy.snapshot()
	var provs []config.LLMProvider
	if wire.Settings != nil {
		provs = config.LLMProvidersFromSettings(wire.Settings.LLMProviders)
	}
	return dashboard.LLMProvidersView{Providers: worker.BuildLLMProviderViews(provs)}
}
