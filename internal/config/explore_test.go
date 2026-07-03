package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExplore_WireRoundTrip verifies Policy.Explore projects onto the secret-free
// SettingsWire and reverses back to the same ExploreConfig, carrying only a
// provider NAME. It also proves explore ALONE makes the wire non-nil (the any=true
// flag), so a policy whose only behavioral block is explore still emits a wire the
// control plane can read.
func TestExplore_WireRoundTrip(t *testing.T) {
	orig := ExploreConfig{LLMProvider: "explore-prov"}

	wire := SettingsWireFromPolicy(Policy{Explore: orig})
	if wire == nil {
		t.Fatal("SettingsWireFromPolicy returned nil; explore alone should make the wire non-nil")
	}
	if wire.Explore == nil {
		t.Fatal("wire.Explore is nil; the explore selection should ride the wire")
	}
	if wire.Explore.LLMProvider != "explore-prov" {
		t.Fatalf("wire.Explore.LLMProvider = %q, want explore-prov", wire.Explore.LLMProvider)
	}

	// Secret-free: the marshaled wire carries only the provider NAME and nothing
	// resembling a key value (the type has no field that could hold one).
	blob, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	if !strings.Contains(string(blob), "explore-prov") {
		t.Fatalf("wire should carry the provider name: %s", blob)
	}
	if strings.Contains(string(blob), "apiKey") {
		t.Fatalf("explore wire must not carry any key material: %s", blob)
	}

	if got := ExploreFromSettings(wire.Explore); got != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, orig)
	}
}

// TestExplore_NoBlockBackCompat verifies that a policy with no explore selection
// adds no "explore" key to the wire (projector returns nil), and the reverse maps
// nil back to the zero ExploreConfig — i.e. Explore reuses the judge's client
// exactly as before (no behavior change).
func TestExplore_NoBlockBackCompat(t *testing.T) {
	if ex := exploreSettingsFromPolicy(ExploreConfig{}); ex != nil {
		t.Fatalf("empty explore should project to nil, got %+v", ex)
	}
	// A policy with another behavioral block but no explore emits a wire whose
	// Explore stays nil (explore does not appear unless selected).
	if wire := SettingsWireFromPolicy(Policy{Judge: JudgeConfig{Enabled: true}}); wire == nil || wire.Explore != nil {
		t.Fatal("no explore block should leave wire.Explore nil")
	}
	if got := ExploreFromSettings(nil); got != (ExploreConfig{}) {
		t.Fatalf("ExploreFromSettings(nil) = %+v, want zero", got)
	}
}

// TestExplore_DeepCopyIsIndependent verifies SettingsWire.DeepCopy clones the
// Explore pointer rather than aliasing it, so a caller can retain the copy without
// mutating the provider's stored wire.
func TestExplore_DeepCopyIsIndependent(t *testing.T) {
	src := &SettingsWire{Explore: &ExploreSettings{LLMProvider: "a"}}
	cp := src.DeepCopy()
	if cp.Explore == nil || cp.Explore == src.Explore {
		t.Fatal("DeepCopy should clone the Explore pointer, not alias it")
	}
	cp.Explore.LLMProvider = "mutated"
	if src.Explore.LLMProvider != "a" {
		t.Fatalf("mutating the copy changed the source: %q", src.Explore.LLMProvider)
	}
}

// TestValidateExploreProviderRef covers the load-time cross-block check: empty is
// fine, a name that matches a registry entry is fine, and a DANGLING name is a
// config LOAD error (an operator typo surfaced strictly, like the judge ref).
func TestValidateExploreProviderRef(t *testing.T) {
	providers := []LLMProvider{{Name: "known"}}

	if err := validateExploreProviderRef(ExploreConfig{}, providers); err != nil {
		t.Fatalf("empty explore: want nil, got %v", err)
	}
	if err := validateExploreProviderRef(ExploreConfig{LLMProvider: "known"}, providers); err != nil {
		t.Fatalf("known provider: want nil, got %v", err)
	}
	if err := validateExploreProviderRef(ExploreConfig{LLMProvider: "ghost"}, providers); err == nil {
		t.Fatal("dangling explore.llmProvider must be a load error")
	}
}
