package audit

import "testing"

// hasControl checks if a ControlID is present in the result set.
func hasControl(mappings []Mapping, controlID string) bool {
	for _, m := range mappings {
		if m.ControlID == controlID {
			return true
		}
	}
	return false
}

// requireControls fails the test if any of the expected ControlIDs are missing.
func requireControls(t *testing.T, mappings []Mapping, expected ...string) {
	t.Helper()
	for _, id := range expected {
		if !hasControl(mappings, id) {
			t.Errorf("expected ControlID %q not found in mappings", id)
		}
	}
}

// requireOnlyControls fails the test if the result set contains any ControlID
// not in the expected list, or if any expected ID is missing.
func requireOnlyControls(t *testing.T, mappings []Mapping, expected ...string) {
	t.Helper()
	requireControls(t, mappings, expected...)
	expectedSet := make(map[string]bool)
	for _, id := range expected {
		expectedSet[id] = true
	}
	for _, m := range mappings {
		if !expectedSet[m.ControlID] {
			t.Errorf("unexpected ControlID %q in mappings", m.ControlID)
		}
	}
}

func TestDeniedRequest(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("deny", "https", nil)
	requireOnlyControls(t, result, "T1048", "T1071")
}

func TestInjectionDetection(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"prompt-injection"})
	requireOnlyControls(t, result, "T1059", "LLM01", "T1071")
}

func TestCredentialLeakDetection(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"credential-leak"})
	requireOnlyControls(t, result, "T1552", "LLM02", "T1071")
}

func TestAllowNoDetections(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", nil)
	requireOnlyControls(t, result, "T1071")
}

func TestMultipleDetections(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("deny", "https", []string{"prompt-injection", "credential-leak"})
	requireControls(t, result, "T1048", "T1059", "LLM01", "T1552", "LLM02", "T1071")
}

func TestUnrecognizedDetections(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"unknown-thing"})
	requireOnlyControls(t, result, "T1071")
}
