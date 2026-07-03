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
	result := mapper.MapEvent("deny", "https", nil, false)
	requireOnlyControls(t, result, "T1048", "T1071")
}

func TestInjectionDetection(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"prompt-injection"}, false)
	requireOnlyControls(t, result, "T1059", "LLM01", "T1071")
}

func TestCredentialLeakDetection(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"credential-leak"}, false)
	requireOnlyControls(t, result, "T1552", "LLM02", "T1071")
}

func TestAllowNoDetections(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", nil, false)
	requireOnlyControls(t, result, "T1071")
}

func TestMultipleDetections(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("deny", "https", []string{"prompt-injection", "credential-leak"}, false)
	requireControls(t, result, "T1048", "T1059", "LLM01", "T1552", "LLM02", "T1071")
}

func TestUnrecognizedDetections(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"unknown-thing"}, false)
	requireOnlyControls(t, result, "T1071")
}

// TestSecretsBrokeredEmitsProtectiveControl verifies a protective secret swap
// contributes the M1041 mitigation alongside the protocol control (T1071), and
// does NOT synthesize the T1552/LLM02 credential-leakage threat pair when no
// leakage detection actually fired.
func TestSecretsBrokeredEmitsProtectiveControl(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", nil, true)
	requireOnlyControls(t, result, "M1041", "T1071")
}

// TestSecretsBrokeredDoesNotEmitLeakagePair asserts the swap flag never lights
// up the credential-leakage controls on its own — only a genuine leakage
// detection may add T1552/LLM02.
func TestSecretsBrokeredDoesNotEmitLeakagePair(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", nil, true)
	if hasControl(result, "T1552") || hasControl(result, "LLM02") {
		t.Error("secretsBrokered must not emit the T1552/LLM02 leakage pair without a leakage detection")
	}
	requireControls(t, result, "M1041")
}

// TestSecretsBrokeredCoexistsWithLeakageDetection verifies the protective M1041
// row and the leakage pair can both appear when a swap happens AND a genuine
// leakage detection fired — they are independent signals.
func TestSecretsBrokeredCoexistsWithLeakageDetection(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", []string{"credential-leak"}, true)
	requireOnlyControls(t, result, "M1041", "T1552", "LLM02", "T1071")
}

// TestNoSwapNoProtectiveControl verifies an event without a swap emits no
// secrets-brokering row.
func TestNoSwapNoProtectiveControl(t *testing.T) {
	mapper := NewMapper()
	result := mapper.MapEvent("allow", "https", nil, false)
	if hasControl(result, "M1041") {
		t.Error("expected no M1041 control when secretsBrokered is false")
	}
}
