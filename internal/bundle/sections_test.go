package bundle

import (
	"encoding/json"
	"testing"
)

// TestParsePerUserSections: the per-user sections decode, an absent one is nil,
// unknown members are ignored (a later control plane may add some), and a
// malformed one is an error.
func TestParsePerUserSections(t *testing.T) {
	s, err := ParsePerUserSecrets(json.RawMessage(`{"workerCacheTTLSeconds":60,"future":1,"mappings":[{"placeholder":"P","provider":"g","scopes":[],"domains":["a.example"],"in":["header"],"agents":["x"],"later":true}]}`))
	if err != nil || s == nil || s.WorkerCacheTTLSeconds != 60 || len(s.Mappings) != 1 || s.Mappings[0].Agents[0] != "x" {
		t.Fatalf("ParsePerUserSecrets = %+v, %v", s, err)
	}
	if s, err := ParsePerUserSecrets(nil); s != nil || err != nil {
		t.Errorf("absent perUserSecrets = %v, %v, want nil", s, err)
	}
	if _, err := ParsePerUserSecrets(json.RawMessage(`[1]`)); err == nil {
		t.Error("a malformed perUserSecrets section decoded")
	}
	e, err := ParseUserGrantEpochs(json.RawMessage(`{"0123456789abcdef0123456789abcdef":7}`))
	if err != nil || e["0123456789abcdef0123456789abcdef"] != 7 {
		t.Fatalf("ParseUserGrantEpochs = %v, %v", e, err)
	}
	if e, err := ParseUserGrantEpochs(nil); e != nil || err != nil {
		t.Errorf("absent userGrantEpochs = %v, %v, want nil", e, err)
	}
	if _, err := ParseUserGrantEpochs(json.RawMessage(`{"k":"x"}`)); err == nil {
		t.Error("a malformed userGrantEpochs section decoded")
	}
}
