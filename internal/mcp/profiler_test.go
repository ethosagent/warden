package mcp

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/scan"
)

// TestProfilerDetectorsAndEvidence verifies the profiler retains the specific
// detector (pattern + severity) per field path, and the opt-in masked evidence —
// and that the raw value is never stored.
func TestProfilerDetectorsAndEvidence(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner(scan.WithEvidence(true))
	const ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
	raw := json.RawMessage(`{"content":[{"text":"reach me a@b.com and ` + ghToken + `"}]}`)

	p.Observe("list_projects", DirResponse, raw, scanner)

	prof, ok := p.Snapshot()["list_projects\x00response"]
	if !ok {
		t.Fatal("no response profile recorded")
	}
	var dets []FieldDetector
	for path, fv := range prof.Fields {
		if len(fv.Detectors) > 0 {
			if !strings.Contains(path, "content[].text") {
				t.Errorf("detectors on unexpected path %q", path)
			}
			dets = fv.Detectors
		}
	}
	if len(dets) == 0 {
		t.Fatal("no detectors recorded on the flagged field")
	}
	byPattern := map[string]FieldDetector{}
	for _, d := range dets {
		byPattern[d.Pattern] = d
	}
	email, ok := byPattern["email"]
	if !ok || email.Category != "pii" || email.Severity != "medium" {
		t.Errorf("email detector wrong: %+v", email)
	}
	gh, ok := byPattern["github_token"]
	if !ok || gh.Category != "credential_leak" || gh.Severity != "high" {
		t.Errorf("github_token detector wrong: %+v", gh)
	}
	if gh.Evidence == "" || !strings.Contains(gh.Evidence, "•") {
		t.Errorf("expected masked evidence, got %q", gh.Evidence)
	}
	if strings.Contains(gh.Evidence, "ABCDEFGHIJKLMNOPQRST") {
		t.Fatalf("profiler stored the RAW value in evidence: %q", gh.Evidence)
	}
}

// fieldView fetches the view for a (tool, dir) profile and a single path.
func fieldView(t *testing.T, p *SchemaProfiler, tool string, dir Direction, path string) (FieldProfileView, bool) {
	t.Helper()
	snap := p.Snapshot()
	prof, ok := snap[profileKey(tool, dir)]
	if !ok {
		return FieldProfileView{}, false
	}
	fv, ok := prof.Fields[path]
	return fv, ok
}

func TestObserve_ShapeMergeWidensTypes(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	p.Observe("get", DirRequest, json.RawMessage(`{"id":1}`), scanner)
	p.Observe("get", DirRequest, json.RawMessage(`{"id":"x","name":"y"}`), scanner)

	id, ok := fieldView(t, p, "get", DirRequest, "params.id")
	if !ok {
		t.Fatal("expected params.id to be profiled")
	}
	if got := strings.Join(id.Types, ","); got != "number,string" {
		t.Errorf("params.id Types = %q, want \"number,string\"", got)
	}
	if id.SeenCount != 2 {
		t.Errorf("params.id SeenCount = %d, want 2", id.SeenCount)
	}

	name, ok := fieldView(t, p, "get", DirRequest, "params.name")
	if !ok {
		t.Fatal("expected params.name to be profiled")
	}
	if got := strings.Join(name.Types, ","); got != "string" {
		t.Errorf("params.name Types = %q, want \"string\"", got)
	}
	if name.SeenCount != 1 {
		t.Errorf("params.name SeenCount = %d, want 1", name.SeenCount)
	}
}

func TestObserve_ArraysCollapseToElementPath(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	p.Observe("list", DirRequest, json.RawMessage(`{"orders":[{"total":1},{"total":2}]}`), scanner)

	fv, ok := fieldView(t, p, "list", DirRequest, "params.orders[].total")
	if !ok {
		t.Fatal("expected params.orders[].total to be profiled")
	}
	if got := strings.Join(fv.Types, ","); got != "number" {
		t.Errorf("params.orders[].total Types = %q, want \"number\"", got)
	}
	// Two array elements both touched this path.
	if fv.SeenCount != 2 {
		t.Errorf("params.orders[].total SeenCount = %d, want 2", fv.SeenCount)
	}

	// No per-index path leaked in.
	snap := p.Snapshot()
	for path := range snap[profileKey("list", DirRequest)].Fields {
		if strings.Contains(path, "[0]") || strings.Contains(path, "[1]") {
			t.Errorf("found per-index path %q, expected collapsed [] form", path)
		}
	}
}

func TestObserve_PerFieldSensitivity(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	raw := json.RawMessage(`{"email":"a@b.com","card":"4111111111111111"}`)
	dets := p.Observe("acct", DirResponse, raw, scanner)

	email, ok := fieldView(t, p, "acct", DirResponse, "result.email")
	if !ok {
		t.Fatal("expected result.email to be profiled")
	}
	if !contains(email.Sensitivity, "pii") {
		t.Errorf("result.email Sensitivity = %v, want to contain \"pii\"", email.Sensitivity)
	}

	card, ok := fieldView(t, p, "acct", DirResponse, "result.card")
	if !ok {
		t.Fatal("expected result.card to be profiled")
	}
	if !contains(card.Sensitivity, "pii") {
		t.Errorf("result.card Sensitivity = %v, want to contain \"pii\"", card.Sensitivity)
	}

	// Returned FieldDetections carry the right paths.
	paths := make(map[string]bool)
	for _, d := range dets {
		paths[d.Path] = true
	}
	if !paths["result.email"] {
		t.Error("expected a FieldDetection for result.email")
	}
	if !paths["result.card"] {
		t.Error("expected a FieldDetection for result.card")
	}
}

func TestObserve_LuhnInvalidCardNoPII(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	// 16 digits but fails the Luhn checksum.
	raw := json.RawMessage(`{"card":"4111111111111112"}`)
	p.Observe("acct", DirResponse, raw, scanner)

	card, ok := fieldView(t, p, "acct", DirResponse, "result.card")
	if !ok {
		t.Fatal("expected result.card to be profiled")
	}
	if contains(card.Sensitivity, "pii") {
		t.Errorf("Luhn-invalid card should not be tagged pii, got %v", card.Sensitivity)
	}
}

func TestObserve_FieldCapBounded(t *testing.T) {
	p := NewSchemaProfiler(3)
	scanner := scan.NewScanner()

	obj := `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10}`
	p.Observe("big", DirRequest, json.RawMessage(obj), scanner)

	snap := p.Snapshot()
	prof := snap[profileKey("big", DirRequest)]
	if len(prof.Fields) > 3 {
		t.Errorf("field count = %d, want <= 3", len(prof.Fields))
	}

	// Existing paths still update on later calls even though the profile is full.
	// Pick one already-present path.
	var present string
	for path := range prof.Fields {
		present = path
		break
	}
	before := prof.Fields[present].SeenCount

	// Re-observe the whole object; present path's SeenCount must bump.
	p.Observe("big", DirRequest, json.RawMessage(obj), scanner)
	snap2 := p.Snapshot()
	after := snap2[profileKey("big", DirRequest)].Fields[present].SeenCount
	if after != before+1 {
		t.Errorf("existing path SeenCount = %d, want %d (existing paths must keep updating)", after, before+1)
	}
	if len(snap2[profileKey("big", DirRequest)].Fields) > 3 {
		t.Errorf("field count grew past cap to %d", len(snap2[profileKey("big", DirRequest)].Fields))
	}
}

func TestObserve_NoValuesStored(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	raw := json.RawMessage(`{"card":"4111111111111111","email":"secret@x.com","note":"4111111111111111"}`)
	p.Observe("leaky", DirResponse, raw, scanner)

	// Marshal the entire snapshot and assert no value substrings appear.
	snap := p.Snapshot()
	blob, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, secret := range []string{"4111111111111111", "secret@x.com"} {
		if strings.Contains(s, secret) {
			t.Errorf("snapshot leaked value %q: %s", secret, s)
		}
	}
}

func TestObserve_DirectionsKeyedSeparately(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	// Same tool, different shapes per direction.
	p.Observe("t", DirRequest, json.RawMessage(`{"q":"hi"}`), scanner)
	p.Observe("t", DirResponse, json.RawMessage(`{"items":[1,2]}`), scanner)

	if _, ok := fieldView(t, p, "t", DirRequest, "params.q"); !ok {
		t.Error("expected params.q in request profile")
	}
	if _, ok := fieldView(t, p, "t", DirResponse, "result.items[]"); !ok {
		t.Error("expected result.items[] in response profile")
	}
	// Request profile must not contain response paths and vice versa.
	snap := p.Snapshot()
	if _, ok := snap[profileKey("t", DirRequest)].Fields["result.items[]"]; ok {
		t.Error("request profile leaked a response path")
	}
	if _, ok := snap[profileKey("t", DirResponse)].Fields["params.q"]; ok {
		t.Error("response profile leaked a request path")
	}
}

func TestObserve_Concurrent(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Observe("tool", DirRequest, json.RawMessage(`{"id":1,"name":"x","tags":["a","b"]}`), scanner)
			p.Observe("tool", DirResponse, json.RawMessage(`{"email":"a@b.com"}`), scanner)
			_ = p.Snapshot()
		}()
	}
	wg.Wait()

	id, ok := fieldView(t, p, "tool", DirRequest, "params.id")
	if !ok {
		t.Fatal("expected params.id after concurrent observes")
	}
	if id.SeenCount != 50 {
		t.Errorf("params.id SeenCount = %d, want 50", id.SeenCount)
	}
}

func TestObserve_EmptyAndNil(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()
	if dets := p.Observe("x", DirRequest, nil, scanner); dets != nil {
		t.Errorf("nil raw should yield nil detections, got %v", dets)
	}
	if dets := p.Observe("x", DirRequest, json.RawMessage{}, scanner); dets != nil {
		t.Errorf("empty raw should yield nil detections, got %v", dets)
	}
	if len(p.Snapshot()) != 0 {
		t.Error("no profiles should exist after empty observes")
	}
}

func TestRestore_RoundTripsSnapshot(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()
	p.Observe("get", DirRequest, json.RawMessage(`{"id":1,"name":"y"}`), scanner)
	p.Observe("get", DirRequest, json.RawMessage(`{"id":"x"}`), scanner)
	p.Observe("send", DirResponse, json.RawMessage(`{"ok":true}`), scanner)

	snap := p.Snapshot()

	restored := NewSchemaProfiler(0)
	restored.Restore(snap)

	got := restored.Snapshot()
	if !reflect.DeepEqual(got, snap) {
		t.Fatalf("Restore(Snapshot()) mismatch:\n got=%#v\nwant=%#v", got, snap)
	}

	// Restored profiler must own independent state: mutating the source snapshot
	// after Restore must not affect the restored profiler.
	for _, view := range snap {
		for _, fv := range view.Fields {
			if len(fv.Types) > 0 {
				fv.Types[0] = "MUTATED"
			}
		}
	}
	if !reflect.DeepEqual(restored.Snapshot(), got) {
		t.Error("Restore did not deep-copy: mutating source snapshot changed restored state")
	}
}

func TestRestore_NilIsIgnored(t *testing.T) {
	p := NewSchemaProfiler(0)
	scanner := scan.NewScanner()
	p.Observe("get", DirRequest, json.RawMessage(`{"id":1}`), scanner)
	before := p.Snapshot()
	p.Restore(nil)
	if !reflect.DeepEqual(p.Snapshot(), before) {
		t.Error("Restore(nil) should be a no-op")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
